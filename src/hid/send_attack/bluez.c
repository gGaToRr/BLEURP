

#include <signal.h>
#include "bluez.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <dbus/dbus.h>

#define BLUEZ_BUS     "org.bluez"
#define AGENT_MGR     "org.bluez.AgentManager1"
#define AGENT_IFACE   "org.bluez.Agent"
#define PROP_IFACE    "org.freedesktop.DBus.Properties"
#define AGENT_PATH    "/org/blueducky/agent"
#define AGENT_CAP     "NoInputNoOutput"

static void dev_path(char *out, size_t len, const char *adapter, const char *mac)
{
    char up[32];
    snprintf(up, sizeof(up), "%s", mac);
    for (char *p = up; *p; p++)
        *p = (*p == ':') ? '_' : (char)toupper((unsigned char)*p);
    snprintf(out, len, "/org/bluez/%s/dev_%s", adapter, up);
}

static DBusMessage *call(DBusConnection *c, const char *path, const char *iface,
                         const char *method, int timeout_ms)
{
    DBusMessage *msg = dbus_message_new_method_call(BLUEZ_BUS, path, iface, method);
    if (!msg) return NULL;
    DBusError err;
    dbus_error_init(&err);
    DBusMessage *rep = dbus_connection_send_with_reply_and_block(c, msg, timeout_ms, &err);
    dbus_message_unref(msg);
    if (!rep) {
        fprintf(stderr, "bluez: %s: %s\n", method, err.message);
        dbus_error_free(&err);
    }
    return rep;
}

/* ---- Agent (processus fils) ---- */

static void agent_serve(DBusConnection *c)
{
    while (dbus_connection_read_write_dispatch(c, -1)) {
        DBusMessage *m = dbus_connection_pop_message(c);
        if (!m) continue;

        if (dbus_message_is_method_call(m, AGENT_IFACE, dbus_message_get_member(m))) {
            const char *member = dbus_message_get_member(m);
            DBusMessage *rep = dbus_message_new_method_return(m);

            if (!strcmp(member, "RequestPinCode")) {
                const char *pin = "0000";
                dbus_message_append_args(rep, DBUS_TYPE_STRING, &pin, DBUS_TYPE_INVALID);
            } else if (!strcmp(member, "RequestPasskey")) {
                dbus_uint32_t pk = 0;
                dbus_message_append_args(rep, DBUS_TYPE_UINT32, &pk, DBUS_TYPE_INVALID);
            }
            /* RequestConfirmation, RequestAuthorization, AuthorizeService,
               DisplayPasskey, DisplayPinCode, Release, Cancel :
               réponse vide = acceptation. */

            dbus_connection_send(c, rep, NULL);
            dbus_message_unref(rep);
        }
        dbus_message_unref(m);
    }
}

static void agent_loop(void)
{
    DBusError err;
    dbus_error_init(&err);
    DBusConnection *c = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!c) _exit(1);

    /* RegisterAgent(path, capability) */
    DBusMessage *msg = dbus_message_new_method_call(
        BLUEZ_BUS, "/org/bluez", AGENT_MGR, "RegisterAgent");
    const char *path = AGENT_PATH, *cap = AGENT_CAP;
    dbus_message_append_args(msg,
        DBUS_TYPE_OBJECT_PATH, &path,
        DBUS_TYPE_STRING, &cap, DBUS_TYPE_INVALID);
    DBusMessage *rep = dbus_connection_send_with_reply_and_block(c, msg, 5000, &err);
    dbus_message_unref(msg);
    if (!rep) _exit(1);
    dbus_message_unref(rep);

    /* RequestDefaultAgent(path) — best effort */
    msg = dbus_message_new_method_call(BLUEZ_BUS, "/org/bluez", AGENT_MGR,
                                       "RequestDefaultAgent");
    dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID);
    rep = dbus_connection_send_with_reply_and_block(c, msg, 5000, NULL);
    if (rep) dbus_message_unref(rep);
    dbus_message_unref(msg);

    agent_serve(c);
    _exit(0);
}

int bluez_agent_start(const char *adapter, pid_t *out_pid)
{
    (void)adapter; /* l'agent est enregistré au niveau AgentManager, pas adapter */
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        /* Meurt automatiquement si le parent meurt */
        prctl(PR_SET_PDEATHSIG, SIGTERM);
        agent_loop();
        _exit(1); /* inatteignable */
    }
    *out_pid = pid;
    return 0;
}

void bluez_agent_stop(pid_t pid)
{
    if (pid <= 0) return;
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
}

/* ---- Opérations device ---- */

int bluez_device_remove(const char *adapter, const char *mac)
{
    char path[128];
    dev_path(path, sizeof(path), adapter, mac);

    char adapter_path[64];
    snprintf(adapter_path, sizeof(adapter_path), "/org/bluez/%s", adapter);

    DBusError err;
    dbus_error_init(&err);
    DBusConnection *c = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!c) return -1;

    DBusMessage *msg = dbus_message_new_method_call(
        BLUEZ_BUS, adapter_path, "org.bluez.Adapter1", "RemoveDevice");
    const char *obj = path;
    dbus_message_append_args(msg, DBUS_TYPE_OBJECT_PATH, &obj, DBUS_TYPE_INVALID);

    DBusMessage *rep = dbus_connection_send_with_reply_and_block(c, msg, 5000, &err);
    dbus_message_unref(msg);
    /* Device absent = pas grave */
    if (!rep) dbus_error_free(&err);
    else dbus_message_unref(rep);
    return rep ? 0 : -1;
}

/* Fait decouvrir la cible par bluetoothd : StartDiscovery, attend que
   l'objet Device1 apparaisse (le scan mgmt ne le cree pas), puis
   StopDiscovery. Sans ca, Pair() echoue avec "Device1 doesn't exist". */
int bluez_device_discover(const char *adapter, const char *mac)
{
    DBusError err;
    dbus_error_init(&err);
    DBusConnection *c = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!c) { dbus_error_free(&err); return -1; }

    char apath[64];
    snprintf(apath, sizeof(apath), "/org/bluez/%s", adapter);

    DBusMessage *rep = call(c, apath, "org.bluez.Adapter1", "StartDiscovery", 5000);
    if (rep) dbus_message_unref(rep);

    char path[128];
    dev_path(path, sizeof(path), adapter, mac);

    int found = -1;
    for (int i = 0; i < 20; i++) {          /* 20 x 500ms = 10s max */
        DBusMessage *m = dbus_message_new_method_call(BLUEZ_BUS, path,
                                                      PROP_IFACE, "Get");
        if (m) {
            const char *iface = "org.bluez.Device1", *prop = "Address";
            dbus_message_append_args(m, DBUS_TYPE_STRING, &iface,
                                     DBUS_TYPE_STRING, &prop, DBUS_TYPE_INVALID);
            DBusError e;
            dbus_error_init(&e);
            DBusMessage *r = dbus_connection_send_with_reply_and_block(c, m, 1000, &e);
            dbus_message_unref(m);
            if (r) { dbus_message_unref(r); found = 0; break; }
            dbus_error_free(&e);
        }
        usleep(500000);
    }

    rep = call(c, apath, "org.bluez.Adapter1", "StopDiscovery", 5000);
    if (rep) dbus_message_unref(rep);

    return found;
}

int bluez_device_pair(const char *adapter, const char *mac)
{
    char path[128];
    dev_path(path, sizeof(path), adapter, mac);

    DBusError err;
    dbus_error_init(&err);
    DBusConnection *c = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!c) return -1;

    DBusMessage *rep = call(c, path, "org.bluez.Device1", "Pair", 30000);
    if (rep) dbus_message_unref(rep);
    return rep ? 0 : -1;
}

int bluez_device_trust(const char *adapter, const char *mac)
{
    char path[128];
    dev_path(path, sizeof(path), adapter, mac);

    DBusError err;
    dbus_error_init(&err);
    DBusConnection *c = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!c) return -1;

    DBusMessage *msg = dbus_message_new_method_call(
        BLUEZ_BUS, path, PROP_IFACE, "Set");
    DBusMessageIter iter, var;
    dbus_message_iter_init_append(msg, &iter);
    const char *iface = "org.bluez.Device1", *prop = "Trusted";
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &iface);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &prop);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_VARIANT, "b", &var);
    dbus_bool_t val = TRUE;
    dbus_message_iter_append_basic(&var, DBUS_TYPE_BOOLEAN, &val);
    dbus_message_iter_close_container(&iter, &var);

    dbus_connection_send(c, msg, NULL);
    dbus_connection_flush(c);
    dbus_message_unref(msg);
    return 0;
}
