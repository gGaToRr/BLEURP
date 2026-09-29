// ========================================
//  nom du fichier: main.c
//  description courte: BLEURP entry point. Drives kernel mgmt LE discovery,
//  parses advertising data, merges devices into a table and renders a live,
//  wifite-style sorted view until a duration elapses or Ctrl-C is pressed.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ad_parse.h"
#include "addr_priv.h"
#include "audit.h"
#include "banner.h"
#include "dev_table.h"
#include "gatt.h"
#include "l2cap.h"
#include "mgmt.h"
#include "smp.h"
#include "ui.h"
#include "hid_cmd.h"
#include "fingerprint.h"
#include "smp_native.h"
#include "peripheral_native.h"
#include "hci_dev.h"

// How often to re-arm discovery, to keep reports flowing and refresh the
// view (wifite keeps a continuous scan going and redraws steadily).
#define SCAN_REFRESH_SEC 10

// Set by SIGINT so the scan loop can stop cleanly.
static volatile sig_atomic_t g_stop = 0;

// SIGINT handler: request a clean stop.
static void on_sigint(int sig) {
    (void)sig;
    g_stop = 1;
}

// Context passed to the per-device callback.
struct scan_ctx {
    struct dev_table *table;
};


// Merge one discovered device into the table. We only trust the real device
// name (from the advertising data or scan response); we do NOT guess a vendor
// from the manufacturer company id, which produces misleading labels (e.g.
// everything showing as "Apple"). No name -> shown as unknown. The verbose
// vendor/service summary is stored separately in the entry's details.
static void on_device(const struct mgmt_device *d, void *user) {
    struct scan_ctx *c = user;
    struct ad_info info;
    int ok = (ad_parse(d->eir, d->eir_len, &info) == 0);
    const char *name = (ok && info.has_name) ? info.name : "";
    struct dev_entry *e = dev_table_upsert(c->table, d->address, d->addr_type,
                                           d->rssi, name, time(NULL));
    if (e) {
        // Build a passive fingerprint from the advertising data and the
        // address posture: category, vendor, privacy and an exposure score.
        struct fingerprint fp = fingerprint_make(ok ? &info : NULL,
                                                e->address, e->addr_type);
        fingerprint_summary(&fp, e->details, sizeof e->details);
        strncpy(e->category, fp.category_label, sizeof e->category - 1);
        e->category[sizeof e->category - 1] = '\0';
        e->exposure = fp.exposure;
    }
}

// Print usage for the scan command / top level.
static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s                                      interactive menu (default)\n"
            "  %s wizard                               guided all-in-one audit pipeline\n"
            "  %s scan  [-i index] [-t seconds] [-v]   live BLE scan\n"
            "  %s enum  <ADDR> [-t public|random]      connect and dump GATT\n"
            "  %s audit <ADDR> [-t public|random]      audit unauthenticated GATT access\n"
            "  %s read  <ADDR> <handle> [-t ...]       read a value by handle\n"
            "  %s write <ADDR> <handle> <hex> [-t ...] write bytes by handle\n"
            "  %s hid   -i hciX -t <ADDR> -f <payload> send a HID payload\n"
            "  %s smp   <ADDR> [-i index] [-t ...]     probe SMP pairing security level (native HCI)\n"
            "  %s keyboard [-i index] [-n name] [-d ..] BLE Keyboard Peripheral emulator (HOGP)\n"
            "  -i index    HCI controller index (default 0 = hci0)\n"
            "  -t seconds  scan duration; 0 = until Ctrl-C (default 0)\n"
            "  -v          verbose scan (per-device vendor/services details)\n"
            "Only use on devices you own or are authorized to test.\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}

// Write an mgmt packet; returns 0 if the write did not error, -1 otherwise.
static int send_pkt(int fd, const uint8_t *pkt, ssize_t n) {
    if (n < 0) {
        return -1;
    }
    return (write(fd, pkt, (size_t)n) < 0) ? -1 : 0;
}

// Run a live scan into `table` (already initialized) until `duration` seconds
// elapse or Ctrl-C. `verbose` shows a per-device details line. Returns 0 on a
// normal stop, or -1 on a setup failure (message already printed).
static int run_scan(int index, long duration, int verbose,
                    struct dev_table *table) {
    g_stop = 0;

    int fd = mgmt_open();
    if (fd < 0) {
        perror("mgmt_open");
        return -1;
    }

    uint8_t cmd[64];
    uint8_t buf[2048];

    // Read controller info to show the adapter and confirm LE support.
    ssize_t n = mgmt_build_command(cmd, sizeof cmd, MGMT_OP_READ_CONTROLLER_INFO,
                                   (uint16_t)index, NULL, 0);
    if (send_pkt(fd, cmd, n) < 0) { perror("write"); mgmt_close(fd); return -1; }
    ssize_t r = read(fd, buf, sizeof buf);
    struct mgmt_controller_info info;
    if (r > 0 && mgmt_parse_controller_info(buf, (size_t)r, &info) == 0) {
        printf("Adapter hci%d: %02X:%02X:%02X:%02X:%02X:%02X  BT v%u  '%s'  "
               "LE=%s  powered=%s\n", index,
               info.address[5], info.address[4], info.address[3],
               info.address[2], info.address[1], info.address[0],
               info.bluetooth_version, info.name,
               mgmt_has_setting(info.supported_settings, MGMT_SETTING_LE) ? "yes" : "no",
               mgmt_has_setting(info.current_settings, MGMT_SETTING_POWERED) ? "yes" : "no");
        if (!mgmt_has_setting(info.current_settings, MGMT_SETTING_POWERED)) {
            fprintf(stderr, "warning: adapter not powered (bluetoothctl power on)\n");
        }
    } else {
        fprintf(stderr, "warning: could not read controller info\n");
    }

    // Start LE discovery, then read the command response to catch errors.
    n = mgmt_build_start_discovery(cmd, sizeof cmd, (uint16_t)index, MGMT_ADDR_LE);
    if (send_pkt(fd, cmd, n) < 0) { perror("write"); mgmt_close(fd); return -1; }

    r = read(fd, buf, sizeof buf);
    if (r >= 9) {
        struct mgmt_hdr h;
        mgmt_parse_header(buf, (size_t)r, &h);
        if (h.opcode == MGMT_EV_CMD_STATUS || h.opcode == MGMT_EV_CMD_COMPLETE) {
            uint8_t status = buf[8];
            if (status != 0x00) {
                fprintf(stderr, "Start Discovery failed: mgmt status 0x%02x%s\n",
                        status, status == 0x14 ?
                        " (Permission Denied: run with sudo, or setcap cap_net_admin)" : "");
                mgmt_close(fd);
                return -1;
            }
        }
    }

    struct scan_ctx ctx = { .table = table };

    // A Device Found may have arrived in the response read above.
    if (r > 0) { (void)mgmt_dispatch_event(buf, (size_t)r, on_device, &ctx); }

    signal(SIGINT, on_sigint);
    time_t start = time(NULL);
    time_t last_refresh = start;
    printf("\033[2J"); // clear once before the live view

    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    while (!g_stop) {
        time_t now = time(NULL);
        if (duration > 0 && (now - start) >= duration) {
            break;
        }
        int pr = poll(&pfd, 1, 250);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            ssize_t m = read(fd, buf, sizeof buf);
            if (m > 0) { (void)mgmt_dispatch_event(buf, (size_t)m, on_device, &ctx); }
        }

        // Periodic re-scan: stop then start discovery to re-arm the kernel
        // scan so reports keep coming and the view stays fresh.
        now = time(NULL);
        if (now - last_refresh >= SCAN_REFRESH_SEC) {
            n = mgmt_build_stop_discovery(cmd, sizeof cmd, (uint16_t)index, MGMT_ADDR_LE);
            (void)send_pkt(fd, cmd, n);
            n = mgmt_build_start_discovery(cmd, sizeof cmd, (uint16_t)index, MGMT_ADDR_LE);
            (void)send_pkt(fd, cmd, n);
            last_refresh = now;
        }

        dev_table_sort_by_rssi(table);
        ui_render(table, start, now, verbose, stdout);
    }

    // Stop discovery and draw a final frame.
    n = mgmt_build_stop_discovery(cmd, sizeof cmd, (uint16_t)index, MGMT_ADDR_LE);
    (void)send_pkt(fd, cmd, n);
    dev_table_sort_by_rssi(table);
    ui_render(table, start, time(NULL), verbose, stdout);

    mgmt_close(fd);
    return 0;
}

// scan subcommand: a one-shot live scan (until duration or Ctrl-C).
static int cmd_scan(int argc, char **argv) {
    int index = 0;
    long duration = 0;
    int verbose = 0;

    int opt;
    while ((opt = getopt(argc, argv, "i:t:vh")) != -1) {
        switch (opt) {
        case 'i': index = atoi(optarg); break;
        case 't': duration = atol(optarg); break;
        case 'v': verbose = 1; break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }

    struct dev_table table;
    if (dev_table_init(&table) < 0) { perror("dev_table_init"); return 1; }
    int rc = run_scan(index, duration, verbose, &table);
    printf("\nStopped. %zu device(s) found.\n", dev_table_count(&table));
    dev_table_free(&table);
    return rc < 0 ? 1 : 0;
}

// Parse "AA:BB:CC:DD:EE:FF" into HCI byte order (LSB first). Returns 0 or -1.
static int parse_addr(const char *s, uint8_t out[6]) {
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff) return -1;
        out[5 - i] = (uint8_t)v[i]; // typed MSB-first -> stored LSB-first
    }
    return 0;
}

// Format characteristic properties as short flags, e.g. "R W N".
static void props_str(uint8_t p, char *buf, size_t n) {
    buf[0] = '\0';
    struct { uint8_t bit; const char *s; } m[] = {
        {GATT_PROP_READ, "R"}, {GATT_PROP_WRITE, "W"},
        {GATT_PROP_WRITE_NR, "w"}, {GATT_PROP_NOTIFY, "N"},
        {GATT_PROP_INDICATE, "I"},
    };
    for (size_t i = 0; i < sizeof m / sizeof m[0]; i++) {
        if (p & m[i].bit) {
            if (buf[0] != '\0') strncat(buf, " ", n - strlen(buf) - 1);
            strncat(buf, m[i].s, n - strlen(buf) - 1);
        }
    }
}

// Connect to a device and print its GATT tree. Address is in HCI byte order.
static int do_enum(const uint8_t addr[6], uint8_t atype) {
    char as[18];
    snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);

    fprintf(stderr, "Authorized targets only. Connecting to %s ...\n", as);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    uint16_t mtu = 0;
    (void)gatt_exchange_mtu(fd, 517, &mtu);
    printf("Connected to %s (ATT MTU=%u)\n\n", as, mtu ? mtu : 23);

    struct gatt_service svcs[64];
    size_t nsvc = 0;
    if (gatt_discover_services(fd, svcs, 64, &nsvc) < 0) {
        perror("discover services");
        bleurp_l2_close(fd);
        return 1;
    }

    size_t shown = nsvc < 64 ? nsvc : 64;
    printf("GATT tree (%zu service(s)):\n", nsvc);
    for (size_t i = 0; i < shown; i++) {
        const struct gatt_service *s = &svcs[i];
        if (s->uuid_is_128) {
            printf("[SVC] 0x%04X-0x%04X  128-bit UUID\n", s->start_handle, s->end_handle);
        } else {
            const char *name = ad_service_name(s->uuid16);
            printf("[SVC] 0x%04X-0x%04X  0x%04X%s%s\n", s->start_handle,
                   s->end_handle, s->uuid16, name ? "  " : "", name ? name : "");
        }
        struct gatt_char chs[64];
        size_t nch = 0;
        gatt_discover_characteristics(fd, s->start_handle, s->end_handle, chs, 64, &nch);
        size_t cshown = nch < 64 ? nch : 64;
        for (size_t j = 0; j < cshown; j++) {
            const struct gatt_char *c = &chs[j];
            char pr[16];
            props_str(c->properties, pr, sizeof pr);
            if (c->uuid_is_128) {
                printf("   [CHR] val 0x%04X  [%s]  128-bit UUID\n", c->value_handle, pr);
            } else {
                printf("   [CHR] val 0x%04X  [%s]  0x%04X\n", c->value_handle, pr, c->uuid16);
            }
        }
    }

    bleurp_l2_close(fd);
    return 0;
}

// Probe one readable characteristic and print its audit verdict. Reads the
// value handle and classifies the outcome; never writes. `atype` is unused
// beyond the already-open socket but kept for signature symmetry.
static void audit_probe_char(int fd, const struct gatt_char *c) {
    char pr[16];
    props_str(c->properties, pr, sizeof pr);

    char uuid[24];
    if (c->uuid_is_128) snprintf(uuid, sizeof uuid, "128-bit");
    else                snprintf(uuid, sizeof uuid, "0x%04X", c->uuid16);

    const char *svc_name = c->uuid_is_128 ? NULL : ad_service_name(c->uuid16);

    if (c->properties & GATT_PROP_READ) {
        uint8_t buf[517];
        size_t len = 0;
        uint8_t err = 0;
        int rc = gatt_read(fd, c->value_handle, buf, sizeof buf, &len, &err);
        audit_verdict_t v = audit_classify_read(rc == 0, err);
        printf("  0x%04X  [%-6s]  %-8s %-10s", c->value_handle, pr, uuid,
               audit_verdict_label(v));
        if (v == AUDIT_OPEN)           printf(" %zu byte(s) readable unauthenticated", len);
        else if (v == AUDIT_PROTECTED) printf(" needs pairing (ATT 0x%02x)", err);
        else if (v == AUDIT_OTHER && err) printf(" ATT 0x%02x", err);
        if (svc_name) printf("  (%s)", svc_name);
        printf("\n");
    } else {
        // Not readable: report the capability, do not touch the value.
        printf("  0x%04X  [%-6s]  %-8s %-10s", c->value_handle, pr, uuid, "-");
        if (c->properties & (GATT_PROP_WRITE | GATT_PROP_WRITE_NR | GATT_PROP_SIGNED_WRITE))
            printf(" write-capable (not tested)");
        if (svc_name) printf("  (%s)", svc_name);
        printf("\n");
    }
}

// Connect to an authorized device and audit which characteristics are
// accessible without pairing. Reads readable values only; write-capable
// characteristics are reported but never written. Address is in HCI order.
static int do_audit(const uint8_t addr[6], uint8_t atype) {
    char as[18];
    snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);

    addr_privacy_t p = addr_privacy(addr, atype);
    fprintf(stderr, "Authorized targets only. Connecting to %s ...\n", as);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    uint16_t mtu = 0;
    (void)gatt_exchange_mtu(fd, 517, &mtu);
    printf("GATT access audit for %s (priv=%s%s, ATT MTU=%u)\n\n", as,
           addr_privacy_label(p), addr_is_trackable(p) ? " [trackable]" : "",
           mtu ? mtu : 23);

    struct gatt_service svcs[64];
    size_t nsvc = 0;
    if (gatt_discover_services(fd, svcs, 64, &nsvc) < 0) {
        perror("discover services");
        bleurp_l2_close(fd);
        return 1;
    }

    printf("  handle  props       uuid     verdict    detail\n");
    printf("  ------  ----------  -------- ---------- ------\n");
    size_t shown = nsvc < 64 ? nsvc : 64;
    for (size_t i = 0; i < shown; i++) {
        struct gatt_char chs[64];
        size_t nch = 0;
        gatt_discover_characteristics(fd, svcs[i].start_handle,
                                      svcs[i].end_handle, chs, 64, &nch);
        size_t cshown = nch < 64 ? nch : 64;
        for (size_t j = 0; j < cshown; j++)
            audit_probe_char(fd, &chs[j]);
    }

    printf("\nLegend: OPEN=readable without pairing  PROTECTED=needs pairing"
           "  DENIED=read not permitted  OTHER=other ATT error\n");
    bleurp_l2_close(fd);
    return 0;
}

// enum subcommand: parse the address/type then dump the GATT tree.
static int cmd_enum(int argc, char **argv) {
    uint8_t atype = BLEURP_BDADDR_LE_PUBLIC;
    int opt;
    while ((opt = getopt(argc, argv, "t:h")) != -1) {
        switch (opt) {
        case 't':
            atype = (strcmp(optarg, "random") == 0) ? BLEURP_BDADDR_LE_RANDOM
                                                     : BLEURP_BDADDR_LE_PUBLIC;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: bleurp enum <ADDR> [-t public|random]\n");
            return (opt == 'h') ? 0 : 2;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Usage: bleurp enum <ADDR> [-t public|random]\n");
        return 2;
    }
    uint8_t addr[6];
    if (parse_addr(argv[optind], addr) < 0) {
        fprintf(stderr, "invalid address: %s\n", argv[optind]);
        return 2;
    }
    return do_enum(addr, atype);
}

// audit subcommand: parse the address/type then audit unauthenticated access.
static int cmd_audit(int argc, char **argv) {
    uint8_t atype = BLEURP_BDADDR_LE_PUBLIC;
    int opt;
    while ((opt = getopt(argc, argv, "t:h")) != -1) {
        switch (opt) {
        case 't':
            atype = (strcmp(optarg, "random") == 0) ? BLEURP_BDADDR_LE_RANDOM
                                                     : BLEURP_BDADDR_LE_PUBLIC;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: bleurp audit <ADDR> [-t public|random]\n");
            return (opt == 'h') ? 0 : 2;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Usage: bleurp audit <ADDR> [-t public|random]\n");
        return 2;
    }
    uint8_t addr[6];
    if (parse_addr(argv[optind], addr) < 0) {
        fprintf(stderr, "invalid address: %s\n", argv[optind]);
        return 2;
    }
    return do_audit(addr, atype);
}

// Hex digit value, or -1.
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse a 16-bit number (accepts 0x-prefixed). Returns 0 or -1.
static int parse_u16(const char *s, uint16_t *out) {
    char *end;
    long v = strtol(s, &end, 0);
    if (*end != '\0' || v < 0 || v > 0xffff) return -1;
    *out = (uint16_t)v;
    return 0;
}

// Parse a hex string (optional ':'/' ' separators) into bytes. Returns len or -1.
static ssize_t parse_hex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (*s) {
        if (*s == ':' || *s == ' ') { s++; continue; }
        int hi = hexval(*s++);
        int lo = (*s) ? hexval(*s++) : -1;
        if (hi < 0 || lo < 0 || n >= cap) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return (ssize_t)n;
}

// Shared option/positional parse for read/write: address + handle (+ value).
static int connect_target(int argc, char **argv, uint8_t addr[6],
                          uint8_t *atype, int *pos) {
    *atype = BLEURP_BDADDR_LE_PUBLIC;
    int opt;
    while ((opt = getopt(argc, argv, "t:h")) != -1) {
        if (opt == 't') {
            *atype = (strcmp(optarg, "random") == 0) ? BLEURP_BDADDR_LE_RANDOM
                                                      : BLEURP_BDADDR_LE_PUBLIC;
        } else {
            return -1;
        }
    }
    if (optind >= argc || parse_addr(argv[optind], addr) < 0) return -1;
    *pos = optind + 1;
    return 0;
}

// read subcommand: read a characteristic/descriptor value by handle.
static int cmd_read(int argc, char **argv) {
    uint8_t addr[6], atype;
    int pos;
    if (connect_target(argc, argv, addr, &atype, &pos) < 0 || pos >= argc) {
        fprintf(stderr, "Usage: bleurp read <ADDR> <handle> [-t public|random]\n");
        return 2;
    }
    uint16_t handle;
    if (parse_u16(argv[pos], &handle) < 0) {
        fprintf(stderr, "invalid handle: %s\n", argv[pos]);
        return 2;
    }

    fprintf(stderr, "Authorized targets only. Connecting to %s ...\n", argv[optind]);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) { perror("connect"); return 1; }
    (void)gatt_exchange_mtu(fd, 517, NULL);

    uint8_t buf[512];
    size_t len = 0;
    uint8_t err = 0;
    if (gatt_read(fd, handle, buf, sizeof buf, &len, &err) < 0) {
        if (err) fprintf(stderr, "read denied (ATT error 0x%02x)\n", err);
        else perror("read");
        bleurp_l2_close(fd);
        return 1;
    }
    printf("handle 0x%04X = %zu byte(s):\n  hex:", handle, len);
    for (size_t i = 0; i < len; i++) printf(" %02x", buf[i]);
    printf("\n  txt: ");
    for (size_t i = 0; i < len; i++) putchar((buf[i] >= 32 && buf[i] < 127) ? buf[i] : '.');
    printf("\n");
    bleurp_l2_close(fd);
    return 0;
}

// write subcommand: write bytes to a characteristic by handle.
static int cmd_write(int argc, char **argv) {
    uint8_t addr[6], atype;
    int pos;
    if (connect_target(argc, argv, addr, &atype, &pos) < 0 || pos + 1 >= argc) {
        fprintf(stderr, "Usage: bleurp write <ADDR> <handle> <hexbytes> [-t public|random]\n");
        return 2;
    }
    uint16_t handle;
    if (parse_u16(argv[pos], &handle) < 0) {
        fprintf(stderr, "invalid handle: %s\n", argv[pos]);
        return 2;
    }
    uint8_t value[512];
    ssize_t vlen = parse_hex(argv[pos + 1], value, sizeof value);
    if (vlen < 0) {
        fprintf(stderr, "invalid hex value: %s\n", argv[pos + 1]);
        return 2;
    }

    fprintf(stderr, "Authorized targets only. Writing %zd byte(s) to handle 0x%04X ...\n",
            (ssize_t)vlen, handle);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) { perror("connect"); return 1; }
    (void)gatt_exchange_mtu(fd, 517, NULL);

    uint8_t err = 0;
    if (gatt_write(fd, handle, value, (size_t)vlen, &err) < 0) {
        if (err) fprintf(stderr, "write denied (ATT error 0x%02x)\n", err);
        else perror("write");
        bleurp_l2_close(fd);
        return 1;
    }
    printf("write ok (handle 0x%04X)\n", handle);
    bleurp_l2_close(fd);
    return 0;
}

// smp subcommand: probe SMP pairing security parameters via native HCI User Channel.
static int cmd_smp_native(int argc, char **argv) {
    int dev_id = 0;
    uint8_t atype = BLEURP_BDADDR_LE_PUBLIC;
    int opt;
    while ((opt = getopt(argc, argv, "i:t:h")) != -1) {
        switch (opt) {
        case 'i': dev_id = atoi(optarg); break;
        case 't':
            atype = (strcmp(optarg, "random") == 0) ? BLEURP_BDADDR_LE_RANDOM
                                                     : BLEURP_BDADDR_LE_PUBLIC;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: bleurp smp <ADDR> [-i index] [-t public|random]\n");
            return (opt == 'h') ? 0 : 2;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Usage: bleurp smp <ADDR> [-i index] [-t public|random]\n");
        return 2;
    }
    uint8_t addr[6];
    if (parse_addr(argv[optind], addr) < 0) {
        fprintf(stderr, "invalid address: %s\n", argv[optind]);
        return 2;
    }

    char as[18];
    snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);

    printf("Connecting to %s (hci%d, type=%s) via native HCI User Channel...\n",
           as, dev_id, atype == BLEURP_BDADDR_LE_RANDOM ? "random" : "public");

    struct smp_probe_result res;
    if (smp_native_probe_device(dev_id, addr, atype, 6000, &res) < 0) {
        fprintf(stderr, "Sonde SMP échouée (vérifiez que rfkill/bluetoothd ne verrouille pas l'interface, ou lancez ./scripts/reset_bluetooth.sh)\n");
        return 1;
    }

    smp_native_print_result(&res, as);
    return 0;
}

// Read a line from stdin into buf (newline stripped). Returns 0 or -1 on EOF.
static int read_line(char *buf, size_t n) {
    if (!fgets(buf, (int)n, stdin)) return -1;
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

// Ask a yes/no question with a short description; empty input keeps the
// default. Used by the scan wizard below.
static int ask_yes_no(const char *label, const char *desc, int default_yes) {
    printf("  %s%s%s  %s(%s)%s [%s]: ", UI_PINK, label, UI_RESET,
           UI_PURPLE, desc, UI_RESET, default_yes ? "O/n" : "o/N");
    fflush(stdout);
    char line[16];
    if (read_line(line, sizeof line) < 0 || line[0] == '\0') return default_yes;
    return (line[0] == 'o' || line[0] == 'O' || line[0] == 'y' || line[0] == 'Y');
}

// Ask a numeric value with a short description; empty or invalid input
// keeps the default. Used by the scan wizard below.
static long ask_number(const char *label, const char *desc, long default_val) {
    printf("  %s%s%s  %s(%s)%s [%ld]: ", UI_PINK, label, UI_RESET,
           UI_PURPLE, desc, UI_RESET, default_val);
    fflush(stdout);
    char line[32];
    if (read_line(line, sizeof line) < 0 || line[0] == '\0') return default_val;
    char *end;
    long v = strtol(line, &end, 10);
    if (*end != '\0') return default_val;
    return v;
}

// Ask which HCI controller to use. Accepts either a plain index ("1") or
// the "hciN" form ("hci1", as the real CLI's -i flag and its own usage
// text expect), so a device on hci1 works from the menu just as it does
// via `bleurp scan -i 1` or `bleurp hid -i hci1 ...`. Falls back to the
// default on anything else (no silent drop back to hci0 on a typo).
static long ask_interface(long default_val) {
    printf("  %sInterface%s  %s(index ou nom, ex. 1 ou hci1 ; %ld = hci%ld)%s [%ld]: ",
           UI_PINK, UI_RESET, UI_PURPLE, default_val, default_val, UI_RESET, default_val);
    fflush(stdout);
    char line[32];
    if (read_line(line, sizeof line) < 0 || line[0] == '\0') return default_val;
    const char *p = line;
    if ((p[0] == 'h' || p[0] == 'H') && (p[1] == 'c' || p[1] == 'C') &&
        (p[2] == 'i' || p[2] == 'I')) {
        p += 3;
    }
    char *end;
    long v = strtol(p, &end, 10);
    if (p == end || *end != '\0') return default_val;
    return v;
}

// Path to the bundled DuckyScript payloads, listed by the HID wizard below.
// Baked in by the Makefile as an absolute path; the relative fallback keeps
// this file buildable on its own.
#ifndef BLEURP_PAYLOADS_DIR
#define BLEURP_PAYLOADS_DIR "src/send_attack/payloads"
#endif

#define HID_PAYLOAD_MAX 32

// Read a payload file's first "REM ..." or "# ..." comment line as its
// short description (as written by every file under payloads/), or leave
// `out` empty if there is none.
static void payload_desc(const char *path, char *out, size_t out_len) {
    out[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return;
    char line[128];
    if (fgets(line, sizeof line, f)) {
        line[strcspn(line, "\r\n")] = '\0';
        const char *p = line;
        if (strncmp(p, "REM ", 4) == 0) p += 4;
        else if (p[0] == '#') { p++; while (*p == ' ') p++; }
        // Bounded copy in place of snprintf("%s", p): `line` is wider than
        // most description buffers, so gcc cannot prove %s fits and flags a
        // (harmless, intentional) possible truncation under -Werror.
        size_t n = strlen(p);
        if (n >= out_len) n = out_len - 1;
        memcpy(out, p, n);
        out[n] = '\0';
    }
    fclose(f);
}

// List the bundled DuckyScript payloads (*.txt under BLEURP_PAYLOADS_DIR),
// alphabetically, with their one-line description. Returns the count.
static int list_payloads(char names[][64], char paths[][256], char descs[][96]) {
    int n = 0;
    DIR *d = opendir(BLEURP_PAYLOADS_DIR);
    if (!d) return 0;

    struct dirent *ent;
    while (n < HID_PAYLOAD_MAX && (ent = readdir(d)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len < 5 || strcmp(ent->d_name + len - 4, ".txt") != 0) continue;
        snprintf(names[n], sizeof names[0], "%s", ent->d_name);
        snprintf(paths[n], sizeof paths[0], "%s/%s", BLEURP_PAYLOADS_DIR, ent->d_name);
        payload_desc(paths[n], descs[n], sizeof descs[0]);
        n++;
    }
    closedir(d);

    // Small insertion sort by name so the listing is stable and alphabetic.
    for (int i = 1; i < n; i++) {
        int j = i;
        while (j > 0 && strcmp(names[j - 1], names[j]) > 0) {
            char tn[64]; strcpy(tn, names[j - 1]); strcpy(names[j - 1], names[j]); strcpy(names[j], tn);
            char tp[256]; strcpy(tp, paths[j - 1]); strcpy(paths[j - 1], paths[j]); strcpy(paths[j], tp);
            char td[96]; strcpy(td, descs[j - 1]); strcpy(descs[j - 1], descs[j]); strcpy(descs[j], td);
            j--;
        }
    }
    return n;
}

// Show the bundled payloads by default and let the operator pick one by
// number, or type a custom file path. Fills `out` and returns 1, or
// returns 0 on an empty answer (cancel).
static int pick_payload(char *out, size_t out_len) {
    char names[HID_PAYLOAD_MAX][64], paths[HID_PAYLOAD_MAX][256], descs[HID_PAYLOAD_MAX][96];
    int n = list_payloads(names, paths, descs);

    printf("\n  %sPayloads disponibles%s (%s) :\n", UI_PINK, UI_RESET, BLEURP_PAYLOADS_DIR);
    if (n == 0) {
        printf("  (aucun payload trouve dans ce dossier)\n");
    }
    for (int i = 0; i < n; i++) {
        printf("  %s[-%d-]%s %-22s %s%s%s\n", UI_YELLOW, i + 1, UI_RESET,
               names[i], UI_PURPLE, descs[i], UI_RESET);
    }
    printf("\n  numero ci-dessus, ou un chemin de fichier personnalise (vide = annuler)\n> ");
    fflush(stdout);

    char line[256];
    if (read_line(line, sizeof line) < 0 || line[0] == '\0') return 0;

    char *end;
    long num = strtol(line, &end, 10);
    if (*end == '\0' && num >= 1 && num <= n) {
        snprintf(out, out_len, "%s", paths[num - 1]);
    } else {
        snprintf(out, out_len, "%s", line); // custom path
    }
    return 1;
}

// Optional pre-step for the HID wizard: connect on the SMP fixed channel
// (CID 0x0006) and run the re-pairing downgrade probe (see smp.h). Reports
// the peer's raw negotiation behaviour -- never a bare "vulnerable" verdict,
// since replying to a Pairing Request is normal SMP behaviour; what matters
// is whether the peer's own AuthReq still lacks MITM/SC, and the signal is
// strongest against a device already paired with this controller (that is
// what the BLERP re-pairing vulnerabilities, NDSS 2026, are actually about).
static void run_smp_probe(const char *addr_str) {
    uint8_t addr[6];
    if (parse_addr(addr_str, addr) < 0) {
        printf("  adresse invalide, module SMP ignore.\n\n");
        return;
    }

    printf("  %sType%s (public/random) [public]: ", UI_PINK, UI_RESET);
    fflush(stdout);
    char t[16];
    uint8_t atype = BLEURP_BDADDR_LE_PUBLIC;
    if (read_line(t, sizeof t) == 0 && strncmp(t, "random", 6) == 0) {
        atype = BLEURP_BDADDR_LE_RANDOM;
    }

    printf("  connexion SMP (CID 0x%04x)...\n", BLEURP_SMP_CID);
    int fd = bleurp_l2_connect_cid_timeout(addr, atype, BLEURP_SMP_CID, 4000);
    if (fd < 0) {
        printf("  %sechec de connexion SMP%s (%s)\n\n", UI_RED, UI_RESET, strerror(errno));
        return;
    }

    struct smp_pairing_params resp;
    memset(&resp, 0, sizeof resp);
    smp_probe_t v = smp_downgrade_probe(fd, 4000, &resp);
    bleurp_l2_close(fd);

    if (v == SMP_PROBE_RESPONDED) {
        int mitm = (resp.auth_req & SMP_AUTHREQ_MITM) != 0;
        int sc   = (resp.auth_req & SMP_AUTHREQ_SC) != 0;
        printf("  %sreponse SMP%s : AuthReq peer=0x%02x  MITM=%s  SC=%s\n",
               UI_YELLOW, UI_RESET, resp.auth_req, mitm ? "oui" : "non", sc ? "oui" : "non");
        if (!mitm && !sc) {
            printf("  %s%sa suivi notre demande affaiblie%s (bonding seul) sans exiger plus fort\n",
                   UI_ORANGE, UI_BOLD, UI_RESET);
        }
    } else if (v == SMP_PROBE_REJECTED) {
        printf("  %srefuse%s : Pairing Failed en reponse a la demande affaiblie\n", UI_GREEN, UI_RESET);
    } else {
        printf("  pas de reponse SMP exploitable (timeout ou canal ferme)\n");
    }
    printf("  %s(signal plus parlant si l'appareil est deja appaire avec ce controleur --"
           " cf. BLERP, NDSS 2026, sur le RE-pairing)%s\n\n", UI_PURPLE, UI_RESET);
}

// [-3-] HID Payload: show the bundled payloads by default, ask a few short
// questions and run the injection. `target` pre-fills the address (e.g.
// when called with a device already picked from a scan); pass NULL to ask
// for it. This is the one place that calls hid_cmd_run's real, richer CLI
// (pairing, delay, --no-pair) instead of a bare, unlisted file-path prompt.
static void run_hid_wizard(const char *target) {
    signal(SIGINT, SIG_DFL);
    char addr[64];
    if (target) {
        snprintf(addr, sizeof addr, "%s", target);
        printf("  %sTarget%s: %s\n", UI_PINK, UI_RESET, addr);
    } else {
        printf("%sTarget address%s (AA:BB:CC:DD:EE:FF): ", UI_PINK, UI_RESET);
        fflush(stdout);
        if (read_line(addr, sizeof addr) < 0 || addr[0] == '\0') return;
    }

    if (ask_yes_no("Module SMP",
        "teste si l'appareil accepte un re-pairing affaibli, avant l'injection", 0)) {
        run_smp_probe(addr);
    }

    long index = ask_interface(bleurp_hci_find_default_dev());

    char payload[256];
    if (!pick_payload(payload, sizeof payload)) return;

    long delay = ask_number("Delai apres connexion (ms)",
        "pause avant d'injecter, laisse le temps au HID de s'etablir", 1000);
    int repair = ask_yes_no("Re-appairer",
        "pair+trust avant l'envoi ; decoche si deja appaire", 1);

    char iface[16], delay_s[16];
    snprintf(iface, sizeof iface, "hci%ld", index);
    snprintf(delay_s, sizeof delay_s, "%ld", delay);

    char *hid_argv[12];
    int n = 0;
    hid_argv[n++] = "hid";
    hid_argv[n++] = "-i"; hid_argv[n++] = iface;
    hid_argv[n++] = "-t"; hid_argv[n++] = addr;
    hid_argv[n++] = "-f"; hid_argv[n++] = payload;
    hid_argv[n++] = "-d"; hid_argv[n++] = delay_s;
    if (!repair) hid_argv[n++] = "--no-pair";
    hid_argv[n] = NULL;

    printf("\n");
    hid_cmd_run(n, hid_argv);

    printf("\n(entree pour continuer) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
}

// One device's Auto-Try outcome: connect (bounded by `timeout_ms`), then run
// the same audit pipeline as do_audit (services -> characteristics ->
// classify every readable one) but tallied into counts instead of printed
// line by line, so a whole device list stays a compact scan. Returns 1 on a
// successful connection (whatever the audit finds), 0 if it never connects.
static int auto_try_probe(const uint8_t addr[6], uint8_t atype, int timeout_ms,
                          uint16_t *out_mtu, size_t *out_nsvc, size_t *out_nchr,
                          int *out_open) {
    int fd = bleurp_l2_connect_timeout(addr, atype, timeout_ms);
    if (fd < 0) return 0;

    uint16_t mtu = 0;
    (void)gatt_exchange_mtu(fd, 517, &mtu);

    struct gatt_service svcs[64];
    size_t nsvc = 0;
    gatt_discover_services(fd, svcs, 64, &nsvc);
    size_t sshown = nsvc < 64 ? nsvc : 64;

    size_t nchr = 0;
    int open_count = 0;
    for (size_t i = 0; i < sshown; i++) {
        struct gatt_char chs[64];
        size_t nch = 0;
        gatt_discover_characteristics(fd, svcs[i].start_handle, svcs[i].end_handle,
                                      chs, 64, &nch);
        size_t cshown = nch < 64 ? nch : 64;
        nchr += cshown;
        for (size_t j = 0; j < cshown; j++) {
            if (!(chs[j].properties & GATT_PROP_READ)) continue;
            uint8_t buf[64];
            size_t len = 0;
            uint8_t err = 0;
            int rc = gatt_read(fd, chs[j].value_handle, buf, sizeof buf, &len, &err);
            if (audit_classify_read(rc == 0, err) == AUDIT_OPEN) open_count++;
        }
    }

    bleurp_l2_close(fd);
    *out_mtu = mtu ? mtu : 23;
    *out_nsvc = nsvc;
    *out_nchr = nchr;
    *out_open = open_count;
    return 1;
}

// [-4-] Auto-Try [Agressive]: connect to every device in the list, one by
// one, and run the audit pipeline above on each successful connection, then
// report which ones succeeded and what they exposed. Deliberately blunt (no
// pairing, no address-type guessing beyond what the scan already saw) --
// this is a fast recon pass across everything found, not a targeted attack.
// Ctrl-C stops the pass cleanly and returns here, same as the scan itself.
// Authorized targets only, same as every other connecting feature here.
static void run_auto_try(struct dev_table *table) {
    dev_table_sort_by_rssi(table);
    size_t cnt = dev_table_count(table);
    if (cnt == 0) { printf("\naucun appareil dans la liste.\n"); return; }

    long timeout_ms = ask_number("Timeout par appareil (ms)",
        "temps max avant d'abandonner une connexion", 4000);

    printf("\n  %sAuto-Try %s[Agressive]%s \342\200\224 %zu appareil(s), Ctrl-C pour arreter\n\n",
           UI_YELLOW, UI_ORANGE, UI_RESET, cnt);

    signal(SIGINT, on_sigint);
    g_stop = 0;

    int ok_count = 0, open_devices = 0;
    for (size_t i = 0; i < cnt && !g_stop; i++) {
        const struct dev_entry *e = dev_table_at(table, i);
        const uint8_t *a = e->address;
        const char *name = (e->has_name && e->name[0] != '\0') ? e->name : "(unknown)";

        printf("  [%2zu/%2zu] %02X:%02X:%02X:%02X:%02X:%02X  %-20s ... ",
               i + 1, cnt, a[5], a[4], a[3], a[2], a[1], a[0], name);
        fflush(stdout);

        uint16_t mtu = 0;
        size_t nsvc = 0, nchr = 0;
        int open_count = 0;
        if (!auto_try_probe(a, e->addr_type, (int)timeout_ms, &mtu, &nsvc, &nchr, &open_count)) {
            printf("%sechec%s\n", UI_RED, UI_RESET);
            continue;
        }

        ok_count++;
        if (open_count > 0) {
            open_devices++;
            printf("%sCONNECTE%s  MTU=%u  svc=%zu chr=%zu  %s%s!%d ouvert(s)%s\n",
                   UI_GREEN, UI_RESET, mtu, nsvc, nchr, UI_ORANGE, UI_BOLD, open_count, UI_RESET);
        } else {
            printf("%sCONNECTE%s  MTU=%u  svc=%zu chr=%zu\n",
                   UI_GREEN, UI_RESET, mtu, nsvc, nchr);
        }
    }

    signal(SIGINT, SIG_DFL);
    printf("\n  %s%d/%zu connexion(s) reussie(s)%s", UI_PINK, ok_count, cnt, UI_RESET);
    if (open_devices > 0) {
        printf("  %s\342\200\224 %d avec de la lecture sans pairing%s", UI_ORANGE, open_devices, UI_RESET);
    }
    printf("\n(entree pour continuer) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
}

// After a scan: show the results and propose next steps on a device from
// the list (enum GATT, audit, HID payload, or an Auto-Try pass across all
// of them), or go back. This is the menu's link between "found a device"
// and "do something with it".
static void post_scan_actions(struct dev_table *table) {
    signal(SIGINT, SIG_DFL);
    for (;;) {
        dev_table_sort_by_rssi(table);
        size_t cnt = dev_table_count(table);
        size_t shown = cnt < 20 ? cnt : 20;

        printf("\n  %s%zu appareil(s) trouve(s)%s\n", UI_PINK, cnt, UI_RESET);
        char row[192];
        for (size_t i = 0; i < shown; i++) {
            ui_format_row(row, sizeof row, (int)i + 1, dev_table_at(table, i));
            printf("  %s\n", row);
        }

        printf("\n  %sEtape suivante%s :\n", UI_YELLOW, UI_RESET);
        printf("  %s[-1-]%s Enum GATT      %ssur un appareil de la liste%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-2-]%s Audit GATT     %sacces sans pairing, sur un appareil%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-3-]%s HID Payload    %senvoyer un payload a un appareil%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-4-]%s Auto-Try %s[Agressive]%s %sconnexion sur chaque appareil de la liste%s\n",
               UI_YELLOW, UI_RESET, UI_ORANGE, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-5-]%s SMP Probe      %ssonde d'appairage native (HCI User Channel)%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-Q-]%s Retour au menu principal%s\n\n> ", UI_PINK, UI_RESET, UI_RESET);
        fflush(stdout);

        char line[64];
        if (read_line(line, sizeof line) < 0) return;
        if (line[0] == 'q' || line[0] == 'Q' || line[0] == '\0') return;
        if (line[0] == '4') {
            run_auto_try(table);
            continue;
        }
        if (line[0] != '1' && line[0] != '2' && line[0] != '3' && line[0] != '5') continue;
        if (shown == 0) { printf("aucun appareil dans la liste.\n"); continue; }

        long num = ask_number("Appareil #", "numero dans la liste ci-dessus", 0);
        if (num < 1 || (size_t)num > shown) {
            printf("numero invalide.\n");
            continue;
        }
        const struct dev_entry *e = dev_table_at(table, (size_t)num - 1);

        printf("\n");
        if (line[0] == '1') {
            do_enum(e->address, e->addr_type);
        } else if (line[0] == '2') {
            do_audit(e->address, e->addr_type);
        } else if (line[0] == '3') {
            char addr_s[18];
            snprintf(addr_s, sizeof addr_s, "%02X:%02X:%02X:%02X:%02X:%02X",
                     e->address[5], e->address[4], e->address[3],
                     e->address[2], e->address[1], e->address[0]);
            run_hid_wizard(addr_s);
        } else if (line[0] == '5') {
            char addr_s[18];
            snprintf(addr_s, sizeof addr_s, "%02X:%02X:%02X:%02X:%02X:%02X",
                     e->address[5], e->address[4], e->address[3],
                     e->address[2], e->address[1], e->address[0]);
            printf("Lancement de la sonde SMP native sur %s...\n", addr_s);
            struct smp_probe_result res;
            if (smp_native_probe_device(0, e->address, e->addr_type, 6000, &res) < 0) {
                fprintf(stderr, "Sonde SMP échouée (vérifiez l'état de l'adaptateur ou lancez ./scripts/reset_bluetooth.sh)\n");
            } else {
                smp_native_print_result(&res, addr_s);
            }
        }

        if (line[0] != '3') { // run_hid_wizard already pauses on its own
            printf("\n(entree pour continuer) ");
            fflush(stdout);
            char b[8];
            (void)read_line(b, sizeof b);
        }
    }
}

// [-1-] Scan: ask a few short questions (verbose, duration, interface),
// clear the screen and launch the scan. Ctrl-C stops the scan cleanly, then
// the results and a next-steps menu are shown before returning to the menu.
static void menu_scan_wizard(void) {
    signal(SIGINT, SIG_DFL);
    printf("\033[2J\033[H");
    printf("  %s[-1-] Scan%s \342\200\224 quelques questions avant de lancer :\n\n",
           UI_YELLOW, UI_RESET);
    int verbose = ask_yes_no("Verbose",
        "detail vendor/services sous chaque appareil", 1);
    long duration = ask_number("Duree (secondes)",
        "temps de scan ; 0 = illimite jusqu'a Ctrl-C", 30);
    long index = ask_interface(bleurp_hci_find_default_dev());
 
     struct dev_table table;
     if (dev_table_init(&table) < 0) { perror("dev_table_init"); return; }
 
     printf("\033[2J\033[H"); // clear once, then run_scan takes over the view
     int rc = run_scan((int)index, duration, verbose, &table);
     if (rc < 0) {
         printf("\nscan indisponible (voir le message ci-dessus).\n");
         printf("(entree pour revenir au menu) ");
         fflush(stdout);
         char b[8];
         (void)read_line(b, sizeof b);
     } else {
         post_scan_actions(&table);
     }
     dev_table_free(&table);
 }
 
 // Interactive main menu (shown when bleurp runs with no subcommand).
 // [-4-] MAC Spoofer: set the controller's LE static random address (kernel
 // mgmt Set Static Address, 0x002c). Only the *random* address is portable
 // from userspace on Linux this way; the burned-in "public" address needs
 // proprietary, chipset-specific HCI commands and is out of scope here.
 static void menu_mac_spoofer(void) {
     signal(SIGINT, SIG_DFL);
     printf("\033[2J\033[H");
     printf("  %s[-4-] MAC Spoofer%s\n\n", UI_YELLOW, UI_RESET);
     printf("  %sNe change que l'adresse aleatoire statique (random static).%s\n",
            UI_PURPLE, UI_RESET);
     printf("  %sL'adresse publique (burned-in) depend du chipset, pas supportee ici.%s\n\n",
            UI_PURPLE, UI_RESET);
 
     long index = ask_interface(bleurp_hci_find_default_dev());
 
     printf("  %sNouvelle adresse%s (AA:BB:CC:DD:EE:FF) : ", UI_PINK, UI_RESET);
     fflush(stdout);
     char a[64];
     if (read_line(a, sizeof a) < 0 || a[0] == '\0') return;
 
     uint8_t addr[6];
     if (parse_addr(a, addr) < 0) {
         printf("  adresse invalide.\n");
     } else {
         addr[5] |= 0xC0;
 
         int fd = mgmt_open();
         if (fd < 0) {
             perror("mgmt_open");
         } else {
             uint8_t cmd[16], buf[64];
             ssize_t n = mgmt_build_set_static_address(cmd, sizeof cmd, (uint16_t)index, addr);
             if (send_pkt(fd, cmd, n) < 0) {
                 perror("write");
             } else {
                 ssize_t r = read(fd, buf, sizeof buf);
                 struct mgmt_hdr h;
                 uint8_t status = 0xff;
                 if (r >= 9 && mgmt_parse_header(buf, (size_t)r, &h) == 0 &&
                     (h.opcode == MGMT_EV_CMD_STATUS || h.opcode == MGMT_EV_CMD_COMPLETE)) {
                     status = buf[8];
                 }
                 if (status == 0x00) {
                     printf("  %sOK%s : adresse statique = %02X:%02X:%02X:%02X:%02X:%02X\n",
                            UI_GREEN, UI_RESET, addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
                     printf("  %s(coupez/rallumez l'adaptateur, ou redemarrez le scan, pour"
                            " qu'elle serve en connexion/pub)%s\n", UI_PURPLE, UI_RESET);
                 } else {
                     printf("  %secec%s : mgmt status 0x%02x%s\n", UI_RED, UI_RESET, status,
                            status == 0x14 ? " (Permission Denied : sudo ou setcap requis)" : "");
                 }
             }
             mgmt_close(fd);
         }
     }
 
     printf("\n(entree pour continuer) ");
     fflush(stdout);
     char b[8];
     (void)read_line(b, sizeof b);
 }
 
 // [-5-] SMP Probe wizard
 static void menu_smp_wizard(void) {
     signal(SIGINT, SIG_DFL);
     printf("\033[2J\033[H");
     printf("  %s[-5-] SMP Probe (Native)%s \342\200\224 sonde de sécurité d'appairage BLE\n\n",
            UI_YELLOW, UI_RESET);
 
     printf("%sAddress%s (AA:BB:CC:DD:EE:FF): ", UI_PINK, UI_RESET);
     fflush(stdout);
     char a[64];
     if (read_line(a, sizeof a) < 0 || a[0] == '\0') return;
 
     uint8_t addr[6];
     if (parse_addr(a, addr) < 0) {
         printf("  adresse invalide.\n");
         return;
     }
 
     printf("%sType%s (public/random) [random]: ", UI_PINK, UI_RESET);
     fflush(stdout);
     char t[16];
     uint8_t atype = BLEURP_BDADDR_LE_RANDOM;
     if (read_line(t, sizeof t) == 0 && strncmp(t, "public", 6) == 0) {
         atype = BLEURP_BDADDR_LE_PUBLIC;
     }
 
     long dev_id = ask_interface(bleurp_hci_find_default_dev());
 
     char as[18];
     snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
              addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
 
     printf("\nConnexion à %s sur hci%ld via HCI User Channel...\n", as, dev_id);
     struct smp_probe_result res;
     if (smp_native_probe_device((int)dev_id, addr, atype, 6000, &res) < 0) {
         fprintf(stderr, "  %s[-] Sonde échouée (vérifiez rfkill/bluetoothd ou exécutez ./scripts/reset_bluetooth.sh)%s\n",
                 UI_RED, UI_RESET);
     } else {
         smp_native_print_result(&res, as);
     }
 
     printf("\n(entree pour continuer) ");
     fflush(stdout);
     char b[8];
     (void)read_line(b, sizeof b);
 }
 
 // [-0-] Pipeline Audit Tout-en-Un (Epitech Security Suite)
static void menu_guided_audit_wizard(void) {
    signal(SIGINT, SIG_DFL);
    printf("\033[2J\033[H");
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %s%s[-0-] Pipeline d'Audit Complet BLEURP (Tout-en-Un)%s\n", UI_YELLOW, UI_BOLD, UI_RESET);
    printf("  %s============================================================%s\n\n", UI_PURPLE, UI_RESET);
    printf("  %sCe wizard enchaîne automatiquement les phases d'audit BLE :%s\n", UI_PINK, UI_RESET);
    printf("    1. Découverte & Fingerprint des cibles avec suggestions\n");
    printf("    2. Reconnaissance GATT & recensement des caractéristiques ouvertes\n");
    printf("    3. Sonde de sécurité SMP (évaluation de robustesse cryptographique)\n");
    printf("    4. Test interactif / simulation HID si applicable\n");
    printf("    5. Synthèse & Rapport d'audit global structuré\n\n");

    long dev_id = ask_interface(bleurp_hci_find_default_dev());
    long scan_sec = ask_number("Durée du scan initial (sec)", "temps d'écoute", 10);
    if (scan_sec <= 0) scan_sec = 10;

    struct dev_table table;
    if (dev_table_init(&table) < 0) {
        perror("dev_table_init");
        return;
    }

    printf("\n  %s[*] Phase 1/5 : Détection et cartographie des appareils...%s\n", UI_PINK, UI_RESET);
    int rc = run_scan((int)dev_id, scan_sec, 1, &table);
    if (rc < 0 || dev_table_count(&table) == 0) {
        printf("  %s[-] Aucun appareil détecté pendant le scan.%s\n", UI_RED, UI_RESET);
        dev_table_free(&table);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    dev_table_sort_by_rssi(&table);
    size_t count = dev_table_count(&table);
    size_t shown = count < 15 ? count : 15;

    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %sPhase 2/5 : Sélection de la Cible & Suggestions d'Audit%s\n", UI_YELLOW, UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);

    char row[192];
    for (size_t i = 0; i < shown; i++) {
        const struct dev_entry *e = dev_table_at(&table, i);
        ui_format_row(row, sizeof row, (int)i + 1, e);
        printf("  %s\n", row);
    }

    printf("\n  %sNuméro de l'appareil à auditer (1-%zu, ou vide pour annuler)%s : ",
           UI_PINK, shown, UI_RESET);
    fflush(stdout);
    char pick_buf[32];
    if (read_line(pick_buf, sizeof pick_buf) < 0 || pick_buf[0] == '\0') {
        dev_table_free(&table);
        return;
    }

    long target_idx = strtol(pick_buf, NULL, 10);
    if (target_idx < 1 || (size_t)target_idx > shown) {
        printf("  %sNuméro invalide.%s\n", UI_RED, UI_RESET);
        dev_table_free(&table);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    const struct dev_entry *target = dev_table_at(&table, (size_t)target_idx - 1);
    uint8_t target_addr[6];
    memcpy(target_addr, target->address, 6);
    uint8_t target_atype = target->addr_type;
    char target_str[18];
    snprintf(target_str, sizeof(target_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             target_addr[5], target_addr[4], target_addr[3],
             target_addr[2], target_addr[1], target_addr[0]);

    printf("\n  %s[+] Cible sélectionnée : %s%s%s (%s, %s)\n",
           UI_GREEN, UI_BOLD, target_str, UI_RESET,
           (target->has_name && target->name[0]) ? target->name : "Nom inconnu",
           target_atype == BLEURP_BDADDR_LE_RANDOM ? "Random RPA" : "Public");

    // Phase 3 : Audit GATT
    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %sPhase 3/5 : Reconnaissance & Audit GATT Non-Intrusif%s\n", UI_YELLOW, UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    do_audit(target_addr, target_atype);

    // Phase 4 : Sonde SMP
    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %sPhase 4/5 : Sonde de Sécurité SMP (Link Layer)%s\n", UI_YELLOW, UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    struct smp_probe_result smp_res;
    memset(&smp_res, 0, sizeof(smp_res));
    int smp_rc = smp_native_probe_device((int)dev_id, target_addr, target_atype, 6000, &smp_res);
    if (smp_rc == 0) {
        smp_native_print_result(&smp_res, target_str);
    } else {
        printf("  %s[-] Sonde SMP non concluante (cible non joignable en liaison directe ou timeout).\n%s", UI_ORANGE, UI_RESET);
    }

    // Phase 5 : Test interactif / HID
    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %sPhase 5/5 : Test d'Interaction / Simulation HID%s\n", UI_YELLOW, UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    int do_hid = ask_yes_no("Tester l'injection HID sur cette cible ?",
                            "nécessite l'autorisation de la cible", 0);
    if (do_hid) {
        run_hid_wizard(target_str);
    }

    // Synthèse
    printf("\n  %s============================================================%s\n", UI_GREEN, UI_RESET);
    printf("  %s%s[+] SYNTHÈSE D'AUDIT BLEURP : %s%s\n", UI_GREEN, UI_BOLD, target_str, UI_RESET);
    printf("  %s============================================================%s\n", UI_GREEN, UI_RESET);
    printf("  • Cible           : %s [%s]\n", target_str, target_atype == BLEURP_BDADDR_LE_RANDOM ? "Random RPA" : "Public");
    printf("  • Nom             : %s\n", (target->has_name && target->name[0]) ? target->name : "Non annoncé");
    printf("  • Statut SMP      : %s\n",
           smp_res.success ? (smp_res.pairing_failed ? "Rejeté (Sécurisé)" : "Répondu (Évaluable)") : "Inaccessible");
    if (smp_res.success && !smp_res.pairing_failed) {
        bool vuln = (smp_res.auth_req & 0x04) == 0 && (smp_res.auth_req & 0x08) == 0;
        printf("  • Niveau de risque: %s%s%s\n",
               vuln ? UI_RED : UI_GREEN,
               vuln ? "ÉLEVÉ (Accepte appairage sans MITM ni Secure Connections)" : "FAIBLE (Exige protection renforcée)",
               UI_RESET);
    }
    printf("  %s============================================================%s\n\n", UI_GREEN, UI_RESET);

    dev_table_free(&table);
    printf("(entree pour revenir au menu principal) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
}

// [-6-] Keyboard Peripheral wizard
 static void menu_keyboard_wizard(void) {
     signal(SIGINT, SIG_DFL);
     printf("\033[2J\033[H");
     printf("  %s[-6-] BLE Keyboard (Peripheral HOGP)%s \342\200\224 émulateur clavier Bluetooth\n\n",
            UI_YELLOW, UI_RESET);
     printf("  %sLe PC diffuse des annonces de Clavier BLE (Appearance 0x03C1, Service 0x1812).%s\n",
            UI_PURPLE, UI_RESET);
     printf("  %sPermet à l'iPhone / Android de se connecter proprement et de négocier l'appairage SMP.%s\n\n",
            UI_PURPLE, UI_RESET);
 
     long dev_id = ask_interface(bleurp_hci_find_default_dev());
 
     printf("  %sNom du périphérique%s [BLEURP Keyboard] : ", UI_PINK, UI_RESET);
     fflush(stdout);
     char name_buf[64];
     const char *name = "BLEURP Keyboard";
     if (read_line(name_buf, sizeof(name_buf)) == 0 && name_buf[0] != '\0') {
         name = name_buf;
     }
 
     printf("\n  %sMode de sécurité SMP%s :\n", UI_PINK, UI_RESET);
     printf("    %s1.%s Just Works (Bonding seul, AuthReq=0x01)\n", UI_YELLOW, UI_RESET);
     printf("    %s2.%s MITM Protection (AuthReq=0x05)\n", UI_YELLOW, UI_RESET);
     printf("    %s3.%s Secure Connections + MITM (AuthReq=0x0D)\n", UI_YELLOW, UI_RESET);
     printf("    %s4.%s Downgrade Test (KeySize=7, AuthReq=0x01)\n", UI_YELLOW, UI_RESET);
     long mode = ask_number("Choix du mode", "1-4", 1);
 
     uint8_t auth = 0x01;
     uint8_t ksize = 16;
     uint8_t iocap = 0x03; // NoInputNoOutput (Just Works)
     if (mode == 2) { auth = 0x05; iocap = 0x00; } // DisplayOnly
     else if (mode == 3) { auth = 0x0D; iocap = 0x03; }
     else if (mode == 4) { auth = 0x01; ksize = 7; iocap = 0x03; }
 
     struct peripheral_config cfg = {
         .dev_id = (int)dev_id,
         .device_name = name,
         .io_capability = iocap,
         .auth_req = auth,
         .max_key_size = ksize,
         .trigger_sec_req = true,
         .payload_file = NULL
     };
 
     peripheral_keyboard_run(&cfg);
 
     printf("\n(entree pour continuer) ");
     fflush(stdout);
     char b[8];
     (void)read_line(b, sizeof b);
 }
 
static int cmd_keyboard(int argc, char **argv) {
    int dev_id = bleurp_hci_find_default_dev();
    const char *name = "BLEURP Keyboard";
    uint8_t auth = 0x01; // Bonding
    uint8_t keysize = 16;
    uint8_t iocap = 0x03; // NoInputNoOutput (Just Works)
    const char *payload = NULL;

    int opt;
    optind = 1;
    while ((opt = getopt(argc, argv, "i:n:a:k:o:d:h")) != -1) {
        switch (opt) {
            case 'i': dev_id = (int)strtol(optarg, NULL, 0); break;
            case 'n': name = optarg; break;
            case 'a': auth = (uint8_t)strtol(optarg, NULL, 0); break;
            case 'k': keysize = (uint8_t)strtol(optarg, NULL, 0); break;
            case 'o': iocap = (uint8_t)strtol(optarg, NULL, 0); break;
            case 'd': payload = optarg; break;
            case 'h':
            default:
                fprintf(stderr, "Usage: bleurp keyboard [-i hciX] [-n name] [-a authreq_hex] [-k keysize] [-o iocap] [-d payload.ducky]\n");
                return 1;
        }
    }

    struct peripheral_config cfg = {
        .dev_id = dev_id,
        .device_name = name,
        .io_capability = iocap,
        .auth_req = auth,
        .max_key_size = keysize,
        .trigger_sec_req = true,
        .payload_file = payload
    };

    return peripheral_keyboard_run(&cfg);
}

static int cmd_menu(void) {
    for (;;) {
        signal(SIGINT, SIG_DFL); // Ctrl-C at the menu exits
        printf("\033[2J\033[H");
        banner_print(stdout);
        printf("\n  %sBLE recon%s %s/%s%s attack toolkit%s\n",
               UI_PINK, UI_RESET, UI_PURPLE, UI_RESET, UI_PINK, UI_RESET);
        printf("  %s------------------------------------------------------------%s\n",
               UI_PURPLE, UI_RESET);
        printf("  %s[-0-]%s Suite Audit   %spipeline tout-en-un (Scan -> GATT -> SMP -> HID)%s\n",
               UI_GREEN, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-1-]%s Scan          %sdecouverte BLE en direct + fingerprint%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-2-]%s Enum GATT     %sconnexion a un appareil, arbre GATT%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-3-]%s HID Payload   %sinjection de frappes (BLE HID)%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-4-]%s MAC Spoofer   %sadresse aleatoire statique (LE)%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-5-]%s SMP Probe     %ssonde d'appairage native (HCI User Channel)%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-6-]%s BLE Keyboard  %sémulateur clavier HID (HOGP Périphérique)%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-Q-]%s Quitter%s\n\n> ", UI_PINK, UI_RESET, UI_RESET);
        fflush(stdout);

        char line[64];
        if (read_line(line, sizeof line) < 0) return 0;
        if (line[0] == 'q' || line[0] == 'Q') return 0;

        if (line[0] == '0') {
            menu_guided_audit_wizard();
        } else if (line[0] == '1') {
            menu_scan_wizard();
        } else if (line[0] == '2') {
            signal(SIGINT, SIG_DFL);
            printf("%sAddress%s (AA:BB:CC:DD:EE:FF): ", UI_PINK, UI_RESET);
            fflush(stdout);
            char a[64];
            if (read_line(a, sizeof a) == 0) {
                uint8_t addr[6];
                if (parse_addr(a, addr) == 0) {
                    printf("%sType%s (public/random) [public]: ", UI_PINK, UI_RESET);
                    fflush(stdout);
                    char t[16];
                    uint8_t at = BLEURP_BDADDR_LE_PUBLIC;
                    if (read_line(t, sizeof t) == 0 && strncmp(t, "random", 6) == 0) {
                        at = BLEURP_BDADDR_LE_RANDOM;
                    }
                    do_enum(addr, at);
                } else {
                    printf("invalid address\n");
                }
            }
            printf("\n(enter to continue) ");
            fflush(stdout);
            char b[8];
            (void)read_line(b, sizeof b);
        } else if (line[0] == '3') {
            run_hid_wizard(NULL);
        } else if (line[0] == '4') {
            menu_mac_spoofer();
        } else if (line[0] == '5') {
            menu_smp_wizard();
        } else if (line[0] == '6') {
            menu_keyboard_wizard();
        }
    }
}

// Dispatch: subcommands, flags -> scan, otherwise the interactive menu.
int main(int argc, char **argv) {
    if (argc >= 2) {
        if (strcmp(argv[1], "wizard") == 0 ||
            strcmp(argv[1], "suite") == 0 ||
            strcmp(argv[1], "pipeline") == 0)   { menu_guided_audit_wizard(); return 0; }
        if (strcmp(argv[1], "enum") == 0)       return cmd_enum(argc - 1, argv + 1);
        if (strcmp(argv[1], "audit") == 0)      return cmd_audit(argc - 1, argv + 1);
        if (strcmp(argv[1], "read") == 0)       return cmd_read(argc - 1, argv + 1);
        if (strcmp(argv[1], "write") == 0)      return cmd_write(argc - 1, argv + 1);
        if (strcmp(argv[1], "hid") == 0)        return hid_cmd_run(argc - 1, argv + 1);
        if (strcmp(argv[1], "smp") == 0)        return cmd_smp_native(argc - 1, argv + 1);
        if (strcmp(argv[1], "keyboard") == 0 ||
            strcmp(argv[1], "peripheral") == 0 ||
            strcmp(argv[1], "adv") == 0)        return cmd_keyboard(argc - 1, argv + 1);
        if (strcmp(argv[1], "scan") == 0)       return cmd_scan(argc - 1, argv + 1);
        if (strcmp(argv[1], "menu") == 0)       return cmd_menu();
        if (argv[1][0] == '-')                  return cmd_scan(argc, argv); // back-compat
        usage(argv[0]);
        return 2;
    }
    return cmd_menu();
}
