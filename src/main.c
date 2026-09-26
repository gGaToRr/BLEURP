// ========================================
//  nom du fichier: main.c
//  description courte: BLEURP entry point. Drives kernel mgmt LE discovery,
//  parses advertising data, merges devices into a table and renders a live,
//  wifite-style sorted view until a duration elapses or Ctrl-C is pressed.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

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
#include "dev_table.h"
#include "gatt.h"
#include "l2cap.h"
#include "mgmt.h"
#include "ui.h"

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

// Build a verbose one-line summary from parsed advertising data: vendor,
// service count/name, TX power, flags, appearance. Purely descriptive; it is
// not a device name (we never present a guessed vendor as the name).
static void make_details(const struct ad_info *in, char *out, size_t n) {
    size_t used = 0;
    out[0] = '\0';
#define APP(...) do { \
        if (used < n) { \
            int w = snprintf(out + used, n - used, __VA_ARGS__); \
            if (w < 0) { /* ignore */ } \
            else if ((size_t)w >= n - used) used = n - 1; \
            else used += (size_t)w; \
        } \
    } while (0)
    if (in->has_company) {
        const char *v = ad_company_name(in->company_id);
        if (v) APP("vendor=%s ", v);
        else   APP("mfr=0x%04x ", in->company_id);
    }
    if (in->n_uuid16 > 0) {
        const char *s = NULL;
        for (int i = 0; i < in->n_uuid16 && !s; i++) s = ad_service_name(in->uuid16[i]);
        APP("svc=%d%s%s ", in->n_uuid16, s ? ":" : "", s ? s : "");
    }
    if (in->has_tx_power)   APP("tx=%ddBm ", in->tx_power);
    if (in->has_flags)      APP("flags=0x%02x ", in->flags);
    if (in->has_appearance) APP("appr=0x%04x ", in->appearance);
#undef APP
}

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
        // Lead the verbose line with the address privacy posture, flagging a
        // stable (trackable) address as a recon/privacy finding, then append
        // the advertising summary when we could parse it.
        addr_privacy_t p = addr_privacy(e->address, e->addr_type);
        char ad[96];
        ad[0] = '\0';
        if (ok) make_details(&info, ad, sizeof ad);
        snprintf(e->details, sizeof e->details, "priv=%s%s%s%s",
                 addr_privacy_label(p),
                 addr_is_trackable(p) ? " [trackable]" : "",
                 ad[0] ? " " : "", ad);
    }
}

// Print usage for the scan command / top level.
static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s                                      interactive menu (default)\n"
            "  %s scan  [-i index] [-t seconds] [-v]   live BLE scan\n"
            "  %s enum  <ADDR> [-t public|random]      connect and dump GATT\n"
            "  %s read  <ADDR> <handle> [-t ...]       read a value by handle\n"
            "  %s write <ADDR> <handle> <hex> [-t ...] write bytes by handle\n"
            "  -i index    HCI controller index (default 0 = hci0)\n"
            "  -t seconds  scan duration; 0 = until Ctrl-C (default 0)\n"
            "  -v          verbose scan (per-device vendor/services details)\n"
            "Only use on devices you own or are authorized to test.\n",
            prog, prog, prog, prog, prog);
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

// Read a line from stdin into buf (newline stripped). Returns 0 or -1 on EOF.
static int read_line(char *buf, size_t n) {
    if (!fgets(buf, (int)n, stdin)) return -1;
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

// After a scan: list results and let the operator enumerate a device by its
// number, rescan, or return. Returns 1 to rescan, 0 to go back to the menu.
static int post_scan_submenu(struct dev_table *table) {
    signal(SIGINT, SIG_DFL);
    for (;;) {
        dev_table_sort_by_rssi(table);
        size_t cnt = dev_table_count(table);
        size_t shown = cnt < 40 ? cnt : 40;
        printf("\n== Results (%zu device(s)) ==\n", cnt);
        char row[192];
        for (size_t i = 0; i < shown; i++) {
            ui_format_row(row, sizeof row, (int)i + 1, dev_table_at(table, i));
            printf("  %s\n", row);
        }
        printf("\n[number]=enumerate GATT   r=rescan   q=back to menu\n> ");
        fflush(stdout);

        char line[64];
        if (read_line(line, sizeof line) < 0) return 0;
        if (line[0] == 'q' || line[0] == '\0') return 0;
        if (line[0] == 'r') return 1;
        int num = atoi(line);
        if (num >= 1 && (size_t)num <= shown) {
            const struct dev_entry *e = dev_table_at(table, (size_t)num - 1);
            printf("\n");
            do_enum(e->address, e->addr_type);
            printf("\n(enter to continue) ");
            fflush(stdout);
            char b[8];
            (void)read_line(b, sizeof b);
        }
    }
}

// Interactive main menu (shown when bleurp runs with no subcommand).
static int cmd_menu(void) {
    for (;;) {
        signal(SIGINT, SIG_DFL); // Ctrl-C at the menu exits
        printf("\033[2J\033[H");
        printf("  BLEURP menu\n");
        printf("  ----------------------------------------------\n");
        printf("  1) Automatic verbose scan (active, all devices)\n");
        printf("  2) Enumerate a device (GATT) by address\n");
        printf("  q) Quit\n\n> ");
        fflush(stdout);

        char line[64];
        if (read_line(line, sizeof line) < 0) return 0;
        if (line[0] == 'q' || line[0] == 'Q') return 0;

        if (line[0] == '1') {
            struct dev_table table;
            if (dev_table_init(&table) < 0) { perror("dev_table_init"); continue; }
            for (;;) {
                if (run_scan(0, 0, 1, &table) < 0) {
                    printf("\n(scan unavailable; enter to return) ");
                    fflush(stdout);
                    char b[8];
                    (void)read_line(b, sizeof b);
                    break;
                }
                if (post_scan_submenu(&table) != 1) break; // 1 = rescan
            }
            dev_table_free(&table);
        } else if (line[0] == '2') {
            signal(SIGINT, SIG_DFL);
            printf("Address (AA:BB:CC:DD:EE:FF): ");
            fflush(stdout);
            char a[64];
            if (read_line(a, sizeof a) == 0) {
                uint8_t addr[6];
                if (parse_addr(a, addr) == 0) {
                    printf("Type (public/random) [public]: ");
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
        }
    }
}

// Dispatch: subcommands, flags -> scan, otherwise the interactive menu.
int main(int argc, char **argv) {
    if (argc >= 2) {
        if (strcmp(argv[1], "enum") == 0)  return cmd_enum(argc - 1, argv + 1);
        if (strcmp(argv[1], "read") == 0)  return cmd_read(argc - 1, argv + 1);
        if (strcmp(argv[1], "write") == 0) return cmd_write(argc - 1, argv + 1);
        if (strcmp(argv[1], "scan") == 0)  return cmd_scan(argc - 1, argv + 1);
        if (strcmp(argv[1], "menu") == 0)  return cmd_menu();
        if (argv[1][0] == '-')             return cmd_scan(argc, argv); // back-compat
        usage(argv[0]);
        return 2;
    }
    return cmd_menu();
}
