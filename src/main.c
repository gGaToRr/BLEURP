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

// Merge one discovered device into the table. We only trust the real device
// name (from the advertising data or scan response); we do NOT guess a vendor
// from the manufacturer company id, which produces misleading labels (e.g.
// everything showing as "Apple"). No name -> shown as unknown.
static void on_device(const struct mgmt_device *d, void *user) {
    struct scan_ctx *c = user;
    struct ad_info info;
    const char *name = "";
    if (ad_parse(d->eir, d->eir_len, &info) == 0 && info.has_name) {
        name = info.name;
    }
    dev_table_upsert(c->table, d->address, d->addr_type, d->rssi,
                     name, time(NULL));
}

// Print usage for the scan command / top level.
static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [-i index] [-t seconds]              live BLE scan (default)\n"
            "  %s enum  <ADDR> [-t public|random]      connect and dump GATT\n"
            "  %s read  <ADDR> <handle> [-t ...]       read a value by handle\n"
            "  %s write <ADDR> <handle> <hex> [-t ...] write bytes by handle\n"
            "  -i index    HCI controller index (default 0 = hci0)\n"
            "  -t seconds  scan duration; 0 = until Ctrl-C (default 0)\n"
            "  -h          show this help\n"
            "Only use on devices you own or are authorized to test.\n",
            prog, prog, prog, prog);
}

// Write an mgmt packet; returns 0 if the write did not error, -1 otherwise.
static int send_pkt(int fd, const uint8_t *pkt, ssize_t n) {
    if (n < 0) {
        return -1;
    }
    return (write(fd, pkt, (size_t)n) < 0) ? -1 : 0;
}

static int cmd_scan(int argc, char **argv) {
    int index = 0;
    long duration = 0;

    int opt;
    while ((opt = getopt(argc, argv, "i:t:h")) != -1) {
        switch (opt) {
        case 'i': index = atoi(optarg); break;
        case 't': duration = atol(optarg); break;
        case 'h': usage(argv[0]); return 0;
        default:  usage(argv[0]); return 2;
        }
    }

    int fd = mgmt_open();
    if (fd < 0) {
        perror("mgmt_open");
        return 1;
    }

    uint8_t cmd[64];
    uint8_t buf[2048];

    // Read controller info to show the adapter and confirm LE support.
    ssize_t n = mgmt_build_command(cmd, sizeof cmd, MGMT_OP_READ_CONTROLLER_INFO,
                                   (uint16_t)index, NULL, 0);
    if (send_pkt(fd, cmd, n) < 0) { perror("write"); mgmt_close(fd); return 1; }
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
    if (send_pkt(fd, cmd, n) < 0) { perror("write"); mgmt_close(fd); return 1; }

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
                return 1;
            }
        }
    }

    struct dev_table table;
    if (dev_table_init(&table) < 0) { perror("dev_table_init"); mgmt_close(fd); return 1; }
    struct scan_ctx ctx = { .table = &table };

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

        dev_table_sort_by_rssi(&table);
        ui_render(&table, start, now, stdout);
    }

    // Stop discovery and draw a final frame.
    n = mgmt_build_stop_discovery(cmd, sizeof cmd, (uint16_t)index, MGMT_ADDR_LE);
    (void)send_pkt(fd, cmd, n);
    dev_table_sort_by_rssi(&table);
    ui_render(&table, start, time(NULL), stdout);
    printf("\nStopped. %zu device(s) found.\n", dev_table_count(&table));

    dev_table_free(&table);
    mgmt_close(fd);
    return 0;
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

// enum subcommand: connect to a device and print its GATT tree.
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

    const char *addr_str = argv[optind];
    uint8_t addr[6];
    if (parse_addr(addr_str, addr) < 0) {
        fprintf(stderr, "invalid address: %s\n", addr_str);
        return 2;
    }

    fprintf(stderr, "Authorized targets only. Connecting to %s ...\n", addr_str);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    uint16_t mtu = 0;
    (void)gatt_exchange_mtu(fd, 517, &mtu);
    printf("Connected to %s (ATT MTU=%u)\n\n", addr_str, mtu ? mtu : 23);

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

// Dispatch: enum/read/write subcommands, otherwise the live scan.
int main(int argc, char **argv) {
    if (argc >= 2 && strcmp(argv[1], "enum") == 0)  return cmd_enum(argc - 1, argv + 1);
    if (argc >= 2 && strcmp(argv[1], "read") == 0)  return cmd_read(argc - 1, argv + 1);
    if (argc >= 2 && strcmp(argv[1], "write") == 0) return cmd_write(argc - 1, argv + 1);
    return cmd_scan(argc, argv);
}
