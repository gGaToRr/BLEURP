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

// Print usage.
static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [-i index] [-t seconds] [-h]\n"
            "  -i index    HCI controller index (default 0 = hci0)\n"
            "  -t seconds  scan duration; 0 = until Ctrl-C (default 0)\n"
            "  -h          show this help\n"
            "Only scan devices you own or are authorized to test.\n",
            prog);
}

// Write an mgmt packet; returns 0 if the write did not error, -1 otherwise.
static int send_pkt(int fd, const uint8_t *pkt, ssize_t n) {
    if (n < 0) {
        return -1;
    }
    return (write(fd, pkt, (size_t)n) < 0) ? -1 : 0;
}

int main(int argc, char **argv) {
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
