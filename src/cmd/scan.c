// ========================================
//  nom du fichier: scan.c
//  description courte: Implementation of the `scan` subcommand: kernel-mgmt
//  live discovery (active) and the raw-HCI passive scan engine. Extracted
//  from src/main.c during the v2 rewrite's Phase 8 breakup. See scan.h for
//  the contract.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "scan.h"
#include "export.h"
#include "ad_parse.h"
#include "cli.h"
#include "dev_table.h"
#include "fingerprint.h"
#include "hci_cmd.h"
#include "hci_dev.h"
#include "hci_info.h"
#include "hci_scan.h"
#include "mgmt.h"
#include "ui.h"
#include "wire/hci_wire.h"

#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>

// How often to re-arm discovery, to keep reports flowing and refresh the
// view (wifite keeps a continuous scan going and redraws steadily).
#define SCAN_REFRESH_SEC 10

// Set by SIGINT so the scan loop can stop cleanly.
volatile sig_atomic_t g_stop = 0;

// SIGINT handler: request a clean stop.
void on_sigint(int sig) {
    (void)sig;
    g_stop = 1;
}

// Context passed to the per-device callback.
struct scan_ctx {
    struct dev_table *table;
};

// Merge one discovered device into the table and build its passive
// fingerprint (category, vendor, privacy, exposure score) from the
// advertising data and address posture. We only trust the real device name
// (from the advertising data or scan response); we do NOT guess a vendor
// from the manufacturer company id, which produces misleading labels (e.g.
// everything showing as "Apple"). No name -> shown as unknown. `addr_type`
// is MGMT_ADDR_TYPE_* (both the mgmt and raw-HCI scan paths normalize to
// this before calling here -- see on_device() and on_adv_report()).
static void merge_device(struct dev_table *table, const uint8_t address[6],
                         uint8_t addr_type, int8_t rssi,
                         const uint8_t *ad_data, size_t ad_len) {
    struct ad_info info;
    int ok = (ad_parse(ad_data, ad_len, &info) == 0);
    const char *name = (ok && info.has_name) ? info.name : "";
    struct dev_entry *e = dev_table_upsert(table, address, addr_type,
                                           rssi, name, time(NULL));
    if (e) {
        struct fingerprint fp = fingerprint_make(ok ? &info : NULL,
                                                e->address, e->addr_type);
        fingerprint_summary(&fp, e->details, sizeof e->details);
        strncpy(e->category, fp.category_label, sizeof e->category - 1);
        e->category[sizeof e->category - 1] = '\0';
        e->exposure = fp.exposure;
    }
}

// mgmt_device_cb for the kernel-mgmt discovery path (active scan).
static void on_device(const struct mgmt_device *d, void *user) {
    struct scan_ctx *c = user;
    merge_device(c->table, d->address, d->addr_type, d->rssi, d->eir, d->eir_len);
}

// hci_adv_cb for the raw-HCI passive scan path (see run_scan_passive()).
// hci_adv_report's addr_type is the raw LE type (0 public, 1 random, plus
// the resolved-private variants 0x02/0x03 extended reports can carry); all
// of those are random addresses for dev_table/addr_priv's purposes, which
// expect MGMT_ADDR_TYPE_* (only LE_PUBLIC vs LE_RANDOM matters there).
static void on_adv_report(const struct hci_adv_report *r, void *user) {
    struct scan_ctx *c = user;
    uint8_t mgmt_type = (r->addr_type == 0) ? MGMT_ADDR_TYPE_LE_PUBLIC
                                             : MGMT_ADDR_TYPE_LE_RANDOM;
    merge_device(c->table, r->address, mgmt_type, r->rssi, r->data, r->data_len);
}

// Write an mgmt packet; returns 0 if the write did not error, -1 otherwise.
int send_pkt(int fd, const uint8_t *pkt, ssize_t n) {
    if (n < 0) {
        return -1;
    }
    return (write(fd, pkt, (size_t)n) < 0) ? -1 : 0;
}

// Run a live scan into `table` (already initialized) until `duration` seconds
// elapse or Ctrl-C. `verbose` shows a per-device details line. Returns 0 on a
// normal stop, or -1 on a setup failure (message already printed).
int run_scan(int index, long duration, int verbose, struct dev_table *table) {
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

// Detect legacy vs extended LE scanning support by sending HCI_Read_Local_
// Version_Information and reading its Command Complete reply. Falls back to
// legacy on any failure or timeout (hci_supports_extended(NULL) is false),
// which every controller this tool targets accepts.
static enum hci_scan_mode detect_scan_mode(int fd) {
    uint8_t cmd[8];
    ssize_t cn = hci_build_command(cmd, sizeof cmd, HCI_OP_READ_LOCAL_VERSION, NULL, 0);
    if (cn < 0 || hci_send(fd, cmd, (size_t)cn) < 0) return HCI_SCAN_MODE_LEGACY;

    struct timeval start, now;
    gettimeofday(&start, NULL);
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        if (elapsed >= 1000) return HCI_SCAN_MODE_LEGACY;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, (int)(1000 - elapsed)) <= 0) return HCI_SCAN_MODE_LEGACY;

        uint8_t buf[256];
        ssize_t n = read(fd, buf, sizeof buf);
        if (n < 2 || buf[0] != HCI_EVENT_PKT) continue;

        struct hci_local_version v;
        if (hci_parse_local_version(&buf[1], (size_t)(n - 1), &v) == 0) {
            return hci_supports_extended(&v) ? HCI_SCAN_MODE_EXTENDED : HCI_SCAN_MODE_LEGACY;
        }
        // Not our reply (e.g. a leftover advertising report): keep polling.
    }
}

// Run a live PASSIVE scan into `table` via a raw (non-exclusive) HCI socket
// -- coexists with bluetoothd, unlike the HCI_CHANNEL_USER engines used by
// the SMP/BLERP commands. Otherwise mirrors run_scan()'s live view and
// duration/Ctrl-C handling; see hci_scan.h for the passive-scan engine this
// wires in (previously built and tested, but never called until now).
int run_scan_passive(int index, long duration, int verbose, struct dev_table *table) {
    g_stop = 0;

    int fd = bleurp_hci_open(index, BLEURP_HCI_CHANNEL_RAW);
    if (fd < 0) {
        perror("bleurp_hci_open(HCI_CHANNEL_RAW)");
        return -1;
    }

    enum hci_scan_mode mode = detect_scan_mode(fd);
    printf("Adapter hci%d: passive scan, %s mode\n", index,
           mode == HCI_SCAN_MODE_EXTENDED ? "extended (BT5)" : "legacy");

    if (hci_scan_start(fd, mode, HCI_LE_SCAN_PASSIVE) < 0) {
        perror("hci_scan_start");
        bleurp_hci_close(fd);
        return -1;
    }

    struct scan_ctx ctx = { .table = table };

    signal(SIGINT, on_sigint);
    time_t start = time(NULL);
    printf("\033[2J"); // clear once before the live view

    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    while (!g_stop) {
        time_t now = time(NULL);
        if (duration > 0 && (now - start) >= duration) break;

        int pr = poll(&pfd, 1, 250);
        if (pr > 0 && (pfd.revents & POLLIN)) {
            uint8_t buf[2048];
            ssize_t n = read(fd, buf, sizeof buf);
            if (n > 1 && buf[0] == HCI_EVENT_PKT) {
                (void)hci_dispatch_event(&buf[1], (size_t)(n - 1), on_adv_report, &ctx);
            }
        }

        dev_table_sort_by_rssi(table);
        ui_render(table, start, now, verbose, stdout);
    }

    hci_scan_stop(fd, mode);
    dev_table_sort_by_rssi(table);
    ui_render(table, start, time(NULL), verbose, stdout);

    bleurp_hci_close(fd);
    return 0;
}

// scan subcommand: a one-shot live scan (until duration or Ctrl-C).
int cmd_scan(int argc, char **argv) {
    struct cli_opts opts;
    char err[128];
    cli_status_t st = cli_parse(argc, argv, &opts, err, sizeof err);
    if (st == CLI_HELP) { cli_print_usage(argv[0], stdout); return 0; }
    if (st == CLI_ERR) {
        fprintf(stderr, "scan: %s\n", err);
        cli_print_usage(argv[0], stderr);
        return 2;
    }
    struct dev_table table;
    if (dev_table_init(&table) < 0) { perror("dev_table_init"); return 1; }
    int rc = opts.passive
        ? run_scan_passive(opts.iface, opts.duration, opts.verbose, &table)
        : run_scan(opts.iface, opts.duration, opts.verbose, &table);

    if (opts.output[0] != '\0') {
        FILE *f = fopen(opts.output, "w");
        if (!f) {
            fprintf(stderr, "scan: could not open output file '%s': %s\n", opts.output, strerror(errno));
        } else {
            size_t olen = strlen(opts.output);
            if (olen > 4 && strcasecmp(opts.output + olen - 4, ".csv") == 0) {
                export_csv(&table, f);
            } else {
                export_json(&table, f);
            }
            fclose(f);
            printf("\nResults exported to %s (%zu devices)\n", opts.output, dev_table_count(&table));
        }
    } else if (opts.json) {
        export_json(&table, stdout);
    } else {
        printf("\nStopped. %zu device(s) found.\n", dev_table_count(&table));
    }

    dev_table_free(&table);
    return rc < 0 ? 1 : 0;
}
