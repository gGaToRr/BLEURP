// ========================================
//  nom du fichier: secreq_cmd.c
//  description courte: Implementation of the `secreq` subcommand.
//  Extracted from src/main.c during the v2 rewrite's Phase 8 breakup. See
//  secreq_cmd.h for the contract.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "secreq_cmd.h"
#include "common.h"
#include "repair.h"
#include "secreq.h"
#include "smp_native.h"
#include "ui.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

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
int cmd_secreq(int argc, char **argv) {
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
