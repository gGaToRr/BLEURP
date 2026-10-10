// ========================================
//  nom du fichier: repair_cmd.c
//  description courte: Implementation of the `repair` subcommand.
//  Extracted from src/main.c during the v2 rewrite's Phase 8 breakup. See
//  repair_cmd.h for the contract.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "repair_cmd.h"
#include "common.h"
#include "l2cap.h"
#include "repair.h"
#include "smp_native.h"
#include "ui.h"

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>

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
int cmd_repair(int argc, char **argv) {
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
