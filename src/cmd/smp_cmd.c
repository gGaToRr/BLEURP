// ========================================
//  nom du fichier: smp_cmd.c
//  description courte: Implementation of the `smp` subcommand. Extracted
//  from src/main.c during the v2 rewrite's Phase 8 breakup. See smp_cmd.h.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "smp_cmd.h"
#include "common.h"
#include "l2cap.h"
#include "smp_native.h"

#include <getopt.h>
#include <stdio.h>
#include <string.h>

// smp subcommand: probe SMP pairing security parameters via native HCI User Channel.
int cmd_smp_native(int argc, char **argv) {
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
