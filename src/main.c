// ========================================
//  nom du fichier: main.c
//  description courte: BLEURP entry point. Prints top-level usage and
//  dispatches argv[1] to the right subcommand, or to the interactive menu
//  with none given. All actual logic lives in src/cmd/ and src/menu/ (see
//  docs/architecture.md) -- this file is deliberately thin after the v2
//  rewrite's Phase 8 breakup (was ~3400 lines; subcommand implementations
//  and the whole interactive menu/wizard subsystem moved out).
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include "cmd/scan.h"
#include "cmd/gatt_cmd.h"
#include "cmd/smp_cmd.h"
#include "cmd/repair_cmd.h"
#include "cmd/secreq_cmd.h"
#include "cmd/blerp_cmd.h"
#include "hid_cmd.h"
#include "menu/menu.h"

// Print usage for the scan command / top level.
static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s                                      interactive menu (default)\n"
            "  %s wizard                               guided all-in-one audit pipeline\n"
            "  %s finale [--all-test]                  scan 15s + test connexion re-pairing (cible unique ou All-Test) + bannière SUCCESS\n"
            "  %s scan  [-i index] [-t seconds] [-v]   live BLE scan\n"
            "  %s autotry [-i index] [-t s] [-T ms]    scan, then connect + audit every device found (no prompts)\n"
            "  %s enum  <ADDR> [-t public|random]      connect and dump GATT\n"
            "  %s audit <ADDR> [-t public|random]      audit unauthenticated GATT access\n"
            "  %s read  <ADDR> <handle> [-t ...]       read a value by handle\n"
            "  %s write <ADDR> <handle> <hex> [-t ...] write bytes by handle\n"
            "  %s hid   -i hciX -t <ADDR> -f <payload> send a HID payload\n"
            "  %s smp   <ADDR> [-i index] [-t ...]     probe SMP pairing security level (native HCI)\n"
            "  %s repair [ADDR] [-i index] [-t ...]    re-pairing check on a bonded device (BLERP); no ADDR lists bonds\n"
            "  %s secreq <ADDR> [-r ARSR] [-c s] [-w s] Security Request test on a bonded Central (BLERP, Apple finding)\n"
            "  %s blerp <pi|ci|mitm|audit> [ADDR]      BLERP attack & audit suite (NDSS 2026)\n"
            "  %s keyboard [-i index] [-n name] [-d ..] BLE Keyboard Peripheral emulator (HOGP)\n"
            "  -i index    HCI controller index (default 0 = hci0)\n"
            "  -t seconds  scan duration; 0 = until Ctrl-C (default 0)\n"
            "  -v          verbose scan (per-device vendor/services details)\n"
            "Only use on devices you own or are authorized to test.\n",
            prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog, prog);
}
int main(int argc, char **argv) {
    if (argc >= 2) {
        if (strcmp(argv[1], "wizard") == 0 ||
            strcmp(argv[1], "suite") == 0 ||
            strcmp(argv[1], "pipeline") == 0)   { menu_guided_audit_wizard(); return 0; }
        if (strcmp(argv[1], "finale") == 0) {
            int all = -1;
            if (argc >= 3 && (strcmp(argv[2], "--all-test") == 0 ||
                              strcmp(argv[2], "all-test") == 0 ||
                              strcmp(argv[2], "-a") == 0)) {
                all = 1;
            }
            menu_finale_wizard(all);
            return 0;
        }
        if (strcmp(argv[1], "enum") == 0)       return cmd_enum(argc - 1, argv + 1);
        if (strcmp(argv[1], "audit") == 0)      return cmd_audit(argc - 1, argv + 1);
        if (strcmp(argv[1], "read") == 0)       return cmd_read(argc - 1, argv + 1);
        if (strcmp(argv[1], "write") == 0)      return cmd_write(argc - 1, argv + 1);
        if (strcmp(argv[1], "hid") == 0)        return hid_cmd_run(argc - 1, argv + 1);
        if (strcmp(argv[1], "smp") == 0)        return cmd_smp_native(argc - 1, argv + 1);
        if (strcmp(argv[1], "repair") == 0)     return cmd_repair(argc - 1, argv + 1);
        if (strcmp(argv[1], "secreq") == 0)     return cmd_secreq(argc - 1, argv + 1);
        if (strcmp(argv[1], "blerp") == 0)      return cmd_blerp(argc - 1, argv + 1);
        if (strcmp(argv[1], "keyboard") == 0 ||
            strcmp(argv[1], "peripheral") == 0 ||
            strcmp(argv[1], "adv") == 0)        return cmd_keyboard(argc - 1, argv + 1);
        if (strcmp(argv[1], "scan") == 0)       return cmd_scan(argc - 1, argv + 1);
        if (strcmp(argv[1], "autotry") == 0)   return cmd_autotry(argc - 1, argv + 1);
        if (strcmp(argv[1], "menu") == 0)       return cmd_menu();
        if (argv[1][0] == '-')                  return cmd_scan(argc, argv); // back-compat
        usage(argv[0]);
        return 2;
    }
    return cmd_menu();
}
