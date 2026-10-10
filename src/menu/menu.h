// ========================================
//  nom du fichier: menu.h
//  description courte: Entry points src/main.c's dispatcher (and
//  src/cmd/blerp_cmd.c, for the `blerp finale` shortcut) call into the
//  interactive menu module.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_MENU_H
#define BLEURP_MENU_H

// The guided, all-in-one audit pipeline (`bleurp wizard`/`suite`/`pipeline`).
void menu_guided_audit_wizard(void);

// The "Option Finale" automated pipeline (`bleurp finale`, and `bleurp
// blerp finale`). force_all_test: -1 asks interactively, 1 forces All-Test.
void menu_finale_wizard(int force_all_test);

// `autotry` subcommand: scan, then connect + audit every device found.
int cmd_autotry(int argc, char **argv);

// `keyboard`/`peripheral`/`adv` subcommand: BLE HOGP keyboard emulator.
int cmd_keyboard(int argc, char **argv);

// No-argument interactive menu (`bleurp menu`, or no arguments at all).
int cmd_menu(void);

#endif // BLEURP_MENU_H
