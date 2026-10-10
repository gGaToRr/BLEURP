// ========================================
//  nom du fichier: gatt_cmd.h
//  description courte: The `enum`/`audit`/`read`/`write` subcommands (GATT
//  connection, tree dump, unauthenticated-access audit, raw handle I/O).
//  do_enum()/do_audit() are also called directly by the interactive menu
//  and cmd_keyboard (src/main.c), not just their own cmd_* wrappers.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_CMD_GATT_CMD_H
#define BLEURP_CMD_GATT_CMD_H

#include <stdint.h>

int cmd_enum(int argc, char **argv);
int cmd_audit(int argc, char **argv);
int cmd_read(int argc, char **argv);
int cmd_write(int argc, char **argv);

// Connect to a device and print its GATT tree. Address is in HCI byte order.
int do_enum(const uint8_t addr[6], uint8_t atype);

// Connect to an authorized device and audit which characteristics are
// accessible without pairing. Address is in HCI byte order.
int do_audit(const uint8_t addr[6], uint8_t atype);

#endif // BLEURP_CMD_GATT_CMD_H
