// ========================================
//  nom du fichier: common.h
//  description courte: Small utilities shared across BLEURP's CLI
//  subcommands (src/cmd/) and the interactive menu (src/menu/): argument
//  parsing (parse_addr, parse_long_arg) and the terminal prompt helpers
//  the menu wizards are built from (read_line, ask_yes_no, ask_number,
//  ask_interface). Not a public library API -- internal glue extracted
//  from what was previously one 3400-line src/main.c.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_CMD_COMMON_H
#define BLEURP_CMD_COMMON_H

#include <stddef.h>
#include <stdint.h>

// Parse "AA:BB:CC:DD:EE:FF" into HCI byte order (LSB first). Returns 0 or -1.
int parse_addr(const char *s, uint8_t out[6]);

// Parse an integer option that must fall in [min, max]. Returns 0 or -1.
// Unlike atoi()/atol(), "-i abc" or "-t -5" is refused rather than silently
// becoming 0 or an out-of-range value. `base` 0 also accepts 0x-prefixed hex.
int parse_long_arg(const char *s, int base, long min, long max, long *out);

// Read a line from stdin into buf (newline stripped). Returns 0 or -1 on EOF.
int read_line(char *buf, size_t n);

// Ask a yes/no question with a short description; empty input keeps the default.
int ask_yes_no(const char *label, const char *desc, int default_yes);

// Ask a numeric value with a short description; empty or invalid input
// keeps the default.
long ask_number(const char *label, const char *desc, long default_val);

// Ask which HCI controller to use. Accepts either a plain index ("1") or
// the "hciN" form ("hci1"). Falls back to the default on anything else (no
// silent drop back to hci0 on a typo).
long ask_interface(long default_val);

#endif // BLEURP_CMD_COMMON_H
