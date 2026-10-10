// ========================================
//  nom du fichier: scan.h
//  description courte: The `scan` subcommand and its live-view engine
//  (kernel-mgmt active discovery, and the raw-HCI passive scan wired in
//  during the v2 rewrite). run_scan() is also called directly by the
//  interactive menu's scan wizard (src/menu/menu.c), not just cmd_scan().
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_CMD_SCAN_H
#define BLEURP_CMD_SCAN_H

#include <signal.h>
#include <sys/types.h>

#include "dev_table.h"

// Set by SIGINT so a scan loop can stop cleanly; shared with the not-yet-
// extracted menu wizards in main.c that also run their own Ctrl-C loops.
extern volatile sig_atomic_t g_stop;
// SIGINT handler: request a clean stop (sets g_stop).
void on_sigint(int sig);
// Write an mgmt packet; returns 0 if the write did not error, -1 otherwise.
int send_pkt(int fd, const uint8_t *pkt, ssize_t n);

// scan subcommand: parses argv (-i/-t/-v/--passive/--active/-h via cli.h),
// then runs a live scan until `duration` seconds elapse or Ctrl-C.
int cmd_scan(int argc, char **argv);

// Run a live ACTIVE scan into `table` (already initialized) via the
// kernel-mgmt discovery path, until `duration` seconds elapse or Ctrl-C.
// `verbose` shows a per-device details line. Returns 0 on a normal stop,
// or -1 on a setup failure (message already printed).
int run_scan(int index, long duration, int verbose, struct dev_table *table);

// Run a live PASSIVE scan into `table` via a raw (non-exclusive) HCI
// socket. Otherwise mirrors run_scan(). Returns 0 or -1.
int run_scan_passive(int index, long duration, int verbose, struct dev_table *table);

#endif // BLEURP_CMD_SCAN_H
