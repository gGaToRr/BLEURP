// ========================================
//  nom du fichier: ui.h
//  description courte: Terminal UI for the live, wifite-style device table.
//  Provides pure helpers (RSSI colour and signal bars, one formatted row)
//  and an in-place redraw of the whole table sorted by signal.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_UI_H
#define BLEURP_UI_H

#include <stddef.h>
#include <stdio.h>
#include <time.h>

#include "dev_table.h"

// ANSI reset sequence for callers that colour their own output.
#define UI_RESET "\033[0m"

// Shared theme colours, public so the interactive menu (main.c) and the
// scan/fingerprint tables (ui.c) share one consistent look.
#define UI_GREEN  "\033[32m"
#define UI_YELLOW "\033[33m"
#define UI_RED    "\033[31m"
#define UI_CYAN   "\033[36m"
#define UI_PINK   "\033[38;5;213m"
#define UI_PURPLE "\033[38;5;141m"
#define UI_ORANGE "\033[38;5;208m" // 256-colour orange, used as an alert accent
#define UI_BOLD   "\033[1m"

// ANSI colour escape for an RSSI value, by signal band (green/yellow/red).
const char *ui_rssi_color(int8_t rssi);

// Signal strength as a number of bars, 0 (weakest) to 5 (strongest).
int ui_rssi_bars(int8_t rssi);

// Format one table row into `buf`: index, address, RSSI, address type, seen
// count and name/label (or "(unknown)"). Returns the snprintf length.
int ui_format_row(char *buf, size_t buf_len, int index,
                  const struct dev_entry *e);

// Redraw the whole table in place (cursor home + clear), with a header line
// showing elapsed seconds and device count. When `verbose` is non-zero, an
// indented details line is shown under each device. The caller sorts first.
void ui_render(const struct dev_table *t, time_t start, time_t now,
               int verbose, FILE *out);

#endif // BLEURP_UI_H
