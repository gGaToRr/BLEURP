// ========================================
//  nom du fichier: ui.c
//  description courte: Implementation of the terminal UI. Maps RSSI to colour
//  and bars, formats a device row (address shown MSB-first), and redraws the
//  whole sorted table in place using ANSI cursor control.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "ui.h"

// ANSI colours by signal band.
#define UI_GREEN  "\033[32m"
#define UI_YELLOW "\033[33m"
#define UI_RED    "\033[31m"

// Colour for an RSSI value. See ui.h for the contract.
const char *ui_rssi_color(int8_t rssi) {
    if (rssi >= -65) return UI_GREEN;
    if (rssi >= -80) return UI_YELLOW;
    return UI_RED;
}

// Signal bars, 0..5. See ui.h for the contract.
int ui_rssi_bars(int8_t rssi) {
    if (rssi >= -55) return 5;
    if (rssi >= -65) return 4;
    if (rssi >= -75) return 3;
    if (rssi >= -85) return 2;
    if (rssi >= -95) return 1;
    return 0;
}

// Human string for an address type.
static const char *addr_type_str(uint8_t t) {
    switch (t) {
    case 1:  return "public";
    case 2:  return "random";
    default: return "other";
    }
}

// Format one row. See ui.h for the contract.
int ui_format_row(char *buf, size_t buf_len, int index,
                  const struct dev_entry *e) {
    const uint8_t *a = e->address;
    const char *name = (e->has_name && e->name[0] != '\0') ? e->name : "(unknown)";
    return snprintf(buf, buf_len,
                    "%2d  %02X:%02X:%02X:%02X:%02X:%02X  %4d dBm  %-6s  %4u  %s",
                    index, a[5], a[4], a[3], a[2], a[1], a[0],
                    e->rssi, addr_type_str(e->addr_type), e->seen, name);
}

// Draw a small signal bar like [###..].
static void write_bars(FILE *out, int bars) {
    fputc('[', out);
    for (int i = 0; i < 5; i++) fputc(i < bars ? '#' : '.', out);
    fputc(']', out);
}

// Redraw the whole table in place. See ui.h for the contract.
void ui_render(const struct dev_table *t, time_t start, time_t now,
               FILE *out) {
    size_t count = dev_table_count(t);
    long elapsed = (long)(now - start);

    // Home the cursor, then clear each line to end as we go.
    fprintf(out, "\033[H");
    fprintf(out, "  BLEURP  \342\200\224  scanning BLE (kernel mgmt, active)   "
                 "%3lds   %zu device(s)\033[K\n", elapsed, count);
    fprintf(out, "  --------------------------------------------------"
                 "-----------------\033[K\n");
    fprintf(out, "   #  ADDRESS            RSSI       SIGNAL  TYPE    "
                 "SEEN  NAME\033[K\n");

    char row[160];
    for (size_t i = 0; i < count; i++) {
        const struct dev_entry *e = dev_table_at(t, i);
        ui_format_row(row, sizeof row, (int)i + 1, e);
        // Row text, then a colour-coded signal bar for the band.
        fprintf(out, "  %s  ", row);
        fprintf(out, "%s", ui_rssi_color(e->rssi));
        write_bars(out, ui_rssi_bars(e->rssi));
        fprintf(out, "%s\033[K\n", UI_RESET);
    }

    // Clear anything left below (devices that dropped off a shorter frame).
    fprintf(out, "\033[J");
    fprintf(out, "\n  Ctrl-C to stop.\033[K\n");
    fflush(out);
}
