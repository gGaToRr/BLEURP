// ========================================
//  nom du fichier: ui.c
//  description courte: Implementation of the terminal UI. Maps RSSI to colour
//  and bars, formats a widely-spaced device row (address shown MSB-first,
//  signal as [+++..]), and redraws the whole sorted table in place.
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

    // Signal as a fixed-width [+++..] gauge.
    char bars[6];
    int b = ui_rssi_bars(e->rssi);
    for (int i = 0; i < 5; i++) bars[i] = (i < b) ? '+' : '.';
    bars[5] = '\0';

    return snprintf(buf, buf_len,
                    "%3d    %02X:%02X:%02X:%02X:%02X:%02X    %4d dBm    [%s]"
                    "    %-6s    %5u    %s",
                    index, a[5], a[4], a[3], a[2], a[1], a[0],
                    e->rssi, bars, addr_type_str(e->addr_type), e->seen, name);
}

// Redraw the whole table in place. See ui.h for the contract.
void ui_render(const struct dev_table *t, time_t start, time_t now,
               int verbose, FILE *out) {
    size_t count = dev_table_count(t);
    long elapsed = (long)(now - start);

    fprintf(out, "\033[H"); // home the cursor
    fprintf(out, "  BLEURP  \342\200\224  live BLE scan (kernel mgmt, active)"
                 "     %3lds     %zu device(s)\033[K\n", elapsed, count);
    fprintf(out, "    #    ADDRESS              RSSI        SIGNAL     TYPE  "
                 "     SEEN    NAME\033[K\n");
    fprintf(out, "  ----------------------------------------------------------"
                 "----------------------\033[K\n");

    char row[192];
    for (size_t i = 0; i < count; i++) {
        const struct dev_entry *e = dev_table_at(t, i);
        ui_format_row(row, sizeof row, (int)i + 1, e);
        // Colour the whole line by signal band (like wifite colours targets).
        fprintf(out, "  %s%s%s\033[K\n", ui_rssi_color(e->rssi), row, UI_RESET);
        if (verbose && e->details[0] != '\0') {
            fprintf(out, "         \342\224\224 %s\033[K\n", e->details);
        }
    }

    fprintf(out, "\033[J"); // clear anything left below a shorter frame
    fprintf(out, "\n  Ctrl-C to stop.\033[K\n");
    fflush(out);
}
