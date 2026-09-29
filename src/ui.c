// ========================================
//  nom du fichier: ui.c
//  description courte: Implementation of the terminal UI. Maps RSSI to colour
//  and bars, formats a widely-spaced device row (address MSB-first, signal as
//  [+++..]), and redraws in place the sorted scan table plus a fingerprint
//  table (category, vendor, privacy, HID, exposure) with an exposure legend.
//  dernière modification : 2026-09-27
//  auteur: GitHub/@gGaToRr
// ========================================

#include "ui.h"

#include <string.h>

// ANSI colours by signal band, and the fingerprint table's theme colours
// (yellow/pink/purple + an orange alert accent) all live in ui.h so they
// stay consistent with the interactive menu's banner and prompts.

// A device at or above this exposure score is flagged with a '!' marker.
#define UI_EXPOSURE_FLAG 60

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

// Extract the privacy posture token from the fingerprint details line, which
// begins "...priv=<token>...". Returns a short static string; "-" if absent.
static const char *privacy_from_details(const char *details) {
    const char *p = strstr(details, "priv=");
    if (!p) return "-";
    p += 5;
    static char tok[12];
    size_t i = 0;
    while (p[i] && p[i] != ' ' && i < sizeof tok - 1) { tok[i] = p[i]; i++; }
    tok[i] = '\0';
    return tok[0] ? tok : "-";
}

// True when the fingerprint details mention the HID service.
static int details_has_hid(const char *details) {
    return strstr(details, "HID") != NULL;
}

// Format one scan row. See ui.h for the contract. Unchanged layout.
int ui_format_row(char *buf, size_t buf_len, int index,
                  const struct dev_entry *e) {
    const uint8_t *a = e->address;
    const char *name = (e->has_name && e->name[0] != '\0') ? e->name : "(unknown)";

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

// Render the fingerprint table under the scan. Same device order as the scan
// (the '#' matches between the two tables). Columns: index, address, category,
// vendor, privacy posture, HID flag, exposure score (+ orange '!' when high).
static void ui_render_fingerprints(const struct dev_table *t, FILE *out) {
    size_t count = dev_table_count(t);

    fprintf(out, "\n  %s%sFINGERPRINT (passive)%s\033[K\n", UI_BOLD, UI_YELLOW, UI_RESET);
    fprintf(out, "  %s  #    ADDRESS              CAT           VENDOR        "
                 "PRIVACY   HID   EXPO%s\033[K\n", UI_PINK, UI_RESET);
    fprintf(out, "  %s----------------------------------------------------------"
                 "------------------------%s\033[K\n", UI_PURPLE, UI_RESET);

    int any_flagged = 0;
    for (size_t i = 0; i < count; i++) {
        const struct dev_entry *e = dev_table_at(t, i);
        const uint8_t *a = e->address;

        const char *cat = (e->category[0] != '\0') ? e->category : "-";
        const char *priv = privacy_from_details(e->details);
        int hid = details_has_hid(e->details);

        // Vendor: parse "vendor=<name>" out of details, else "-".
        char vendor[16] = "-";
        const char *vp = strstr(e->details, "vendor=");
        if (vp) {
            vp += 7;
            size_t j = 0;
            while (vp[j] && vp[j] != ' ' && j < sizeof vendor - 1) {
                vendor[j] = vp[j]; j++;
            }
            vendor[j] = '\0';
        }

        char mark = (e->exposure >= UI_EXPOSURE_FLAG) ? '!' : ' ';
        if (mark == '!') any_flagged = 1;

        // Line body, then paint: orange marker if flagged, cyan-ish otherwise.
        char line[192];
        snprintf(line, sizeof line,
                 "%3d    %02X:%02X:%02X:%02X:%02X:%02X    %-10s    %-10s    "
                 "%-7s   %-3s   %3d",
                 (int)i + 1, a[5], a[4], a[3], a[2], a[1], a[0],
                 cat, vendor, priv, hid ? "yes" : "-", e->exposure);

        if (mark == '!') {
            fprintf(out, "  %s%s%c %s%s\033[K\n",
                    UI_ORANGE, UI_BOLD, mark, line, UI_RESET);
        } else {
            fprintf(out, "  %s%c %s%s\033[K\n", UI_PURPLE, mark, line, UI_RESET);
        }
    }

    // Legend under the fingerprint table.
    fprintf(out, "\n  %sCAT%s = type d'appareil  \342\200\242  %sPRIVACY%s = posture "
                 "d'adresse (public/static = tra\303\247able)\033[K\n",
            UI_PINK, UI_RESET, UI_PINK, UI_RESET);
    if (any_flagged) {
        fprintf(out, "  %s%s!%s %s= EXPO \342\211\245 %d : forte exposition "
                     "(adresse tra\303\247able et/ou HID expos\303\251) "
                     "\342\200\224 int\303\251r\303\252t recon, pas une faille%s\033[K\n",
                UI_ORANGE, UI_BOLD, UI_RESET, UI_ORANGE, UI_EXPOSURE_FLAG, UI_RESET);
    }
}

// Redraw the whole view in place: scan table on top, fingerprint table below.
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
        // Verbose detail goes beside the row, not on an indented line below
        // it: a device that only just got its details filled in would
        // otherwise change the frame's line count and shove every row
        // under it up/down on each redraw.
        fprintf(out, "  %s%s%s", ui_rssi_color(e->rssi), row, UI_RESET);
        if (verbose && e->details[0] != '\0') {
            fprintf(out, "    %s%s%s", UI_PURPLE, e->details, UI_RESET);
        }
        fprintf(out, "\033[K\n");
    }

    // Fingerprint table directly under the scan.
    ui_render_fingerprints(t, out);

    fprintf(out, "\033[J"); // clear anything left below a shorter frame
    fprintf(out, "\n  Ctrl-C to stop.\033[K\n");
    fflush(out);
}
