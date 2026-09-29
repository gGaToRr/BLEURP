// ========================================
//  nom du fichier: banner.c
//  description courte: Minimal FIGfont (.flf) parser for the BLEURP menu
//  banner. Reads the bundled assets/fonts/slant.flf, lays out the glyph
//  rows for "BLEURP" (plain concatenation, no smushing), then paints the
//  result with a diagonal rainbow gradient using lolcat's own sine-wave
//  formula, reimplemented in C so no figlet/lolcat process is spawned.
//  dernière modification : 2026-09-27
//  auteur: GitHub/@gGaToRr
// ========================================

#include "banner.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

// Baked in by the Makefile as an absolute path to the repo's font file.
// A relative fallback keeps this translation unit self-contained too.
#ifndef BLEURP_FONT_PATH
#define BLEURP_FONT_PATH "assets/fonts/slant.flf"
#endif

#define BANNER_TEXT "BLEURP"

// FIGfont required block: codes 32 ('space') through 126 ('~').
#define FLF_FIRST_CODE 32
#define FLF_NUM_CODES  95
#define FLF_MAX_HEIGHT 16
#define FLF_MAX_WIDTH  64

// One parsed glyph: up to FLF_MAX_HEIGHT rows, each up to FLF_MAX_WIDTH cols
// (hardblanks already swapped for real spaces, endmarks stripped).
struct flf_glyph {
    char row[FLF_MAX_HEIGHT][FLF_MAX_WIDTH + 1];
};

struct flf_font {
    int height;
    struct flf_glyph glyph[FLF_NUM_CODES];
};

// Keep reading `buf` until a full line (ending in '\n') has been consumed,
// discarding anything past the buffer's capacity. Protects the fixed-size
// line buffer against unexpectedly long lines (e.g. a verbose comment).
static void flf_skip_to_eol(FILE *f, char *buf, size_t buf_len) {
    while (strchr(buf, '\n') == NULL) {
        if (!fgets(buf, (int)buf_len, f)) return;
    }
}

// Strip the trailing newline, then the FIGfont endmark run (the last
// character on a glyph row, doubled on a character's final row) from one
// raw line read out of the font file.
static void flf_strip_endmarks(char *line) {
    size_t n = strcspn(line, "\r\n");
    line[n] = '\0';
    if (n == 0) return;
    char mark = line[n - 1];
    while (n > 0 && line[n - 1] == mark) n--;
    line[n] = '\0';
}

// Parse the FIGfont header line ("flf2a$ <height> <baseline> ..."). Returns
// 0 and fills `height`/`hardblank`/`comment_lines` on success, -1 if the
// line does not look like a FIGfont header.
static int flf_parse_header(const char *header, int *height, char *hardblank,
                            int *comment_lines) {
    if (strncmp(header, "flf2", 4) != 0 || strlen(header) < 7) return -1;
    *hardblank = header[5];
    int baseline, max_len, old_layout;
    if (sscanf(header + 6, "%d %d %d %d %d", height, &baseline, &max_len,
              &old_layout, comment_lines) != 5) {
        return -1;
    }
    (void)baseline; (void)max_len; (void)old_layout;
    if (*height <= 0 || *height > FLF_MAX_HEIGHT || *comment_lines < 0) return -1;
    return 0;
}

// Load and parse a FIGfont file into `font`. Returns 0 on success, -1 if the
// file is missing or malformed (the caller falls back to a built-in banner).
static int flf_load(const char *path, struct flf_font *font) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[256];
    int height, comment_lines;
    char hardblank;
    if (!fgets(line, sizeof line, f) ||
        flf_parse_header(line, &height, &hardblank, &comment_lines) < 0) {
        fclose(f);
        return -1;
    }

    for (int i = 0; i < comment_lines; i++) {
        if (!fgets(line, sizeof line, f)) { fclose(f); return -1; }
        flf_skip_to_eol(f, line, sizeof line);
    }

    font->height = height;
    for (int c = 0; c < FLF_NUM_CODES; c++) {
        for (int r = 0; r < height; r++) {
            if (!fgets(line, sizeof line, f)) { fclose(f); return -1; }
            flf_skip_to_eol(f, line, sizeof line);
            flf_strip_endmarks(line);
            for (char *p = line; *p; p++) if (*p == hardblank) *p = ' ';
            snprintf(font->glyph[c].row[r], sizeof font->glyph[c].row[r], "%s", line);
        }
    }
    fclose(f);
    return 0;
}

// Lay out one glyph row of `text` (plain horizontal concatenation, no
// smushing/kerning) into `out`.
static void flf_render_row(const struct flf_font *font, const char *text,
                           int r, char *out, size_t out_len) {
    out[0] = '\0';
    for (const char *p = text; *p; p++) {
        unsigned char ch = (unsigned char)*p;
        if (ch < FLF_FIRST_CODE || ch >= FLF_FIRST_CODE + FLF_NUM_CODES) continue;
        const char *g = font->glyph[ch - FLF_FIRST_CODE].row[r];
        strncat(out, g, out_len - strlen(out) - 1);
    }
}

// lolcat's own colour formula: a phase-shifted sine wave per RGB channel
// walked along `i`, reimplemented here so the banner gets the same "crazy
// rainbow" look without shelling out to lolcat.
static void banner_rainbow(double freq, double i, int *r, int *g, int *b) {
    *r = (int)(sin(freq * i) * 127.0 + 128.0);
    *g = (int)(sin(freq * i + 2.0943951023931953) * 127.0 + 128.0); // +2*pi/3
    *b = (int)(sin(freq * i + 4.1887902047863905) * 127.0 + 128.0); // +4*pi/3
}

// Print each laid-out row with a diagonal rainbow gradient (truecolour
// ANSI per character); spaces are left uncoloured.
static void banner_print_gradient(char lines[][FLF_MAX_WIDTH * 8], int nlines,
                                  FILE *out) {
    for (int row = 0; row < nlines; row++) {
        double i = row * 3.0; // per-row phase offset, like lolcat's diagonal band
        for (const char *p = lines[row]; *p; p++, i += 1.0) {
            if (*p == ' ') { fputc(' ', out); continue; }
            int r, g, b;
            banner_rainbow(0.15, i, &r, &g, &b);
            fprintf(out, "\033[38;2;%d;%d;%dm%c", r, g, b, *p);
        }
        fprintf(out, "\033[0m\n");
    }
}

// Built-in fallback banner (no font file needed), used only if the bundled
// .flf font cannot be read, so the menu never breaks without it.
static const char *banner_fallback[] = {
    " ______   _        ______  __   __  ______   ______  ",
    "|  __  | | |      |  ____| |  | |  ||  __  | |  __  | ",
    "| |__| | | |      | |__    | |  | || |__| | | |__| | ",
    "|  __ <  | |      |  __|   | |  | ||  __ <  |  __ <  ",
    "| |__| | | |____  | |____  | |__| || |__| | | |__| | ",
    "|______| |______| |______|  \\____/ |______| |______| ",
};

void banner_print(FILE *out) {
    struct flf_font font;
    memset(&font, 0, sizeof font);

    char lines[FLF_MAX_HEIGHT][FLF_MAX_WIDTH * 8];
    int nlines;

    if (flf_load(BLEURP_FONT_PATH, &font) == 0) {
        nlines = font.height;
        for (int r = 0; r < nlines; r++) {
            flf_render_row(&font, BANNER_TEXT, r, lines[r], sizeof lines[r]);
        }
    } else {
        nlines = (int)(sizeof banner_fallback / sizeof banner_fallback[0]);
        for (int r = 0; r < nlines; r++) {
            snprintf(lines[r], sizeof lines[r], "%s", banner_fallback[r]);
        }
    }

    banner_print_gradient(lines, nlines, out);
}
