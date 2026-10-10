// ========================================
//  nom du fichier: common.c
//  description courte: Implementation of the shared CLI/menu utilities.
//  See common.h for the contract.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "common.h"
#include "ui.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Parse "AA:BB:CC:DD:EE:FF" into HCI byte order (LSB first). Returns 0 or -1.
int parse_addr(const char *s, uint8_t out[6]) {
    unsigned v[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        if (v[i] > 0xff) return -1;
        out[5 - i] = (uint8_t)v[i]; // typed MSB-first -> stored LSB-first
    }
    return 0;
}

int parse_long_arg(const char *s, int base, long min, long max, long *out) {
    char *end;
    errno = 0;
    long v = strtol(s, &end, base);
    if (end == s || *end != '\0' || errno == ERANGE || v < min || v > max) return -1;
    *out = v;
    return 0;
}

int read_line(char *buf, size_t n) {
    if (!fgets(buf, (int)n, stdin)) return -1;
    buf[strcspn(buf, "\n")] = '\0';
    return 0;
}

int ask_yes_no(const char *label, const char *desc, int default_yes) {
    printf("  %s%s%s  %s(%s)%s [%s]: ", UI_PINK, label, UI_RESET,
           UI_PURPLE, desc, UI_RESET, default_yes ? "O/n" : "o/N");
    fflush(stdout);
    char line[16];
    if (read_line(line, sizeof line) < 0 || line[0] == '\0') return default_yes;
    return (line[0] == 'o' || line[0] == 'O' || line[0] == 'y' || line[0] == 'Y');
}

long ask_number(const char *label, const char *desc, long default_val) {
    printf("  %s%s%s  %s(%s)%s [%ld]: ", UI_PINK, label, UI_RESET,
           UI_PURPLE, desc, UI_RESET, default_val);
    fflush(stdout);
    char line[32];
    if (read_line(line, sizeof line) < 0 || line[0] == '\0') return default_val;
    char *end;
    long v = strtol(line, &end, 10);
    if (*end != '\0') return default_val;
    return v;
}

long ask_interface(long default_val) {
    printf("  %sInterface%s  %s(index ou nom, ex. 1 ou hci1 ; %ld = hci%ld)%s [%ld]: ",
           UI_PINK, UI_RESET, UI_PURPLE, default_val, default_val, UI_RESET, default_val);
    fflush(stdout);
    char line[32];
    if (read_line(line, sizeof line) < 0 || line[0] == '\0') return default_val;
    const char *p = line;
    if ((p[0] == 'h' || p[0] == 'H') && (p[1] == 'c' || p[1] == 'C') &&
        (p[2] == 'i' || p[2] == 'I')) {
        p += 3;
    }
    char *end;
    long v = strtol(p, &end, 10);
    if (p == end || *end != '\0') return default_val;
    return v;
}
