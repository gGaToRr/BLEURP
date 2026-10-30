// ========================================
//  nom du fichier: export.c
//  description courte: Implementation of CSV and JSON device table exporters.
//  auteur: GitHub/@gGaToRr
// ========================================

#include "export.h"
#include "addr_priv.h"
#include <string.h>

void export_escape_csv(const char *in, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    if (!in) { out[0] = '\0'; return; }

    bool needs_quotes = false;
    for (const char *p = in; *p; p++) {
        if (*p == ',' || *p == '"' || *p == '\n' || *p == '\r') {
            needs_quotes = true;
            break;
        }
    }

    if (!needs_quotes) {
        snprintf(out, out_len, "%s", in);
        return;
    }

    size_t j = 0;
    if (j < out_len - 1) out[j++] = '"';
    for (size_t i = 0; in[i] && j < out_len - 2; i++) {
        if (in[i] == '"') {
            if (j < out_len - 3) out[j++] = '"';
        }
        out[j++] = in[i];
    }
    if (j < out_len - 1) out[j++] = '"';
    out[j] = '\0';
}

void export_escape_json(const char *in, char *out, size_t out_len) {
    if (!out || out_len == 0) return;
    if (!in) { out[0] = '\0'; return; }

    size_t j = 0;
    for (size_t i = 0; in[i] && j < out_len - 2; i++) {
        unsigned char c = (unsigned char)in[i];
        if (c == '"') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = '"'; }
        } else if (c == '\\') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = '\\'; }
        } else if (c == '\n') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = 'n'; }
        } else if (c == '\r') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = 'r'; }
        } else if (c == '\t') {
            if (j + 2 < out_len) { out[j++] = '\\'; out[j++] = 't'; }
        } else if (c < 0x20) {
            // Drop unprintable control characters
            continue;
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
}

int export_csv(const struct dev_table *t, FILE *out) {
    if (!t || !out) return -1;

    fprintf(out, "address,address_type,privacy,trackable,rssi,best_rssi,name,category,exposure,seen\n");
    for (size_t i = 0; i < t->count; i++) {
        const struct dev_entry *e = &t->entries[i];
        char addr_str[18];
        snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 e->address[5], e->address[4], e->address[3],
                 e->address[2], e->address[1], e->address[0]);

        addr_privacy_t p = addr_privacy(e->address, e->addr_type);
        bool trackable = addr_is_trackable(p);

        char esc_name[512];
        export_escape_csv(e->name, esc_name, sizeof(esc_name));

        char esc_cat[32];
        export_escape_csv(e->category, esc_cat, sizeof(esc_cat));

        fprintf(out, "%s,%s,%s,%s,%d,%d,%s,%s,%d,%u\n",
                addr_str,
                e->addr_type == 2 ? "random" : "public",
                addr_privacy_label(p),
                trackable ? "true" : "false",
                (int)e->rssi,
                (int)e->best_rssi,
                esc_name,
                esc_cat,
                e->exposure,
                (unsigned)e->seen);
    }
    return 0;
}

int export_json(const struct dev_table *t, FILE *out) {
    if (!t || !out) return -1;

    fprintf(out, "[\n");
    for (size_t i = 0; i < t->count; i++) {
        const struct dev_entry *e = &t->entries[i];
        char addr_str[18];
        snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 e->address[5], e->address[4], e->address[3],
                 e->address[2], e->address[1], e->address[0]);

        addr_privacy_t p = addr_privacy(e->address, e->addr_type);
        bool trackable = addr_is_trackable(p);

        char esc_name[512];
        export_escape_json(e->name, esc_name, sizeof(esc_name));

        char esc_cat[32];
        export_escape_json(e->category, esc_cat, sizeof(esc_cat));

        fprintf(out, "  {\n");
        fprintf(out, "    \"address\": \"%s\",\n", addr_str);
        fprintf(out, "    \"address_type\": \"%s\",\n", e->addr_type == 2 ? "random" : "public");
        fprintf(out, "    \"privacy\": \"%s\",\n", addr_privacy_label(p));
        fprintf(out, "    \"trackable\": %s,\n", trackable ? "true" : "false");
        fprintf(out, "    \"rssi\": %d,\n", (int)e->rssi);
        fprintf(out, "    \"best_rssi\": %d,\n", (int)e->best_rssi);
        fprintf(out, "    \"name\": \"%s\",\n", esc_name);
        fprintf(out, "    \"category\": \"%s\",\n", esc_cat);
        fprintf(out, "    \"exposure\": %d,\n", e->exposure);
        fprintf(out, "    \"seen\": %u\n", (unsigned)e->seen);
        fprintf(out, "  }%s\n", (i + 1 < t->count) ? "," : "");
    }
    fprintf(out, "]\n");
    return 0;
}
