// ========================================
//  nom du fichier: export.h
//  description courte: Export discovered devices to CSV and JSON formats.
//  Handles field escaping and formatting for structured tool outputs.
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_EXPORT_H
#define BLEURP_EXPORT_H

#include "dev_table.h"
#include <stdio.h>

// Export device table to CSV. Writes header then one line per device.
// Returns 0 on success, -1 on failure.
int export_csv(const struct dev_table *t, FILE *out);

// Export device table to JSON array.
// Returns 0 on success, -1 on failure.
int export_json(const struct dev_table *t, FILE *out);

// Helper to escape string for CSV (wraps in quotes and doubles internal quotes if needed).
void export_escape_csv(const char *in, char *out, size_t out_len);

// Helper to escape string for JSON (escapes \", \\, and control characters).
void export_escape_json(const char *in, char *out, size_t out_len);

#endif // BLEURP_EXPORT_H
