// ========================================
//  nom du fichier: banner.h
//  description courte: Menu banner for BLEURP. Renders the word "BLEURP"
//  from a bundled FIGlet font file (.flf) and paints it with a home-grown
//  lolcat-style diagonal rainbow gradient. No external figlet/lolcat
//  process is spawned: the font file is parsed directly.
//  dernière modification : 2026-09-27
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_BANNER_H
#define BLEURP_BANNER_H

#include <stdio.h>

// Render the BLEURP banner to `out`. Falls back to a small built-in
// block-letter banner if the bundled .flf font file cannot be read, so the
// menu never breaks without it.
void banner_print(FILE *out);

#endif // BLEURP_BANNER_H
