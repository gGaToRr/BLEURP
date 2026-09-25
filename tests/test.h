// ========================================
//  nom du fichier: test.h
//  description courte: Minimal, dependency-free unit-test helpers for the
//  TDD workflow. Provides a non-aborting CHECK assertion and a summary
//  macro that yields a process exit code. One test binary per source file.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_TEST_H
#define BLEURP_TEST_H

#include <stdio.h>

// Per-binary counters. Each test file includes this header exactly once.
static int bleurp_checks = 0;
static int bleurp_failures = 0;

// Assert a condition, recording (not aborting on) a failure so the whole
// suite still runs and every failing line is reported.
#define CHECK(cond)                                                        \
    do {                                                                   \
        bleurp_checks++;                                                   \
        if (!(cond)) {                                                     \
            bleurp_failures++;                                             \
            fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        }                                                                  \
    } while (0)

// Print a summary and evaluate to an exit code (0 = every check passed).
#define TEST_REPORT()                                                      \
    (printf("  %d checks, %d failures\n", bleurp_checks, bleurp_failures), \
     bleurp_failures == 0 ? 0 : 1)

#endif // BLEURP_TEST_H
