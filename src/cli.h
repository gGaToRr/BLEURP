// ========================================
//  nom du fichier: cli.h
//  description courte: Command-line argument parsing shared by BLEURP's
//  subcommands. Turns argv into a plain config struct (interface, duration,
//  output file, JSON flag, passive/active), independent of any one
//  subcommand so it can be unit tested on its own.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_CLI_H
#define BLEURP_CLI_H

#include <stdbool.h>
#include <stdio.h>

// Longest accepted -o/--output path, including the terminating NUL.
#define CLI_OUTPUT_MAX 256

// Parsed command-line configuration. Populated by cli_parse(); see
// cli_set_defaults() for the values used when a flag is not given.
struct cli_opts {
    int  iface;               // HCI controller index (0 = hci0, 1 = hci1, ...)
    long duration;             // scan duration in seconds; 0 = until Ctrl-C
    char output[CLI_OUTPUT_MAX]; // -o/--output path; empty = no output file
    bool json;                 // --json: emit machine-readable JSON
    bool passive;              // --passive: listen only (default is active)
    bool help;                  // -h/--help was requested
};

// Result of cli_parse(). CLI_ERR is negative so callers can keep using the
// usual "< 0 is failure" check if they only care about success/failure.
typedef enum {
    CLI_ERR  = -1, // invalid input; a message was written to `err`
    CLI_OK   = 0,  // parsed successfully, `out` is ready to use
    CLI_HELP = 1   // -h/--help was given; usage was not run, print & exit 0
} cli_status_t;

// Reset `out` to its defaults: hci0, duration 0 (until Ctrl-C), no output
// file, JSON off, active scan, help not requested.
void cli_set_defaults(struct cli_opts *out);

// Parse `argv[0..argc)` into `out` (already reset by cli_set_defaults).
// On CLI_ERR, a human-readable, English message is written into `err`
// (a caller-owned buffer of `errlen` bytes) describing what was wrong.
// Accepted flags: -i/--iface <name|index>, -t/--time <seconds>,
// -o/--output <file>, --json, --passive, --active, -h/--help.
cli_status_t cli_parse(int argc, char **argv, struct cli_opts *out,
                        char *err, size_t errlen);

// Print the flag summary for cli_parse() to `stream` (e.g. stdout for -h,
// stderr for a usage reminder after a parse error).
void cli_print_usage(const char *prog, FILE *stream);

#endif // BLEURP_CLI_H
