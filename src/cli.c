// ========================================
//  nom du fichier: cli.c
//  description courte: Implements cli_parse(): wraps getopt_long() to turn
//  argv into a struct cli_opts, with clear rejection messages for invalid
//  interfaces, durations, and output paths. See cli.h for the accepted
//  flags.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

#include "cli.h"

#include <getopt.h>
#include <stdlib.h>
#include <string.h>

// Long-only flags map to option codes outside the short optstring below, so
// getopt_long() never confuses them with a single-dash short option.
enum { OPT_JSON = 256, OPT_PASSIVE, OPT_ACTIVE };

static const struct option long_opts[] = {
    {"iface",   required_argument, NULL, 'i'},
    {"time",    required_argument, NULL, 't'},
    {"output",  required_argument, NULL, 'o'},
    {"json",    no_argument,       NULL, OPT_JSON},
    {"passive", no_argument,       NULL, OPT_PASSIVE},
    {"active",  no_argument,       NULL, OPT_ACTIVE},
    {"help",    no_argument,       NULL, 'h'},
    {NULL, 0, NULL, 0},
};

// Reset `out` to its defaults (see cli.h for what each field means).
void cli_set_defaults(struct cli_opts *out) {
    out->iface = 0;
    out->duration = 0;
    out->output[0] = '\0';
    out->json = false;
    out->passive = false;
    out->help = false;
}

// Print the accepted flags. Kept in one place so -h and error paths agree.
void cli_print_usage(const char *prog, FILE *stream) {
    fprintf(stream,
            "Usage: %s [options]\n"
            "  -i, --iface <name|index>  HCI controller, e.g. hci0 or 0 (default hci0)\n"
            "  -t, --time <seconds>      scan duration; 0 = until Ctrl-C (default 0)\n"
            "  -o, --output <file>       write results to <file>\n"
            "      --json                emit machine-readable JSON\n"
            "      --passive             passive scan (listen only)\n"
            "      --active              active scan (default)\n"
            "  -h, --help                show this help and exit\n",
            prog);
}

// Accept "hci0"/"hci12" or a bare index ("0"/"12"). Returns 0, or -1 if `s`
// is not one of those forms or is out of the 0-255 HCI index range.
static int parse_iface(const char *s, int *out) {
    if (!s || !*s) {
        return -1;
    }
    if (strncmp(s, "hci", 3) == 0) {
        s += 3;
    }
    if (!*s) {
        return -1;
    }
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 0 || v > 255) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

// Parse a non-negative second count. Returns 0, or -1 if not a plain
// non-negative integer.
static int parse_duration(const char *s, long *out) {
    if (!s || !*s) {
        return -1;
    }
    char *end;
    long v = strtol(s, &end, 10);
    if (*end != '\0' || v < 0) {
        return -1;
    }
    *out = v;
    return 0;
}

// See cli.h.
cli_status_t cli_parse(int argc, char **argv, struct cli_opts *out,
                        char *err, size_t errlen) {
    cli_set_defaults(out);

    opterr = 0; // we report our own messages instead of getopt's
    optind = 1; // rescan argv from the start (argv may be reused by tests)

    int c;
    while ((c = getopt_long(argc, argv, "i:t:o:h", long_opts, NULL)) != -1) {
        switch (c) {
        case 'i':
            if (parse_iface(optarg, &out->iface) < 0) {
                snprintf(err, errlen, "invalid interface: %s (expected hciN or an index)",
                         optarg);
                return CLI_ERR;
            }
            break;
        case 't':
            if (parse_duration(optarg, &out->duration) < 0) {
                snprintf(err, errlen, "invalid duration: %s (expected 0 or a positive number of seconds)",
                         optarg);
                return CLI_ERR;
            }
            break;
        case 'o':
            if (optarg[0] == '\0') {
                snprintf(err, errlen, "output path cannot be empty");
                return CLI_ERR;
            }
            if (strlen(optarg) >= sizeof out->output) {
                snprintf(err, errlen, "output path too long (max %zu characters)",
                         sizeof out->output - 1);
                return CLI_ERR;
            }
            strcpy(out->output, optarg);
            break;
        case OPT_JSON:
            out->json = true;
            break;
        case OPT_PASSIVE:
            out->passive = true;
            break;
        case OPT_ACTIVE:
            out->passive = false;
            break;
        case 'h':
            out->help = true;
            return CLI_HELP;
        default: { // '?': unknown flag, or a required argument was missing
            const char *tok = (optind > 1 && optind - 1 < argc) ? argv[optind - 1] : "?";
            snprintf(err, errlen, "invalid option: %s", tok);
            return CLI_ERR;
        }
        }
    }

    return CLI_OK;
}
