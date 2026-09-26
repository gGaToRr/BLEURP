// ========================================
//  nom du fichier: test_cli.c
//  description courte: Unit tests for cli_parse(): defaults, every accepted
//  flag (-i/-t/-o/--json/--passive/--active/-h), and rejection of invalid
//  interfaces, durations, output paths, and unknown options.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "cli.h"
#include "test.h"

#include <string.h>

// Build an argv-like array from string literals and run cli_parse() on it.
// argv[0] is always a fake program name, matching how main() sees argc/argv.
#define PARSE(opts, err, errlen, ...)                                     \
    do {                                                                  \
        char *argv_[] = {"bleurp", __VA_ARGS__};                          \
        int argc_ = (int)(sizeof argv_ / sizeof argv_[0]);                \
        status_ = cli_parse(argc_, argv_, opts, err, errlen);             \
    } while (0)

static cli_status_t status_; // last cli_parse() return, set by PARSE()

// No flags: every field should hold the documented default.
static void test_defaults(void) {
    struct cli_opts o;
    char err[128];
    PARSE(&o, err, sizeof err);
    CHECK(status_ == CLI_OK);
    CHECK(o.iface == 0);
    CHECK(o.duration == 0);
    CHECK(o.output[0] == '\0');
    CHECK(o.json == false);
    CHECK(o.passive == false);
    CHECK(o.help == false);
}

// -i / --iface accept both "hciN" and a bare index.
static void test_iface(void) {
    struct cli_opts o;
    char err[128];

    PARSE(&o, err, sizeof err, "-i", "hci1");
    CHECK(status_ == CLI_OK);
    CHECK(o.iface == 1);

    PARSE(&o, err, sizeof err, "--iface", "2");
    CHECK(status_ == CLI_OK);
    CHECK(o.iface == 2);

    PARSE(&o, err, sizeof err, "-i", "hciX");
    CHECK(status_ == CLI_ERR);
    CHECK(err[0] != '\0');

    PARSE(&o, err, sizeof err, "-i", "-1");
    CHECK(status_ == CLI_ERR);
}

// -t / --time: 0 or a positive number of seconds; anything else is rejected.
static void test_duration(void) {
    struct cli_opts o;
    char err[128];

    PARSE(&o, err, sizeof err, "-t", "30");
    CHECK(status_ == CLI_OK);
    CHECK(o.duration == 30);

    PARSE(&o, err, sizeof err, "--time", "0");
    CHECK(status_ == CLI_OK);
    CHECK(o.duration == 0);

    PARSE(&o, err, sizeof err, "-t", "-5");
    CHECK(status_ == CLI_ERR);

    PARSE(&o, err, sizeof err, "-t", "soon");
    CHECK(status_ == CLI_ERR);
}

// -o / --output: stores the path; rejects empty or over-length paths.
static void test_output(void) {
    struct cli_opts o;
    char err[128];

    PARSE(&o, err, sizeof err, "-o", "scan.json");
    CHECK(status_ == CLI_OK);
    CHECK(strcmp(o.output, "scan.json") == 0);

    PARSE(&o, err, sizeof err, "-o", "");
    CHECK(status_ == CLI_ERR);

    char big[CLI_OUTPUT_MAX + 16];
    memset(big, 'a', sizeof big - 1);
    big[sizeof big - 1] = '\0';
    PARSE(&o, err, sizeof err, "-o", big);
    CHECK(status_ == CLI_ERR);
}

// --json, --passive / --active are independent boolean flags.
static void test_flags(void) {
    struct cli_opts o;
    char err[128];

    PARSE(&o, err, sizeof err, "--json");
    CHECK(status_ == CLI_OK);
    CHECK(o.json == true);
    CHECK(o.passive == false); // active is still the default

    PARSE(&o, err, sizeof err, "--passive");
    CHECK(status_ == CLI_OK);
    CHECK(o.passive == true);

    // --active after --passive switches back to active.
    PARSE(&o, err, sizeof err, "--passive", "--active");
    CHECK(status_ == CLI_OK);
    CHECK(o.passive == false);
}

// -h/--help stops parsing and reports CLI_HELP without treating it as an
// error, even when combined with other flags.
static void test_help(void) {
    struct cli_opts o;
    char err[128];

    PARSE(&o, err, sizeof err, "-h");
    CHECK(status_ == CLI_HELP);
    CHECK(o.help == true);

    PARSE(&o, err, sizeof err, "-t", "10", "--help");
    CHECK(status_ == CLI_HELP);
}

// Unknown flags and missing required arguments are rejected with a message.
static void test_invalid_option(void) {
    struct cli_opts o;
    char err[128];

    PARSE(&o, err, sizeof err, "--bogus");
    CHECK(status_ == CLI_ERR);
    CHECK(err[0] != '\0');

    PARSE(&o, err, sizeof err, "-i"); // missing required argument
    CHECK(status_ == CLI_ERR);
}

// Every combined flag lands in the same struct in one pass.
static void test_combined(void) {
    struct cli_opts o;
    char err[128];

    PARSE(&o, err, sizeof err, "-i", "hci0", "-t", "15", "-o", "out.csv",
          "--json", "--passive");
    CHECK(status_ == CLI_OK);
    CHECK(o.iface == 0);
    CHECK(o.duration == 15);
    CHECK(strcmp(o.output, "out.csv") == 0);
    CHECK(o.json == true);
    CHECK(o.passive == true);
}

int main(void) {
    printf("test_cli\n");
    test_defaults();
    test_iface();
    test_duration();
    test_output();
    test_flags();
    test_help();
    test_invalid_option();
    test_combined();
    return TEST_REPORT();
}
