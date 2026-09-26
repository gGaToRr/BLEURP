# Command-Line Arguments (`cli.c`)

This document explains, in plain terms, how BLEURP turns the words you type
after `bleurp` into a small settings struct the rest of the program reads.

> Read this if you want to know exactly which flags exist, what they do, or
> why a command was rejected.

## The idea in one picture

Every subcommand eventually needs the same handful of settings: which
adapter to use, how long to run, where to save output. Instead of every
subcommand parsing that by hand, `cli.c` does it once, in one place:

```
   argv (what you typed)                struct cli_opts (what the code reads)
   ----------------------                --------------------------------------
   "-i" "hci1" "-t" "30" "--json"  --->   { iface = 1, duration = 30,
                                             output = "", json = true,
                                             passive = false, help = false }
```

`cli_parse()` is the only function that knows about dashes and letters.
Everything downstream just reads plain struct fields.

## Accepted flags

| Flag | Long form | Argument | Default | Meaning |
|---|---|---|---|---|
| `-i` | `--iface` | `hciN` or a bare index | `hci0` | which Bluetooth controller to use |
| `-t` | `--time` | seconds (`0` = until Ctrl-C) | `0` | how long to scan |
| `-o` | `--output` | file path | *(none)* | where to save results |
| | `--json` | *(flag)* | off | save/print results as JSON instead of plain text |
| | `--passive` | *(flag)* | off | passive scan (listen only, no `SCAN_REQ`) |
| | `--active` | *(flag)* | on | active scan (the default; see [`scan-overview.md`](scan-overview.md)) |
| `-h` | `--help` | *(flag)* | off | print the usage text and stop |

`--passive` and `--active` both just set the same `passive` boolean; whichever
one you pass last wins, so `--passive --active` ends up active.

## Three possible outcomes

`cli_parse()` never exits the program itself — it hands the caller one of
three results and lets the caller decide what to do:

```
                     cli_parse(argc, argv, &opts, err, sizeof err)
                                     |
             +-----------------------+-----------------------+
             |                       |                       |
          CLI_OK                  CLI_HELP                 CLI_ERR
     (opts is ready to        (-h/--help was given;    (bad input; `err` holds
      use, keep going)         print usage, exit 0)      a message, exit non-0)
```

This mirrors how the rest of BLEURP reports success/failure (see
`gatt.c`'s `int`+`err` pattern), so it feels familiar and is easy to test
without the parser ever calling `exit()` behind your back.

## Why invalid input is rejected early

An interface index outside `0..255`, a negative duration, an empty `-o`
path, or an unknown flag are all caught inside `cli_parse()`, before any
Bluetooth socket is opened. Rejecting bad input at the door, with a message
that says exactly what was wrong (e.g. `invalid duration: -5 (expected 0 or
a positive number of seconds)`), is cheaper and safer than discovering it
three function calls later next to a raw HCI socket.

## Testing

`tests/test_cli.c` builds small `argv`-style arrays in memory and calls
`cli_parse()` directly — no real command line, no subprocess, no Bluetooth
adapter needed. That is what makes it fast enough to run on every `make
test`, and it is why the parsing logic lives in its own file instead of
being inlined into `main.c`.
