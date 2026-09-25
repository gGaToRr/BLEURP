# BLEURP — Architecture

A small, dependency-free BLE scanner written in C for Linux. Each module is
built and tested in isolation (TDD) before it is wired into the tool.

## Modules

```
  src/
    hci.h        wire constants: packet types + LE scan opcodes
    hci_cmd.c    build raw HCI command packets            [DONE, tested]
    hci_cmd.h
    (next) hci_dev.c   open/bind the raw HCI socket to an adapter
    (next) hci_scan.c  drive legacy/extended LE scanning
    (next) ad_parse.c  decode advertising data (name, RSSI, UUIDs)
    (next) main.c      CLI + live device table
  tests/
    test.h            tiny assertion framework
    test_hci_cmd.c    unit tests for hci_cmd               [DONE]
```

## Build & test

```sh
make        # compile library objects
make test   # build and run every tests/test_*.c
make clean  # remove build/
```

Flags: `-std=c11 -Wall -Wextra -Werror`. Warnings are errors on purpose.

## Data flow (target)

```
  CLI args ──► hci_dev (open socket) ──► hci_scan (enable LE scan)
                                              │
                                    HCI events (advertising reports)
                                              ▼
                                         ad_parse (name, RSSI, UUIDs)
                                              ▼
                                    live device table  ──►  CSV / JSON
```

## Conventions

- English comments above every function, struct, and enum.
- File header banner at the top of every source file.
- Per-feature docs live in `docs/`, with a diagram where it helps.
- Linux only, for now.
