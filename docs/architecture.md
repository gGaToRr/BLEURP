# BLEURP — Architecture

A small, dependency-free BLE scanner written in C for Linux. Each module is
built and tested in isolation (TDD) before it is wired into the tool.

## Modules

```
  src/
    hci.h        wire constants: packet types + LE scan opcodes
    hci_cmd.c    build raw HCI command packets            [DONE, tested]
    hci_cmd.h
    hci_dev.c    open/bind the raw HCI socket to an adapter [DONE, tested]
    hci_dev.h
    hci_info.c   read controller version, pick legacy/ext  [DONE, tested]
    hci_info.h
    hci_scan.c   scan commands, mode switch, event dispatch [DONE, tested]
    hci_scan.h                                    (raw mode; kept as advanced)
    mgmt.c       kernel mgmt: socket, packets, controller info [DONE, tested]
    mgmt.h       (primary discovery path: clean, coexists with bluetoothd)
    ad_parse.c   decode AD (name, UUIDs, company), best label [DONE, tested]
    ad_parse.h
    (next) dev_table.c merge Device Found, dedup, keep best name (#6)
    (next) ui.c + main.c  wifite-style live table (#8) + CLI (#7)
  tests/
    test.h            tiny assertion framework
    test_hci_cmd.c    unit tests for hci_cmd               [DONE]
    test_hci_dev.c    unit tests for hci_dev               [DONE]
    test_hci_info.c   unit tests for hci_info              [DONE]
    test_hci_scan.c   unit tests for hci_scan              [DONE]
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
