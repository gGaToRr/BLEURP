# BLEURP — Architecture

A modular, dependency-free BLE security scanner and audit toolkit written in C for Linux. Each module is built and tested in isolation (TDD) before being wired into the tool.

---

## Modules

```
  src/
    Phase 1 (Discovery & Parsing):
      hci.h                  wire constants: packet types + LE scan opcodes
      hci_cmd.c / .h         build raw HCI command packets                  [DONE, tested]
      hci_dev.c / .h         open/bind raw HCI socket & controller queries  [DONE, tested]
      hci_info.c / .h        read controller version, pick legacy/ext       [DONE, tested]
      hci_scan.c / .h        scan commands, mode switch, event dispatch     [DONE, tested]
      mgmt.c / .h            kernel mgmt: socket, packets, controller info  [DONE, tested]
      ad_parse.c / .h        decode AD (name, UUIDs, company), labels       [DONE, tested]
      addr_priv.c / .h       classify BLE address privacy (RPA/Static/etc.) [DONE, tested]
      dev_table.c / .h       merge/dedup Device Found, best name + RSSI     [DONE, tested]
      cli.c / .h             argv -> struct cli_opts (-i/-t/-o/--json/...)  [DONE, tested]

    Phase 2 (GATT Connection & Access Audit):
      att.c / .h             ATT PDU build/parse (GATT protocol engine)     [DONE, tested]
      l2cap.c / .h           connect ATT (CID 4) / SMP (CID 6) sockets      [DONE, tested]
      gatt.c / .h            discovery + read/write/subscribe/descriptors   [DONE, tested]
      audit.c / .h           unauthenticated characteristic access audit    [DONE, tested]

    Phase 3 (Recon, SMP Security & Keystroke Injection):
      banner.c / .h          FIGlet slant font parser + rainbow gradient    [DONE]
      fingerprint.c / .h     passive device categorization & exposure score [DONE, tested]
      smp.c / .h             SMP packet codec & L2CAP CID 6 downgrade probe [DONE, tested]
      smp_native/
        smp_native.c / .h    native HCI User Channel SMP diagnostic probe   [DONE, tested]
      peripheral_native.c/.h native BLE HOGP Keyboard emulator + SMP STK    [DONE, tested]
      send_attack/
        ducky.c / .h         DuckyScript syntax parser                      [DONE]
        hid.c / .h           HID Report Descriptor & GATT HID Service       [DONE]
        hid_cmd.c / .h       CLI subcommand orchestration for HID attack    [DONE]
        keymap.c / .h        ASCII to USB HID keycode translation           [DONE]
        bluez.c / .h         BlueZ D-Bus pairing, trust, and connection     [DONE]
        payloads/            DuckyScript attack payloads (OS-specific)      [DONE]

    User Interface & Entry Point:
      ui.c / .h              wifite-style live table + fingerprint table    [DONE, tested]
      main.c                 CLI dispatcher, interactive menu, wizards      [DONE]

  tests/
    test.h                   tiny standalone assertion framework
    test_addr_priv.c         unit tests for addr_priv                       [DONE]
    test_ad_parse.c          unit tests for ad_parse                        [DONE]
    test_att.c               unit tests for att codec                       [DONE]
    test_audit.c             unit tests for GATT audit classifier           [DONE]
    test_cli.c               unit tests for cli parser                      [DONE]
    test_dev_table.c         unit tests for device table deduplication      [DONE]
    test_fingerprint.c       unit tests for passive fingerprinting          [DONE]
    test_gatt.c              unit tests for GATT discovery / transactions   [DONE]
    test_hci_cmd.c           unit tests for HCI command framing             [DONE]
    test_hci_dev.c           unit tests for HCI device socket helpers       [DONE]
    test_hci_info.c          unit tests for HCI version detection           [DONE]
    test_hci_scan.c          unit tests for HCI scan event dispatch         [DONE]
    test_l2cap.c             unit tests for L2CAP address structures        [DONE]
    test_mgmt.c              unit tests for mgmt protocol build/parse       [DONE]
    test_peripheral_native.c unit tests for native peripheral & SMP crypto  [DONE]
    test_smp.c               unit tests for SMP packet codec                [DONE]
    test_smp_native.c        unit tests for native SMP probe logic          [DONE]
    test_ui.c                unit tests for UI rendering and RSSI bars      [DONE]
```

---

## Build & Test

```sh
make        # compile library objects and build/bleurp binary
make test   # build and run all 18 test suites in tests/
make clean  # remove build/ directory
```

Compilation flags: `-std=c11 -Wall -Wextra -Werror -O2`.

---

## Data & Control Flow

```
                                  ┌───────────────────────────┐
                                  │   CLI / Interactive Menu  │
                                  └─────────────┬─────────────┘
                                                │
         ┌──────────────────────────────┬───────┴──────────────────────┬──────────────────────────────┐
         ▼                              ▼                              ▼                              ▼
  [Passive Scan]              [GATT Access Audit]            [SMP Security Probe]         [HID Peripheral Mode]
         │                              │                              │                              │
         ▼                              ▼                              ▼                              ▼
  mgmt discovery                 L2CAP ATT (CID 4)              HCI User Channel /            HCI User Channel /
         │                              │                       L2CAP SMP (CID 6)             D-Bus BlueZ
         ▼                              ▼                              │                              │
  ad_parse & fingerprint         ATT read/write &              AuthReq & Key Size             HOGP GATT + SMP STK
         │                       audit classifier              Downgrade Probing              AES-128 Crypto &
         ▼                              │                              │                      Keystroke Injection
  Live UI + Exposure Score              ▼                              ▼                              │
                                 Security Verdict               Vulnerability Verdict                 ▼
                                                                                               Target Execution
```

---

## Documentation Index

- [`scan-overview.md`](scan-overview.md): Phase 1 scanning architecture and discovery pipeline.
- [`phase2-gatt-connection.md`](phase2-gatt-connection.md): Phase 2 GATT connection and ATT codec design.
- [`gatt-access-audit.md`](gatt-access-audit.md): GATT unauthenticated access audit module.
- [`ble-attack-surface.md`](ble-attack-surface.md): BLE attack surface taxonomy and security checklist.
- [`device-fingerprinting.md`](device-fingerprinting.md): Passive device categorization, address privacy, and exposure scoring.
- [`smp-security-audit.md`](smp-security-audit.md): Security Manager Protocol (SMP) probe and downgrade vulnerability testing.
- [`hid-peripheral-injection.md`](hid-peripheral-injection.md): Native HOGP keyboard peripheral emulation and DuckyScript injection.
- [`guided-audit-pipeline.md`](guided-audit-pipeline.md): Interactive console, guided audit pipeline, and Auto-Try batch scanner.
- [`cli-args.md`](cli-args.md): Command-line argument parsing reference.
