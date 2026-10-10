# BLEURP v2 — Architecture

A modular, dependency-free BLE security scanner and audit toolkit written in C for Linux. Each module is built and tested in isolation (TDD) before being wired into the tool. This is the v2 rewrite (`v2/rewrite` branch): same philosophy as v1, restructured into one directory per concern instead of a flat `src/`, with duplicated HCI/mgmt plumbing consolidated into shared modules and `main.c` reduced to pure dispatch. See "What changed from v1" below for the concrete before/after.

---

## Modules

```
  src/
    wire/                     Shared HCI_CHANNEL_USER plumbing (the one thing
                               every raw-HCI engine below needs):
      hci_wire.h                 HCI packet types, opcodes, event/sub-event
                                  codes -- single source, supersedes the old
                                  per-file copies.
      hci_user_channel.c/.h      open/close the exclusive HCI_CHANNEL_USER
                                  socket (+ mgmt power toggle), raw command
                                  and ACL/L2CAP packet send.             [tested]

    cli/
      cli.c/.h                   argv -> struct cli_opts (-i/-t/-o/--json/
                                  --passive/--active/-v/-h), used by `scan`.   [tested]

    recon/                    Phase 1: discovery & parsing
      hci_dev.c/.h                raw (non-exclusive) HCI socket open/close [tested]
      hci_info.c/.h               controller version -> legacy/extended      [tested]
      hci_scan.c/.h               LE scan command builders + event dispatch  [tested]
      hci_cmd.c/.h                raw HCI command packet builder             [tested]
      ad_parse.c/.h                advertising-data parser                   [tested]
      addr_priv.c/.h               address privacy classification            [tested]
      dev_table.c/.h               discovered-device table                   [tested]
      fingerprint.c/.h              passive device fingerprinting            [tested]

    gatt/                     Phase 2: GATT connection & access audit
      att.c/.h                    ATT PDU codec                              [tested]
      l2cap.c/.h                   connect ATT (CID 4) / SMP (CID 6)         [tested]
      gatt.c/.h                     discovery + read/write/subscribe        [tested]
      audit.c/.h                    unauthenticated-access classifier        [tested]

    mgmt/
      mgmt.c/.h                   kernel BlueZ management (mgmt) socket      [tested]

    smp/                      SMP core
      smp.c/.h                    SMP PDU codec (Pairing Req/Rsp, opcodes)   [tested]
      smp_legacy.c/.h              Legacy pairing crypto (c1/s1/STK)         [tested]
      smp_sc.c/.h                  NEW: LE Secure Connections toolbox --
                                   ECDH P-256 + f4/f5/f6/g2 (AES-CMAC)       [tested]
      smp_sc_engine.c/.h           NEW: SC Just Works Phase 2 state machine
                                   (both roles), built on smp_sc.c          [tested]
      smp_native.c/.h              HCI_CHANNEL_USER diagnostic probe        [tested]

    blerp/                    BLERP attack engine (NDSS 2026)
      secreq.c/.h                  Security Request test, pure logic        [tested]
      repair.c/.h                   re-pairing downgrade check, pure logic  [tested]
      blerp_attack.c/.h             PI / CI / double-channel MitM / full
                                   V1-V6 audit cascade; PI can complete SC
                                   (-S flag) via smp_sc_engine.c instead of
                                   only downgrading to Legacy               [tested]
      blerp_mitm_relay.c/.h        NEW: single-channel MitM -- relays real
                                   SMP PDUs between the two victims,
                                   tampering only the feature-negotiation
                                   ones (Fig. 6 of the paper)               [tested]
      hardened_audit.c/.h          NEW: VII-A hardened re-pairing rule
                                   classification (Consistency Check /
                                   Anti-Downgrade / Encryption Failure
                                   Termination), derived from the existing
                                   V1-V6 report                             [tested]
      authenticated_repair.c/.h    NEW: VII-B reference protocol (key
                                   chaining + transcript hashing); a
                                   demonstration that the paper's proposed
                                   fix defeats BLERP, not something a real
                                   unmodified stack speaks                  [tested]

    hid/                      HID keyboard emulation & injection
      peripheral_native.c/.h      native HOGP Keyboard peripheral + SMP STK [tested]
      send_attack/
        ducky.c/.h                  DuckyScript parser                      [DONE]
        hid.c/.h                     HID Report Descriptor & GATT service    [DONE]
        hid_cmd.c/.h                  CLI subcommand orchestration           [DONE]
        keymap.c/.h                    ASCII -> USB HID keycode              [DONE]
        bluez.c/.h                      BlueZ D-Bus pairing/trust/connect    [DONE]
        payloads/                        bundled DuckyScript payloads        [DONE]

    ui.c/.h, banner.c/.h       terminal UI + FIGlet banner                   [tested]

    cmd/                      One file per CLI subcommand -- a thin
                               getopt() parse + call into the module above:
      common.c/.h                 shared argv/menu-prompt utilities
                                   (parse_addr, parse_long_arg, read_line,
                                   ask_yes_no/number/interface, print_verdict) [tested]
      scan.c/.h                    `scan`                                   [tested]
      gatt_cmd.c/.h                 `enum`/`audit`/`read`/`write`
      smp_cmd.c/.h                   `smp`
      repair_cmd.c/.h                 `repair`
      secreq_cmd.c/.h                  `secreq`
      blerp_cmd.c/.h                    `blerp`

    menu/
      menu.c/.h                   the interactive menu and every wizard it
                                   drives, plus `autotry`/`keyboard` (share
                                   helpers with the wizards). Kept as one
                                   file: no automated test coverage (pure
                                   terminal I/O) and heavily cross-coupled
                                   internally -- splitting further would
                                   trade a real, unverifiable regression
                                   risk for a cosmetic win.

    main.c                     usage() + argv[1] dispatch table. No logic
                               of its own.

  tests/                      Same philosophy: test.h's CHECK()/TEST_REPORT(),
                               pure logic, no hardware/root required. One
                               file per module above; new in v2:
                               test_hci_user_channel.c, test_smp_sc.c,
                               test_smp_sc_engine.c, test_blerp_mitm_relay.c,
                               test_hardened_audit.c, test_authenticated_repair.c.
```

Non-regression rule: **no stub**. Every public function shipped either does what its comment says, or does not exist yet — no silent "TODO" that compiles clean. (v1 shipped `blerp_run_mitm` as exactly that kind of stub for a while; the fix is what started this rewrite.)

---

## Build & Test

```sh
make        # compile library objects and build/bleurp binary
make test   # build and run every test binary in tests/
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
  [Passive Scan]              [GATT Access Audit]            [SMP / BLERP Security]        [HID Peripheral Mode]
         │                              │                              │                              │
         ▼                              ▼                              ▼                              ▼
  mgmt discovery /               L2CAP ATT (CID 4)              HCI User Channel /            HCI User Channel /
  raw HCI passive scan                                         L2CAP SMP (CID 6)             D-Bus BlueZ
         │                              │                              │                              │
         ▼                              ▼                              ▼                              ▼
  ad_parse & fingerprint         ATT read/write &              AuthReq/KeySize/SC             HOGP GATT + SMP STK
         │                       audit classifier              downgrade, V1-V6,              AES-128 Crypto &
         ▼                              │                       VII-A/VII-B                   Keystroke Injection
  Live UI + Exposure Score              ▼                              │                              │
                                 Security Verdict               Vulnerability Verdict                 ▼
                                                                                               Target Execution
```

---

## What changed from v1

- **Dead code wired in, not left to rot.** `cli.c`'s `cli_parse()` was tested (43 checks) but never called by `main.c`; `hci_scan.c`'s passive/legacy/extended scan engine was tested (116 checks) but never called either. Both are now live (`scan --passive`, `scan -v`).
- **One HCI_CHANNEL_USER implementation, not four.** The "mgmt power off → open → bind → … → mgmt power on" sequence, plus the raw HCI command and ACL/L2CAP packet builders, were independently reimplemented in `smp_native.c`, `blerp_attack.c`, and `peripheral_native.c`. Now: `src/wire/hci_user_channel.c`.
- **`main.c`: 3438 lines → 87.** Every subcommand moved to `src/cmd/`, the entire interactive menu/wizard subsystem to `src/menu/menu.c`.
- **LE Secure Connections support** (`src/smp/smp_sc.c`, `smp_sc_engine.c`): the attack engine previously could only downgrade to Legacy pairing, which fails outright against a peer locked to Secure Connections Only. `bleurp blerp pi -S` completes real SC Just Works instead.
- **Single-channel MitM** (`src/blerp/blerp_mitm_relay.c`, `bleurp blerp mitm-single`): the paper's other MitM variant (Fig. 6), never implemented in v1.
- **The paper's two countermeasures**, as a detector (`hardened_audit.c`, wired into `blerp audit`) and a reference implementation (`authenticated_repair.c`, library-only with its own test suite — see its header for why no CLI wraps it).

---

## Documentation Index

- [`scan-overview.md`](scan-overview.md): Phase 1 scanning architecture and discovery pipeline.
- [`phase2-gatt-connection.md`](phase2-gatt-connection.md): Phase 2 GATT connection and ATT codec design.
- [`gatt-access-audit.md`](gatt-access-audit.md): GATT unauthenticated access audit module.
- [`ble-attack-surface.md`](ble-attack-surface.md): BLE attack surface taxonomy and security checklist.
- [`device-fingerprinting.md`](device-fingerprinting.md): Passive device categorization, address privacy, and exposure scoring.
- [`smp-security-audit.md`](smp-security-audit.md): Security Manager Protocol (SMP) probe and downgrade vulnerability testing.
- [`blerp-attacks.md`](blerp-attacks.md): The BLERP attack engine (V1-V6, PI/CI/MitM) in depth.
- [`hid-peripheral-injection.md`](hid-peripheral-injection.md): Native HOGP keyboard peripheral emulation and DuckyScript injection.
- [`guided-audit-pipeline.md`](guided-audit-pipeline.md): Interactive console, guided audit pipeline, and Auto-Try batch scanner.
- [`cli-args.md`](cli-args.md): Command-line argument parsing reference.
