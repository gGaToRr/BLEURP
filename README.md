# BLEURP

**Bluetooth Low Energy Unauthenticated Reconnaissance & Probing**

A modular, dependency-free BLE security scanner, auditor, and penetration testing toolkit for Linux.

> ⚠️ **Authorized use only.** Only use BLEURP on devices and networks you own or are explicitly authorized to test. Interacting with third-party BLE devices without authorization may violate local laws and regulations.

---

## Features

- **Live BLE Reconnaissance (`scan`, `wizard`)**: Wifite-style live terminal scanner driven by Linux kernel mgmt discovery, sorting devices by RSSI with color-coded signal meters.
- **Passive Device Fingerprinting**: Infers device category (*phone, computer, wearable, audio, input, health, sensor, network, peripheral*), identifies vendor OUI/company IDs, assesses MAC address privacy (*Public, Static, RPA, NRPA*), and computes a recon **Exposure Score (0–100)** without transmitting any RF frames.
- **GATT Enumeration & Access Audit (`enum`, `audit`)**: Discovers services, characteristics, and descriptors over L2CAP ATT. Identifies readable characteristics exposed unauthenticated (`OPEN`) vs protected (`PROTECTED`).
- **SMP Pairing Security Audit (`smp`)**: Probes target pairing negotiation behavior (AuthReq flags, IO Capabilities, minimum encryption key size) via native HCI User Channel or L2CAP SMP (CID 6) to detect security downgrades (inspired by the BLERP research).
- **Native BLE Keyboard Peripheral Emulation (`keyboard`)**: Emulates a standalone BLE HOGP (HID over GATT Profile) keyboard peripheral directly via HCI User Channel, handling complete SMP Slave state machines with AES-128 cryptographic handshakes (`c1` confirm and `s1` STK generation) to pair with smartphones and hosts.
- **Keystroke Injection (`hid`)**: Injects DuckyScript payloads into authorized targets using standard USB HID scancodes with cross-platform payload profiles (Linux, Windows, macOS, Android).
- **Auto-Try Batch Recon**: Rapidly probes unauthenticated GATT characteristics across all discovered devices with aggressive, non-blocking connection timeouts.
- **MAC Spoofer & Adapter Recovery**: Live LE Static Random address manipulation and system Bluetooth stack restoration scripts.

---

## Requirements

- Linux with BlueZ kernel stack (no heavy userland dependencies required).
- Bluetooth adapter with BLE support (e.g. `hci0`).
- `gcc`, `make`, and `libdbus-1-dev` (for D-Bus HID helper).

---

## Quickstart

### Build & Test

```sh
# Build binary
make

# Run the 18-suite test framework
make test
```

### Granting Network Capabilities (Recommended)

Kernel mgmt discovery requires `CAP_NET_ADMIN` and raw socket capabilities:

```sh
# Grant capabilities to the bleurp binary once:
make setcap

# Run interactive console (unprivileged):
./build/bleurp
```

*(Alternatively, run commands directly under `sudo ./build/bleurp ...`)*.

---

## CLI Usage

### Interactive Menu & Wizards

```sh
./build/bleurp             # Interactive menu with ASCII Slant banner
./build/bleurp wizard      # Guided all-in-one audit pipeline
```

### Scanning & Reconnaissance

```sh
./build/bleurp scan        # Live scan until Ctrl-C
./build/bleurp scan -t 10  # Scan for 10 seconds
./build/bleurp scan -v     # Verbose scan (displays vendor EIR & advertised services)
```

### GATT Enumeration & Unauthenticated Access Audit

```sh
# Dump GATT tree (services, characteristics, descriptors):
./build/bleurp enum AA:BB:CC:DD:EE:FF -t random

# Audit which characteristics are readable without pairing:
./build/bleurp audit AA:BB:CC:DD:EE:FF -t public

# Direct handle read and write operations:
./build/bleurp read  AA:BB:CC:DD:EE:FF 0x0012 -t random
./build/bleurp write AA:BB:CC:DD:EE:FF 0x0012 01ff -t random
```

### SMP Pairing Security Diagnostic

```sh
# Run native HCI User Channel SMP downgrade probe:
./build/bleurp smp AA:BB:CC:DD:EE:FF -i 0 -t random
```

### Native Keyboard Peripheral Mode & Keystroke Injection

```sh
# Start native BLE keyboard peripheral (advertises HOGP keyboard, handles SMP pairing):
./build/bleurp keyboard -i 0 -n "BLEURP Keyboard" -d src/send_attack/payloads/demo-hello.txt

# Inject DuckyScript payload via BlueZ D-Bus:
./build/bleurp hid -i hci0 -t AA:BB:CC:DD:EE:FF -f src/send_attack/payloads/linux-terminal.txt
```

---

## Documentation

Detailed architectural and technical guides are available in the [`docs/`](docs/) directory:

- 📋 [**Architecture & Module Overview**](docs/architecture.md)
- 🔍 [**Passive Device Fingerprinting & Exposure Scoring**](docs/device-fingerprinting.md)
- 🔒 [**SMP Security Audit & Downgrade Probing**](docs/smp-security-audit.md)
- ⌨️ [**HID Peripheral Emulation & Keystroke Injection**](docs/hid-peripheral-injection.md)
- 🧭 [**Guided Audit Pipeline & Interactive Menu**](docs/guided-audit-pipeline.md)
- 🛡️ [**GATT Access Audit**](docs/gatt-access-audit.md)
- 🎯 [**BLE Attack Surface Reference**](docs/ble-attack-surface.md)
- ⚙️ [**CLI Arguments Reference**](docs/cli-args.md)
- 📡 [**Scanning Architecture**](docs/scan-overview.md)
- 🔗 [**Phase 2 GATT Connection Design**](docs/phase2-gatt-connection.md)
