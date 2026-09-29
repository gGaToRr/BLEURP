# BLE HID Peripheral Emulation & Keystroke Injection

BLEURP provides two independent subsystems for HID over GATT Profile (HOGP) interaction and authorized keystroke injection testing:
1. **Native Peripheral Mode (`src/peripheral_native.c`)**: Turns your Linux PC into a standalone BLE Keyboard peripheral via raw HCI User Channel, handling full GATT and SMP cryptographic handshakes.
2. **BlueZ D-Bus HID Engine (`src/send_attack/`)**: Connects to target hosts via BlueZ D-Bus APIs to inject DuckyScript payloads.

> ⚠️ **Authorized use only.** HID injection tests must strictly be conducted on target systems you own or have explicit authorization to assess.

---

## 1. Native Peripheral Mode (`bleurp keyboard`)

The native peripheral module drives the Bluetooth controller directly at the HCI level without requiring BlueZ daemon support for peripheral services.

```
       Linux Host (BLEURP Native Peripheral)                Target Host / Smartphone
                        │                                              │
                        │ 1. LE Advertising (UUID 0x1812, HID)         │
                        ├─────────────────────────────────────────────►│
                        │                                              │
                        │ 2. LE Connection Complete                    │
                        │◄─────────────────────────────────────────────┤
                        │                                              │
                        │ 3. SMP Pairing Request / Response            │
                        │◄════════════════════════════════════════════►│
                        │   (Calculates c1 Confirm & s1 STK Crypto)    │
                        │                                              │
                        │ 4. GATT Service Discovery (HOGP 0x1812)      │
                        │◄─────────────────────────────────────────────►│
                        │                                              │
                        │ 5. ATT Notification (Handle 0x0018)          │
                        │    [Modifiers + 6-byte USB HID Scan Codes]   │
                        ├─────────────────────────────────────────────►│
```

### Features
- **HCI Advertising Setup**: Builds proper AD/SRD frames containing Complete Local Name and 16-bit Service UUID `0x1812` (HID).
- **GATT Database Engine**: Responds to ATT Read/Write requests for GAP (`0x1800`), DIS (`0x180A`), Battery (`0x180F`), and HOGP (`0x1812`).
- **SMP Slave Security Engine**: Implements the BLE Security Manager state machine, handling Pairing Request, Pairing Confirm, and Pairing Random, computing cryptographic confirmation values (`c1`) and Short Term Key (`s1`) using standard AES-128 primitives.
- **Keystroke Notification Transmitter**: Sends 8-byte HID input reports (1 byte modifiers, 1 reserved, 6 keycodes) through ATT notifications upon CCCD enable.

### CLI Usage

```sh
# Start native BLE keyboard peripheral with default name:
./build/bleurp keyboard -i 0

# Start with custom device name and auto-execute DuckyScript payload on connect:
./build/bleurp keyboard -i 0 -n "Logitech MX Keys" -d src/send_attack/payloads/demo-hello.txt
```

---

## 2. BlueZ D-Bus HID Injection (`bleurp hid`)

The `send_attack` subsystem leverages the host BlueZ stack to discover, pair, trust, and inject keystrokes into a target host.

```
┌──────────────────────────────────────────────────────────┐
│                   DuckyScript Source                     │
│  DELAY 500                                               │
│  GUI r                                                   │
│  STRING cmd.exe                                          │
│  ENTER                                                   │
└────────────────────────────┬─────────────────────────────┘
                             │
                             ▼
               src/send_attack/ducky.c (Parser)
                             │
                             ▼
               src/send_attack/keymap.c (ASCII to HID Codes)
                             │
                             ▼
               src/send_attack/bluez.c (D-Bus Pair & Send)
```

### Supported DuckyScript Syntax

- `REM` or `#`: Comment line.
- `DELAY <ms>`: Pause execution for specified milliseconds.
- `STRING <text>`: Type plain ASCII text (auto-translates upper/lower case and symbols).
- `GUI <key>` / `WINDOWS <key>`: Super/Command key combo (e.g., `GUI r`, `GUI SPACE`).
- `CTRL-ALT <key>` / `CTRL <key>` / `ALT <key>` / `SHIFT <key>`: Modifier combinations.
- Key names: `ENTER`, `ESC`, `TAB`, `SPACE`, `BACKSPACE`, `UP`, `DOWN`, `LEFT`, `RIGHT`, `F1`–`F12`.
- `REPEAT <count>`: Replays the preceding instruction N times.

### Bundled Payloads

Payloads are stored in `src/send_attack/payloads/`:
- `demo-hello.txt`: Harmless demonstration typing "Hello from BLEURP!".
- `linux-terminal.txt`: Spawns GNOME/Linux terminal (`Ctrl+Alt+T`).
- `windows-cmd.txt`: Opens Windows Run (`Win+R`) and runs command prompt.
- `macos-spotlight.txt`: Opens Spotlight Search (`Cmd+Space`) and launches Terminal.
- `android-url.txt`: Opens default browser to specified test URL.
- `test-keymap.txt`: Verifies full alphanumeric and symbol key translation.

### CLI Usage

```sh
# Inject payload to target device:
./build/bleurp hid -i hci0 -t AA:BB:CC:DD:EE:FF -f src/send_attack/payloads/demo-hello.txt
```
