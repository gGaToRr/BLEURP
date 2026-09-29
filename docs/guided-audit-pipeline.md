# Guided Audit Pipeline & Interactive Menu

BLEURP features an interactive terminal interface (`src/main.c`, `src/ui.c`, `src/banner.c`) designed for guided BLE security assessments.

---

## 1. Interactive Menu & Banner

Launching BLEURP without CLI arguments (`./build/bleurp`) presents an interactive console driven by FIGlet slant ASCII banner rendering and color-coded status gauges:

```
   ____  __    _______  ______  ____ 
  / __ )/ /   / ____/ / / / __ \/ __ \
 / __  / /   / __/ / / / / /_/ / /_/ /
/ /_/ / /___/ /___/ /_/ / _, _/ ____/ 
/_____/_____/_____/\____/_/ |_/_/      
   Bluetooth Low Energy Unauthenticated Reconnaissance & Probing
```

### Main Menu Options

1. **Scan Wizard**: Live BLE scanner with dynamic device table, live fingerprinting, and post-scan interaction menu.
2. **Guided Audit Pipeline**: Automated multi-step audit (Scan → Target Selection → Address Privacy Check → GATT Enumeration → Unauthenticated Access Audit → SMP Diagnostic).
3. **Auto-Try Unauthenticated Access**: Connects to all discovered targets in rapid sequence with bounded timeouts to identify unauthenticated GATT characteristics across an entire environment.
4. **SMP Pairing Security Diagnostic**: Evaluates target pairing policies and checks for weak downgrade acceptance.
5. **HID Keystroke Injection Wizard**: Guides through payload selection and target injection.
6. **Native Keyboard Peripheral Mode**: Runs standalone HOGP keyboard peripheral simulation.
7. **MAC Address Spoofer**: Configures the controller's LE static random address via kernel mgmt.
8. **Reset Bluetooth Adapter**: Runs `scripts/reset_bluetooth.sh` to unblock rfkill, restart `bluetoothd`, and reinitialize controller state.

---

## 2. Scan Wizard Workflow

```
[Start Scan] ──► [Live Table + Fingerprint] ──► [Select Target (# or ADDR)]
                                                        │
                      ┌─────────────────────────────────┴─────────────────────────────────┐
                      ▼                                 ▼                                 ▼
             [GATT Enumeration]                [GATT Access Audit]               [SMP Security Probe]
                      │                                 │                                 │
                      └─────────────────────────────────┼─────────────────────────────────┘
                                                        ▼
                                             [HID Keystroke Attack]
```

### Post-Scan Actions

Once a scan completes (after specified duration or Ctrl-C), the user can pick a device from the numbered list and immediately trigger:
- `[1] Enumerate GATT Tree`: Walks services, characteristics, and descriptors.
- `[2] Audit Unauthenticated Access`: Tests all readable characteristics for open permissions.
- `[3] SMP Pairing Security Probe`: Tests for weak AuthReq acceptance and encryption key truncation.
- `[4] HID Keystroke Injection`: Selects and sends a DuckyScript payload.

---

## 3. Auto-Try Batch Audit

The **Auto-Try** engine (`run_auto_try` in `src/main.c`) automates recon across dozens of discovered devices:
1. Iterates through every unique address detected during the scan.
2. Establishes an L2CAP ATT connection with an aggressive, non-blocking timeout (`bleurp_l2_connect_timeout`, default 2.5s) to avoid stalling on unreachable or sleeping nodes.
3. Automatically queries the GATT hierarchy and attempts unauthenticated reads on all exposed handles.
4. Summarizes findings in a unified assessment report, highlighting any device exposing sensitive characteristics without pairing.

---

## 4. MAC Address Spoofer

The MAC Spoofer utility uses the kernel BlueZ management interface (`MGMT_OP_SET_STATIC_ADDRESS` via `src/mgmt.c`) to set an arbitrary LE Static Random Address on the active adapter.

This allows auditors to:
- Test whether peer devices perform address whitelisting or access control based on MAC addresses.
- Prevent tracking of the audit station across consecutive test runs.
