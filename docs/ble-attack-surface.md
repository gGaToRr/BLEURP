# BLE Attack Surface & Known Vulnerabilities

A practitioner reference for **authorized** BLE security testing. It maps the
BLE stack, the classic attack classes, and the best-known public
vulnerabilities (CVEs), so an engagement has a checklist to work from.

> ⚠️ **Authorized use only.** Everything here is for devices you own or are
> explicitly contracted to test. Connecting to, pairing with, or writing to a
> device is *active* interaction — do it only with written permission.
>
> This document catalogues **public** vulnerabilities for defensive and
> assessment purposes. It is not a recipe for attacking third parties.

## 1. The BLE stack (where attacks live)

```
   Application / Profiles
   ────────────────────────────────────────────
   GATT   Generic Attribute Profile   ← services, characteristics
   ATT    Attribute Protocol          ← read/write/notify PDUs
   SMP    Security Manager Protocol   ← pairing, keys, encryption
   GAP    Generic Access Profile      ← roles, advertising, discovery
   ────────────────────────────────────────────
   L2CAP  Logical Link Control        ← channels, fragmentation
   ────────────────────────────────────────────
   Link Layer (LL)                    ← connections, encryption, PHY
   Physical (PHY)                     ← 2.4 GHz radio
```

Attacks target every layer: the **radio/LL** (sniffing, fuzzing), **SMP**
(pairing/MITM), **ATT/GATT** (unauthenticated read/write), and the **host
stack implementation** (memory-corruption bugs like BleedingTooth).

## 2. Assessment phases

| Phase | What | Our tool |
|-------|------|----------|
| 1. Recon | Discover devices, RSSI, names, services (passive/active scan) | ✅ done (mgmt scanner) |
| 2. Connect | Open an L2CAP/ATT link to an authorized device | 🔜 phase 2 |
| 3. Enumerate | Walk the GATT tree (services → characteristics → descriptors) | 🔜 phase 2 |
| 4. Interact | Read/write characteristics, subscribe to notifications | 🔜 phase 2 |
| 5. Pairing/SMP | Assess pairing method and key strength | reference below |

## 3. Pairing & Security Manager (SMP) weaknesses

The **pairing method** decides whether a link is protected against
man-in-the-middle (MITM). Weak choices are the most common real-world finding.

- **Just Works pairing** — used when a device has no display/keyboard. It runs
  ECDH **without authenticating** the public keys, so it is **open to MITM**.
  Very common on cheap IoT.
- **LE Legacy pairing** — the Temporary Key can be `0` (Just Works) or a
  6-digit passkey with only ~20 bits of entropy → **offline brute force**
  (see the `crackle` tool).
- **Key-size negotiation** — BLE allows 7–16 byte keys, negotiated **in the
  clear**; an attacker can force **7 bytes (56 bits)** and brute force it
  (this is the idea behind **KNOB**).
- **Encryption before authentication** — some stacks let a session be
  encrypted with an **unauthenticated** key, granting read/write to protected
  GATT data (documented on TI CC2640R2).

**Test checklist:** which pairing method is offered? Is Just Works accepted?
Is the passkey static? Is the minimum key size enforced?

## 4. Spec-level vulnerabilities (design flaws)

| Name | CVE | Layer | One line |
|------|-----|-------|----------|
| **KNOB** | CVE-2019-9506 | LL/encryption | Force low key entropy (down to 1 byte on BR/EDR; short keys on LE) |
| **BIAS** | CVE-2020-10135 | LL/auth | Impersonate a previously-paired device (MITM) |
| **BLURtooth** | CVE-2020-15802 | Cross-transport | Abuse Cross-Transport Key Derivation to overwrite keys |
| **BLESA** | CVE-2020-9770 | Reconnection | Spoof a server on **reconnection**; the client skips re-auth |

These are **specification** flaws: they affect many compliant stacks, not one
vendor. Mitigation usually requires updated firmware/OS and enforcing Secure
Connections + minimum key size.

## 5. Implementation vulnerabilities (bugs in a stack)

| Name | CVE(s) | Target | One line |
|------|--------|--------|----------|
| **SweynTooth** | family, e.g. Zero-LTK **CVE-2019-19194**, LL length overflow **CVE-2019-16336** | BLE SoC SDKs (6 vendors) | Crashes, deadlocks, and **bypassing pairing with a zero LTK** |
| **BrakTooth** | family, e.g. **CVE-2021-28139** (ESP32) | BR/EDR controllers | Fuzzing the Link Manager → crashes / code exec |
| **BleedingTooth** | **CVE-2020-12351**, CVE-2020-12352, CVE-2020-24490 | **Linux kernel BlueZ** | Zero-click L2CAP type confusion → kernel RCE within radio range |
| **BleedingBit** | CVE-2018-16986, CVE-2018-7080 | TI BLE chips (APs) | RCE via advertising / OTA firmware feature |
| **BlueBorne** | family (2017) | Android/Linux/Windows | Airborne RCE without pairing (mostly BR/EDR) |

> **Note on CVEs.** Several of these are *families* spanning many CVE IDs and
> affected products. Always confirm the exact CVE and affected version against
> [NVD](https://nvd.nist.gov/) for the device under test.

## 6. Reconnaissance & privacy issues

- **Address tracking** — devices using a fixed public (or static random)
  address can be tracked over time. Resolvable Private Addresses (RPA) rotate
  to prevent this; a device that does **not** use RPA is a privacy finding.
- **Verbose advertising** — names, service UUIDs and manufacturer data can leak
  device type, vendor and state (our scanner surfaces these).

## 7. Tooling map (Linux)

| Job | Tools |
|-----|-------|
| Scan / recon | **BLEURP**, `bluetoothctl`, `btmgmt` |
| GATT client / enum | `gatttool` (legacy), `bettercap` (`ble.recon`/`ble.enum`), **BLEURP (phase 2)** |
| MITM proxy | `gattacker`, `btlejack` |
| Sniffing (hardware) | Ubertooth, nRF52 sniffer, `btmon` (local HCI) |
| Pairing key cracking | `crackle` |
| Fuzzing / PoC | SweynTooth PoCs, L2Fuzz, WHAD |

## Sources

- [BlueZ management API](https://github.com/bluez/bluez/wiki/MGMT)
- [SweynTooth: Unleashing Mayhem over BLE (paper)](https://asset-group.github.io/disclosures/sweyntooth/sweyntooth.pdf)
- [SweynTooth PoC (GitHub)](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks)
- [BleedingTooth write-up (Google Security Research)](https://google.github.io/security-research/pocs/linux/bleedingtooth/writeup.html)
- [CVE-2020-12351 (SentinelOne DB)](https://www.sentinelone.com/vulnerability-database/cve-2020-12351/)
- [BLURtooth (paper)](https://arxiv.org/pdf/2009.11776)
- [Breaking Secure Pairing of BLE — BLESA (USENIX)](https://www.usenix.org/system/files/sec20-zhang-yue.pdf)
- [Introduction to Bluetooth attacks (Tarlogic)](https://www.tarlogic.com/blog/introduction-to-bluetooth-attacks/)
- [BLE Security Attack & Defence catalogue (GitHub)](https://github.com/Charmve/BLE-Security-Attack-Defence)
- [BLE GATT Fuzzing (Quarkslab)](https://blog.quarkslab.com/bluetooth-low-energy-gatt-fuzzing.html)
- [BLE Security & Privacy 2025 Guide (Argenox)](https://argenox.com/blog/bluetooth-low-energy-ble-security-privacy-a-2025-guide)
