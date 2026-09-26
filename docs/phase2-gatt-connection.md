# Phase 2 — Contact & GATT Connection

How BLEURP will move from *listening* (recon) to *talking* to an authorized
device: opening a connection and walking its GATT database, in the same
self-contained, low-level C style as the scanner.

> ⚠️ **Authorized targets only.** A connection is active interaction. The
> `enum`/read/write features gate on the operator confirming authorization.

## 1. From advertising to a connection

```
   Recon (phase 1)                 Connect (phase 2)
   ───────────────                 ─────────────────
   ADV / SCAN_RSP  ───────────►    L2CAP connect to the device address
   (we know addr + type)                     │
                                    ATT channel (CID 0x0004)
                                              │
                                    GATT: discover + read/write
```

## 2. How we connect (what works on Linux)

We use a **kernel L2CAP socket** bound to the ATT channel — the same mechanism
`gatttool`/`gattlib` use. It is low-level and self-contained (no D-Bus), and it
lets us drive raw ATT PDUs, which is what a pentest tool wants.

```c
// AF_BLUETOOTH + BTPROTO_L2CAP, connect to the device on the ATT CID (0x0004)
int s = socket(AF_BLUETOOTH, SOCK_SEQPACKET, BTPROTO_L2CAP);
// sockaddr_l2: device address + address type (public/random) + CID 0x0004
connect(s, (struct sockaddr *)&addr, sizeof addr);
```

For links that need **pairing/encryption**, the kernel (BlueZ) handles SMP —
this is exactly the "use the kernel for the hard parts" split we chose in
phase 1: raw for control, kernel for pairing/crypto.

## 3. ATT — the language of GATT

Everything over the ATT channel is a small PDU: `[opcode][parameters]`.
The ones we need:

| Purpose | Request | Response |
|---------|---------|----------|
| Negotiate MTU | Exchange MTU (0x02) | 0x03 |
| Find descriptors | Find Information (0x04) | 0x05 |
| Discover services | Read By Group Type (0x10) | 0x11 |
| Discover characteristics | Read By Type (0x08) | 0x09 |
| Read a value | Read (0x0A) | 0x0B |
| Write (acked) | Write Request (0x12) | 0x13 |
| Write (no ack) | Write Command (0x52) | — |
| Errors | — | Error Response (0x01) |
| Server push | — | Handle Value Notification (0x1B) |

## 4. GATT discovery flow

```
   Exchange MTU
        │
        ▼
   Read By Group Type  (UUID 0x2800 "Primary Service")   → list of services
        │   for each service handle range:
        ▼
   Read By Type        (UUID 0x2803 "Characteristic")     → characteristics
        │   for each characteristic:
        ▼
   Find Information                                        → descriptors (CCCD…)
        │
        ▼
   Read / Write / subscribe (write CCCD 0x2902 = 0x0001)  → interact
```

The result is a tree: **services → characteristics (with properties: read,
write, notify) → descriptors**, exactly what `bettercap ble.enum` prints.

## 5. What we build (issues)

| Issue | Module | Testable without hardware? |
|-------|--------|----------------------------|
| ATT PDU build/parse | `src/att.c` | ✅ pure PDUs, TDD |
| L2CAP connect | `src/l2cap.c` | partly (sockaddr build) |
| GATT discovery | `src/gatt.c` | ✅ response parsing via fixtures |
| Read/write + notify | `src/gatt.c` | ✅ PDU level |
| `bleurp enum <ADDR>` | `src/main.c` | end-to-end on authorized device |

## 6. Security notes tied to this phase

While connected, an assessment checks the items from
[`ble-attack-surface.md`](ble-attack-surface.md):

- Are characteristics **readable/writable without pairing** (unauthenticated
  GATT access)? That is the most common real finding.
- Which **pairing method** is offered (Just Works vs authenticated)?
- Is the **minimum key size** enforced?

These are read/observe checks on authorized devices — not exploits.

## Sources

- [gattclient — GATT over a BlueZ socket (GitHub)](https://github.com/gbrault/gattclient)
- [bettercap BLE modules](https://www.bettercap.org/modules/ble/)
- [BLE GATT Fuzzing (Quarkslab)](https://blog.quarkslab.com/bluetooth-low-energy-gatt-fuzzing.html)
- [Paint it blue: attacking the Bluetooth stack (Synacktiv)](https://www.synacktiv.com/en/publications/paint-it-blue-attacking-the-bluetooth-stack)
