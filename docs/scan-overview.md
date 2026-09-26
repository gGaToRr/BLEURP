# BLE Scanning — Overview

This document explains, in plain terms, how BLEURP discovers nearby
Bluetooth Low Energy (BLE) devices, and why it is built the way it is.

> Read this first if you are new to BLE. It is written to be understood by
> anyone, not only Bluetooth engineers.

## What a BLE scan actually is

BLE devices that want to be found broadcast small radio messages called
**advertising packets** — a phone, a smartwatch, a beacon, a headset. A
scanner is simply a listener that collects those packets.

There are two independent choices when you scan.

### 1. Passive vs Active

```
   PASSIVE                                ACTIVE
   -------                                ------
   Advertiser  --- ADV --->  Scanner      Advertiser  --- ADV --->  Scanner
                                                       <-- SCAN_REQ --
                                                       -- SCAN_RSP -->
   (listen only)                          (ask for more; get the name
                                           and extra data)
```

- **Passive**: only listen. Stealthy and low power, but you often miss the
  device name.
- **Active**: reply to an advertiser with a `SCAN_REQ`; it answers with a
  `SCAN_RSP` that usually carries the name and extra data. **More
  informative**, so it is the default for reconnaissance.

### 2. Legacy vs Extended

| | Legacy | Extended |
|---|---|---|
| Bluetooth version | 4.0 – 4.2 | 5.0+ |
| HCI commands | `LE Set Scan Parameters/Enable` (0x200b/0x200c) | `LE Set Extended Scan Parameters/Enable` (0x2041/0x2042) |
| Report event | `LE Advertising Report` | `LE Extended Advertising Report` |
| Payload | up to 31 bytes | larger |
| New PHYs (2M, Coded/long range) | no | yes |

**BLEURP asks the controller what it supports** (via `Read Local Version`,
opcode 0x1001) and then:

```
        controller supports extended advertising?
                     /                  \
                  yes                    no
                   |                      |
          extended scanning        legacy scanning
          (BT 5.x, all PHYs)       (BT 4.x fallback)
```

This single rule gives us both worlds: modern devices **and** older ones.

## How we talk to the adapter (the C side)

BLEURP speaks to the Bluetooth controller directly through a **raw HCI
socket** (`AF_BLUETOOTH`, `BTPROTO_HCI`). HCI is the standard command/event
protocol between the host (our program) and the controller (the chip).

```
  +------------------+      HCI commands      +------------------+
  |  BLEURP (C)      |  -------------------->  |  BT controller   |
  |  raw HCI socket  |  <-------------------   |  (adapter hci0)  |
  +------------------+      HCI events         +------------------+
        builds packets            LE Advertising Report(s)
        (hci_cmd.c)               parsed into a device list
```

We build the command bytes ourselves (`src/hci_cmd.c`), so BLEURP needs **no
`libbluetooth-dev`** dependency — only the standard C library and the Linux
kernel headers.

## Permissions

Raw HCI access needs the `CAP_NET_RAW` capability. Rather than running as
root, grant it to the built binary only:

```sh
sudo setcap cap_net_raw,cap_net_admin+eip ./bleurp
```

## Raspberry Pi & portability

BLEURP targets Linux and is written to run unchanged on a Raspberry Pi.

- **Endianness**: every multi-byte HCI field is encoded/decoded with explicit
  little-endian helpers (`wr_le16` / `rd_le16`), so the code does not rely on
  the host byte order. It is correct on both x86-64 and ARM.
- **No x86-only code**: standard C11 + POSIX sockets only; builds with the
  Raspberry Pi OS `gcc`.
- **Legacy vs extended matters here**: the Pi 3B's built-in controller is BT
  4.x (legacy only), while the Pi 4 / 400 / Zero 2 W / 5 are BT 5.0
  (extended). The capability check (`hci_info`) plus the mode `switch` in
  `hci_scan_start` pick the right command set automatically.

```
   controller (hci_info)          scan start (hci_scan)
   -------------------            ---------------------
   BT 4.x  ── legacy ─────────►   0x200b / 0x200c
   BT 5.x  ── extended ───────►   0x2041 / 0x2042
```

Build on the Pi exactly as elsewhere:

```sh
make && make test
sudo setcap cap_net_raw,cap_net_admin+eip ./bleurp
```

## Legal note

Only scan devices you own or are explicitly authorized to test.
