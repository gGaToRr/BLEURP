# BLEURP

A Bluetooth Low Energy (BLE) scanning tool for authorized security testing on Linux.

> ⚠️ **Authorized use only.** Only use this tool on devices you own or are
> explicitly authorized to test. Scanning or interacting with third-party
> devices without permission may be illegal.

## Status

Working wifite-style live BLE scanner: it drives kernel BlueZ management
(mgmt) discovery, decodes advertising data (name, vendor, services), merges
devices and shows a live table sorted by signal. Deeper GATT enumeration
(connections) is a later phase.

## Requirements

- Linux with a BlueZ kernel stack (no libbluetooth-dev needed)
- A Bluetooth adapter supporting BLE
- `gcc` and `make`

## Build & run

```sh
make                       # build ./build/bleurp
make test                  # run the unit tests

# Discovery needs CAP_NET_ADMIN. Grant it once to the binary:
make setcap                # sudo setcap cap_net_raw,cap_net_admin+eip ./build/bleurp
./build/bleurp             # interactive menu (option 1 = verbose scan)
./build/bleurp scan        # live scan until Ctrl-C
./build/bleurp scan -t 10  # scan for 10 seconds
./build/bleurp scan -v     # verbose (per-device vendor/services details)

# Connect to an authorized device and interact with GATT:
./build/bleurp enum  AA:BB:CC:DD:EE:FF -t random           # dump the GATT tree
./build/bleurp audit AA:BB:CC:DD:EE:FF -t random           # audit unauthenticated access
./build/bleurp read  AA:BB:CC:DD:EE:FF 0x0012 -t random    # read a handle
./build/bleurp write AA:BB:CC:DD:EE:FF 0x0012 01ff -t random  # write bytes
```

Use `enum`/`read`/`write` only on devices you own or are authorized to test.

Without the capability, run under `sudo ./build/bleurp`. Reading the adapter
info works unprivileged; starting a discovery does not.

## Documentation

See the [`docs/`](docs/) folder for per-feature documentation.
