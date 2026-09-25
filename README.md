# BLEURP

A Bluetooth Low Energy (BLE) scanning tool for authorized security testing on Linux.

> ⚠️ **Authorized use only.** Only use this tool on devices you own or are
> explicitly authorized to test. Scanning or interacting with third-party
> devices without permission may be illegal.

## Status

Early development. First milestone: a wifite-style live BLE scanner
(discovery of nearby devices with address, RSSI, name).

## Requirements

- Linux with BlueZ (`bluetoothctl`)
- A Bluetooth adapter supporting BLE
- User in the `bluetooth` group (scanning needs no root)

## Documentation

See the [`docs/`](docs/) folder for per-feature documentation.
