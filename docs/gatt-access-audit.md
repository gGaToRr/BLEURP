# GATT Access Audit

The `audit` command connects to an **authorized** device and reports which
GATT characteristics are reachable **without pairing** — the classic
"unauthenticated read/write" finding (see
[`ble-attack-surface.md`](ble-attack-surface.md) §3).

> ⚠️ **Authorized use only.** `audit` opens a real connection and reads
> characteristic values. Only run it against devices you own or are explicitly
> authorized to test.

## Usage

```sh
./build/bleurp audit AA:BB:CC:DD:EE:FF -t random
```

`-t public|random` selects the peer address type (default `public`).

## What it does

1. Connect an ATT socket and exchange the MTU.
2. Walk the GATT tree (services → characteristics), reusing the same discovery
   used by `enum`.
3. For every characteristic:
   - if it advertises the **READ** property, read the value and classify the
     result;
   - otherwise report the capability (e.g. *write-capable*) **without** writing
     anything.

Writes are never performed — the audit is read-only by design, so it cannot
change device state.

## Verdicts

Each characteristic gets one verdict, derived from the read outcome:

| Verdict | Meaning | Trigger |
|---------|---------|---------|
| `OPEN` | Value returned with no pairing → **unauthenticated read** | read succeeded |
| `PROTECTED` | Value exists but needs pairing/encryption | ATT `0x05` / `0x08` / `0x0c` / `0x0f` |
| `DENIED` | Attribute cannot be read at all | ATT `0x02` (Read Not Permitted) |
| `OTHER` | Any other ATT error or a transport failure | any other code / none |

```
 read char value ──► success ───────────────► OPEN
                 └─► ATT error ─┬─ 0x05/08/0c/0f ─► PROTECTED
                                ├─ 0x02 ──────────► DENIED
                                └─ else ──────────► OTHER
```

The report header also shows the target's address privacy posture
(`priv=public|static|rpa|nrpa`, see [`addr_priv`](../src/addr_priv.c)), so a
trackable address and open characteristics show up together.

## Example

```
GATT access audit for 12:34:56:78:9A:BC (priv=rpa, ATT MTU=247)

  handle  props       uuid     verdict    detail
  ------  ----------  -------- ---------- ------
  0x0003  [R]         0x2A00   OPEN       7 byte(s) readable unauthenticated  (Generic Access)
  0x0012  [R W]       0x2A19   PROTECTED  needs pairing (ATT 0x05)
  0x0020  [W]         128-bit  -          write-capable (not tested)
```

The pure classifier (`audit_classify_read`) is unit-tested in
`tests/test_audit.c`.
