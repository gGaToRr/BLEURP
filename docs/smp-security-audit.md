# SMP Security Audit & Re-pairing Check

BLEURP implements two SMP (Security Manager Protocol) diagnostics, both driven by the native HCI User Channel (`src/smp_native/`):

| Mode | Command | What it does | Needs a bond? |
| :--- | :--- | :--- | :--- |
| **First-pairing probe** | `bleurp smp` (menu `[-5-]`) | Sends a weak Pairing Request to a device and reads the first reply. | No |
| **Re-pairing check** | `bleurp repair` | Offers a pairing weaker than the bond the device already has with this adapter, and reads the reply. | Yes |

> ⚠️ **Authorized use only.** Only run these probes on devices you own or are explicitly authorized to test.

---

## 1. Background & Threat Model

In Bluetooth LE, pairing is governed by SMP (fixed L2CAP CID `0x0006`). The Initiator (Central) and Responder (Peripheral) first exchange **Pairing Request** and **Pairing Response** to negotiate:
- **AuthReq**: bonding, MITM protection, Secure Connections (SC).
- **IO Capabilities**: decide between Just Works, Passkey Entry, Numeric Comparison or OOB.
- **Maximum encryption key size**: between 7 and 16 bytes.

The BLERP paper (*BLERP: BLE Re-Pairing Attacks and Defenses*, NDSS 2026, `scratch/paper.pdf`) studies **re-pairing**: two devices that already share a key (PK) and its security level (ARPK). The standard only says a device may overwrite its PK if the new level is higher. The paper identifies six design issues:

| ID | Issue | Where it shows |
| :--- | :--- | :--- |
| V1 | Central accepts an unauthenticated Security Request | Security Request handling |
| V2 | Peripheral accepts re-pairing without authenticating the Central | Peripheral, even when not discoverable |
| V3 | Peripheral announces a high level, then lowers it in its Pairing Response | Central does not compare request and response |
| V4 | Re-pairing accepts a level below the one of the original bond (ARPK) | Both roles |
| V5 | Re-pairing can be forced by interrupting session establishment | Peripheral |
| V6 | PK entropy (key size) can be lowered below the stored key | Both roles |

The key point: **every BLERP issue compares the new negotiation with a bond that already exists.** A first pairing has nothing to compare against.

```
      Initiator (BLEURP)                        Responder (Target)
              │                                          │
              │   1. Pairing Request (weak offer)        │
              │   ─────────────────────────────────►     │
              │                                          │
              │   2. Pairing Response / Failed           │
              │   ◄─────────────────────────────────     │
              │                                          │
              ▼                                          ▼
     [Verdict: refused (anti-downgrade) / accepted below bond / no reply]
```

---

## 2. First-Pairing Probe (`bleurp smp`)

Connects over the HCI User Channel, sends the weakest offer (`AuthReq=0x01` bonding only, `KeySize=7`, NoInputNoOutput), then reads the first reply and disconnects. It never sends a second message, so no key is derived.

- The module is `src/smp_native/smp_native.c`. It reports where it stopped: no link, controller refusal (HCI status), connected without SMP reply, or SMP reply.
- Requires `CAP_NET_ADMIN` (`make setcap`) or `sudo`: the adapter is powered off through BlueZ mgmt, then bound with `HCI_CHANNEL_USER`.

```sh
./build/bleurp smp AA:BB:CC:DD:EE:FF -t public
./build/bleurp smp AA:BB:CC:DD:EE:FF -i 1 -t random
```

### Reading the result

| Observation | Meaning | Note |
| :--- | :--- | :--- |
| *No link before timeout* | The target does not advertise connectably at that address. | Random (RPA) addresses change: use a fresh one or the identity address. |
| *Controller refused (HCI 0x0c, 0x12, …)* | The adapter rejected the command. | Often the adapter is busy or not initialised. Retry, or run `./scripts/reset_bluetooth.sh`. |
| *Connected, no SMP reply* | The target ignores Pairing Requests made outside pairing. | Common, and expected for a device that is not in pairing mode. |
| *Pairing Failed (reason)* | The target refused the first pairing. | Refusal is the secure behaviour. |
| *Reply with MITM=0 and SC=0* | Accepts a first pairing without MITM and without SC. | **Normal for Just Works.** It is not the BLERP issue by itself. |
| *Reply accepting 7-byte keys* | Accepts minimal key entropy. | Candidate for the KNOB-style risk. KNOB concerns the session key negotiation, which this probe does not reach, so the finding needs qualifying. |

---

## 3. Re-pairing Check (`bleurp repair`)

This is the test that matches the BLERP paper. It works on a device **already bonded** with this adapter.

### 3.1 Prerequisite: create the bond

The bond is created by BlueZ, not by BLEURP. Pair the device once with `bluetoothctl`:

```sh
bluetoothctl
[bluetooth]# agent KeyboardOnly     # we type the PIN the device shows: authenticated bond
[bluetooth]# default-agent
[bluetooth]# scan on                 # wait until the device appears
[bluetooth]# pair AA:BB:CC:DD:EE:FF
[bluetooth]# trust AA:BB:CC:DD:EE:FF
```

- `KeyboardOnly` makes the bond **authenticated** (passkey, MITM protection on). With `NoInputNoOutput` the bond is Just Works, which leaves no level to downgrade for MITM (only the key size remains to test).
- BlueZ stores the bond under `/var/lib/bluetooth/<adapter>/<device>/info`. This directory is root-only.

### 3.2 Find the identity address

After pairing, the bonded device is listed by its **identity address**, which stays the same when a phone rotates its random address (RPA):

```sh
sudo ./build/bleurp repair          # lists the bonded identity addresses of hci0
```

Use that address with `-t public` or `-t random` depending on its type. For an iPhone, always use this identity address, not the address seen during a scan.

### 3.3 Run the check

```sh
sudo ./build/bleurp repair AA:BB:CC:DD:EE:FF -i 0 -t public
```

The tool reads the stored bond (`Authenticated`, `EncSize`), offers the weak pairing (no MITM, 7-byte key, same bytes as the first-pairing probe), then classifies the reply.

### 3.4 Verdicts

| Verdict | Reading | Paper |
| :--- | :--- | :--- |
| *No reply* | Inconclusive: the device did not answer the offer. | — |
| *Refused (Pairing Failed 0x06)* | The device checks key size against its bond: anti-downgrade on entropy is active. | Fix for V6 (Anti-Downgrade rule). |
| *Refused (Pairing Failed 0x03)* | The device checks the authentication requirements: anti-downgrade on MITM is active. | Fix for V4. |
| *Refused (Pairing Failed 0x09)* | The device limits repeated pairing attempts. | Not a BLERP finding; report it as a rate limit. |
| *Accepted: MITM dropped* | The bond was authenticated and the device proceeds without MITM. | Candidate for **V4** (and V3 on the Peripheral side). |
| *Accepted: key size lower* | The negotiated key size (minimum of both maxima) is below the bond. | Candidate for **V6**. |
| *Accepted, no downgrade* | The device proceeds without going below its bond. | No candidate on this check. |

> The verdict is an **indicator**. The paper confirms a downgrade only after the pairing completes (key derivation, association). BLEURP stops after the first reply on purpose: it never exchanges a key.

---

## 4. Scope & Limitations

- **Negotiation only.** BLEURP does not send a Security Request (V1, V5), does not complete the pairing, and never derives or stores a key. It cannot impersonate a device.
- **Peripheral-side behaviour.** When the target is a Peripheral (TV, wearable), the check exercises its re-pairing logic (V2, V4, V6). When the target is a Central (iPhone, laptop), the Apple finding of the paper (a re-pairing triggered when `ARSR ≥ ARPK` instead of `ARSR > ARPK`) needs the phone to act as the Central. This check does not cover that case.
- **SC is not visible.** BlueZ's bond file does not record whether the bond used Secure Connections, so an SC-to-LSC downgrade is not tested.
- **Root required.** Reading `/var/lib/bluetooth` and driving the adapter both need root or the capabilities from `make setcap` (for the adapter part only; the bond read needs root).
- **One bond per run.** Each run reads the bond at that moment. Pair again if you re-bond.

---

## 5. Source map

| File | Role |
| :--- | :--- |
| `src/smp_native/smp_native.c` | HCI User Channel probe: link, HCI status, offer, reply, printing. |
| `src/smp_native/repair.c` | Bond file parser, bond listing, sysfs adapter address, verdict classification (pure). |
| `src/smp.c`, `src/smp.h` | SMP codec and the shared weak offer. |
| `src/main.c` | `smp` and `repair` subcommands, menu entry `[-5-]`. |
| `tests/test_repair.c`, `tests/test_smp_native.c` | Unit tests for the parser, the classifier and the HCI helpers. |

## Couverture V1-V6 (papier BLERP, NDSS 2026)

Ce que l'outil mesure, vulnérabilité par vulnérabilité. Chaque test écrit une ligne `[VERDICT] V<n> : OUI|NON|NON CONCLUANT - détail`, que `scripts/audit_ble.sh` agrège dans la matrice du rapport.

| Vuln. | Ce qui est testé | Commande | Verdict OUI | Limite |
| :--- | :--- | :--- | :--- | :--- |
| V1 | ARSR à bits rfu (`0xc0`) : la Central traite-t-elle une demande non authentifiée comme un re-pairing ? | `secreq -r 0xc0` | re-pairing déclenché | ne vérifie que la réaction, pas l'appairage |
| V2 | Offre de re-pairing non liée au bond : acceptée par le Peripheral ? | `repair` | offre acceptée | un refus ne prouve pas que l'expéditeur est vérifié : non concluant |
| V3 | Réponse d'appairage plus faible que l'ARSR : la Central continue-t-elle ? | `secreq -m v3 -r 0x0d` | la Central continue (Confirm ou Public Key) | une seule réponse, côté Central seulement |
| V4 | Bond authentifié, négociation sans MITM : acceptée ? | `repair` | MITM retiré accepté | non applicable à un bond non authentifié |
| V5 | Demande de chiffrement rejetée (LL_REJECT_IND), puis SEC REQ : re-pairing ? | `secreq -m v5 -r 0x0d` | re-pairing après rejet | la Central doit demander le chiffrement |
| V6 | Taille de clé négociée sous celle du bond : acceptée ? | `repair` | clé sous la taille du bond | ne mesure que la négociation |

Les prérequis des attaques (table II du papier) sont estimés dans le rapport : Peripheral Impersonation demande V1 et V5, Central Impersonation demande V2. Ce sont des prérequis, pas une attaque.

**Non implémenté, volontairement** : l'exécution des attaques PI, CI et MitM (single et double canal). Elles impliquent d'usurper une identité et de dériver des clés, ce que cet outil ne fait pas. Les correctifs du papier (hardening, ré-appairage authentifié) sont des modifications de pile, pas un test à lancer sur un appareil tiers.
