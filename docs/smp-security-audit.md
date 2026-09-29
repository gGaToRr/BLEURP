# SMP Security Audit & Downgrade Probing

BLEURP implements a Security Manager Protocol (SMP) security diagnostic engine (`src/smp.c`, `src/smp.h`, `src/smp_native/smp_native.c`, `src/smp_native/smp_native.h`). It probes how a target Bluetooth LE device handles pairing feature negotiation and identifies security downgrades.

> ⚠️ **Authorized use only.** Only execute SMP pairing probes on devices you own or are explicitly authorized to test.

---

## 1. Background & Threat Model

In Bluetooth Low Energy, pairing is governed by the Security Manager Protocol (SMP, fixed L2CAP CID `0x0006`). During Phase 1 of pairing, the Initiator (Central) and Responder (Peripheral) exchange **Pairing Request** and **Pairing Response** packets to negotiate:
- **Authentication Requirements (`AuthReq`)**: Bonding, Man-in-the-Middle (MITM) protection, Secure Connections (SC / LE SC vs Legacy Pairing).
- **IO Capabilities**: Determines whether Just Works, Passkey Entry, or Numeric Comparison is used.
- **Maximum Encryption Key Size**: Allowed entropy range between 7 and 16 bytes (56 to 128 bits).
- **Key Distribution Bitmasks**: Long Term Key (LTK), Identity Resolving Key (IRK), Connection Signature Resolving Key (CSRK).

Academic research (e.g., *BLERP: Breaking BLE Link Layer Security via Re-Pairing*, NDSS 2026) demonstrated that many BLE stacks improperly handle unsolicited or downgraded re-pairing requests, accepting unauthenticated Just Works pairing (no MITM) or legacy encryption with truncated key sizes even when a higher security bond was previously established.

```
      Initiator (BLEURP)                        Responder (Target)
              │                                          │
              │   1. Pairing Request                     │
              │   ─────────────────────────────────►     │
              │   [IOCap=0x03 (NoInNoOut),               │
              │    AuthReq=0x01 (Bonding only, no MITM), │
              │    MaxKeySize=7 (56-bit min entropy)]    │
              │                                          │
              │   2. Pairing Response / Failed           │
              │   ◄─────────────────────────────────     │
              │   [Examines returned AuthReq,            │
              │    IOCap, and accepted Key Size]         │
              │                                          │
              ▼                                          ▼
     [Diagnostic verdict: Downgrade accepted vs Policy enforced]
```

---

## 2. Probing Mechanisms

BLEURP provides two probing implementations:

### A. Native HCI User Channel Probe (`src/smp_native/`)
- Connects directly to the adapter via Linux `HCI_CHANNEL_USER` or raw socket.
- Bypasses kernel bluez pairing state to craft exact L2CAP B-frame SMP packets.
- Implements microsecond-precise polling and timeout management without depending on `bluetoothd`.

### B. Standard L2CAP Fixed-Channel Probe (`src/l2cap.c`, `src/smp.c`)
- Uses Linux `AF_BLUETOOTH` / `BTPROTO_L2CAP` with fixed CID `BLEURP_SMP_CID (0x0006)`.
- Delivers standalone packet serialization/deserialization for unit testing and modular integration.

---

## 3. CLI Usage

```sh
# Probe a target device with public address:
./build/bleurp smp AA:BB:CC:DD:EE:FF -t public

# Probe a target device with random/RPA address on hci1:
./build/bleurp smp AA:BB:CC:DD:EE:FF -i 1 -t random
```

### Sample Output

```
=== Diagnostic SMP Native (Cible: AA:BB:CC:DD:EE:FF) ===
Capacité I/O cible  : 0x03 (NoInputNoOutput)
Données OOB         : 0x00
AuthReq négocié     : 0x01 [MITM=NON, SC=NON, Bonding=OUI]
Taille clé acceptée : 7 octets (56 bits)
Dist. Clés (Init/Rsp): 0x01 / 0x01

[+] Vulnérabilité d'affaiblissement observée : la cible accepte une négociation sans MITM ni SC !
```

---

## 4. Verdicts & Interpretation

| Observation | Security Significance | Risk Level |
| :--- | :--- | :--- |
| **AuthReq accepts `MITM=0` & `SC=0`** | Target accepts unauthenticated Just Works legacy pairing without cryptographic peer authentication. | **High** |
| **Max Key Size = 7 bytes (56-bit)** | Target accepts minimal encryption key entropy, vulnerable to offline bruteforce attacks (e.g. KNOB-style key reduction). | **High** |
| **Pairing Failed (`0x05` - Auth Requirements)** | Target strictly enforces its security policy and rejects downgraded pairing proposals. | **Secure** |
| **Timeout / Connection Rejected** | Target rejects unbonded SMP connections or drops connection upon unexpected Pairing Request. | **Defended** |
