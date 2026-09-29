# Passive Device Fingerprinting

BLEURP includes a passive device fingerprinting engine (`src/fingerprint.c`, `src/fingerprint.h`) that categorizes observed BLE devices, assesses address privacy posture, and calculates a recon **Exposure Score** (0–100) strictly from publicly broadcast advertising frames without transmitting any RF packets.

---

## 1. Overview & Passive Philosophy

Passive fingerprinting relies entirely on standard Bluetooth LE Advertising Data (AD) and Scan Response Data (SRD) received during kernel discovery.

```
       LE Advertising Packet / Scan Response
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
  GAP Appearance & UUIDs         Manufacturer & Flags
         │                               │
         ▼                               ▼
    Category Heuristic            Vendor Identification
         │                               │
         └───────────────┬───────────────┘
                         ▼
        + Address Privacy Posture (MSB bits)
                         ▼
             ╔═════════════════════════╗
             ║   Device Fingerprint    ║
             ║  • Category (Audio...)  ║
             ║  • Vendor (Samsung...)  ║
             ║  • Privacy (RPA/Static) ║
             ║  • Exposure Score 0-100 ║
             ╚═════════════════════════╝
```

---

## 2. Device Categorization

BLEURP infers the device category (`fp_category_t`) by cross-referencing GAP Appearance values and advertised 16-bit Service UUIDs:

| Category | Enum Constant | Matching Criteria |
| :--- | :--- | :--- |
| **Phone** | `FP_CAT_PHONE` | Appearance category `0x0040` (Generic Phone) |
| **Computer** | `FP_CAT_COMPUTER` | Appearance category `0x0080` (Generic Computer / Laptop) |
| **Wearable** | `FP_CAT_WEARABLE` | Appearance category `0x00C0` (Watch / Band) |
| **Audio** | `FP_CAT_AUDIO` | UUIDs `0x180A` (DIS) with audio appearance, or Audio Sink profiles |
| **Input / HID** | `FP_CAT_INPUT` | Appearance category `0x03C0` or Service UUID `0x1812` (Human Interface Device) |
| **Health** | `FP_CAT_HEALTH` | UUIDs `0x180D` (Heart Rate), `0x1808` (Glucose), `0x1809` (Thermometer), `0x1810` (Blood Pressure) |
| **Sensor / Beacon**| `FP_CAT_SENSOR` | UUIDs `0x181A` (Environmental), `0x1802` (Immediate Alert), proximity tags |
| **Network** | `FP_CAT_NETWORK` | Appearance category `0x0280` (Generic Access Point) |
| **Peripheral** | `FP_CAT_PERIPHERAL`| Known service UUIDs present but unclassified above |
| **Unknown** | `FP_CAT_UNKNOWN` | No appearance and no known 16-bit service UUIDs |

---

## 3. Exposure Score Calculation

The **Exposure Score** is an integer in the range `[0, 100]`. It measures the broadcast attack surface and tracking exposure of a device to help security auditors prioritize reconnaissance targets.

> [!NOTE]
> The Exposure Score reflects reconnaissance interest and metadata leakage, **not** guaranteed exploitability.

### Scoring Factors

1. **Address Privacy Posture (Base Score)**
   - `Public Address` (`0x00`): **+35 points** (Fixed IEEE MAC assigned by vendor, permanently trackable).
   - `Static Random Address` (`0x01`): **+30 points** (Randomized at boot or flashed, persistent across connections, trackable).
   - `Resolvable Private Address (RPA)` (`0x02`): **+10 points** (Rotated periodically via Identity Resolving Key).
   - `Non-Resolvable Private Address (NRPA)` (`0x03`): **+5 points** (Temporary randomized address).

2. **Advertised Local Name**
   - Broadcasting a Complete or Shortened Local Name: **+20 points** (Exposes user identity or device brand).

3. **HID Service Presence**
   - Exposing Service UUID `0x1812` (Human Interface Device): **+25 points** (Target is a potential candidate for HID injection / keyboard attacks).

4. **Service Count Density**
   - Each advertised 16-bit service UUID adds **+5 points** (up to a maximum of **+20 points**).

---

## 4. Live UI & Terminal Integration

During a live scan or scan wizard, BLEURP displays a dedicated **FINGERPRINT** table directly beneath the signal table:

```
  FINGERPRINT (passive)
    #    ADDRESS              CAT           VENDOR        PRIVACY   HID   EXPO
  ----------------------------------------------------------------------------------
    1    DC:2C:26:A1:B2:C3    audio         Samsung       rpa       -      35
  ! 2    F4:B7:E2:11:22:33    input         Logitech      static    yes    85
    3    44:65:0D:AA:BB:CC    phone         Apple         rpa       -      30

  CAT = type d'appareil  •  PRIVACY = posture d'adresse (public/static = traçable)
  ! = EXPO ≥ 60 : forte exposition (adresse traçable et/ou HID exposé) — intérêt recon, pas une faille
```

- High exposure targets (score ≥ 60) are flagged with an orange alert marker `!` and bold text.
