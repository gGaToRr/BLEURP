// ========================================
//  nom du fichier: fingerprint.h
//  description courte: Passive device fingerprinting. Aggregates parsed
//  advertising data and address-privacy posture into a compact profile:
//  a device category (from appearance + service UUIDs), a vendor class
//  (from the manufacturer company id), the privacy posture, and an exposure
//  score. Purely interpretive over publicly broadcast data; emits nothing.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_FINGERPRINT_H
#define BLEURP_FINGERPRINT_H

#include <stdbool.h>
#include <stdint.h>

#include "ad_parse.h"
#include "addr_priv.h"

// Coarse device category, inferred from GAP appearance and/or the set of
// advertised 16-bit service UUIDs. FP_CAT_UNKNOWN when nothing is decodable.
typedef enum {
    FP_CAT_UNKNOWN = 0,
    FP_CAT_PHONE,          // handset / generic computer
    FP_CAT_COMPUTER,       // laptop / desktop
    FP_CAT_WEARABLE,       // watch, band
    FP_CAT_AUDIO,          // headset, speaker, earbuds
    FP_CAT_INPUT,          // keyboard, mouse, HID
    FP_CAT_HEALTH,         // heart rate, glucose, thermometer
    FP_CAT_SENSOR,         // environmental / proximity beacon / tag
    FP_CAT_NETWORK,        // access point, router, gateway
    FP_CAT_PERIPHERAL      // known service but uncategorised above
} fp_category_t;

// Compact fingerprint of one device. All fields are derived; nothing here is
// a guessed identity presented as fact — an absent signal stays absent.
struct fingerprint {
    fp_category_t  category;
    const char    *category_label;  // static string, never NULL
    const char    *vendor;          // ad_company_name() result, or NULL
    addr_privacy_t privacy;
    bool           trackable;       // addr_is_trackable(privacy)

    bool           has_hid;         // advertises the HID service (0x1812)
    bool           has_name;        // a real local name was advertised
    int            service_count;   // number of decoded 16-bit services

    // Exposure score in [0,100]. Higher = more attack surface / less privacy:
    // a stable trackable address, a rich advertised service set, an exposed
    // HID service and a broadcast name all raise it. It ranks recon interest,
    // not vulnerability — it never implies an exploitable flaw.
    int            exposure;
};

// Build a fingerprint from parsed advertising data and the device address.
// `info` may be NULL (no advertising decoded): the fingerprint then rests on
// the address posture alone. `addr` is in HCI byte order (addr[5] = MSB),
// `addr_type` follows the mgmt convention (ADDR_TYPE_*). Never fails.
struct fingerprint fingerprint_make(const struct ad_info *info,
                                    const uint8_t addr[6], uint8_t addr_type);

// Static label for a category ("phone", "audio", ...). Never NULL.
const char *fingerprint_category_label(fp_category_t c);

// Write a one-line human summary of the fingerprint into `out` (NUL-terminated,
// truncated to `n`). Example: "audio vendor=Samsung priv=rpa svc=3 exposure=42".
// Returns the number of bytes that would have been written (snprintf semantics).
int fingerprint_summary(const struct fingerprint *fp, char *out, size_t n);

#endif // BLEURP_FINGERPRINT_H
