// ========================================
//  nom du fichier: ad_parse.h
//  description courte: Advertising Data (AD/EIR) parser. Decodes the
//  length/type/value structures of a BLE advertising payload into fields
//  (name, flags, TX power, appearance, service UUIDs, manufacturer company
//  id) and derives a best-effort human label to reduce "unknown" devices.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_AD_PARSE_H
#define BLEURP_AD_PARSE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// AD type codes (Bluetooth Core / Assigned Numbers) that we decode.
#define AD_TYPE_FLAGS          0x01
#define AD_TYPE_UUID16_INCOMP  0x02
#define AD_TYPE_UUID16_COMP    0x03
#define AD_TYPE_UUID32_INCOMP  0x04
#define AD_TYPE_UUID32_COMP    0x05
#define AD_TYPE_UUID128_INCOMP 0x06
#define AD_TYPE_UUID128_COMP   0x07
#define AD_TYPE_NAME_SHORT     0x08
#define AD_TYPE_NAME_COMPLETE  0x09
#define AD_TYPE_TX_POWER       0x0a
#define AD_TYPE_APPEARANCE     0x19
#define AD_TYPE_MANUFACTURER   0xff

// How many 16-bit service UUIDs we keep per device.
#define AD_MAX_UUID16 16

// Decoded advertising data. Absent fields are left zero / has_* = false.
struct ad_info {
    char     name[249];       // local name (NUL-terminated)
    bool     has_name;
    bool     name_is_short;   // true if only a shortened name was seen

    bool     has_flags;
    uint8_t  flags;

    bool     has_tx_power;
    int8_t   tx_power;         // dBm

    bool     has_appearance;
    uint16_t appearance;

    bool     has_company;
    uint16_t company_id;       // from manufacturer-specific data
    bool     has_uuid128;      // at least one 128-bit service UUID present

    uint16_t uuid16[AD_MAX_UUID16];
    int      n_uuid16;
};

// Parse an advertising payload into `out`. Tolerant of truncation/padding
// (stops at the first malformed field). Returns 0 on success, or -1 with
// errno=EINVAL when out is NULL, or data is NULL while len > 0.
int ad_parse(const uint8_t *data, size_t len, struct ad_info *out);

// Human-readable company name for a Bluetooth SIG company identifier, or
// NULL if unknown. Covers the most common vendors.
const char *ad_company_name(uint16_t company_id);

// Human-readable name for a common 16-bit service UUID, or NULL if unknown.
const char *ad_service_name(uint16_t uuid16);

// Best-effort label for display: the device name if present, otherwise a
// "<vendor> device" hint, otherwise a known service name, otherwise NULL.
// The returned pointer is either into `info` or a static string.
const char *ad_best_label(const struct ad_info *info);

#endif // BLEURP_AD_PARSE_H
