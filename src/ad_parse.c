// ========================================
//  nom du fichier: ad_parse.c
//  description courte: Implementation of the advertising-data parser. Walks
//  the length/type/value AD structures with bounds checks, fills an ad_info,
//  and provides small vendor/service lookup tables plus a best label helper.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "ad_parse.h"

#include <errno.h>
#include <string.h>

// Read a little-endian 16-bit value from a byte buffer.
static uint16_t rd_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

// Copy a name value into the NUL-terminated destination, clamped to size.
static void set_name(struct ad_info *out, const uint8_t *val, size_t vlen,
                     bool is_short) {
    size_t n = vlen < sizeof out->name - 1 ? vlen : sizeof out->name - 1;
    memcpy(out->name, val, n);
    out->name[n] = '\0';
    out->name_is_short = is_short;
    out->has_name = true;
}

// Append the 16-bit UUIDs of a UUID list value, up to the fixed capacity.
static void add_uuid16(struct ad_info *out, const uint8_t *val, size_t vlen) {
    for (size_t j = 0; j + 2 <= vlen; j += 2) {
        if (out->n_uuid16 < AD_MAX_UUID16) {
            out->uuid16[out->n_uuid16++] = rd_le16(&val[j]);
        }
    }
}

// Parse an advertising payload. See ad_parse.h for the contract.
int ad_parse(const uint8_t *data, size_t len, struct ad_info *out) {
    if (out == NULL || (len > 0 && data == NULL)) {
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, sizeof *out);

    size_t i = 0;
    while (i < len) {
        uint8_t field_len = data[i]; // number of bytes after this length byte
        if (field_len == 0) {
            break; // early terminator / padding
        }
        if (i + 1 + (size_t)field_len > len) {
            break; // truncated field: stop, keep what we have
        }

        uint8_t type = data[i + 1];
        const uint8_t *val = &data[i + 2];
        size_t vlen = (size_t)field_len - 1;

        switch (type) {
        case AD_TYPE_FLAGS:
            if (vlen >= 1) { out->flags = val[0]; out->has_flags = true; }
            break;
        case AD_TYPE_NAME_SHORT:
            if (!out->has_name) { set_name(out, val, vlen, true); }
            break;
        case AD_TYPE_NAME_COMPLETE:
            set_name(out, val, vlen, false); // complete always wins
            break;
        case AD_TYPE_TX_POWER:
            if (vlen >= 1) { out->tx_power = (int8_t)val[0]; out->has_tx_power = true; }
            break;
        case AD_TYPE_APPEARANCE:
            if (vlen >= 2) { out->appearance = rd_le16(val); out->has_appearance = true; }
            break;
        case AD_TYPE_UUID16_INCOMP:
        case AD_TYPE_UUID16_COMP:
            add_uuid16(out, val, vlen);
            break;
        case AD_TYPE_UUID128_INCOMP:
        case AD_TYPE_UUID128_COMP:
            out->has_uuid128 = true;
            break;
        case AD_TYPE_MANUFACTURER:
            if (vlen >= 2) { out->company_id = rd_le16(val); out->has_company = true; }
            break;
        default:
            break; // unknown AD type: skip
        }

        i += 1 + (size_t)field_len;
    }
    return 0;
}

// One entry in a 16-bit-id lookup table.
struct id_name { uint16_t id; const char *name; };

// A small, easily extended set of common Bluetooth SIG company identifiers.
static const struct id_name k_companies[] = {
    {0x0006, "Microsoft"},
    {0x004c, "Apple"},
    {0x0059, "Nordic Semiconductor"},
    {0x0075, "Samsung"},
    {0x0087, "Garmin"},
    {0x00e0, "Google"},
    {0x0157, "Amazfit"},
    {0x02e5, "Espressif"},
    {0x0499, "Ruuvi"},
};

// A small set of common 16-bit service UUIDs.
static const struct id_name k_services[] = {
    {0x1800, "Generic Access"},
    {0x1801, "Generic Attribute"},
    {0x180a, "Device Information"},
    {0x180d, "Heart Rate"},
    {0x180f, "Battery Service"},
    {0x181a, "Environmental Sensing"},
    {0xfd6f, "Exposure Notification"},
    {0xfe2c, "Google Fast Pair"},
    {0xfeaa, "Eddystone"},
    {0xfeed, "Tile"},
};

// Linear lookup in an id/name table.
static const char *lookup(const struct id_name *table, size_t n, uint16_t id) {
    for (size_t i = 0; i < n; i++) {
        if (table[i].id == id) { return table[i].name; }
    }
    return NULL;
}

// Company name lookup. See ad_parse.h for the contract.
const char *ad_company_name(uint16_t company_id) {
    return lookup(k_companies, sizeof k_companies / sizeof k_companies[0], company_id);
}

// Service name lookup. See ad_parse.h for the contract.
const char *ad_service_name(uint16_t uuid16) {
    return lookup(k_services, sizeof k_services / sizeof k_services[0], uuid16);
}

// Best-effort display label. See ad_parse.h for the contract.
const char *ad_best_label(const struct ad_info *info) {
    if (info == NULL) {
        return NULL;
    }
    if (info->has_name && info->name[0] != '\0') {
        return info->name;
    }
    if (info->has_company) {
        const char *vendor = ad_company_name(info->company_id);
        if (vendor != NULL) { return vendor; }
    }
    for (int i = 0; i < info->n_uuid16; i++) {
        const char *svc = ad_service_name(info->uuid16[i]);
        if (svc != NULL) { return svc; }
    }
    return NULL;
}
