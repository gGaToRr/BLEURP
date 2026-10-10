// ========================================
//  nom du fichier: fingerprint.c
//  description courte: Passive device fingerprinting implementation. Maps GAP
//  appearance and advertised service UUIDs to a device category, folds in the
//  vendor and address-privacy posture, and computes an exposure score. Reads
//  only what a device broadcasts in the clear; transmits nothing.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "fingerprint.h"

#include <stddef.h>
#include <stdio.h>

// --- Assigned Numbers: 16-bit GATT service UUIDs we categorise. ---
#define SVC_DEVICE_INFO     0x180a
#define SVC_HEART_RATE      0x180d
#define SVC_BATTERY         0x180f
#define SVC_HID             0x1812
#define SVC_GLUCOSE         0x1808
#define SVC_HEALTH_THERMO   0x1809
#define SVC_BLOOD_PRESSURE  0x1810
#define SVC_RUNNING_SPEED   0x1814
#define SVC_CYCLING_SPEED   0x1816
#define SVC_AUDIO_SINK      0x110b   // Bluetooth Classic A2DP sink
#define SVC_HANDS_FREE      0x111e
#define SVC_HEADSET         0x1108

// --- GAP appearance category (top 10 bits of the 16-bit appearance). ---
#define APPEARANCE_CATEGORY(a) ((uint16_t)((a) >> 6))
#define APP_CAT_PHONE      0x001
#define APP_CAT_COMPUTER   0x002
#define APP_CAT_WATCH      0x003
#define APP_CAT_CLOCK      0x004
#define APP_CAT_DISPLAY    0x005
#define APP_CAT_HID        0x00f
#define APP_CAT_HEART_RATE 0x012
#define APP_CAT_BLOOD_PRES 0x013
#define APP_CAT_THERMO     0x011
#define APP_CAT_GLUCOSE    0x010
#define APP_CAT_WEARABLE   0x02c
#define APP_CAT_AUDIO      0x009

static const char *k_category_labels[] = {
    [FP_CAT_UNKNOWN]    = "unknown",
    [FP_CAT_PHONE]      = "phone",
    [FP_CAT_COMPUTER]   = "computer",
    [FP_CAT_WEARABLE]   = "wearable",
    [FP_CAT_AUDIO]      = "audio",
    [FP_CAT_INPUT]      = "input",
    [FP_CAT_HEALTH]     = "health",
    [FP_CAT_SENSOR]     = "sensor",
    [FP_CAT_NETWORK]    = "network",
    [FP_CAT_PERIPHERAL] = "peripheral",
};

const char *fingerprint_category_label(fp_category_t c)
{
    if (c < 0 || (size_t)c >= sizeof k_category_labels / sizeof k_category_labels[0])
        return "unknown";
    const char *s = k_category_labels[c];
    return s ? s : "unknown";
}

// Map a single service UUID to a category, or FP_CAT_UNKNOWN if it doesn't
// pin one down on its own.
static fp_category_t category_from_service(uint16_t uuid)
{
    switch (uuid) {
    case SVC_HID:            return FP_CAT_INPUT;
    case SVC_HEART_RATE:
    case SVC_GLUCOSE:
    case SVC_HEALTH_THERMO:
    case SVC_BLOOD_PRESSURE: return FP_CAT_HEALTH;
    case SVC_RUNNING_SPEED:
    case SVC_CYCLING_SPEED:  return FP_CAT_SENSOR;
    case SVC_AUDIO_SINK:
    case SVC_HANDS_FREE:
    case SVC_HEADSET:        return FP_CAT_AUDIO;
    default:                 return FP_CAT_UNKNOWN;
    }
}

// Map the GAP appearance category bits to a device category.
static fp_category_t category_from_appearance(uint16_t appearance)
{
    switch (APPEARANCE_CATEGORY(appearance)) {
    case APP_CAT_PHONE:      return FP_CAT_PHONE;
    case APP_CAT_COMPUTER:   return FP_CAT_COMPUTER;
    case APP_CAT_WATCH:
    case APP_CAT_CLOCK:
    case APP_CAT_WEARABLE:   return FP_CAT_WEARABLE;
    case APP_CAT_DISPLAY:
    case APP_CAT_AUDIO:      return FP_CAT_AUDIO;
    case APP_CAT_HID:        return FP_CAT_INPUT;
    case APP_CAT_HEART_RATE:
    case APP_CAT_BLOOD_PRES:
    case APP_CAT_THERMO:
    case APP_CAT_GLUCOSE:    return FP_CAT_HEALTH;
    default:                 return FP_CAT_UNKNOWN;
    }
}

// Decide the category: appearance is authoritative when present, otherwise the
// most specific service hint wins; a bare service set with only generic
// entries falls back to FP_CAT_PERIPHERAL.
static fp_category_t decide_category(const struct ad_info *info, bool *has_hid)
{
    *has_hid = false;
    if (!info) return FP_CAT_UNKNOWN;

    if (info->has_appearance) {
        fp_category_t c = category_from_appearance(info->appearance);
        // still scan services so has_hid is accurate
        for (int i = 0; i < info->n_uuid16; i++)
            if (info->uuid16[i] == SVC_HID) *has_hid = true;
        if (c != FP_CAT_UNKNOWN) return c;
    }

    fp_category_t best = FP_CAT_UNKNOWN;
    bool any_service = false;
    for (int i = 0; i < info->n_uuid16; i++) {
        uint16_t u = info->uuid16[i];
        if (u == SVC_HID) *has_hid = true;
        // Ignore ubiquitous services that don't categorise (battery, devinfo).
        if (u == SVC_BATTERY || u == SVC_DEVICE_INFO) { any_service = true; continue; }
        any_service = true;
        fp_category_t c = category_from_service(u);
        if (c != FP_CAT_UNKNOWN) best = c;
    }
    if (best != FP_CAT_UNKNOWN) return best;
    if (any_service || info->has_uuid128) return FP_CAT_PERIPHERAL;
    return FP_CAT_UNKNOWN;
}

// Exposure score in [0,100]. Components, additive then clamped:
//   +40  trackable address (public / static random) — stable identifier
//   +10  a broadcast local name (leaks identity/model)
//   + 5  per advertised 16-bit service, capped at +25 (rich surface)
//   +15  advertises the HID service (a keystroke-injection surface)
//   +10  a 128-bit (vendor-custom) service present (custom attack surface)
// A rotating private address with no name and no services scores near 0.
static int compute_exposure(const struct ad_info *info, addr_privacy_t priv,
                            bool has_hid)
{
    int score = 0;
    if (addr_is_trackable(priv)) score += 40;

    if (info) {
        if (info->has_name) score += 10;

        int svc = info->n_uuid16;
        if (svc > 5) svc = 5;            // cap the per-service contribution
        score += svc * 5;

        if (has_hid)            score += 15;
        if (info->has_uuid128)  score += 10;
    }

    if (score > 100) score = 100;
    if (score < 0)   score = 0;
    return score;
}

struct fingerprint fingerprint_make(const struct ad_info *info,
                                    const uint8_t addr[6], uint8_t addr_type)
{
    struct fingerprint fp;

    bool has_hid = false;
    fp.category       = decide_category(info, &has_hid);
    fp.category_label = fingerprint_category_label(fp.category);
    fp.vendor         = (info && info->has_company)
                            ? ad_company_name(info->company_id) : NULL;
    fp.privacy        = addr_privacy(addr, addr_type);
    fp.trackable      = addr_is_trackable(fp.privacy);
    fp.has_hid        = has_hid;
    fp.has_name       = info ? info->has_name : false;
    fp.service_count  = info ? info->n_uuid16 : 0;
    fp.exposure       = compute_exposure(info, fp.privacy, has_hid);

    return fp;
}

int fingerprint_summary(const struct fingerprint *fp, char *out, size_t n)
{
    if (!fp || !out || n == 0) return 0;
    return snprintf(out, n, "%s%s%s priv=%s%s svc=%d%s exposure=%d",
                    fp->category_label,
                    fp->vendor ? " vendor=" : "",
                    fp->vendor ? fp->vendor : "",
                    addr_privacy_label(fp->privacy),
                    fp->trackable ? " [trackable]" : "",
                    fp->service_count,
                    fp->has_hid ? " HID" : "",
                    fp->exposure);
}
