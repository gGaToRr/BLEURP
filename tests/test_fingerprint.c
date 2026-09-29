// ========================================
//  nom du fichier: test_fingerprint.c
//  description courte: Unit tests for the passive device fingerprinter.
//  Covers category inference from appearance and from service UUIDs, HID
//  detection, vendor pass-through, privacy posture, the exposure score's
//  components, and the NULL-advertising fallback. No radio, no I/O.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "fingerprint.h"

#include <string.h>

// A trackable public address (any bytes; type decides posture here).
static const uint8_t PUB_ADDR[6] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

// A random address whose top two bits are 0b01 -> resolvable private (RPA),
// i.e. rotating / not trackable. MSB is addr[5] in HCI byte order.
static const uint8_t RPA_ADDR[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x40 };

// A random address whose top two bits are 0b11 -> static random (trackable).
static const uint8_t STATIC_ADDR[6] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0xC0 };

// Zero out an ad_info and return it ready to populate.
static struct ad_info blank_ad(void)
{
    struct ad_info a;
    memset(&a, 0, sizeof a);
    return a;
}

int main(void)
{
    // --- Category from appearance: a phone (appearance category 0x001). ---
    {
        struct ad_info a = blank_ad();
        a.has_appearance = true;
        a.appearance = 0x001 << 6;   // category bits = 0x001 (Phone)
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.category == FP_CAT_PHONE);
        CHECK(strcmp(fp.category_label, "phone") == 0);
    }

    // --- Category from a service UUID: heart rate -> health. ---
    {
        struct ad_info a = blank_ad();
        a.n_uuid16 = 1;
        a.uuid16[0] = 0x180d;        // Heart Rate service
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.category == FP_CAT_HEALTH);
        CHECK(fp.service_count == 1);
    }

    // --- HID service (0x1812) -> input category, and has_hid flag set. ---
    {
        struct ad_info a = blank_ad();
        a.n_uuid16 = 1;
        a.uuid16[0] = 0x1812;        // Human Interface Device
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.category == FP_CAT_INPUT);
        CHECK(fp.has_hid == true);
    }

    // --- Appearance wins over services, but has_hid still tracked. ---
    {
        struct ad_info a = blank_ad();
        a.has_appearance = true;
        a.appearance = 0x009 << 6;   // category 0x009 (audio-ish) -> AUDIO
        a.n_uuid16 = 1;
        a.uuid16[0] = 0x1812;        // HID present alongside
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.category == FP_CAT_AUDIO);   // appearance authoritative
        CHECK(fp.has_hid == true);            // service scan still ran
    }

    // --- Only generic services (battery/devinfo) -> PERIPHERAL, not UNKNOWN. ---
    {
        struct ad_info a = blank_ad();
        a.n_uuid16 = 2;
        a.uuid16[0] = 0x180f;        // Battery
        a.uuid16[1] = 0x180a;        // Device Information
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.category == FP_CAT_PERIPHERAL);
    }

    // --- Vendor is passed through from the company id. ---
    {
        struct ad_info a = blank_ad();
        a.has_company = true;
        a.company_id = 0x0075;       // Samsung (per test dep)
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.vendor != NULL);
        CHECK(strcmp(fp.vendor, "Samsung") == 0);
    }

    // --- Privacy posture: public is trackable, RPA is not. ---
    {
        struct ad_info a = blank_ad();
        struct fingerprint pub = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(pub.privacy == ADDR_PRIV_PUBLIC);
        CHECK(pub.trackable == true);

        struct fingerprint rpa = fingerprint_make(&a, RPA_ADDR, ADDR_TYPE_LE_RANDOM);
        CHECK(rpa.privacy == ADDR_PRIV_RPA);
        CHECK(rpa.trackable == false);

        struct fingerprint stat = fingerprint_make(&a, STATIC_ADDR, ADDR_TYPE_LE_RANDOM);
        CHECK(stat.privacy == ADDR_PRIV_STATIC_RANDOM);
        CHECK(stat.trackable == true);
    }

    // --- Exposure: a private, nameless, service-less device scores near 0. ---
    {
        struct ad_info a = blank_ad();
        struct fingerprint fp = fingerprint_make(&a, RPA_ADDR, ADDR_TYPE_LE_RANDOM);
        CHECK(fp.exposure == 0);
    }

    // --- Exposure: trackable (+40) alone. ---
    {
        struct ad_info a = blank_ad();
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.exposure == 40);
    }

    // --- Exposure: trackable + name + one HID service.
    //     40 (trackable) + 10 (name) + 5 (1 service) + 15 (HID) = 70. ---
    {
        struct ad_info a = blank_ad();
        a.has_name = true;
        strcpy(a.name, "KAETS-TEST");
        a.n_uuid16 = 1;
        a.uuid16[0] = 0x1812;        // HID
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.exposure == 70);
        CHECK(fp.has_name == true);
    }

    // --- Exposure clamps at 100 (many services + name + HID + 128-bit + trackable). ---
    {
        struct ad_info a = blank_ad();
        a.has_name = true;
        strcpy(a.name, "loud");
        a.has_uuid128 = true;
        a.n_uuid16 = 8;
        for (int i = 0; i < 8; i++) a.uuid16[i] = 0x1800 + (uint16_t)i;
        a.uuid16[0] = 0x1812;        // ensure HID counted
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.exposure == 100);   // clamped
    }

    // --- NULL advertising: fingerprint rests on address alone, no crash. ---
    {
        struct fingerprint fp = fingerprint_make(NULL, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        CHECK(fp.category == FP_CAT_UNKNOWN);
        CHECK(fp.vendor == NULL);
        CHECK(fp.has_hid == false);
        CHECK(fp.service_count == 0);
        CHECK(fp.trackable == true);         // public address is still trackable
        CHECK(fp.exposure == 40);            // only the address component
    }

    // --- Summary string is well-formed and mentions the category. ---
    {
        struct ad_info a = blank_ad();
        a.has_company = true;
        a.company_id = 0x0075;       // Samsung
        a.n_uuid16 = 1;
        a.uuid16[0] = 0x180d;        // heart rate -> health
        struct fingerprint fp = fingerprint_make(&a, PUB_ADDR, ADDR_TYPE_LE_PUBLIC);
        char buf[128];
        int w = fingerprint_summary(&fp, buf, sizeof buf);
        CHECK(w > 0);
        CHECK(strstr(buf, "health") != NULL);
        CHECK(strstr(buf, "vendor=Samsung") != NULL);
        CHECK(strstr(buf, "exposure=") != NULL);
    }

    printf("\ntest_fingerprint\n");
    return TEST_REPORT();
}
