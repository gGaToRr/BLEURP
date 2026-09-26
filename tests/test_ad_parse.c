// ========================================
//  nom du fichier: test_ad_parse.c
//  description courte: Unit tests for the advertising-data parser. Covers
//  name (complete vs short), flags, TX power, appearance, 16/128-bit service
//  UUIDs, manufacturer company id, vendor/service lookups, the best-effort
//  label, and tolerance to truncated input.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "ad_parse.h"

#include <errno.h>
#include <string.h>

// Flags + complete local name are both decoded.
static void test_flags_and_name(void) {
    const uint8_t ad[] = {
        0x02, AD_TYPE_FLAGS, 0x06,
        0x05, AD_TYPE_NAME_COMPLETE, 'A', 'C', 'M', 'E',
    };
    struct ad_info info;
    CHECK(ad_parse(ad, sizeof ad, &info) == 0);
    CHECK(info.has_flags == true);
    CHECK(info.flags == 0x06);
    CHECK(info.has_name == true);
    CHECK(info.name_is_short == false);
    CHECK(strcmp(info.name, "ACME") == 0);
}

// A complete name is preferred even if a shortened name comes first.
static void test_prefer_complete_name(void) {
    const uint8_t ad[] = {
        0x03, AD_TYPE_NAME_SHORT, 'A', 'C',
        0x05, AD_TYPE_NAME_COMPLETE, 'A', 'C', 'M', 'E',
    };
    struct ad_info info;
    CHECK(ad_parse(ad, sizeof ad, &info) == 0);
    CHECK(strcmp(info.name, "ACME") == 0);
    CHECK(info.name_is_short == false);
}

// A shortened name alone is used and flagged as short.
static void test_short_name_only(void) {
    const uint8_t ad[] = {0x03, AD_TYPE_NAME_SHORT, 'H', 'i'};
    struct ad_info info;
    CHECK(ad_parse(ad, sizeof ad, &info) == 0);
    CHECK(info.has_name == true);
    CHECK(info.name_is_short == true);
    CHECK(strcmp(info.name, "Hi") == 0);
}

// TX power (signed) and appearance (little-endian) are decoded.
static void test_tx_power_and_appearance(void) {
    const uint8_t ad[] = {
        0x02, AD_TYPE_TX_POWER, (uint8_t)(-12),
        0x03, AD_TYPE_APPEARANCE, 0xc0, 0x03, // 0x03c0 = HID
    };
    struct ad_info info;
    CHECK(ad_parse(ad, sizeof ad, &info) == 0);
    CHECK(info.has_tx_power == true);
    CHECK(info.tx_power == -12);
    CHECK(info.has_appearance == true);
    CHECK(info.appearance == 0x03c0);
}

// A complete list of 16-bit service UUIDs is collected.
static void test_uuid16_list(void) {
    const uint8_t ad[] = {
        0x05, AD_TYPE_UUID16_COMP, 0x0f, 0x18, 0x0d, 0x18, // 0x180f, 0x180d
    };
    struct ad_info info;
    CHECK(ad_parse(ad, sizeof ad, &info) == 0);
    CHECK(info.n_uuid16 == 2);
    CHECK(info.uuid16[0] == 0x180f);
    CHECK(info.uuid16[1] == 0x180d);
}

// Manufacturer data yields the company id; a 128-bit UUID sets the flag.
static void test_manufacturer_and_uuid128(void) {
    const uint8_t ad[] = {
        0x03, AD_TYPE_MANUFACTURER, 0x4c, 0x00,           // Apple (0x004c)
        0x11, AD_TYPE_UUID128_COMP, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    };
    struct ad_info info;
    CHECK(ad_parse(ad, sizeof ad, &info) == 0);
    CHECK(info.has_company == true);
    CHECK(info.company_id == 0x004c);
    CHECK(info.has_uuid128 == true);
}

// Lookups return the expected names, and NULL for unknown values.
static void test_lookups(void) {
    CHECK(ad_company_name(0x004c) != NULL && strcmp(ad_company_name(0x004c), "Apple") == 0);
    CHECK(ad_company_name(0x0006) != NULL && strcmp(ad_company_name(0x0006), "Microsoft") == 0);
    CHECK(ad_company_name(0xabcd) == NULL);
    CHECK(ad_service_name(0x180f) != NULL && strcmp(ad_service_name(0x180f), "Battery Service") == 0);
    CHECK(ad_service_name(0xfeaa) != NULL && strcmp(ad_service_name(0xfeaa), "Eddystone") == 0);
    CHECK(ad_service_name(0x1234) == NULL);
}

// The best label is the name, else the vendor, else a known service, else NULL.
static void test_best_label(void) {
    struct ad_info info;

    memset(&info, 0, sizeof info);
    info.has_name = true; strcpy(info.name, "MyWatch");
    CHECK(strcmp(ad_best_label(&info), "MyWatch") == 0);

    memset(&info, 0, sizeof info);
    info.has_company = true; info.company_id = 0x004c;
    CHECK(strcmp(ad_best_label(&info), "Apple") == 0);

    memset(&info, 0, sizeof info);
    info.n_uuid16 = 1; info.uuid16[0] = 0xfeaa;
    CHECK(strcmp(ad_best_label(&info), "Eddystone") == 0);

    memset(&info, 0, sizeof info);
    CHECK(ad_best_label(&info) == NULL);
}

// Truncated fields and padding are tolerated (no crash, valid part kept).
static void test_truncated_tolerant(void) {
    const uint8_t ad[] = {
        0x05, AD_TYPE_NAME_COMPLETE, 'O', 'K', 'A', 'Y',
        0x08, AD_TYPE_MANUFACTURER, 0x4c, // claims 8 bytes but only 1 present
    };
    struct ad_info info;
    CHECK(ad_parse(ad, sizeof ad, &info) == 0);
    CHECK(strcmp(info.name, "OKAY") == 0); // valid field before the bad one
    CHECK(info.has_company == false);      // malformed field not decoded
}

// NULL output is rejected; empty input parses to an empty struct.
static void test_edge_cases(void) {
    errno = 0;
    CHECK(ad_parse((const uint8_t *)"", 0, NULL) == -1);
    CHECK(errno == EINVAL);
    struct ad_info info;
    CHECK(ad_parse(NULL, 0, &info) == 0); // len 0 with NULL data is allowed
    CHECK(info.has_name == false);
    CHECK(info.n_uuid16 == 0);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_ad_parse\n");
    test_flags_and_name();
    test_prefer_complete_name();
    test_short_name_only();
    test_tx_power_and_appearance();
    test_uuid16_list();
    test_manufacturer_and_uuid128();
    test_lookups();
    test_best_label();
    test_truncated_tolerant();
    test_edge_cases();
    return TEST_REPORT();
}
