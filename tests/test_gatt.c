// ========================================
//  nom du fichier: test_gatt.c
//  description courte: Unit tests for the GATT response parsers: service and
//  characteristic elements in both 16-bit and 128-bit UUID forms, plus
//  rejection of unsupported element sizes and NULL arguments.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "gatt.h"

#include <errno.h>
#include <string.h>

// A 16-bit-UUID service element (6 bytes): start, end, uuid.
static void test_service_uuid16(void) {
    const uint8_t el[] = {0x01, 0x00, 0x05, 0x00, 0x0f, 0x18}; // 1..5, 0x180f
    struct gatt_service s;
    CHECK(gatt_parse_service(el, sizeof el, &s) == 0);
    CHECK(s.start_handle == 0x0001);
    CHECK(s.end_handle == 0x0005);
    CHECK(s.uuid_is_128 == false);
    CHECK(s.uuid16 == 0x180f);
}

// A 128-bit-UUID service element (20 bytes).
static void test_service_uuid128(void) {
    uint8_t el[20] = {0x10, 0x00, 0x20, 0x00};
    for (int i = 0; i < 16; i++) el[4 + i] = (uint8_t)(i + 1);
    struct gatt_service s;
    CHECK(gatt_parse_service(el, sizeof el, &s) == 0);
    CHECK(s.start_handle == 0x0010);
    CHECK(s.end_handle == 0x0020);
    CHECK(s.uuid_is_128 == true);
    CHECK(s.uuid128[0] == 1 && s.uuid128[15] == 16);
}

// A 16-bit-UUID characteristic element (7 bytes): decl, props, value, uuid.
static void test_char_uuid16(void) {
    const uint8_t el[] = {0x10, 0x00, 0x02, 0x12, 0x00, 0x00, 0x2a}; // read, val 0x12, 0x2a00
    struct gatt_char c;
    CHECK(gatt_parse_characteristic(el, sizeof el, &c) == 0);
    CHECK(c.decl_handle == 0x0010);
    CHECK(c.properties == GATT_PROP_READ);
    CHECK(c.value_handle == 0x0012);
    CHECK(c.uuid_is_128 == false);
    CHECK(c.uuid16 == 0x2a00);
}

// A 128-bit-UUID characteristic element (21 bytes).
static void test_char_uuid128(void) {
    uint8_t el[21] = {0x30, 0x00, GATT_PROP_NOTIFY, 0x32, 0x00};
    for (int i = 0; i < 16; i++) el[5 + i] = (uint8_t)(0xa0 + i);
    struct gatt_char c;
    CHECK(gatt_parse_characteristic(el, sizeof el, &c) == 0);
    CHECK(c.properties == GATT_PROP_NOTIFY);
    CHECK(c.value_handle == 0x0032);
    CHECK(c.uuid_is_128 == true);
    CHECK(c.uuid128[0] == 0xa0 && c.uuid128[15] == 0xaf);
}

// Unsupported element sizes and NULL args are rejected.
static void test_bad(void) {
    const uint8_t el[8] = {0};
    struct gatt_service s;
    struct gatt_char c;
    errno = 0;
    CHECK(gatt_parse_service(el, 5, &s) == -1);       // not 6 or 20
    CHECK(errno == EBADMSG);
    errno = 0;
    CHECK(gatt_parse_characteristic(el, 8, &c) == -1); // not 7 or 21
    CHECK(errno == EBADMSG);
    errno = 0;
    CHECK(gatt_parse_service(NULL, 6, &s) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(gatt_parse_characteristic(el, 7, NULL) == -1);
    CHECK(errno == EINVAL);
}

// A 16-bit-UUID descriptor element (4 bytes): handle, uuid.
static void test_descriptor_uuid16(void) {
    const uint8_t el[] = {0x25, 0x00, 0x02, 0x29}; // handle 0x25, CCCD 0x2902
    struct gatt_descriptor d;
    CHECK(gatt_parse_descriptor(el, sizeof el, &d) == 0);
    CHECK(d.handle == 0x0025);
    CHECK(d.uuid_is_128 == false);
    CHECK(d.uuid16 == 0x2902);
}

// A 128-bit-UUID descriptor element (18 bytes).
static void test_descriptor_uuid128(void) {
    uint8_t el[18] = {0x40, 0x00};
    for (int i = 0; i < 16; i++) el[2 + i] = (uint8_t)(i + 1);
    struct gatt_descriptor d;
    CHECK(gatt_parse_descriptor(el, sizeof el, &d) == 0);
    CHECK(d.handle == 0x0040);
    CHECK(d.uuid_is_128 == true);
    CHECK(d.uuid128[0] == 1 && d.uuid128[15] == 16);
    // Unsupported size rejected.
    errno = 0;
    CHECK(gatt_parse_descriptor(el, 5, &d) == -1);
    CHECK(errno == EBADMSG);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_gatt\n");
    test_service_uuid16();
    test_service_uuid128();
    test_char_uuid16();
    test_char_uuid128();
    test_bad();
    test_descriptor_uuid16();
    test_descriptor_uuid128();
    return TEST_REPORT();
}
