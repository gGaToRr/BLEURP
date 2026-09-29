// ==============================================================================
//  nom du fichier: test_peripheral_native.c
//  description courte: Tests unitaires du module d'émulation de périphérique
//  Clavier BLE HID (HOGP) et de la base de données GATT / SMP associée.
// ==============================================================================

#include "test.h"
#include "peripheral_native.h"
#include <string.h>

static void test_adv_data_generation(void) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));

    int len = peripheral_build_adv_data("TestKey", buf, sizeof(buf));
    CHECK(len > 0);
    CHECK(len <= 31);

    // Flags: 0x02, 0x01, 0x06
    CHECK(buf[0] == 0x02);
    CHECK(buf[1] == 0x01);
    CHECK(buf[2] == 0x06);

    // 16-bit Service UUID: 0x03, 0x03, 0x12, 0x18
    CHECK(buf[3] == 0x03);
    CHECK(buf[4] == 0x03);
    CHECK(buf[5] == 0x12);
    CHECK(buf[6] == 0x18);

    // Appearance: 0x03, 0x19, 0xC1, 0x03 (Keyboard)
    CHECK(buf[7] == 0x03);
    CHECK(buf[8] == 0x19);
    CHECK(buf[9] == 0xC1);
    CHECK(buf[10] == 0x03);

    // Name: len+1, 0x09, "TestKey"
    CHECK(buf[11] == 8);
    CHECK(buf[12] == 0x09);
    CHECK(memcmp(&buf[13], "TestKey", 7) == 0);
}

static void test_scan_rsp_generation(void) {
    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));

    int len = peripheral_build_scan_rsp("BLEURP Keyboard", buf, sizeof(buf));
    CHECK(len > 0);
    CHECK(len <= 31);

    // Name
    CHECK(buf[0] == 16);
    CHECK(buf[1] == 0x09);
    CHECK(memcmp(&buf[2], "BLEURP Keyboard", 15) == 0);
}

static void test_gatt_mtu_exchange(void) {
    uint8_t req[3] = { 0x02, 0xF7, 0x00 }; // Client MTU = 247
    uint8_t rsp[64];
    bool notif = false;

    int rlen = gatt_server_handle_att_packet(0x0040, req, sizeof(req), rsp, sizeof(rsp), "BLEURP", &notif);
    CHECK(rlen == 3);
    CHECK(rsp[0] == 0x03); // Exchange MTU Response
    CHECK(rsp[1] == 0xF7); // MTU = 247
    CHECK(rsp[2] == 0x00);
}

static void test_gatt_primary_services_discovery(void) {
    // Read By Group Type Req: 0x10, Start=0x0001, End=0xFFFF, UUID=0x2800
    uint8_t req[7] = { 0x10, 0x01, 0x00, 0xFF, 0xFF, 0x00, 0x28 };
    uint8_t rsp[128];
    bool notif = false;

    int rlen = gatt_server_handle_att_packet(0x0040, req, sizeof(req), rsp, sizeof(rsp), "BLEURP", &notif);
    CHECK(rlen > 2);
    CHECK(rsp[0] == 0x11); // Read By Group Type Response
    CHECK(rsp[1] == 6);    // Length of each element

    // Vérifier la présence des 4 services : 0x1800, 0x180A, 0x180F, 0x1812
    CHECK(rlen == 2 + 4 * 6); // 26 octets
}

static void test_gatt_characteristics_discovery(void) {
    // Read By Type Req: 0x08, Start=0x0001, End=0x0005, Type=0x2803 (GAP Char Declarations)
    uint8_t req[7] = { 0x08, 0x01, 0x00, 0x05, 0x00, 0x03, 0x28 };
    uint8_t rsp[128];
    bool notif = false;

    int rlen = gatt_server_handle_att_packet(0x0040, req, sizeof(req), rsp, sizeof(rsp), "BLEURP", &notif);
    CHECK(rlen > 2);
    CHECK(rsp[0] == 0x09); // Read By Type Response
    CHECK(rsp[1] == 7);    // Length of each element (Handle 2 + Prop 1 + ValHandle 2 + UUID 2)
}

static void test_gatt_read_report_map(void) {
    // Read Req: 0x0A, Handle = 0x0014 (Report Map)
    uint8_t req[3] = { 0x0a, 0x14, 0x00 };
    uint8_t rsp[128];
    bool notif = false;

    int rlen = gatt_server_handle_att_packet(0x0040, req, sizeof(req), rsp, sizeof(rsp), "BLEURP", &notif);
    CHECK(rlen == 64); // Opcode 0x0B (1) + 63 bytes of HID report map
    CHECK(rsp[0] == 0x0b); // Read Response
    CHECK(rsp[1] == 0x05); // Usage Page (Generic Desktop)
    CHECK(rsp[2] == 0x01);
}

static void test_gatt_write_cccd(void) {
    // Write Req: 0x12, Handle = 0x0019 (Input Report CCCD), Value = 0x0001 (Enable Notifications)
    uint8_t req[5] = { 0x12, 0x19, 0x00, 0x01, 0x00 };
    uint8_t rsp[16];
    bool notif = false;

    int rlen = gatt_server_handle_att_packet(0x0040, req, sizeof(req), rsp, sizeof(rsp), "BLEURP", &notif);
    CHECK(rlen == 1);
    CHECK(rsp[0] == 0x13); // Write Response
    CHECK(notif == true);  // Notifications enabled!
}

static void test_smp_crypto_functions(void) {
    uint8_t tk[16] = {0};
    uint8_t r[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t preq[7] = {1, 4, 0, 5, 16, 15, 15};
    uint8_t pres[7] = {2, 2, 0, 1, 16, 1, 1};
    uint8_t ia[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t ra[6] = {0x82, 0x76, 0xc9, 0x56, 0x9e, 0x84};
    uint8_t c1[16];
    smp_c1_calc(tk, r, pres, preq, 1, 0, ia, ra, c1);

    // Vérifier la déterministe de c1
    uint8_t c1_again[16];
    smp_c1_calc(tk, r, pres, preq, 1, 0, ia, ra, c1_again);
    CHECK(memcmp(c1, c1_again, 16) == 0);

    // Official Bluetooth Core Specification Spec test vector for s1:
    uint8_t k_zero[16] = {0};
    uint8_t mrand[16] = { 0x00, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0,0,0,0,0,0,0,0 };
    uint8_t srand[16] = { 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0,0,0,0,0,0,0,0 };
    const uint8_t exp_stk[16] = {
        0x62, 0xa0, 0x6d, 0x79, 0xae, 0x16, 0x42, 0x5b,
        0x9b, 0xf4, 0xb0, 0xe8, 0xf0, 0xe1, 0x1f, 0x9a
    };
    uint8_t calc_stk[16];
    smp_s1_calc(k_zero, mrand, srand, calc_stk);
    CHECK(memcmp(calc_stk, exp_stk, 16) == 0);
}

static void test_smp_pairing_negotiation(void) {
    // Smartphone envoie Pairing Request:
    // Opcode: 0x01, IOCap: 0x04 (KeyboardDisplay), OOB: 0x00, AuthReq: 0x05 (Bonding+MITM), KeySize: 16, InitKD: 0x0F, RespKD: 0x0F
    uint8_t req[7] = { 0x01, 0x04, 0x00, 0x05, 0x10, 0x0f, 0x0f };
    uint8_t rsp[64];

    struct peripheral_config cfg = {
        .dev_id = 0,
        .device_name = "BLEURP Keyboard",
        .io_capability = 0x02, // KeyboardOnly
        .auth_req = 0x01,      // Bonding
        .max_key_size = 16,
        .trigger_sec_req = true
    };
    struct peripheral_stats stats;
    memset(&stats, 0, sizeof(stats));

    int rlen = smp_server_handle_packet(0x0040, req, sizeof(req), rsp, sizeof(rsp), &cfg, &stats);
    CHECK(rlen == 7);
    CHECK(rsp[0] == 0x02); // Pairing Response
    CHECK(rsp[1] == 0x02); // IO Capability KeyboardOnly
    CHECK(rsp[2] == 0x00); // No OOB
    CHECK(rsp[3] == 0x01); // AuthReq Bonding
    CHECK(rsp[4] == 16);   // Max key size 16
    CHECK(stats.smp_requests_count == 1);
    CHECK(stats.smp_pairings_success == 1);

    uint8_t pres[7];
    memcpy(pres, rsp, 7);

    // Smartphone prépare son random r1 et calcule son confirm c1
    uint8_t r1[16];
    memset(r1, 0x42, sizeof(r1));
    uint8_t tk[16] = {0};
    uint8_t ia[6] = {0}, ra[6] = {0};
    uint8_t expected_c1[16];
    smp_c1_calc(tk, r1, pres, req, 0, 0, ia, ra, expected_c1);

    // Smartphone envoie Pairing Confirm (0x03 + 16 octets c1)
    uint8_t confirm_req[17];
    confirm_req[0] = 0x03;
    memcpy(&confirm_req[1], expected_c1, 16);
    rlen = smp_server_handle_packet(0x0040, confirm_req, sizeof(confirm_req), rsp, sizeof(rsp), &cfg, &stats);
    CHECK(rlen == 17);
    CHECK(rsp[0] == 0x03); // Pairing Confirm response (c2)

    // Smartphone envoie Pairing Random (0x04 + 16 octets r1)
    uint8_t random_req[17];
    random_req[0] = 0x04;
    memcpy(&random_req[1], r1, 16);
    rlen = smp_server_handle_packet(0x0040, random_req, sizeof(random_req), rsp, sizeof(rsp), &cfg, &stats);
    CHECK(rlen == 17);
    CHECK(rsp[0] == 0x04); // Pairing Random response (r2)
}

int main(void) {
    printf("test_peripheral_native\n");
    test_adv_data_generation();
    test_scan_rsp_generation();
    test_gatt_mtu_exchange();
    test_gatt_primary_services_discovery();
    test_gatt_characteristics_discovery();
    test_gatt_read_report_map();
    test_gatt_write_cccd();
    test_smp_crypto_functions();
    test_smp_pairing_negotiation();
    return TEST_REPORT();
}
