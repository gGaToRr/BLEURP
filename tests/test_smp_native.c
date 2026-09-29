// ========================================
//  nom du fichier: test_smp_native.c
//  description courte: Tests unitaires pour le module smp_native
// ========================================

#include "test.h"
#include "smp_native.h"

#include <string.h>

static void test_smp_native_null_args(void) {
    struct smp_probe_result res;
    uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};

    CHECK(smp_native_probe_device(0, NULL, 1, 100, &res) == -1);
    CHECK(smp_native_probe_device(0, addr, 1, 100, NULL) == -1);
}

static void test_smp_native_print_format(void) {
    struct smp_probe_result res;
    memset(&res, 0, sizeof(res));
    res.success = true;
    res.io_capability = 0x03;
    res.oob_data_flag = 0x00;
    res.auth_req = 0x01; // Bonding seul
    res.max_key_size = 7;
    res.init_key_dist = 0x01;
    res.resp_key_dist = 0x01;

    // Ne doit pas crasher
    smp_native_print_result(&res, "AA:BB:CC:DD:EE:FF");

    res.pairing_failed = true;
    res.fail_reason = 0x05; // Pairing Not Supported
    smp_native_print_result(&res, "AA:BB:CC:DD:EE:FF");

    res.success = false;
    smp_native_print_result(&res, "AA:BB:CC:DD:EE:FF");
    CHECK(1);
}

int main(void) {
    printf("test_smp_native\n");
    test_smp_native_null_args();
    test_smp_native_print_format();
    return TEST_REPORT();
}
