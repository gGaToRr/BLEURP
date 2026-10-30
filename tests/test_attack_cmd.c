// ========================================
//  nom du fichier: test_attack_cmd.c
//  description courte: Unit tests for the unified attack chain subcommand.
//  Checks argument parsing, target profiling calculation, JSON serialization,
//  and error boundaries.
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "cmd/attack_cmd.h"

#include <string.h>

static void test_json_formatting(void) {
    struct attack_result res;
    memset(&res, 0, sizeof(res));

    snprintf(res.target_str, sizeof(res.target_str), "11:22:33:44:55:66");
    snprintf(res.target_name, sizeof(res.target_name), "TestBLEDevice");
    res.addr_type = 2; // random
    res.rssi = -55;
    res.priv = ADDR_PRIV_RPA;
    res.trackable = false;
    res.exposure_score = 45;

    res.gatt_connected = true;
    res.gatt_open_reads = 3;
    res.gatt_open_writes = 1;
    res.gatt_protected = 5;

    res.smp_probed = true;
    res.smp_responded = true;
    res.smp_just_works = true;
    res.smp_entropy_downgrade = true;
    res.smp_auth_req = 0x01;
    res.smp_max_key_size = 7;

    res.exploit_attempted = true;
    res.exploit_success = true;
    res.stk_len = 7;
    for (int i = 0; i < 7; i++) res.stk[i] = (uint8_t)(i + 1);

    res.payload_attempted = true;
    res.payload_success = true;

    char buf[2048];
    int rc = attack_format_json(&res, buf, sizeof(buf));
    CHECK(rc == 0);

    // Verify key fields are serialized
    CHECK(strstr(buf, "\"target\": \"11:22:33:44:55:66\"") != NULL);
    CHECK(strstr(buf, "\"name\": \"TestBLEDevice\"") != NULL);
    CHECK(strstr(buf, "\"exposure_score\": 45") != NULL);
    CHECK(strstr(buf, "\"open_reads\": 3") != NULL);
    CHECK(strstr(buf, "\"open_writes\": 1") != NULL);
    CHECK(strstr(buf, "\"just_works_accepted\": true") != NULL);
    CHECK(strstr(buf, "\"entropy_downgrade\": true") != NULL);
    CHECK(strstr(buf, "\"exploit_success\": true") != NULL);
    CHECK(strstr(buf, "\"stk\": \"01020304050607\"") != NULL);
    CHECK(strstr(buf, "\"success\": true") != NULL);

    // Null safety
    CHECK(attack_format_json(NULL, buf, sizeof(buf)) == -1);
    CHECK(attack_format_json(&res, NULL, 100) == -1);
    CHECK(attack_format_json(&res, buf, 0) == -1);
}

static void test_cli_parsing(void) {
    // -h must return 0
    char *h_argv[] = {"attack", "-h"};
    CHECK(cmd_attack(2, h_argv) == 0);

    // Missing target without --scan returns 2
    char *empty_argv[] = {"attack"};
    CHECK(cmd_attack(1, empty_argv) == 2);

    // Invalid MAC returns 2
    char *bad_mac[] = {"attack", "ZZ:INVALID:MAC"};
    CHECK(cmd_attack(2, bad_mac) == 2);

    // Invalid -i index returns 2
    char *bad_i[] = {"attack", "-i", "abc", "AA:BB:CC:DD:EE:FF"};
    CHECK(cmd_attack(4, bad_i) == 2);

    // Invalid -k keysize returns 2
    char *bad_k[] = {"attack", "-k", "20", "AA:BB:CC:DD:EE:FF"};
    CHECK(cmd_attack(4, bad_k) == 2);

    // Invalid -t type returns 2
    char *bad_t[] = {"attack", "-t", "foo", "AA:BB:CC:DD:EE:FF"};
    CHECK(cmd_attack(4, bad_t) == 2);
}

static void test_target_profiling(void) {
    struct attack_options opts = {
        .dev_id = 0,
        .audit_only = true,
    };
    uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    struct attack_result res;

    // Null check
    CHECK(attack_run_target(NULL, addr, 1, "test", -70, &res) == -1);
    CHECK(attack_run_target(&opts, NULL, 1, "test", -70, &res) == -1);
    CHECK(attack_run_target(&opts, addr, 1, "test", -70, NULL) == -1);

    // Execution with audit_only doesn't crash even if device is offline
    int rc = attack_run_target(&opts, addr, 1, "UnitDevice", -50, &res);
    CHECK(rc == 0);
    CHECK(strcmp(res.target_str, "66:55:44:33:22:11") == 0);
    CHECK(strcmp(res.target_name, "UnitDevice") == 0);
    CHECK(res.exposure_score > 0);
}

int main(void) {
    printf("test_attack_cmd\n");
    test_json_formatting();
    test_cli_parsing();
    test_target_profiling();
    return TEST_REPORT();
}
