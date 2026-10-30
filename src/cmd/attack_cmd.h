// ========================================
//  nom du fichier: attack_cmd.h
//  description courte: Unified automated BLE attack chain.
//  Coordinates target profiling, GATT unauthenticated surface audit,
//  SMP security downgrade probing, BLERP re-pairing exploit, and
//  post-exploitation payload execution.
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_ATTACK_CMD_H
#define BLEURP_ATTACK_CMD_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "addr_priv.h"
#include "blerp_attack.h"

struct attack_result {
    char target_str[18];
    char target_name[64];
    uint8_t addr_type;
    int8_t rssi;
    addr_privacy_t priv;
    bool trackable;
    int exposure_score;

    // GATT attack surface
    bool gatt_connected;
    int gatt_open_reads;
    int gatt_open_writes;
    int gatt_protected;

    // SMP policy & downgrade
    bool smp_probed;
    bool smp_responded;
    bool smp_just_works;
    bool smp_entropy_downgrade;
    uint8_t smp_auth_req;
    uint8_t smp_max_key_size;

    // BLERP Re-Pairing exploit
    bool exploit_attempted;
    bool exploit_success;
    uint8_t stk[16];
    int stk_len;
    enum blerp_verdict verdicts[BLERP_VULN_COUNT];

    // Payload injection
    bool payload_attempted;
    bool payload_success;
};

struct attack_options {
    int dev_id;
    int dev_id_sec;
    char target_str[18];
    uint8_t target_addr[6];
    uint8_t addr_type;
    bool has_target;
    int scan_seconds;
    enum blerp_attack_type attack_type;
    uint8_t min_key_size;
    bool force_sc;
    bool reject_enc;
    const char *payload_file;
    bool json_output;
    bool audit_only;
};

// Execute the complete attack chain on a single target.
int attack_run_target(const struct attack_options *opts,
                      const uint8_t addr[6], uint8_t atype,
                      const char *name, int8_t rssi,
                      struct attack_result *res);

// Print attack result summary to stdout.
void attack_print_result(const struct attack_result *res);

// Format result as a JSON string.
int attack_format_json(const struct attack_result *res, char *buf, size_t buf_size);

// CLI subcommand entry point: bleurp attack [ARGS]
int cmd_attack(int argc, char **argv);

#endif // BLEURP_ATTACK_CMD_H
