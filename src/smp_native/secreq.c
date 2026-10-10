// ========================================
//  nom du fichier: secreq.c
//  description courte: Pure logic for the Security Request test (BLERP, NDSS
//  2026, Apple finding): advertising payload, ARPK estimate, expected reaction
//  per Listing 1, outcome classification and the non-conformity rule. No I/O.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#include "secreq.h"

#include <string.h>

// Legacy advertising payload limit (bytes).
#define ADV_MAX 31

// Build Flags + Complete Local Name. See secreq.h for the contract.
size_t secreq_build_adv(const char *name, uint8_t *out, size_t max) {
    if (!name || !out) return 0;

    size_t name_len = strlen(name);
    size_t needed = 3 + 2 + name_len; // flags AD + name AD header + name
    if (needed > max || needed > ADV_MAX) return 0;

    size_t off = 0;
    out[off++] = 0x02; // length
    out[off++] = 0x01; // AD type: Flags
    out[off++] = 0x06; // LE General Discoverable, BR/EDR not supported

    out[off++] = (uint8_t)(name_len + 1); // length
    out[off++] = 0x09;                    // AD type: Complete Local Name
    memcpy(&out[off], name, name_len);
    off += name_len;

    return off;
}

// Estimate ARPK from the bond. See secreq.h for the contract.
uint8_t secreq_arpk_guess(const struct smp_bond_info *bond) {
    const uint8_t bonding = 0x01;
    const uint8_t mitm = 0x04;
    if (!bond) return bonding;
    return (uint8_t)(bonding | (bond->authenticated ? mitm : 0x00));
}

// Listing 1 expectation. See secreq.h for the contract.
enum secreq_outcome secreq_expected(uint8_t arsr, uint8_t arpk) {
    return (arsr > arpk) ? SECREQ_PAIRING_STARTED : SECREQ_SESSION_STARTED;
}

// Map raw facts to an outcome. See secreq.h for the contract.
enum secreq_outcome secreq_classify(const struct secreq_observation *obs) {
    if (!obs || !obs->linked) return SECREQ_NO_LINK;
    if (obs->pairing_request) return SECREQ_PAIRING_STARTED;
    if (obs->ltk_request) return SECREQ_SESSION_STARTED;
    return SECREQ_NO_REACTION;
}

// Non-conformity rule. See secreq.h for the contract.
bool secreq_is_nonconform(uint8_t arsr, uint8_t arpk, enum secreq_outcome outcome) {
    // Only a reaction that is one of the two expected paths can be non-conform.
    if (outcome != SECREQ_PAIRING_STARTED && outcome != SECREQ_SESSION_STARTED) {
        return false;
    }
    return outcome != secreq_expected(arsr, arpk);
}

// Verdicts. See secreq.h for the contract.
enum blerp_verdict secreq_verdict_v1(const struct secreq_observation *obs) {
    if (!obs || !obs->linked) return BLERP_VERDICT_INCONCLUSIVE;
    return obs->pairing_request ? BLERP_VERDICT_YES : BLERP_VERDICT_NO;
}

enum blerp_verdict secreq_verdict_v5(const struct secreq_observation *obs) {
    if (!obs || !obs->enc_rejected) return BLERP_VERDICT_INCONCLUSIVE;
    return obs->pairing_request ? BLERP_VERDICT_YES : BLERP_VERDICT_NO;
}

enum blerp_verdict secreq_verdict_v3(const struct secreq_observation *obs) {
    if (!obs || !obs->pairing_response_sent) return BLERP_VERDICT_INCONCLUSIVE;
    if (obs->central_proceeded) return BLERP_VERDICT_YES;
    if (obs->pairing_failed) return BLERP_VERDICT_NO;
    return BLERP_VERDICT_INCONCLUSIVE;
}
