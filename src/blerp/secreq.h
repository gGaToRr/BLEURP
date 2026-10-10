// ========================================
//  nom du fichier: secreq.h
//  description courte: Pure logic for the Security Request test (BLERP, NDSS
//  2026, Apple finding). Builds a minimal advertising payload (no keyboard
//  profile), estimates the stored level ARPK from the bond, gives the reaction
//  Listing 1 of the paper expects, and flags a non-conforming Central.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_SECREQ_H
#define BLEURP_SECREQ_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "repair.h"

// What the Central did after our Security Request.
enum secreq_outcome {
    SECREQ_NO_LINK,          // no connection from the Central before timeout
    SECREQ_NO_REACTION,      // connected, no pairing and no LTK request seen
    SECREQ_PAIRING_STARTED,  // Central sent a Pairing Request (re-pairing)
    SECREQ_SESSION_STARTED,  // Central asked for the LTK (session establishment)
};

// Raw facts gathered by the probe, before classification.
struct secreq_observation {
    bool linked;           // the Central connected to us
    bool pairing_request;  // an SMP Pairing Request arrived on CID 0x0006
    bool ltk_request;      // the controller raised LE Long Term Key Request
    bool enc_rejected;     // REJECT_ENC mode: we refused the encryption request
    bool pairing_response_sent; // DOWNGRADE_RSP mode: our weaker response went out
    bool central_proceeded;     // after it, the Central sent Pairing Confirm or Public Key
    bool pairing_failed;        // after it, the Central sent Pairing Failed
    uint8_t fail_reason;        // Pairing Failed reason when pairing_failed is set
};

// Build the advertising data: Flags + Complete Local Name, nothing else.
// Returns the number of bytes written, or 0 when the buffer is too small or
// an argument is NULL.
size_t secreq_build_adv(const char *name, uint8_t *out, size_t max);

// Estimate ARPK, the level stored in the bond: bonding bit always set,
// MITM bit when the bond is authenticated. SC is not stored in the BlueZ
// info file, so it cannot be estimated. NULL gives the unauthenticated level.
uint8_t secreq_arpk_guess(const struct smp_bond_info *bond);

// Reaction Listing 1 of the paper expects: ARSR > ARPK re-pairs, otherwise
// the Central starts session establishment.
enum secreq_outcome secreq_expected(uint8_t arsr, uint8_t arpk);

// Map the raw facts to an outcome. A Pairing Request takes precedence over
// an LTK request, since a re-pairing supersedes the session.
enum secreq_outcome secreq_classify(const struct secreq_observation *obs);

// True when a connected Central reacted differently from what Listing 1
// expects. Apple finding: ARSR equal to ARPK still starts pairing.
bool secreq_is_nonconform(uint8_t arsr, uint8_t arpk, enum secreq_outcome outcome);

// V1, unauthenticated re-pairing: with rfu bits set in ARSR, a re-pairing
// means the Central accepted a security request it cannot authenticate.
enum blerp_verdict secreq_verdict_v1(const struct secreq_observation *obs);

// V5, re-pairing from session establishment: after the encryption request
// was rejected, a Pairing Request means the Central re-paired. Without a
// Pairing Request (disconnect, or session restart) the device is not
// vulnerable here, which is the encryption-failure termination mitigation.
enum blerp_verdict secreq_verdict_v5(const struct secreq_observation *obs);

// V3, Central-side security level downgrade: the Central continues after a
// Pairing Response weaker than the Security Request is a vulnerability. A
// Pairing Failed is the consistency check working.
enum blerp_verdict secreq_verdict_v3(const struct secreq_observation *obs);

#endif // BLEURP_SECREQ_H
