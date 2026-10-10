// ========================================
//  nom du fichier: smp_sc_engine.h
//  description courte: LE Secure Connections Phase 2 state machine (Just
//  Works / Numeric Comparison association only -- the two models a headless
//  tool can complete without a display or keyboard), for both roles. Mirrors
//  smp_legacy.h's shape so the attack engine can swap one for the other
//  depending on whether the peer offered SC. Built on smp_sc.c's crypto
//  toolbox; pure protocol sequencing here, no I/O/HCI.
//
//  IMPORTANT -- read before relying on this against real hardware: the
//  message sequence and field ordering below (who sends Pairing Confirm
//  first, the exact argument order inside f4's Confirm value and f6's
//  DHKey Check values Ea/Eb) are implemented from the author's recollection
//  of Core Spec Vol 3, Part H, Section 2.3.5.6, not re-verified against a
//  fetched copy of the spec this session. tests/test_smp_sc_engine.c proves
//  the two roles are internally self-consistent (an initiator and a
//  responder instance running this exact code against each other agree on
//  the same LTK) -- a real and useful check, but it cannot catch a
//  consistent-with-itself deviation from the actual standard. Treat this as
//  a solid first draft, not yet interop-validated against a real SC peer.
//  See smp_sc.h for the matching caveat on f5's SALT/keyID constants.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_SMP_SC_ENGINE_H
#define BLEURP_SMP_SC_ENGINE_H

#include <stdbool.h>
#include <stdint.h>

#include "smp_sc.h"

#define SMP_SC_OP_PAIRING_REQ     0x01
#define SMP_SC_OP_PAIRING_RSP     0x02
#define SMP_SC_OP_PAIRING_CONFIRM 0x03
#define SMP_SC_OP_PAIRING_RANDOM  0x04
#define SMP_SC_OP_PAIRING_FAILED  0x05
#define SMP_SC_OP_PUBLIC_KEY      0x0c
#define SMP_SC_OP_DHKEY_CHECK     0x0d

// One side of an SC Just Works / Numeric Comparison pairing. The caller
// feeds it the PDUs it received and sends the ones it builds, in order:
//   initiator: make_req, on_rsp, make_pubkey, on_pubkey, on_confirm,
//              make_random, on_random, make_dhkey_check, on_dhkey_check
//   responder: on_req, make_rsp, on_pubkey, make_pubkey, make_confirm,
//              on_random, make_random, on_dhkey_check, make_dhkey_check
// (the responder commits to its nonce with Pairing Confirm before either
// side reveals a Pairing Random -- Just Works/NC has no initiator confirm,
// unlike Legacy pairing where both sides confirm).
struct smp_sc {
    bool initiator;
    bool failed;
    bool done;              // LTK derived and the peer's DHKey Check verified
    uint8_t iat, rat;        // address types (0 public, 1 random)
    uint8_t ia[6], ra[6];    // initiator and responder addresses (wire order)
    uint8_t preq[7], pres[7];
    struct smp_sc_keypair *keypair; // our ECDH key pair, owned (freed by smp_sc_free)
    uint8_t my_pubkey[64];
    uint8_t peer_pubkey[64];
    uint8_t my_nonce[16];    // Na (initiator) or Nb (responder)
    uint8_t peer_nonce[16];
    uint8_t peer_confirm[16]; // initiator only: Cb, until verified in on_random
    uint8_t dhkey[32];
    uint8_t mackey[16];
    uint8_t ltk[16];
    uint8_t reason;          // Pairing Failed reason to send when failed
    uint8_t custom_authreq;  // If non-zero, override default AuthReq (e.g. 0x01 | SC)
    uint8_t custom_maxkey;   // If non-zero, override default max key size (e.g. 0x07)
};

// Set the role, the addresses, and our nonce; generate a fresh ECDH key
// pair. Returns 0 on success, -1 if key generation failed (OpenSSL error --
// in which case the struct is left zeroed and must not be used further).
int smp_sc_init(struct smp_sc *p, bool initiator,
                uint8_t iat, const uint8_t ia[6],
                uint8_t rat, const uint8_t ra[6],
                const uint8_t my_nonce[16]);

// Release the ECDH key pair smp_sc_init() allocated. Safe to call once;
// does not zero the rest of the struct (the derived LTK/MacKey/etc. remain
// readable after this call).
void smp_sc_free(struct smp_sc *p);

// Set custom AuthReq and max key size (e.g. for downgrade attacks). The SC
// bit (0x08) is forced on in AuthReq regardless, since this engine cannot
// run without it.
void smp_sc_set_params(struct smp_sc *p, uint8_t authreq, uint8_t max_keysize);

// Initiator: build the Pairing Request (7 bytes). Returns 7, or -1.
int smp_sc_make_req(struct smp_sc *p, uint8_t out[7]);
// Initiator: read the Pairing Response (7 bytes).
int smp_sc_on_rsp(struct smp_sc *p, const uint8_t pdu[7]);
// Responder: read the Pairing Request (7 bytes).
int smp_sc_on_req(struct smp_sc *p, const uint8_t pdu[7]);
// Responder: build the Pairing Response (7 bytes). Returns 7, or -1.
int smp_sc_make_rsp(struct smp_sc *p, uint8_t out[7]);

// Build our Pairing Public Key PDU (65 bytes: opcode + 64-byte X||Y).
// Returns 65, or -1.
int smp_sc_make_pubkey(struct smp_sc *p, uint8_t out[65]);
// Read the peer's Pairing Public Key PDU (65 bytes) and compute the DHKey.
// Returns 0, or -1 if the point is invalid (see smp_sc_dhkey).
int smp_sc_on_pubkey(struct smp_sc *p, const uint8_t pdu[65]);

// Responder only: build the Pairing Confirm (17 bytes: opcode + Cb).
// Returns 17, or -1.
int smp_sc_make_confirm(struct smp_sc *p, uint8_t out[17]);
// Initiator only: read the responder's Pairing Confirm (17 bytes). Stores
// Cb for later verification in smp_sc_on_random(); does not fail by itself.
int smp_sc_on_confirm(struct smp_sc *p, const uint8_t pdu[17]);

// Build our Pairing Random (17 bytes: opcode + our nonce). Returns 17, or -1.
int smp_sc_make_random(struct smp_sc *p, uint8_t out[17]);
// Read the peer's Pairing Random (17 bytes). Initiator: verifies it against
// the stored Cb (mismatch sets `failed`, reason 0x04 Confirm Value Failed).
// Responder: just stores it (nothing to verify yet, it committed first).
int smp_sc_on_random(struct smp_sc *p, const uint8_t pdu[17]);

// Derive MacKey/LTK via f5 (both roles call this once both nonces are
// known, before building/checking the DHKey Check). Returns 0, or -1.
int smp_sc_derive_keys(struct smp_sc *p);

// Build our DHKey Check PDU (17 bytes: opcode + Ea or Eb). Returns 17, or -1.
int smp_sc_make_dhkey_check(struct smp_sc *p, uint8_t out[17]);
// Read and verify the peer's DHKey Check PDU (17 bytes). On success (and
// only then) sets `done` and `ltk` is the final session key. A mismatch
// sets `failed`, reason 0x04 (Confirm Value Failed, reused here per the
// Core Spec's "DHKey Check failed" guidance).
int smp_sc_on_dhkey_check(struct smp_sc *p, const uint8_t pdu[17]);

#endif // BLEURP_SMP_SC_ENGINE_H
