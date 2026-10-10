// ========================================
//  nom du fichier: authenticated_repair.h
//  description courte: Reference implementation of the paper's VII-B
//  "authenticated and integrity-protected re-pairing" defense (NDSS 2026,
//  Section VII-B). Unlike VII-A (hardened_audit.h, a backward-compatible
//  check against the existing standard), this is a NEW protocol the paper
//  proposes as a standard amendment: no real unmodified BLE stack speaks
//  it. It exists here as a working demonstration that the two properties
//  the paper describes -- key chaining and transcript hashing -- defeat
//  BLERP by construction, not as something BLEURP can run against a real
//  phone.
//
//  Design (the paper's figure specifies the two amendments and their
//  intent, not exact byte layouts/algorithm choices -- those are this
//  implementation's own, reasonable choices, not transcribed spec
//  constants, so the "verify against the spec text" caveat that applies to
//  smp_sc.h/smp_sc_engine.h does NOT apply here in the same way):
//    - Transcript hashing: a running SHA-256 h, updated as
//      h_{i+1} = SHA256(h_i || message_i) over every Phase 1/2 message, in
//      the fixed order both sides see them (Pairing Request, Pairing
//      Response, Initiator's Public Key, Responder's Public Key).
//    - Key chaining: the new PK is derived with AES-CMAC KEYED BY THE
//      CURRENT PK -- CKDF(PK_old) = AES-CMAC_{PK_old}(ss || h_final) --
//      so computing PK_new requires already knowing PK_old. An attacker
//      who does not have the bond's actual stored PK (every BLEURP
//      downgrade attack: it forges a NEW pairing, it never recovers the
//      victims' existing one) cannot produce the same PK_new as the two
//      legitimate parties, even with full control of the channel and the
//      correct ECDH shared secret ss (see
//      tests/test_authenticated_repair.c's test_attacker_without_old_pk_diverges).
//      Tampering with any message changes h_final and therefore PK_new
//      too (test_tampered_transcript_diverges), which is the integrity
//      protection: the two legitimate parties' PK_new no longer matches if
//      Charlie modified anything in flight, so the re-pairing fails closed
//      instead of silently succeeding at a level Charlie chose.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_AUTHENTICATED_REPAIR_H
#define BLEURP_AUTHENTICATED_REPAIR_H

#include <stdbool.h>
#include <stdint.h>

#include "smp_sc.h" // reuses the Phase 6 ECDH P-256 primitives

#define AUTH_REPAIR_OP_PAIR_REQ 0x01
#define AUTH_REPAIR_OP_PAIR_RSP 0x02
#define AUTH_REPAIR_OP_PUB_KEY  0x0c

// One side of an authenticated re-pairing run. Message order:
//   initiator (Alice): make_req, on_rsp, make_pubkey, on_pubkey, derive_pk
//   responder (Bob):    on_req, make_rsp, on_pubkey, make_pubkey, derive_pk
// (both sides send their own Public Key and receive the peer's; who sends
// first does not affect the transcript, since both incorporate Pub_A then
// Pub_B into h in that fixed order regardless of local send/receive timing).
struct auth_repair {
    bool initiator;
    bool failed;
    bool done;
    uint8_t old_pk[16];       // the bond's current PK (all-zero: first-ever pairing)
    uint8_t transcript[32];   // running SHA-256 h
    struct smp_sc_keypair *keypair;
    uint8_t my_pubkey[64];
    uint8_t peer_pubkey[64];
    uint8_t ss[32];           // ECDH shared secret, valid once both pubkeys are known
    uint8_t new_pk[16];       // PK_new, valid once `done`
    uint8_t ar;                // our own AuthReq/security-level byte (AR_A or AR_B)
    uint8_t ent;                // our own Ent byte (entropy/max key size)
    uint8_t peer_ar, peer_ent;
};

// Set the role and the bond's current PK (16 bytes, all-zero for a
// first-ever pairing), seed the transcript from a fixed constant
// (deliberately NOT old_pk -- see auth_repair.c for why the two mechanisms
// stay independent), and generate a fresh ECDH key pair. Returns 0 on
// success, -1 if key generation failed.
int auth_repair_init(struct auth_repair *p, bool initiator, const uint8_t old_pk[16]);

// Release the ECDH key pair. Safe to call once; does not clear the rest of
// the struct.
void auth_repair_free(struct auth_repair *p);

// Initiator: build the Pairing Request (2 bytes: AR_A, Ent_A) and fold it
// into the transcript. Returns 2, or -1.
int auth_repair_make_req(struct auth_repair *p, uint8_t ar, uint8_t ent, uint8_t out[2]);
// Responder: read the Pairing Request and fold it into the transcript.
int auth_repair_on_req(struct auth_repair *p, const uint8_t pdu[2]);
// Responder: build the Pairing Response (2 bytes: AR_B, Ent_B) and fold it
// into the transcript. Returns 2, or -1.
int auth_repair_make_rsp(struct auth_repair *p, uint8_t ar, uint8_t ent, uint8_t out[2]);
// Initiator: read the Pairing Response and fold it into the transcript.
int auth_repair_on_rsp(struct auth_repair *p, const uint8_t pdu[2]);

// Build our Public Key PDU (64 bytes). Does not touch the transcript by
// itself -- see auth_repair_on_pubkey(), which folds both keys in once
// both are known, so the fold order (initiator's key, then responder's)
// stays fixed regardless of which side calls make_pubkey()/on_pubkey()
// first locally. Returns 64, or -1.
int auth_repair_make_pubkey(struct auth_repair *p, uint8_t out[64]);
// Read the peer's Public Key PDU (64 bytes), fold BOTH public keys into
// the transcript in the fixed initiator-then-responder order, and compute
// the ECDH shared secret. Returns 0, or -1 if the point is invalid.
int auth_repair_on_pubkey(struct auth_repair *p, const uint8_t pdu[64]);

// Derive PK_new = AES-CMAC_{old_pk}(ss || transcript) once both messages
// and both public keys have been folded in. Sets `done` and fills
// `new_pk` on success. Returns 0, or -1 on failure (e.g. called before the
// shared secret is available).
int auth_repair_derive_pk(struct auth_repair *p);

#endif // BLEURP_AUTHENTICATED_REPAIR_H
