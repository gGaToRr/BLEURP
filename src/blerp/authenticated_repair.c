// ========================================
//  nom du fichier: authenticated_repair.c
//  description courte: Implementation of the VII-B authenticated re-pairing
//  reference protocol. See authenticated_repair.h for the contract and
//  design notes.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "authenticated_repair.h"

#include <string.h>

#include <openssl/evp.h>

// h_{i+1} = SHA256(h_i || data). Returns 0 on success, -1 on an OpenSSL
// failure.
static int fold_transcript(uint8_t h[32], const uint8_t *data, size_t len) {
    uint8_t buf[32 + 256];
    if (len > sizeof buf - 32) return -1; // every message this module folds in is far smaller
    memcpy(buf, h, 32);
    memcpy(buf + 32, data, len);

    unsigned int outlen = 0;
    int rc = -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, buf, 32 + len) == 1 &&
        EVP_DigestFinal_ex(ctx, h, &outlen) == 1 && outlen == 32) {
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    return rc;
}

// Set up the role/bond PK and generate a key pair. See the header.
int auth_repair_init(struct auth_repair *p, bool initiator, const uint8_t old_pk[16]) {
    if (!p || !old_pk) return -1;
    memset(p, 0, sizeof *p);
    p->initiator = initiator;
    memcpy(p->old_pk, old_pk, 16);

    // Seed the transcript from a fixed public constant, NOT old_pk: the
    // two amendments stay independent mechanisms this way -- transcript
    // hashing alone proves integrity (same inputs -> same h, regardless of
    // who holds the bond), key chaining alone proves authentication (the
    // final CMAC is keyed by old_pk, see auth_repair_derive_pk). Mixing
    // old_pk into the seed too would make every divergence ambiguous
    // between "tampered message" and "wrong bond".
    memset(p->transcript, 0, 32);
    if (fold_transcript(p->transcript, (const uint8_t *)"auth-repair-v1", 14) < 0) return -1;

    p->keypair = smp_sc_keygen();
    if (!p->keypair) return -1;
    if (smp_sc_public_key(p->keypair, p->my_pubkey) < 0) {
        smp_sc_keypair_free(p->keypair);
        p->keypair = NULL;
        return -1;
    }
    return 0;
}

void auth_repair_free(struct auth_repair *p) {
    if (!p) return;
    smp_sc_keypair_free(p->keypair);
    p->keypair = NULL;
}

int auth_repair_make_req(struct auth_repair *p, uint8_t ar, uint8_t ent, uint8_t out[2]) {
    if (!p || !p->initiator) return -1;
    p->ar = ar;
    p->ent = ent;
    out[0] = ar;
    out[1] = ent;
    if (fold_transcript(p->transcript, out, 2) < 0) return -1;
    return 2;
}

int auth_repair_on_req(struct auth_repair *p, const uint8_t pdu[2]) {
    if (!p || p->initiator) return -1;
    p->peer_ar = pdu[0];
    p->peer_ent = pdu[1];
    return fold_transcript(p->transcript, pdu, 2) < 0 ? -1 : 0;
}

int auth_repair_make_rsp(struct auth_repair *p, uint8_t ar, uint8_t ent, uint8_t out[2]) {
    if (!p || p->initiator) return -1;
    p->ar = ar;
    p->ent = ent;
    out[0] = ar;
    out[1] = ent;
    if (fold_transcript(p->transcript, out, 2) < 0) return -1;
    return 2;
}

int auth_repair_on_rsp(struct auth_repair *p, const uint8_t pdu[2]) {
    if (!p || !p->initiator) return -1;
    p->peer_ar = pdu[0];
    p->peer_ent = pdu[1];
    return fold_transcript(p->transcript, pdu, 2) < 0 ? -1 : 0;
}

// Pure: just emits our own key bytes. Folding both keys into the
// transcript happens in auth_repair_on_pubkey() instead, once both are
// known -- that keeps the fold order (initiator's key, then responder's)
// fixed and identical on both sides regardless of which one calls
// make_pubkey()/on_pubkey() first locally.
int auth_repair_make_pubkey(struct auth_repair *p, uint8_t out[64]) {
    if (!p) return -1;
    memcpy(out, p->my_pubkey, 64);
    return 64;
}

int auth_repair_on_pubkey(struct auth_repair *p, const uint8_t pdu[64]) {
    if (!p) return -1;
    memcpy(p->peer_pubkey, pdu, 64);

    const uint8_t *initiator_key = p->initiator ? p->my_pubkey : p->peer_pubkey;
    const uint8_t *responder_key = p->initiator ? p->peer_pubkey : p->my_pubkey;
    if (fold_transcript(p->transcript, initiator_key, 64) < 0) return -1;
    if (fold_transcript(p->transcript, responder_key, 64) < 0) return -1;

    return smp_sc_dhkey(p->keypair, p->peer_pubkey, p->ss);
}

int auth_repair_derive_pk(struct auth_repair *p) {
    if (!p) return -1;
    uint8_t msg[32 + 32];
    memcpy(msg, p->ss, 32);
    memcpy(msg + 32, p->transcript, 32);

    uint8_t tag[16];
    if (smp_sc_cmac(p->old_pk, msg, sizeof msg, tag) < 0) return -1;
    memcpy(p->new_pk, tag, 16);
    p->done = true;
    return 0;
}
