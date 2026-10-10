// ========================================
//  nom du fichier: smp_sc.h
//  description courte: LE Secure Connections crypto toolbox (Bluetooth Core
//  Spec Vol 3, Part H, Section 2.2.7-2.2.8): ECDH P-256 key agreement and
//  the f4/f5/f6/g2 derivation functions. Built so the attack engine can
//  complete a real SC pairing (needed against a peer locked to Secure
//  Connections Only, which refuses to fall back to Legacy pairing) instead
//  of only ever downgrading to Legacy.
//
//  IMPORTANT: f5's SALT and keyID constants (see smp_sc.c) are transcribed
//  from memory, not re-verified against a fetched copy of the Core
//  Specification during this session. f4/f6/g2 have no such baked-in
//  constants (pure functions of their inputs) and the AES-CMAC primitive
//  underneath everything here is checked against the official RFC 4493
//  test vectors (see tests/test_smp_sc.c) -- but f5's two constants should
//  be cross-checked against Core Spec Vol 3, Part H, Table 2.8 before this
//  module's LTK is relied on against real hardware. Treat f5 (and the LTK
//  it produces) as unverified until that check happens; f4/f6/g2/ECDH are
//  on firmer ground.
//
//  Byte order: every multi-byte value in this API (keys, nonces,
//  addresses, outputs) is in SMP wire order (little-endian), matching
//  smp.c/smp_legacy.c's convention -- not the big-endian order the Core
//  Spec's crypto-toolbox formulas are written in. The conversion happens
//  internally, the same way smp_legacy_e() already does for Legacy c1/s1.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_SMP_SC_H
#define BLEURP_SMP_SC_H

#include <stddef.h>
#include <stdint.h>

// Opaque local ECDH P-256 key pair.
struct smp_sc_keypair;

// Generate a fresh P-256 key pair. Returns a heap-allocated handle to free
// with smp_sc_keypair_free(), or NULL on failure (OpenSSL or allocation
// error).
struct smp_sc_keypair *smp_sc_keygen(void);

// Free a key pair returned by smp_sc_keygen(). No-op if kp is NULL.
void smp_sc_keypair_free(struct smp_sc_keypair *kp);

// Extract the public key as the 64-byte SMP Pairing Public Key PDU payload
// (X || Y, 32 bytes each, SMP wire order). Returns 0 on success, -1 on
// failure.
int smp_sc_public_key(const struct smp_sc_keypair *kp, uint8_t out[64]);

// Compute the DHKey shared with a peer's public key (received over SMP in
// the same 64-byte wire format smp_sc_public_key() produces: X || Y, wire
// order). Returns 0 and fills out[32] (wire order) on success, -1 if the
// peer's point is not a valid P-256 point (reject silently accepting an
// invalid-curve point) or on any other failure.
int smp_sc_dhkey(const struct smp_sc_keypair *kp, const uint8_t peer_pubkey[64],
                 uint8_t out[32]);

// AES-128 CMAC (RFC 4493), generic byte-string-in/16-byte-tag-out. No
// SMP/Core-Spec byte-order opinion -- f4/f5/f6/g2 below are thin
// compositions of this over Core-Spec-ordered buffers, but it is exposed
// directly for other crypto that wants plain AES-CMAC (e.g.
// src/blerp/authenticated_repair.c's own, unrelated CMAC-based KDF).
// Returns 0 on success, -1 on an OpenSSL failure.
int smp_sc_cmac(const uint8_t key[16], const uint8_t *msg, size_t msg_len,
                uint8_t out[16]);

// f4(U, V, X, Z) = AES-CMAC_X(U || V || Z). U, V are 32-byte public key
// X-coordinates; X is the 16-byte CMAC key; Z is one byte (0x00 for the
// Just Works/Numeric Comparison Confirm value; see the Passkey Entry
// association model for its other uses, not implemented here). Returns 0
// and fills out[16] (wire order) on success, -1 on failure.
int smp_sc_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
             uint8_t z, uint8_t out[16]);

// f5(w, n1, n2, a1, a2): derives MacKey and LTK from the 32-byte DHKey w.
// n1, n2 are 16-byte nonces (Na, Nb); a1, a2 are 7-byte "address || type"
// values (6-byte BD_ADDR + 1-byte address type, both wire order). Returns
// 0 and fills out_mackey[16]/out_ltk[16] (wire order) on success, -1 on
// failure. See the module-level SALT/keyID caveat above.
int smp_sc_f5(const uint8_t w[32], const uint8_t n1[16], const uint8_t n2[16],
             const uint8_t a1[7], const uint8_t a2[7],
             uint8_t out_mackey[16], uint8_t out_ltk[16]);

// f6(w, n1, n2, r, iocap, a1, a2) = AES-CMAC_W(N1 || N2 || R || IOcap || A1
// || A2). Used for the DHKey Check values Ea/Eb that close out SC Phase 2.
// w is the 16-byte MacKey f5 produced (the formula reuses the name W for
// both f5's DHKey input and f6's MacKey input -- they are not the same
// value). iocap is the 3-byte AuthReq || OOB_data_flag || IO_Capability
// triple IN THAT ORDER (the Core Spec defines this input with a different
// field order than the Pairing Request/Response PDU itself). Returns 0 and
// fills out[16] (wire order) on success, -1 on failure.
int smp_sc_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
             const uint8_t r[16], const uint8_t iocap[3],
             const uint8_t a1[7], const uint8_t a2[7], uint8_t out[16]);

// g2(u, v, x, y) = AES-CMAC_X(U || V || Y) mod 2^32. U, V are 32-byte
// public key X-coordinates; X, Y are the two 16-byte nonces (Na, Nb).
// Returns 0 and fills *out with the Numeric Comparison 6-digit display
// value (0..999999) on success, -1 on failure.
int smp_sc_g2(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
             const uint8_t y[16], uint32_t *out);

#endif // BLEURP_SMP_SC_H
