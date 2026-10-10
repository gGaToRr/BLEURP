// ========================================
//  nom du fichier: smp_legacy.h
//  description courte: Legacy LE pairing (Just Works, TK = 0) for both roles:
//  c1 and s1 (Core Vol 3, Part H, 2.2.3-2.2.4) and the initiator/responder
//  state machines. Works on the little-endian arrays the SMP PDUs carry, with
//  the same byte conventions as the keyboard emulator's responder (which is
//  validated against a real phone). Pure: no I/O, no HCI.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_SMP_LEGACY_H
#define BLEURP_SMP_LEGACY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// SMP opcodes used by the legacy exchange.
#define SMP_LEG_OP_PAIRING_REQ      0x01
#define SMP_LEG_OP_PAIRING_RSP      0x02
#define SMP_LEG_OP_PAIRING_CONFIRM  0x03
#define SMP_LEG_OP_PAIRING_RANDOM   0x04
#define SMP_LEG_OP_PAIRING_FAILED   0x05

// e(key, in) = AES-128 with the PDU byte order (reversed to big-endian for AES).
// Returns 0 on success, -1 if OpenSSL fails.
int smp_legacy_e(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

// c1: confirm value. preq and pres are the 7-byte PDUs including the opcode.
// ia/iat: initiator address and type; ra/rat: responder address and type.
int smp_legacy_c1(const uint8_t k[16], const uint8_t r[16],
                  const uint8_t preq[7], const uint8_t pres[7],
                  uint8_t iat, const uint8_t ia[6],
                  uint8_t rat, const uint8_t ra[6],
                  uint8_t out[16]);

// s1: short term key. mrand is the initiator's random, srand the responder's.
int smp_legacy_s1(const uint8_t k[16], const uint8_t mrand[16],
                  const uint8_t srand[16], uint8_t out[16]);

// One side of a Just Works legacy pairing. The caller feeds it the PDUs it
// received and sends the ones it builds, in the order of the standard:
//   initiator: make_req, on_rsp, make_confirm, on_confirm, make_random, on_random
//   responder: on_req, make_rsp, on_confirm, make_confirm, on_random, make_random
struct smp_legacy {
    bool initiator;
    bool failed;
    bool done;               // STK derived and the peer's random verified
    uint8_t iat, rat;        // address types (0 public, 1 random)
    uint8_t ia[6], ra[6];    // initiator and responder addresses (LE arrays)
    uint8_t preq[7], pres[7];
    uint8_t my_rand[16];     // our random (caller-supplied, e.g. from RAND_bytes)
    uint8_t peer_rand[16];
    uint8_t peer_confirm[16];
    uint8_t stk[16];
    uint8_t reason;          // Pairing Failed reason to send when failed
    uint8_t custom_authreq;  // If non-zero, override default AuthReq (e.g. 0x01)
    uint8_t custom_maxkey;   // If non-zero, override default max key size (e.g. 0x07)
};

// Set the role, the addresses and our random. TK is zero (Just Works).
void smp_legacy_init(struct smp_legacy *p, bool initiator,
                     uint8_t iat, const uint8_t ia[6],
                     uint8_t rat, const uint8_t ra[6],
                     const uint8_t my_rand[16]);

// Set custom AuthReq and max key size (e.g. for downgrade attacks).
void smp_legacy_set_params(struct smp_legacy *p, uint8_t authreq, uint8_t max_keysize);

// Initiator: build the Pairing Request (7 bytes). Returns 7, or -1.
int smp_legacy_make_req(struct smp_legacy *p, uint8_t out[7]);
// Initiator: read the Pairing Response (7 bytes).
int smp_legacy_on_rsp(struct smp_legacy *p, const uint8_t pdu[7]);
// Responder: read the Pairing Request (7 bytes).
int smp_legacy_on_req(struct smp_legacy *p, const uint8_t pdu[7]);
// Responder: build the Pairing Response (7 bytes). Returns 7, or -1.
int smp_legacy_make_rsp(struct smp_legacy *p, uint8_t out[7]);

// Build our Pairing Confirm (17 bytes: opcode + value). Returns 17, or -1.
int smp_legacy_make_confirm(struct smp_legacy *p, uint8_t out[17]);
// Read the peer's Pairing Confirm (17 bytes).
int smp_legacy_on_confirm(struct smp_legacy *p, const uint8_t pdu[17]);

// Build our Pairing Random (17 bytes). Returns 17, or -1.
int smp_legacy_make_random(struct smp_legacy *p, uint8_t out[17]);
// Read the peer's Pairing Random (17 bytes). Verifies its confirm value and,
// on success, derives the STK. A mismatch sets `failed` and `reason` 0x04.
int smp_legacy_on_random(struct smp_legacy *p, const uint8_t pdu[17]);

#endif // BLEURP_SMP_LEGACY_H
