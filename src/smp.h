// ========================================
//  nom du fichier: smp.h
//  description courte: Minimal Security Manager Protocol (SMP) codec, for
//  the "SMP module" re-pairing probe (see BLERP, NDSS 2026: unauthenticated
//  BLE re-pairing lets a peer accept a downgraded security level). Builds a
//  Pairing Request / Security Request with a deliberately weak AuthReq and
//  parses the peer's first reply. This observes negotiation behaviour only
//  -- it never completes key derivation, so it cannot produce a usable key
//  and never actually (re-)pairs the device.
//  dernière modification : 2026-09-27
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_SMP_H
#define BLEURP_SMP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> // ssize_t

// SMP opcodes (Bluetooth Core Specification, Vol 3, Part H) -- the subset
// needed for the pairing feature-negotiation phase.
#define SMP_CODE_PAIRING_REQUEST  0x01
#define SMP_CODE_PAIRING_RESPONSE 0x02
#define SMP_CODE_PAIRING_FAILED   0x05
#define SMP_CODE_SECURITY_REQUEST 0x0b

// AuthReq flag bits (least to most significant): 2-bit Bonding_Flags, then
// MITM, SC, Keypress, CT2, and 2 RFU bits.
#define SMP_AUTHREQ_BONDING  0x01
#define SMP_AUTHREQ_MITM     0x04
#define SMP_AUTHREQ_SC       0x08
#define SMP_AUTHREQ_KEYPRESS 0x10
#define SMP_AUTHREQ_CT2      0x20

// IO Capability value for a device with no input and no output.
#define SMP_IO_CAP_NO_INPUT_NO_OUTPUT 0x03

// Decoded Pairing Request/Response payload (6 bytes after the opcode).
struct smp_pairing_params {
    uint8_t io_capability;
    uint8_t oob_data_flag;
    uint8_t auth_req;
    uint8_t max_key_size;
    uint8_t init_key_dist;
    uint8_t resp_key_dist;
};

// --- Request builders (return packet length, or -1 with errno) ---
// errno is EINVAL for bad args, ENOSPC when buf is too small.

// Pairing Request (0x01).
ssize_t smp_build_pairing_request(uint8_t *buf, size_t buf_len,
                                  const struct smp_pairing_params *p);

// Security Request (0x0B): a bare AuthReq byte, used by a Peripheral to ask
// a Central to (re-)pair or refresh the session.
ssize_t smp_build_security_request(uint8_t *buf, size_t buf_len,
                                   uint8_t auth_req);

// --- Response parsers (return 0, or -1 with errno EINVAL/EBADMSG) ---

// Parse a Pairing Response (0x02) into `out`.
int smp_parse_pairing_response(const uint8_t *pdu, size_t len,
                               struct smp_pairing_params *out);

// Parse a Pairing Failed (0x05) reason code into `reason`.
int smp_parse_pairing_failed(const uint8_t *pdu, size_t len, uint8_t *reason);

// Outcome of a probe: what the peer did with our deliberately weak Pairing
// Request. This is a negotiation-behaviour signal, not proof of the BLERP
// re-pairing vulnerabilities by itself -- those specifically concern a
// device that already holds a Pairing Key accepting a *downgraded* new
// one, so the signal is strongest when run against a device this
// controller has already paired with.
typedef enum {
    SMP_PROBE_RESPONDED,   // peer replied with a Pairing Response
    SMP_PROBE_REJECTED,    // peer replied with Pairing Failed
    SMP_PROBE_NO_RESPONSE, // timeout, or the channel/transport failed
} smp_probe_t;

// Send a Pairing Request offering the weakest AuthReq (bonding only, no
// MITM, no SC, 7-byte key size) over an already-connected SMP channel (see
// BLEURP_SMP_CID in l2cap.h) and classify the peer's first reply. Never
// sends a second message, so pairing never completes. `out_response` is
// filled when the verdict is SMP_PROBE_RESPONDED (may be NULL). Use only on
// devices you are authorized to test.
smp_probe_t smp_downgrade_probe(int fd, int timeout_ms,
                                struct smp_pairing_params *out_response);

#endif // BLEURP_SMP_H
