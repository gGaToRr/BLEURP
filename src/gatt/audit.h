// ========================================
//  nom du fichier: audit.h
//  description courte: GATT access audit. Classifies whether a
//  characteristic is readable without pairing by mapping the outcome of a
//  read attempt (success or an ATT error code) to a verdict, so BLEURP can
//  report unauthenticated-access findings on an authorized target.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_AUDIT_H
#define BLEURP_AUDIT_H

#include <stdbool.h>
#include <stdint.h>

// ATT error codes relevant to an access audit (Bluetooth Core, Vol 3 Part F).
#define ATT_ERR_READ_NOT_PERMITTED           0x02
#define ATT_ERR_INSUFFICIENT_AUTHENTICATION  0x05
#define ATT_ERR_INSUFFICIENT_AUTHORIZATION   0x08
#define ATT_ERR_INSUFFICIENT_ENC_KEY_SIZE    0x0c
#define ATT_ERR_INSUFFICIENT_ENCRYPTION      0x0f

// Verdict for a characteristic read attempt.
typedef enum {
    AUDIT_OPEN,      // value returned without pairing -> unauthenticated read
    AUDIT_PROTECTED, // exists but needs pairing/encryption (insufficient-*)
    AUDIT_DENIED,    // read not permitted at all
    AUDIT_OTHER      // any other ATT error, or a transport failure (no code)
} audit_verdict_t;

// Map a read outcome to a verdict. `read_ok` is true when gatt_read returned
// the value; otherwise `att_error` is the ATT error code (0 if none, e.g. a
// timeout). See the ATT_ERR_* codes above.
audit_verdict_t audit_classify_read(bool read_ok, uint8_t att_error);

// Short, stable upper-case label for the report ("OPEN", "PROTECTED",
// "DENIED", "OTHER"). Returns a static string; never NULL.
const char *audit_verdict_label(audit_verdict_t v);

#endif // BLEURP_AUDIT_H
