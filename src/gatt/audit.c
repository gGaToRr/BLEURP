// ========================================
//  nom du fichier: audit.c
//  description courte: Implementation of the GATT access-audit classifier.
//  Turns a characteristic read outcome into an open/protected/denied/other
//  verdict and provides the matching display labels.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "audit.h"

// Map a read outcome to a verdict (see header).
audit_verdict_t audit_classify_read(bool read_ok, uint8_t att_error) {
    if (read_ok)
        return AUDIT_OPEN;

    switch (att_error) {
    case ATT_ERR_INSUFFICIENT_AUTHENTICATION:
    case ATT_ERR_INSUFFICIENT_AUTHORIZATION:
    case ATT_ERR_INSUFFICIENT_ENC_KEY_SIZE:
    case ATT_ERR_INSUFFICIENT_ENCRYPTION:
        return AUDIT_PROTECTED;
    case ATT_ERR_READ_NOT_PERMITTED:
        return AUDIT_DENIED;
    default:
        return AUDIT_OTHER;
    }
}

// Short upper-case label for the report column.
const char *audit_verdict_label(audit_verdict_t v) {
    switch (v) {
    case AUDIT_OPEN:      return "OPEN";
    case AUDIT_PROTECTED: return "PROTECTED";
    case AUDIT_DENIED:    return "DENIED";
    case AUDIT_OTHER:     return "OTHER";
    }
    return "?";
}
