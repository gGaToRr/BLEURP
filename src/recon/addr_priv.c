// ========================================
//  nom du fichier: addr_priv.c
//  description courte: Implementation of BLE address privacy classification.
//  Reads the two most-significant bits of a random address to tell static,
//  resolvable and non-resolvable addresses apart, and reports trackability.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "addr_priv.h"

// Classify an address given its mgmt address type (see header).
addr_privacy_t addr_privacy(const uint8_t addr[6], uint8_t addr_type) {
    // Only LE random addresses encode a sub-type; everything else is a fixed
    // public address (LE public or BR/EDR).
    if (addr_type != ADDR_TYPE_LE_RANDOM)
        return ADDR_PRIV_PUBLIC;

    // The sub-type lives in the top two bits of the most-significant byte.
    switch (addr[5] >> 6) {
    case 0x3: return ADDR_PRIV_STATIC_RANDOM; // 0b11
    case 0x1: return ADDR_PRIV_RPA;           // 0b01
    default:  return ADDR_PRIV_NRPA;          // 0b00, and reserved 0b10
    }
}

// A stable identifier (public or static random) can be tracked over time.
bool addr_is_trackable(addr_privacy_t p) {
    return p == ADDR_PRIV_PUBLIC || p == ADDR_PRIV_STATIC_RANDOM;
}

// Short lower-case label for the live view.
const char *addr_privacy_label(addr_privacy_t p) {
    switch (p) {
    case ADDR_PRIV_PUBLIC:        return "public";
    case ADDR_PRIV_STATIC_RANDOM: return "static";
    case ADDR_PRIV_RPA:           return "rpa";
    case ADDR_PRIV_NRPA:          return "nrpa";
    }
    return "?";
}
