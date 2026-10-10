// ========================================
//  nom du fichier: addr_priv.h
//  description courte: BLE address privacy classification. Decides whether a
//  device address is trackable (a fixed public MAC or a static random
//  address) or private (a rotating resolvable/non-resolvable address), by
//  decoding the two most-significant bits of a random address.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_ADDR_PRIV_H
#define BLEURP_ADDR_PRIV_H

#include <stdbool.h>
#include <stdint.h>

// Address-type values, mirroring the BlueZ mgmt Device Found convention
// (MGMT_ADDR_TYPE_*). Only LE random addresses carry a random sub-type.
#define ADDR_TYPE_BREDR     0x00 // classic, fixed public address
#define ADDR_TYPE_LE_PUBLIC 0x01 // LE public (fixed IEEE MAC)
#define ADDR_TYPE_LE_RANDOM 0x02 // LE random (sub-type in the top MSB bits)

// Privacy posture of a device address.
typedef enum {
    ADDR_PRIV_PUBLIC,        // fixed public/BR-EDR MAC        -> trackable
    ADDR_PRIV_STATIC_RANDOM, // random, stable until reboot    -> trackable
    ADDR_PRIV_RPA,           // resolvable private, rotating   -> private
    ADDR_PRIV_NRPA           // non-resolvable private, rotating -> private
} addr_privacy_t;

// Classify an address (HCI byte order, so addr[5] is the MSB) given its
// mgmt address type. Non-random types are ADDR_PRIV_PUBLIC; for a random
// address the two MSB bits select the sub-type (0b11 static, 0b01 RPA,
// 0b00 NRPA; the reserved 0b10 is treated conservatively as NRPA).
addr_privacy_t addr_privacy(const uint8_t addr[6], uint8_t addr_type);

// True when the posture is a stable identifier an observer can track over
// time (public or static random); false for the rotating private addresses.
bool addr_is_trackable(addr_privacy_t p);

// Short, stable lower-case label for display ("public", "static", "rpa",
// "nrpa"). Returns a static string; never NULL.
const char *addr_privacy_label(addr_privacy_t p);

#endif // BLEURP_ADDR_PRIV_H
