// ========================================
//  nom du fichier: hci_info.h
//  description courte: Controller information helpers. Parses the Command
//  Complete event of "Read Local Version Information" (opcode 0x1001) and
//  decides whether the controller supports LE extended advertising/scanning
//  (BT 5.0+), so the scanner can pick legacy or extended mode.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_HCI_INFO_H
#define BLEURP_HCI_INFO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Decoded fields of Read Local Version Information.
struct hci_local_version {
    uint8_t  status;         // 0x00 on success
    uint8_t  hci_version;    // HCI_VER_BT_* value
    uint16_t hci_revision;   // vendor-specific revision
    uint8_t  lmp_version;    // Link Manager Protocol version
    uint16_t manufacturer;   // company identifier
    uint16_t lmp_subversion; // vendor-specific subversion
};

// Parse a Command Complete event for Read Local Version Information.
// `evt` points at the event code byte (HCI_EVT_CMD_COMPLETE), i.e. the HCI
// packet type indicator has already been stripped. `len` is the number of
// bytes available at `evt`.
// Returns 0 on success, or -1 with errno set:
//   EINVAL  - evt or out is NULL
//   EBADMSG - not a matching Command Complete event, or truncated
int hci_parse_local_version(const uint8_t *evt, size_t len,
                            struct hci_local_version *out);

// Decide whether the controller supports LE extended advertising/scanning,
// inferred from the HCI version (BT 5.0+). A stricter test would read the LE
// feature bitmap (bit 12); the version is a reliable proxy here.
// Returns false when `v` is NULL.
bool hci_supports_extended(const struct hci_local_version *v);

#endif // BLEURP_HCI_INFO_H
