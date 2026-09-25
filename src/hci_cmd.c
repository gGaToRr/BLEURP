// ========================================
//  nom du fichier: hci_cmd.c
//  description courte: Implementation of the HCI command packet builder.
//  Validates its arguments, then writes the fixed 4-byte header followed by
//  the parameter bytes in little-endian opcode order.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "hci_cmd.h"
#include "hci.h"

#include <errno.h>
#include <string.h>

// Serialize an HCI command packet. See hci_cmd.h for the contract.
ssize_t hci_build_command(uint8_t *buf, size_t buf_len,
                          uint16_t opcode,
                          const uint8_t *params, uint8_t param_len) {
    // A non-zero length with no parameter buffer is a caller mistake.
    if (buf == NULL || (param_len > 0 && params == NULL)) {
        errno = EINVAL;
        return -1;
    }

    // Header is 4 bytes: type + 2-byte opcode + 1-byte length.
    const size_t total = (size_t)4 + param_len;
    if (buf_len < total) {
        errno = ENOSPC;
        return -1;
    }

    buf[0] = HCI_COMMAND_PKT;
    buf[1] = (uint8_t)(opcode & 0x00ff);        // opcode, least significant byte
    buf[2] = (uint8_t)((opcode >> 8) & 0x00ff); // opcode, most significant byte
    buf[3] = param_len;

    if (param_len > 0) {
        memcpy(buf + 4, params, param_len);
    }

    return (ssize_t)total;
}
