// ========================================
//  nom du fichier: hci_cmd.h
//  description courte: Builder for raw HCI command packets. Serializes an
//  opcode plus its parameters into the exact byte layout expected on the
//  HCI socket, with no external Bluetooth library.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_HCI_CMD_H
#define BLEURP_HCI_CMD_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> // ssize_t

// Serialize an HCI command packet into `buf`.
// Wire layout: [HCI_COMMAND_PKT][opcode LSB][opcode MSB][param_len][params...].
// `params` may be NULL only when `param_len` is 0.
// Returns the total number of bytes written (4 + param_len), or -1 with errno:
//   EINVAL - buf is NULL, or params is NULL while param_len > 0
//   ENOSPC - buf_len is smaller than the full packet
ssize_t hci_build_command(uint8_t *buf, size_t buf_len,
                          uint16_t opcode,
                          const uint8_t *params, uint8_t param_len);

#endif // BLEURP_HCI_CMD_H
