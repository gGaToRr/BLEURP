// ========================================
//  nom du fichier: mgmt.h
//  description courte: Kernel BlueZ management (mgmt) interface. Opens the
//  HCI control socket and builds/parses mgmt packets, so BLEURP can drive
//  device discovery through the kernel (clean, coexists with bluetoothd)
//  rather than raw HCI. No D-Bus and no external binary.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_MGMT_H
#define BLEURP_MGMT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> // ssize_t

// mgmt message header size: opcode(2) + index(2) + length(2).
#define MGMT_HDR_SIZE 6

// Controller index meaning "no specific controller".
#define MGMT_INDEX_NONE 0xffff

// mgmt command opcodes (subset used by BLEURP).
#define MGMT_OP_READ_CONTROLLER_INFO 0x0004
#define MGMT_OP_SET_POWERED          0x0005
#define MGMT_OP_START_DISCOVERY      0x0023
#define MGMT_OP_STOP_DISCOVERY       0x0024

// mgmt event codes.
#define MGMT_EV_CMD_COMPLETE 0x0001
#define MGMT_EV_CMD_STATUS   0x0002
#define MGMT_EV_DEVICE_FOUND 0x0012

// Discovery address-type bitmask (Start/Stop Discovery parameter).
#define MGMT_ADDR_BIT_BREDR     0x01
#define MGMT_ADDR_BIT_LE_PUBLIC 0x02
#define MGMT_ADDR_BIT_LE_RANDOM 0x04
#define MGMT_ADDR_LE (MGMT_ADDR_BIT_LE_PUBLIC | MGMT_ADDR_BIT_LE_RANDOM) // 0x06

// Device address type (Device Found event field).
#define MGMT_ADDR_TYPE_BREDR     0x00
#define MGMT_ADDR_TYPE_LE_PUBLIC 0x01
#define MGMT_ADDR_TYPE_LE_RANDOM 0x02

// Decoded mgmt message header (command or event).
struct mgmt_hdr {
    uint16_t opcode; // command opcode, or event code for events
    uint16_t index;  // controller index, or MGMT_INDEX_NONE
    uint16_t len;    // parameter length that follows the header
};

// Build a mgmt command packet into `buf`.
// Wire layout (all 16-bit fields little-endian):
//   opcode(2) index(2) param_len(2) params...
// `params` may be NULL only when `param_len` is 0.
// Returns the total number of bytes written (6 + param_len), or -1 with
// errno set (EINVAL for bad args, ENOSPC when buf is too small).
ssize_t mgmt_build_command(uint8_t *buf, size_t buf_len,
                           uint16_t opcode, uint16_t index,
                           const uint8_t *params, uint16_t param_len);

// Parse the 6-byte mgmt header from `buf` into `out`.
// Returns 0 on success, or -1 with errno set (EINVAL if buf/out is NULL,
// EBADMSG if fewer than MGMT_HDR_SIZE bytes are available).
int mgmt_parse_header(const uint8_t *buf, size_t len, struct mgmt_hdr *out);

// Open the kernel mgmt control socket (HCI_CHANNEL_CONTROL). Returns a file
// descriptor, or -1 with errno set (e.g. EPERM without CAP_NET_ADMIN).
int mgmt_open(void);

// Close a socket returned by mgmt_open. Returns 0 or -1 with errno.
int mgmt_close(int fd);

#endif // BLEURP_MGMT_H
