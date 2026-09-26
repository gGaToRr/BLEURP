// ========================================
//  nom du fichier: l2cap.h
//  description courte: L2CAP connection for GATT. Builds the sockaddr_l2 for
//  the ATT channel and connects an AF_BLUETOOTH/BTPROTO_L2CAP socket to an
//  authorized device address, over which ATT/GATT PDUs are exchanged.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_L2CAP_H
#define BLEURP_L2CAP_H

#include <stdint.h>
#include <sys/socket.h> // sa_family_t

// L2CAP protocol number and the fixed ATT channel identifier.
#define BLEURP_BTPROTO_L2CAP 0
#define BLEURP_ATT_CID       0x0004

// LE device address types (match BlueZ and the mgmt Device Found values).
#define BLEURP_BDADDR_LE_PUBLIC 1
#define BLEURP_BDADDR_LE_RANDOM 2

// 6-byte Bluetooth device address (little-endian / HCI byte order).
struct bleurp_bdaddr {
    uint8_t b[6];
};

// L2CAP socket address, matching the kernel's sockaddr_l2 layout.
struct sockaddr_l2 {
    sa_family_t          l2_family;      // BLEURP_AF_BLUETOOTH
    unsigned short       l2_psm;         // 0 for a fixed channel
    struct bleurp_bdaddr l2_bdaddr;      // device address
    unsigned short       l2_cid;         // BLEURP_ATT_CID for GATT
    uint8_t              l2_bdaddr_type;  // public/random
};

// Fill `addr` for the given device address, address type and channel id.
// Returns 0 on success, or -1 with errno=EINVAL if addr or bdaddr is NULL.
int bleurp_l2_fill_addr(struct sockaddr_l2 *addr, const uint8_t bdaddr[6],
                        uint8_t bdaddr_type, uint16_t cid);

// Open an L2CAP socket and connect to the device on the ATT channel.
// `bdaddr` is in HCI byte order; `bdaddr_type` is public/random.
// Returns a connected file descriptor, or -1 with errno set (EINVAL for a
// NULL address; otherwise the socket/connect error, e.g. permission or
// timeout). Use only on devices you are authorized to test.
int bleurp_l2_connect(const uint8_t bdaddr[6], uint8_t bdaddr_type);

// Close a socket returned by bleurp_l2_connect. Returns 0 or -1 with errno.
int bleurp_l2_close(int fd);

#endif // BLEURP_L2CAP_H
