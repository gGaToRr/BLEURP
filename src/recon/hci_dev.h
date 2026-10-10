// ========================================
//  nom du fichier: hci_dev.h
//  description courte: Raw HCI socket handling. Opens and binds an
//  AF_BLUETOOTH/BTPROTO_HCI socket to a local adapter (hci0, hci1, ...)
//  without any external Bluetooth library. Socket-level constants and the
//  sockaddr_hci layout are declared here to stay self-contained.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_HCI_DEV_H
#define BLEURP_HCI_DEV_H

#include <sys/socket.h> // sa_family_t

// Bluetooth socket family and HCI protocol (mirror of the kernel values).
#define BLEURP_AF_BLUETOOTH 31
#define BLEURP_BTPROTO_HCI  1

// HCI channels: RAW shares the adapter with BlueZ; USER takes exclusive
// control (the adapter must be down first); CONTROL is the kernel BlueZ
// management (mgmt) interface, which coexists cleanly with bluetoothd.
#define BLEURP_HCI_CHANNEL_RAW     0
#define BLEURP_HCI_CHANNEL_USER    1
#define BLEURP_HCI_CHANNEL_CONTROL 3

// Maximum number of local adapters the kernel exposes (hci0 .. hci15).
#define BLEURP_HCI_MAX_DEV 16

// Address of a local HCI adapter, matching the kernel's sockaddr_hci layout.
struct sockaddr_hci {
    sa_family_t    hci_family;  // must be BLEURP_AF_BLUETOOTH
    unsigned short hci_dev;     // adapter index (0 for hci0)
    unsigned short hci_channel; // BLEURP_HCI_CHANNEL_RAW or _USER
};

// Fill `addr` for the given adapter index and channel.
// Returns 0 on success, or -1 with errno=EINVAL when `addr` is NULL or
// `dev_id` is out of range.
int bleurp_hci_fill_addr(struct sockaddr_hci *addr, int dev_id,
                         unsigned short channel);

// Open a raw HCI socket and bind it to the given adapter index and channel.
// Returns a file descriptor on success, or -1 with errno set (EINVAL for a
// bad index; otherwise the socket/bind error, e.g. EPERM without
// CAP_NET_RAW, or ENODEV when the adapter is absent).
int bleurp_hci_open(int dev_id, unsigned short channel);

// Close a socket returned by bleurp_hci_open. Returns 0 or -1 with errno.
int bleurp_hci_close(int fd);

// Detect the first available local HCI device (0..15). Returns index (e.g. 0 or 1).
int bleurp_hci_find_default_dev(void);

#endif // BLEURP_HCI_DEV_H
