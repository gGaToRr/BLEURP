// ========================================
//  nom du fichier: hci_dev.c
//  description courte: Implementation of the raw HCI socket module. Builds
//  the sockaddr_hci, creates an AF_BLUETOOTH/BTPROTO_HCI raw socket and
//  binds it to the requested adapter and channel, cleaning up on failure.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE // for SOCK_CLOEXEC

#include "hci_dev.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

// Fill a sockaddr_hci. See hci_dev.h for the contract.
int bleurp_hci_fill_addr(struct sockaddr_hci *addr, int dev_id,
                         unsigned short channel) {
    if (addr == NULL || dev_id < 0 || dev_id >= BLEURP_HCI_MAX_DEV) {
        errno = EINVAL;
        return -1;
    }
    memset(addr, 0, sizeof *addr);
    addr->hci_family = BLEURP_AF_BLUETOOTH;
    addr->hci_dev = (unsigned short)dev_id;
    addr->hci_channel = channel;
    return 0;
}

// Open and bind a raw HCI socket. See hci_dev.h for the contract.
int bleurp_hci_open(int dev_id, unsigned short channel) {
    struct sockaddr_hci addr;

    // Validate the index first so a bad request never reaches a syscall.
    if (bleurp_hci_fill_addr(&addr, dev_id, channel) < 0) {
        return -1; // errno is EINVAL
    }

    int fd = socket(BLEURP_AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC,
                    BLEURP_BTPROTO_HCI);
    if (fd < 0) {
        return -1; // errno from socket()
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        // Preserve the bind error across close().
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    return fd;
}

// Close an HCI socket. See hci_dev.h for the contract.
int bleurp_hci_close(int fd) {
    return close(fd);
}

// Detect the first available local HCI device (0..15). Returns index (e.g. 0 or 1).
int bleurp_hci_find_default_dev(void) {
    for (int i = 0; i < BLEURP_HCI_MAX_DEV; i++) {
        char path[64];
        snprintf(path, sizeof(path), "/sys/class/bluetooth/hci%d", i);
        if (access(path, F_OK) == 0) {
            return i;
        }
    }
    return 0;
}
