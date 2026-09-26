// ========================================
//  nom du fichier: l2cap.c
//  description courte: Implementation of the L2CAP connection. Builds the
//  sockaddr_l2 for the ATT channel, binds a local source and connects to an
//  authorized device so ATT/GATT PDUs can be exchanged over the socket.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE // for SOCK_CLOEXEC

#include "l2cap.h"
#include "hci_dev.h" // BLEURP_AF_BLUETOOTH

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

// Fill a sockaddr_l2. See l2cap.h for the contract.
int bleurp_l2_fill_addr(struct sockaddr_l2 *addr, const uint8_t bdaddr[6],
                        uint8_t bdaddr_type, uint16_t cid) {
    if (addr == NULL || bdaddr == NULL) {
        errno = EINVAL;
        return -1;
    }
    memset(addr, 0, sizeof *addr);
    addr->l2_family = BLEURP_AF_BLUETOOTH;
    addr->l2_psm = 0; // fixed channel: PSM unused
    addr->l2_cid = cid;
    addr->l2_bdaddr_type = bdaddr_type;
    memcpy(addr->l2_bdaddr.b, bdaddr, 6);
    return 0;
}

// Open and connect an L2CAP ATT socket. See l2cap.h for the contract.
int bleurp_l2_connect(const uint8_t bdaddr[6], uint8_t bdaddr_type) {
    if (bdaddr == NULL) {
        errno = EINVAL;
        return -1;
    }

    int fd = socket(BLEURP_AF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC,
                    BLEURP_BTPROTO_L2CAP);
    if (fd < 0) {
        return -1;
    }

    // Bind a local source on the ATT channel (any local adapter). The source
    // address type is set to public; the kernel selects the adapter.
    struct sockaddr_l2 src;
    static const uint8_t any[6] = {0};
    if (bleurp_l2_fill_addr(&src, any, BLEURP_BDADDR_LE_PUBLIC, BLEURP_ATT_CID) < 0 ||
        bind(fd, (struct sockaddr *)&src, sizeof src) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    // Connect to the target device on the ATT channel.
    struct sockaddr_l2 dst;
    bleurp_l2_fill_addr(&dst, bdaddr, bdaddr_type, BLEURP_ATT_CID);
    if (connect(fd, (struct sockaddr *)&dst, sizeof dst) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    return fd;
}

// Close an L2CAP socket. See l2cap.h for the contract.
int bleurp_l2_close(int fd) {
    return close(fd);
}
