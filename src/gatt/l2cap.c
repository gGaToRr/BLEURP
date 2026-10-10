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
#include <fcntl.h>
#include <poll.h>
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

// Open and connect an L2CAP socket on `cid`, bounded to `timeout_ms`. See
// l2cap.h for the contract. Non-blocking connect + poll() instead of the
// kernel's own (much longer) LE connection timeout.
int bleurp_l2_connect_cid_timeout(const uint8_t bdaddr[6], uint8_t bdaddr_type,
                                  uint16_t cid, int timeout_ms) {
    if (bdaddr == NULL) {
        errno = EINVAL;
        return -1;
    }

    int fd = socket(BLEURP_AF_BLUETOOTH, SOCK_SEQPACKET | SOCK_CLOEXEC,
                    BLEURP_BTPROTO_L2CAP);
    if (fd < 0) {
        return -1;
    }

    struct sockaddr_l2 src;
    static const uint8_t any[6] = {0};
    if (bleurp_l2_fill_addr(&src, any, BLEURP_BDADDR_LE_PUBLIC, cid) < 0 ||
        bind(fd, (struct sockaddr *)&src, sizeof src) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    struct sockaddr_l2 dst;
    bleurp_l2_fill_addr(&dst, bdaddr, bdaddr_type, cid);
    if (connect(fd, (struct sockaddr *)&dst, sizeof dst) < 0 && errno != EINPROGRESS) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }

    // Wait for the non-blocking connect to settle, one way or the other.
    struct pollfd pfd = { .fd = fd, .events = POLLOUT, .revents = 0 };
    int pr = poll(&pfd, 1, timeout_ms);
    if (pr <= 0) {
        int saved = (pr == 0) ? ETIMEDOUT : errno;
        close(fd);
        errno = saved;
        return -1;
    }

    int sockerr = 0;
    socklen_t elen = sizeof sockerr;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sockerr, &elen) < 0 || sockerr != 0) {
        int saved = sockerr ? sockerr : errno;
        close(fd);
        errno = saved;
        return -1;
    }

    fcntl(fd, F_SETFL, flags); // restore blocking mode for the caller's I/O
    return fd;
}

// Open and connect an L2CAP ATT socket, bounded to `timeout_ms`. See
// l2cap.h for the contract.
int bleurp_l2_connect_timeout(const uint8_t bdaddr[6], uint8_t bdaddr_type,
                              int timeout_ms) {
    return bleurp_l2_connect_cid_timeout(bdaddr, bdaddr_type, BLEURP_ATT_CID,
                                         timeout_ms);
}

// Close an L2CAP socket. See l2cap.h for the contract.
int bleurp_l2_close(int fd) {
    return close(fd);
}
