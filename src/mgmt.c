// ========================================
//  nom du fichier: mgmt.c
//  description courte: Implementation of the mgmt packet layer. Serializes
//  and parses the little-endian mgmt header, and opens the kernel control
//  socket on HCI_CHANNEL_CONTROL (index MGMT_INDEX_NONE).
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE // for SOCK_CLOEXEC

#include "mgmt.h"
#include "hci_dev.h" // socket constants + struct sockaddr_hci

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

// Write a little-endian 16-bit value into a byte buffer.
static void wr_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0x00ff);
    p[1] = (uint8_t)((v >> 8) & 0x00ff);
}

// Read a little-endian 16-bit value from a byte buffer.
static uint16_t rd_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

// Build a mgmt command packet. See mgmt.h for the contract.
ssize_t mgmt_build_command(uint8_t *buf, size_t buf_len,
                           uint16_t opcode, uint16_t index,
                           const uint8_t *params, uint16_t param_len) {
    if (buf == NULL || (param_len > 0 && params == NULL)) {
        errno = EINVAL;
        return -1;
    }

    const size_t total = (size_t)MGMT_HDR_SIZE + param_len;
    if (buf_len < total) {
        errno = ENOSPC;
        return -1;
    }

    wr_le16(&buf[0], opcode);
    wr_le16(&buf[2], index);
    wr_le16(&buf[4], param_len);
    if (param_len > 0) {
        memcpy(&buf[6], params, param_len);
    }
    return (ssize_t)total;
}

// Parse a mgmt header. See mgmt.h for the contract.
int mgmt_parse_header(const uint8_t *buf, size_t len, struct mgmt_hdr *out) {
    if (buf == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (len < MGMT_HDR_SIZE) {
        errno = EBADMSG;
        return -1;
    }
    out->opcode = rd_le16(&buf[0]);
    out->index  = rd_le16(&buf[2]);
    out->len    = rd_le16(&buf[4]);
    return 0;
}

// Open the kernel mgmt control socket. See mgmt.h for the contract.
int mgmt_open(void) {
    struct sockaddr_hci addr;
    memset(&addr, 0, sizeof addr);
    addr.hci_family = BLEURP_AF_BLUETOOTH;
    addr.hci_dev = MGMT_INDEX_NONE; // control socket is not per-adapter
    addr.hci_channel = BLEURP_HCI_CHANNEL_CONTROL;

    int fd = socket(BLEURP_AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC,
                    BLEURP_BTPROTO_HCI);
    if (fd < 0) {
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

// Close a mgmt socket. See mgmt.h for the contract.
int mgmt_close(int fd) {
    return close(fd);
}
