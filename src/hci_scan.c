// ========================================
//  nom du fichier: hci_scan.c
//  description courte: Implementation of the LE scan command builders. Each
//  builder lays out the command parameters, then wraps them with the shared
//  HCI packet builder. hci_send writes a finished packet to the socket.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "hci_scan.h"
#include "hci_cmd.h"
#include "hci.h"

#include <errno.h>
#include <unistd.h>

// Write a little-endian 16-bit value into a byte buffer.
static void wr_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0x00ff);
    p[1] = (uint8_t)((v >> 8) & 0x00ff);
}

// Build "LE Set Scan Parameters" (legacy, 0x200b). See hci_scan.h.
ssize_t hci_build_le_scan_params(uint8_t *buf, size_t buf_len,
                                 uint8_t scan_type,
                                 uint16_t interval, uint16_t window,
                                 uint8_t own_addr_type, uint8_t filter_policy) {
    uint8_t p[7];
    p[0] = scan_type;
    wr_le16(&p[1], interval);
    wr_le16(&p[3], window);
    p[5] = own_addr_type;
    p[6] = filter_policy;
    return hci_build_command(buf, buf_len, HCI_OP_LE_SET_SCAN_PARAMS, p, sizeof p);
}

// Build "LE Set Scan Enable" (legacy, 0x200c). See hci_scan.h.
ssize_t hci_build_le_scan_enable(uint8_t *buf, size_t buf_len,
                                 uint8_t enable, uint8_t filter_duplicates) {
    uint8_t p[2];
    p[0] = enable;
    p[1] = filter_duplicates;
    return hci_build_command(buf, buf_len, HCI_OP_LE_SET_SCAN_ENABLE, p, sizeof p);
}

// Build "LE Set Extended Scan Parameters" (0x2041), LE 1M PHY. See hci_scan.h.
ssize_t hci_build_le_ext_scan_params(uint8_t *buf, size_t buf_len,
                                     uint8_t scan_type,
                                     uint16_t interval, uint16_t window,
                                     uint8_t own_addr_type,
                                     uint8_t filter_policy) {
    uint8_t p[8];
    p[0] = own_addr_type;
    p[1] = filter_policy;
    p[2] = HCI_LE_EXT_SCAN_PHY_1M; // one PHY set: LE 1M
    p[3] = scan_type;
    wr_le16(&p[4], interval);
    wr_le16(&p[6], window);
    return hci_build_command(buf, buf_len, HCI_OP_LE_SET_EXT_SCAN_PARAMS, p, sizeof p);
}

// Build "LE Set Extended Scan Enable" (0x2042). See hci_scan.h.
ssize_t hci_build_le_ext_scan_enable(uint8_t *buf, size_t buf_len,
                                     uint8_t enable, uint8_t filter_duplicates,
                                     uint16_t duration, uint16_t period) {
    uint8_t p[6];
    p[0] = enable;
    p[1] = filter_duplicates;
    wr_le16(&p[2], duration);
    wr_le16(&p[4], period);
    return hci_build_command(buf, buf_len, HCI_OP_LE_SET_EXT_SCAN_ENABLE, p, sizeof p);
}

// Write a finished HCI command packet to the socket. See hci_scan.h.
int hci_send(int fd, const uint8_t *pkt, size_t len) {
    if (fd < 0 || pkt == NULL || len == 0) {
        errno = EINVAL;
        return -1;
    }
    ssize_t written = write(fd, pkt, len);
    if (written < 0) {
        return -1; // errno from write()
    }
    if ((size_t)written != len) {
        errno = EIO;
        return -1;
    }
    return 0;
}
