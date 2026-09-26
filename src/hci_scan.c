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
#include <string.h>
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

// Build a packet then send it; returns 0 on success or -1 (errno set).
static int build_and_send(int fd, ssize_t built_len, const uint8_t *pkt) {
    if (built_len < 0) {
        return -1; // errno from the builder
    }
    return hci_send(fd, pkt, (size_t)built_len);
}

// Start scanning, choosing the command set by mode. See hci_scan.h.
int hci_scan_start(int fd, enum hci_scan_mode mode, uint8_t scan_type) {
    uint8_t pkt[32];

    switch (mode) {
    case HCI_SCAN_MODE_LEGACY:
        if (build_and_send(fd, hci_build_le_scan_params(
                pkt, sizeof pkt, scan_type,
                HCI_LE_SCAN_INTERVAL_DEFAULT, HCI_LE_SCAN_WINDOW_DEFAULT,
                HCI_LE_OWN_ADDR_PUBLIC, HCI_LE_FILTER_POLICY_ALL), pkt) < 0) {
            return -1;
        }
        return build_and_send(fd, hci_build_le_scan_enable(
                pkt, sizeof pkt, HCI_LE_SCAN_ENABLE, HCI_LE_FILTER_DUP_OFF), pkt);

    case HCI_SCAN_MODE_EXTENDED:
        if (build_and_send(fd, hci_build_le_ext_scan_params(
                pkt, sizeof pkt, scan_type,
                HCI_LE_SCAN_INTERVAL_DEFAULT, HCI_LE_SCAN_WINDOW_DEFAULT,
                HCI_LE_OWN_ADDR_PUBLIC, HCI_LE_FILTER_POLICY_ALL), pkt) < 0) {
            return -1;
        }
        return build_and_send(fd, hci_build_le_ext_scan_enable(
                pkt, sizeof pkt, HCI_LE_SCAN_ENABLE, HCI_LE_FILTER_DUP_OFF,
                0x0000, 0x0000), pkt);

    default:
        errno = EINVAL;
        return -1;
    }
}

// Stop scanning, choosing the command set by mode. See hci_scan.h.
int hci_scan_stop(int fd, enum hci_scan_mode mode) {
    uint8_t pkt[32];

    switch (mode) {
    case HCI_SCAN_MODE_LEGACY:
        return build_and_send(fd, hci_build_le_scan_enable(
                pkt, sizeof pkt, HCI_LE_SCAN_DISABLE, HCI_LE_FILTER_DUP_OFF), pkt);

    case HCI_SCAN_MODE_EXTENDED:
        return build_and_send(fd, hci_build_le_ext_scan_enable(
                pkt, sizeof pkt, HCI_LE_SCAN_DISABLE, HCI_LE_FILTER_DUP_OFF,
                0x0000, 0x0000), pkt);

    default:
        errno = EINVAL;
        return -1;
    }
}

// Parse a legacy LE Advertising Report (sub-event 0x02) and dispatch each
// report. Layout per report: event_type(1) addr_type(1) address(6)
// data_len(1) data[data_len] rssi(1).
static int dispatch_legacy(const uint8_t *evt, size_t len,
                           hci_adv_cb cb, void *user) {
    if (len < 4) { // code + plen + subevent + num_reports
        errno = EBADMSG;
        return -1;
    }
    uint8_t num = evt[3];
    size_t off = 4;
    int dispatched = 0;

    for (uint8_t i = 0; i < num; i++) {
        // Fixed head (9 bytes) must fit before reading the data length.
        if (off + 9 > len) {
            errno = EBADMSG;
            return -1;
        }
        uint8_t dlen = evt[off + 8];
        // Head + data + trailing RSSI must all fit.
        if (off + 9 + (size_t)dlen + 1 > len) {
            errno = EBADMSG;
            return -1;
        }

        struct hci_adv_report rep;
        rep.extended = false;
        rep.event_type = evt[off];
        rep.addr_type = evt[off + 1];
        memcpy(rep.address, &evt[off + 2], 6);
        rep.data = &evt[off + 9];
        rep.data_len = dlen;
        rep.rssi = (int8_t)evt[off + 9 + dlen];

        cb(&rep, user);
        dispatched++;
        off += 9 + (size_t)dlen + 1;
    }
    return dispatched;
}

// Parse an extended LE Advertising Report (sub-event 0x0d) and dispatch each
// report. Fixed head is 24 bytes; data_length is at offset 23; data follows.
static int dispatch_extended(const uint8_t *evt, size_t len,
                             hci_adv_cb cb, void *user) {
    if (len < 4) {
        errno = EBADMSG;
        return -1;
    }
    uint8_t num = evt[3];
    size_t off = 4;
    int dispatched = 0;

    for (uint8_t i = 0; i < num; i++) {
        if (off + 24 > len) {
            errno = EBADMSG;
            return -1;
        }
        uint8_t dlen = evt[off + 23];
        if (off + 24 + (size_t)dlen > len) {
            errno = EBADMSG;
            return -1;
        }

        struct hci_adv_report rep;
        rep.extended = true;
        rep.event_type = (uint16_t)(evt[off] | ((uint16_t)evt[off + 1] << 8));
        rep.addr_type = evt[off + 2];
        memcpy(rep.address, &evt[off + 3], 6);
        rep.rssi = (int8_t)evt[off + 13];
        rep.data = &evt[off + 24];
        rep.data_len = dlen;

        cb(&rep, user);
        dispatched++;
        off += 24 + (size_t)dlen;
    }
    return dispatched;
}

// Dispatch advertising reports from one HCI event. See hci_scan.h.
int hci_dispatch_event(const uint8_t *evt, size_t len,
                       hci_adv_cb cb, void *user) {
    if (evt == NULL || cb == NULL) {
        errno = EINVAL;
        return -1;
    }
    // Need at least event code + parameter length + sub-event code.
    if (len < 3) {
        errno = EBADMSG;
        return -1;
    }
    if (evt[0] != HCI_EVT_LE_META) {
        return 0; // not an LE meta event: nothing to dispatch
    }

    switch (evt[2]) {
    case HCI_SUBEVT_LE_ADV_REPORT:
        return dispatch_legacy(evt, len, cb, user);
    case HCI_SUBEVT_LE_EXT_ADV_REPORT:
        return dispatch_extended(evt, len, cb, user);
    default:
        return 0; // other LE sub-event: ignored
    }
}
