// ========================================
//  nom du fichier: hci_scan.h
//  description courte: LE scanning command builders and a socket send
//  helper. Produces the exact HCI command packets to start/stop scanning in
//  both legacy (BT 4.x) and extended (BT 5.x) modes, passive or active.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_HCI_SCAN_H
#define BLEURP_HCI_SCAN_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> // ssize_t

// Sensible defaults (units of 0.625 ms; 0x0010 = 10 ms).
#define HCI_LE_SCAN_INTERVAL_DEFAULT 0x0010
#define HCI_LE_SCAN_WINDOW_DEFAULT   0x0010

// Own address type and filter policy for scanning.
#define HCI_LE_OWN_ADDR_PUBLIC   0x00
#define HCI_LE_FILTER_POLICY_ALL 0x00

// Enable/disable and duplicate-filtering flags.
#define HCI_LE_SCAN_ENABLE    0x01
#define HCI_LE_SCAN_DISABLE   0x00
#define HCI_LE_FILTER_DUP_OFF 0x00
#define HCI_LE_FILTER_DUP_ON  0x01

// Extended scanning PHY bit for LE 1M (the mandatory PHY).
#define HCI_LE_EXT_SCAN_PHY_1M 0x01

// Build "LE Set Scan Parameters" (legacy, 0x200b). `scan_type` is
// HCI_LE_SCAN_PASSIVE or HCI_LE_SCAN_ACTIVE. Returns packet length or -1.
ssize_t hci_build_le_scan_params(uint8_t *buf, size_t buf_len,
                                 uint8_t scan_type,
                                 uint16_t interval, uint16_t window,
                                 uint8_t own_addr_type, uint8_t filter_policy);

// Build "LE Set Scan Enable" (legacy, 0x200c). Returns packet length or -1.
ssize_t hci_build_le_scan_enable(uint8_t *buf, size_t buf_len,
                                 uint8_t enable, uint8_t filter_duplicates);

// Build "LE Set Extended Scan Parameters" (0x2041) for the LE 1M PHY.
// Returns packet length or -1.
ssize_t hci_build_le_ext_scan_params(uint8_t *buf, size_t buf_len,
                                     uint8_t scan_type,
                                     uint16_t interval, uint16_t window,
                                     uint8_t own_addr_type,
                                     uint8_t filter_policy);

// Build "LE Set Extended Scan Enable" (0x2042). `duration` and `period` are
// 0 for "scan until disabled". Returns packet length or -1.
ssize_t hci_build_le_ext_scan_enable(uint8_t *buf, size_t buf_len,
                                     uint8_t enable, uint8_t filter_duplicates,
                                     uint16_t duration, uint16_t period);

// Write a fully-built HCI command packet to the socket `fd`.
// Returns 0 on success, or -1 with errno set (EINVAL for bad arguments,
// EIO on a short write, or the underlying write() error).
int hci_send(int fd, const uint8_t *pkt, size_t len);

#endif // BLEURP_HCI_SCAN_H
