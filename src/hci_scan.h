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

#include <stdbool.h>
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

// Scan mode, chosen from the controller's capabilities (see hci_info).
enum hci_scan_mode {
    HCI_SCAN_MODE_LEGACY   = 0, // BT 4.x controllers
    HCI_SCAN_MODE_EXTENDED = 1, // BT 5.x controllers
};

// Start scanning: send the scan parameters, then enable. The mode selects
// the legacy or extended command set (a switch/case for controller
// compatibility). `scan_type` is HCI_LE_SCAN_PASSIVE or _ACTIVE.
// Returns 0 on success, or -1 with errno set (EINVAL on an unknown mode).
int hci_scan_start(int fd, enum hci_scan_mode mode, uint8_t scan_type);

// Stop scanning for the given mode. Returns 0 or -1 with errno set.
int hci_scan_stop(int fd, enum hci_scan_mode mode);

// One advertising report, normalized across legacy and extended formats.
// `data` points into the caller's event buffer and is valid only for the
// duration of the callback. `address` is in HCI order (little-endian).
struct hci_adv_report {
    bool           extended;   // true if from an extended report
    uint16_t       event_type; // legacy: low byte only
    uint8_t        addr_type;  // 0 public, 1 random, ...
    uint8_t        address[6]; // device address, HCI byte order
    int8_t         rssi;       // dBm
    const uint8_t *data;       // advertising data (AD structures)
    uint8_t        data_len;   // length of `data`
};

// Callback invoked once per advertising report found in an event.
typedef void (*hci_adv_cb)(const struct hci_adv_report *report, void *user);

// Parse one HCI event and invoke `cb` for each advertising report it holds.
// `evt` points at the event code byte (packet type indicator stripped).
// Non-advertising events are ignored (returns 0). Returns the number of
// reports dispatched, or -1 with errno set:
//   EINVAL  - evt or cb is NULL
//   EBADMSG - a truncated or malformed advertising report
int hci_dispatch_event(const uint8_t *evt, size_t len,
                       hci_adv_cb cb, void *user);

#endif // BLEURP_HCI_SCAN_H
