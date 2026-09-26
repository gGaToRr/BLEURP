// ========================================
//  nom du fichier: mgmt.h
//  description courte: Kernel BlueZ management (mgmt) interface. Opens the
//  HCI control socket and builds/parses mgmt packets, so BLEURP can drive
//  device discovery through the kernel (clean, coexists with bluetoothd)
//  rather than raw HCI. No D-Bus and no external binary.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_MGMT_H
#define BLEURP_MGMT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> // ssize_t

// mgmt message header size: opcode(2) + index(2) + length(2).
#define MGMT_HDR_SIZE 6

// Controller index meaning "no specific controller".
#define MGMT_INDEX_NONE 0xffff

// mgmt command opcodes (subset used by BLEURP).
#define MGMT_OP_READ_CONTROLLER_INFO 0x0004
#define MGMT_OP_SET_POWERED          0x0005
#define MGMT_OP_START_DISCOVERY      0x0023
#define MGMT_OP_STOP_DISCOVERY       0x0024

// mgmt event codes.
#define MGMT_EV_CMD_COMPLETE 0x0001
#define MGMT_EV_CMD_STATUS   0x0002
#define MGMT_EV_DEVICE_FOUND 0x0012

// Discovery address-type bitmask (Start/Stop Discovery parameter).
#define MGMT_ADDR_BIT_BREDR     0x01
#define MGMT_ADDR_BIT_LE_PUBLIC 0x02
#define MGMT_ADDR_BIT_LE_RANDOM 0x04
#define MGMT_ADDR_LE (MGMT_ADDR_BIT_LE_PUBLIC | MGMT_ADDR_BIT_LE_RANDOM) // 0x06

// Device address type (Device Found event field).
#define MGMT_ADDR_TYPE_BREDR     0x00
#define MGMT_ADDR_TYPE_LE_PUBLIC 0x01
#define MGMT_ADDR_TYPE_LE_RANDOM 0x02

// Controller settings bitmask (Supported_Settings / Current_Settings).
#define MGMT_SETTING_POWERED      (1u << 0)
#define MGMT_SETTING_CONNECTABLE  (1u << 1)
#define MGMT_SETTING_FAST_CONN    (1u << 2)
#define MGMT_SETTING_DISCOVERABLE (1u << 3)
#define MGMT_SETTING_BONDABLE     (1u << 4)
#define MGMT_SETTING_LINK_SEC     (1u << 5)
#define MGMT_SETTING_SSP          (1u << 6)
#define MGMT_SETTING_BREDR        (1u << 7)
#define MGMT_SETTING_HS           (1u << 8)
#define MGMT_SETTING_LE           (1u << 9)  // Low Energy supported/enabled
#define MGMT_SETTING_ADVERTISING  (1u << 10)
#define MGMT_SETTING_SECURE_CONN  (1u << 11)
#define MGMT_SETTING_DEBUG_KEYS   (1u << 12)
#define MGMT_SETTING_PRIVACY      (1u << 13)
#define MGMT_SETTING_STATIC_ADDR  (1u << 15)

// Length of the Read Controller Information return parameters.
#define MGMT_CONTROLLER_INFO_PARAM_LEN 280

// Decoded mgmt message header (command or event).
struct mgmt_hdr {
    uint16_t opcode; // command opcode, or event code for events
    uint16_t index;  // controller index, or MGMT_INDEX_NONE
    uint16_t len;    // parameter length that follows the header
};

// Minimum Device Found parameter length: address(6) type(1) rssi(1)
// flags(4) eir_len(2), before the variable EIR/AD data.
#define MGMT_DEVICE_FOUND_MIN_PARAMS 14

// One device reported by a Device Found event. `eir` points into the
// caller's event buffer and is valid only while that buffer lives.
struct mgmt_device {
    uint8_t        address[6]; // BD_ADDR (little-endian, HCI order)
    uint8_t        addr_type;  // MGMT_ADDR_TYPE_*
    int8_t         rssi;       // dBm
    uint32_t       flags;      // mgmt device flags
    const uint8_t *eir;        // EIR/AD data, or NULL if empty
    uint16_t       eir_len;    // length of `eir`
};

// Callback invoked for each device parsed from a Device Found event.
typedef void (*mgmt_device_cb)(const struct mgmt_device *dev, void *user);

// Decoded Read Controller Information reply.
struct mgmt_controller_info {
    uint8_t  address[6];         // BD_ADDR (little-endian, HCI order)
    uint8_t  bluetooth_version;  // HCI version value
    uint16_t manufacturer;       // company identifier
    uint32_t supported_settings; // MGMT_SETTING_* the controller can do
    uint32_t current_settings;   // MGMT_SETTING_* currently active
    uint8_t  dev_class[3];       // class of device
    char     name[250];          // complete local name (NUL-terminated)
    char     short_name[12];     // short local name (NUL-terminated)
};

// Build a mgmt command packet into `buf`.
// Wire layout (all 16-bit fields little-endian):
//   opcode(2) index(2) param_len(2) params...
// `params` may be NULL only when `param_len` is 0.
// Returns the total number of bytes written (6 + param_len), or -1 with
// errno set (EINVAL for bad args, ENOSPC when buf is too small).
ssize_t mgmt_build_command(uint8_t *buf, size_t buf_len,
                           uint16_t opcode, uint16_t index,
                           const uint8_t *params, uint16_t param_len);

// Parse the 6-byte mgmt header from `buf` into `out`.
// Returns 0 on success, or -1 with errno set (EINVAL if buf/out is NULL,
// EBADMSG if fewer than MGMT_HDR_SIZE bytes are available).
int mgmt_parse_header(const uint8_t *buf, size_t len, struct mgmt_hdr *out);

// Build a Start Discovery command for `index` with an address-type bitmask
// (e.g. MGMT_ADDR_LE). Returns packet length or -1.
ssize_t mgmt_build_start_discovery(uint8_t *buf, size_t buf_len,
                                   uint16_t index, uint8_t addr_type_mask);

// Build a Stop Discovery command (same address-type bitmask as started).
// Returns packet length or -1.
ssize_t mgmt_build_stop_discovery(uint8_t *buf, size_t buf_len,
                                  uint16_t index, uint8_t addr_type_mask);

// Parse a Device Found event into `out`. `evt` points at the start of the
// mgmt event (header included). Returns 0 on success, or -1 with errno set
// (EINVAL if evt/out is NULL, EBADMSG if not a Device Found or truncated).
int mgmt_parse_device_found(const uint8_t *evt, size_t len,
                            struct mgmt_device *out);

// Parse one mgmt event and, if it is a Device Found, invoke `cb`. Other
// events are ignored. Returns 1 when a device was dispatched, 0 when the
// event was ignored, or -1 with errno set (EINVAL for NULL evt/cb, EBADMSG
// for a malformed Device Found).
int mgmt_dispatch_event(const uint8_t *evt, size_t len,
                        mgmt_device_cb cb, void *user);

// Test whether a settings bitmask has a given MGMT_SETTING_* flag.
bool mgmt_has_setting(uint32_t settings, uint32_t flag);

// Parse a Read Controller Information reply (a Command Complete event for
// opcode 0x0004) into `out`. `evt` points at the start of the mgmt event
// (header included). Returns 0 on success, or -1 with errno set:
//   EINVAL  - evt or out is NULL
//   EBADMSG - not a matching Command Complete, or truncated
//   EIO     - the command reported a non-zero status
int mgmt_parse_controller_info(const uint8_t *evt, size_t len,
                               struct mgmt_controller_info *out);

// Open the kernel mgmt control socket (HCI_CHANNEL_CONTROL). Returns a file
// descriptor, or -1 with errno set (e.g. EPERM without CAP_NET_ADMIN).
int mgmt_open(void);

// Close a socket returned by mgmt_open. Returns 0 or -1 with errno.
int mgmt_close(int fd);

#endif // BLEURP_MGMT_H
