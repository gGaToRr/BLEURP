// ========================================
//  nom du fichier: gatt.h
//  description courte: GATT client over a connected ATT socket. Parses the
//  discovery responses into services and characteristics, and drives the
//  request/response loops to walk a device's GATT database.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_GATT_H
#define BLEURP_GATT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// Characteristic property bits (GATT).
#define GATT_PROP_BROADCAST    0x01
#define GATT_PROP_READ         0x02
#define GATT_PROP_WRITE_NR     0x04
#define GATT_PROP_WRITE        0x08
#define GATT_PROP_NOTIFY       0x10
#define GATT_PROP_INDICATE     0x20
#define GATT_PROP_SIGNED_WRITE 0x40
#define GATT_PROP_EXTENDED     0x80

// A primary service in the GATT database.
struct gatt_service {
    uint16_t start_handle;
    uint16_t end_handle;
    bool     uuid_is_128;
    uint16_t uuid16;       // valid when !uuid_is_128
    uint8_t  uuid128[16];  // valid when uuid_is_128
};

// A characteristic declaration.
struct gatt_char {
    uint16_t decl_handle;
    uint8_t  properties;
    uint16_t value_handle;
    bool     uuid_is_128;
    uint16_t uuid16;
    uint8_t  uuid128[16];
};

// A characteristic descriptor (e.g. the CCCD, UUID 0x2902).
struct gatt_descriptor {
    uint16_t handle;
    bool     uuid_is_128;
    uint16_t uuid16;
    uint8_t  uuid128[16];
};

// --- Pure parsers (unit tested) ---

// Parse one Read By Group Type Response element (elem_len 6 = 16-bit UUID,
// 20 = 128-bit) into a service. Returns 0, or -1 with errno (EINVAL/EBADMSG).
int gatt_parse_service(const uint8_t *elem, uint8_t elem_len,
                       struct gatt_service *out);

// Parse one Read By Type Response element (elem_len 7 = 16-bit UUID, 21 =
// 128-bit) into a characteristic. Returns 0, or -1 with errno.
int gatt_parse_characteristic(const uint8_t *elem, uint8_t elem_len,
                              struct gatt_char *out);

// Parse one Find Information Response element (elem_len 4 = 16-bit UUID, 18 =
// 128-bit) into a descriptor. Returns 0, or -1 with errno.
int gatt_parse_descriptor(const uint8_t *elem, uint8_t elem_len,
                          struct gatt_descriptor *out);

// --- Discovery over a connected ATT socket (`fd` from bleurp_l2_connect) ---

// Exchange the ATT MTU. Returns 0 and sets *server_mtu, or -1 with errno.
int gatt_exchange_mtu(int fd, uint16_t client_mtu, uint16_t *server_mtu);

// Discover all primary services. Writes up to `max` into `out`, sets *count
// to the number found (which may exceed `max`). Returns 0 or -1 with errno.
int gatt_discover_services(int fd, struct gatt_service *out, size_t max,
                           size_t *count);

// Discover characteristics within a handle range (a service). Same output
// convention as gatt_discover_services.
int gatt_discover_characteristics(int fd, uint16_t start, uint16_t end,
                                  struct gatt_char *out, size_t max,
                                  size_t *count);

// Discover descriptors (Find Information) within a handle range.
int gatt_discover_descriptors(int fd, uint16_t start, uint16_t end,
                              struct gatt_descriptor *out, size_t max,
                              size_t *count);

// --- Read / write / subscribe on authorized devices ---

// Read a characteristic/descriptor value by handle. On success writes up to
// `cap` bytes into `out` and sets *out_len. On an ATT Error Response, sets
// *att_error (if non-NULL) to the ATT error code and returns -1 (errno
// EACCES). Other failures return -1 with errno set.
int gatt_read(int fd, uint16_t handle, uint8_t *out, size_t cap,
              size_t *out_len, uint8_t *att_error);

// Write a value with acknowledgement (Write Request). Same ATT error
// convention as gatt_read. Returns 0 on the Write Response.
int gatt_write(int fd, uint16_t handle, const uint8_t *value, size_t len,
               uint8_t *att_error);

// Write a value without acknowledgement (Write Command). Returns 0 or -1.
int gatt_write_command(int fd, uint16_t handle, const uint8_t *value,
                       size_t len);

// Subscribe to notifications (or indications) by writing the CCCD handle.
int gatt_subscribe(int fd, uint16_t cccd_handle, bool indicate,
                   uint8_t *att_error);

// Wait for a Handle Value Notification up to `timeout_ms`. On success sets
// *handle and copies up to `cap` bytes into `out` (*out_len). Returns 1 when
// one arrived, 0 on timeout, or -1 with errno.
int gatt_wait_notification(int fd, int timeout_ms, uint16_t *handle,
                           uint8_t *out, size_t cap, size_t *out_len);

#endif // BLEURP_GATT_H
