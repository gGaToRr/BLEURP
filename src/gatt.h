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

// --- Pure parsers (unit tested) ---

// Parse one Read By Group Type Response element (elem_len 6 = 16-bit UUID,
// 20 = 128-bit) into a service. Returns 0, or -1 with errno (EINVAL/EBADMSG).
int gatt_parse_service(const uint8_t *elem, uint8_t elem_len,
                       struct gatt_service *out);

// Parse one Read By Type Response element (elem_len 7 = 16-bit UUID, 21 =
// 128-bit) into a characteristic. Returns 0, or -1 with errno.
int gatt_parse_characteristic(const uint8_t *elem, uint8_t elem_len,
                              struct gatt_char *out);

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

#endif // BLEURP_GATT_H
