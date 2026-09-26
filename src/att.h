// ========================================
//  nom du fichier: att.h
//  description courte: ATT protocol codec. Builds the request PDUs used for
//  GATT discovery and access (Exchange MTU, Read By Group Type, Read By Type,
//  Find Information, Read, Write, Write Command) and parses the responses we
//  need (Error Response, Exchange MTU, and grouped attribute lists).
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_ATT_H
#define BLEURP_ATT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h> // ssize_t

// ATT opcodes (Bluetooth Core, Attribute Protocol).
#define ATT_OP_ERROR_RSP         0x01
#define ATT_OP_EXCHANGE_MTU_REQ  0x02
#define ATT_OP_EXCHANGE_MTU_RSP  0x03
#define ATT_OP_FIND_INFO_REQ     0x04
#define ATT_OP_FIND_INFO_RSP     0x05
#define ATT_OP_READ_BY_TYPE_REQ  0x08
#define ATT_OP_READ_BY_TYPE_RSP  0x09
#define ATT_OP_READ_REQ          0x0a
#define ATT_OP_READ_RSP          0x0b
#define ATT_OP_READ_BY_GROUP_REQ 0x10
#define ATT_OP_READ_BY_GROUP_RSP 0x11
#define ATT_OP_WRITE_REQ         0x12
#define ATT_OP_WRITE_RSP         0x13
#define ATT_OP_WRITE_CMD         0x52
#define ATT_OP_HANDLE_VALUE_NTF  0x1b

// GATT attribute-type UUIDs used during discovery.
#define GATT_UUID_PRIMARY_SERVICE 0x2800
#define GATT_UUID_CHARACTERISTIC  0x2803
#define GATT_UUID_CCCD            0x2902

// Decoded ATT Error Response.
struct att_error {
    uint8_t  request_opcode; // the opcode that failed
    uint16_t handle;         // the attribute handle in error
    uint8_t  error_code;     // ATT error code
};

// Iterator over a grouped attribute list (Read By Type / Read By Group Type
// responses): a length byte followed by fixed-size elements.
struct att_list {
    const uint8_t *data;      // first element
    size_t         remaining; // bytes of elements available
    uint8_t        elem_len;  // size of each element
    size_t         pos;       // cursor
};

// --- Request builders (return packet length, or -1 with errno) ---
// errno is EINVAL for bad args, ENOSPC when buf is too small.

// Exchange MTU Request (0x02): propose a client RX MTU.
ssize_t att_build_exchange_mtu(uint8_t *buf, size_t buf_len, uint16_t mtu);

// Read By Group Type Request (0x10): discover grouping (e.g. primary services).
ssize_t att_build_read_by_group_type(uint8_t *buf, size_t buf_len,
                                     uint16_t start, uint16_t end, uint16_t uuid16);

// Read By Type Request (0x08): discover attributes of a type (e.g. chars).
ssize_t att_build_read_by_type(uint8_t *buf, size_t buf_len,
                               uint16_t start, uint16_t end, uint16_t uuid16);

// Find Information Request (0x04): list handles+UUIDs in a range (descriptors).
ssize_t att_build_find_information(uint8_t *buf, size_t buf_len,
                                   uint16_t start, uint16_t end);

// Read Request (0x0A): read a value by handle.
ssize_t att_build_read(uint8_t *buf, size_t buf_len, uint16_t handle);

// Write Request (0x12): write a value by handle, with acknowledgement.
ssize_t att_build_write(uint8_t *buf, size_t buf_len, uint16_t handle,
                        const uint8_t *value, size_t value_len);

// Write Command (0x52): write a value by handle, no acknowledgement.
ssize_t att_build_write_command(uint8_t *buf, size_t buf_len, uint16_t handle,
                                const uint8_t *value, size_t value_len);

// --- Response parsers (return 0, or -1 with errno) ---

// Parse an Error Response (0x01). errno EBADMSG if not an error PDU.
int att_parse_error(const uint8_t *pdu, size_t len, struct att_error *out);

// Parse an Exchange MTU Response (0x03) into *mtu.
int att_parse_exchange_mtu_rsp(const uint8_t *pdu, size_t len, uint16_t *mtu);

// Begin iterating a Read By Type / Read By Group Type response's element list.
// Returns 0 on success, or -1 with errno (EINVAL/EBADMSG).
int att_list_begin(const uint8_t *pdu, size_t len, struct att_list *it);

// Advance the iterator: sets *elem to the next element and returns 1, or
// returns 0 when the list is exhausted. Element size is `it->elem_len`.
int att_list_next(struct att_list *it, const uint8_t **elem);

// Begin iterating a Find Information Response (0x05). Sets the iterator's
// element size from the format byte (1 = handle+uuid16 = 4 bytes, 2 =
// handle+uuid128 = 18 bytes) and, if non-NULL, *format. Returns 0 or -1.
int att_findinfo_begin(const uint8_t *pdu, size_t len, struct att_list *it,
                       uint8_t *format);

// Parse a Handle Value Notification (0x1B): the attribute handle and a
// pointer/length into the value. Returns 0, or -1 with errno (EINVAL/EBADMSG).
int att_parse_notification(const uint8_t *pdu, size_t len, uint16_t *handle,
                           const uint8_t **value, size_t *value_len);

#endif // BLEURP_ATT_H
