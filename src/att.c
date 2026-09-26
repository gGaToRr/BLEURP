// ========================================
//  nom du fichier: att.c
//  description courte: Implementation of the ATT codec. Serializes request
//  PDUs with little-endian fields, parses the Error and Exchange MTU
//  responses, and iterates grouped attribute lists with bounds checks.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "att.h"

#include <errno.h>
#include <string.h>

// Write a little-endian 16-bit value.
static void wr_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0x00ff);
    p[1] = (uint8_t)((v >> 8) & 0x00ff);
}

// Read a little-endian 16-bit value.
static uint16_t rd_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

// Build a request with two 16-bit handles then a 16-bit type UUID.
static ssize_t build_range_type(uint8_t *buf, size_t buf_len, uint8_t opcode,
                                uint16_t start, uint16_t end, uint16_t uuid16) {
    if (buf == NULL) { errno = EINVAL; return -1; }
    if (buf_len < 7) { errno = ENOSPC; return -1; }
    buf[0] = opcode;
    wr_le16(&buf[1], start);
    wr_le16(&buf[3], end);
    wr_le16(&buf[5], uuid16);
    return 7;
}

// Exchange MTU Request. See att.h.
ssize_t att_build_exchange_mtu(uint8_t *buf, size_t buf_len, uint16_t mtu) {
    if (buf == NULL) { errno = EINVAL; return -1; }
    if (buf_len < 3) { errno = ENOSPC; return -1; }
    buf[0] = ATT_OP_EXCHANGE_MTU_REQ;
    wr_le16(&buf[1], mtu);
    return 3;
}

// Read By Group Type Request. See att.h.
ssize_t att_build_read_by_group_type(uint8_t *buf, size_t buf_len,
                                     uint16_t start, uint16_t end, uint16_t uuid16) {
    return build_range_type(buf, buf_len, ATT_OP_READ_BY_GROUP_REQ, start, end, uuid16);
}

// Read By Type Request. See att.h.
ssize_t att_build_read_by_type(uint8_t *buf, size_t buf_len,
                               uint16_t start, uint16_t end, uint16_t uuid16) {
    return build_range_type(buf, buf_len, ATT_OP_READ_BY_TYPE_REQ, start, end, uuid16);
}

// Find Information Request. See att.h.
ssize_t att_build_find_information(uint8_t *buf, size_t buf_len,
                                   uint16_t start, uint16_t end) {
    if (buf == NULL) { errno = EINVAL; return -1; }
    if (buf_len < 5) { errno = ENOSPC; return -1; }
    buf[0] = ATT_OP_FIND_INFO_REQ;
    wr_le16(&buf[1], start);
    wr_le16(&buf[3], end);
    return 5;
}

// Read Request. See att.h.
ssize_t att_build_read(uint8_t *buf, size_t buf_len, uint16_t handle) {
    if (buf == NULL) { errno = EINVAL; return -1; }
    if (buf_len < 3) { errno = ENOSPC; return -1; }
    buf[0] = ATT_OP_READ_REQ;
    wr_le16(&buf[1], handle);
    return 3;
}

// Shared builder for Write Request / Write Command.
static ssize_t build_write(uint8_t *buf, size_t buf_len, uint8_t opcode,
                           uint16_t handle, const uint8_t *value, size_t value_len) {
    if (buf == NULL || (value_len > 0 && value == NULL)) {
        errno = EINVAL;
        return -1;
    }
    const size_t total = (size_t)3 + value_len;
    if (buf_len < total) { errno = ENOSPC; return -1; }
    buf[0] = opcode;
    wr_le16(&buf[1], handle);
    if (value_len > 0) { memcpy(&buf[3], value, value_len); }
    return (ssize_t)total;
}

// Write Request. See att.h.
ssize_t att_build_write(uint8_t *buf, size_t buf_len, uint16_t handle,
                        const uint8_t *value, size_t value_len) {
    return build_write(buf, buf_len, ATT_OP_WRITE_REQ, handle, value, value_len);
}

// Write Command. See att.h.
ssize_t att_build_write_command(uint8_t *buf, size_t buf_len, uint16_t handle,
                                const uint8_t *value, size_t value_len) {
    return build_write(buf, buf_len, ATT_OP_WRITE_CMD, handle, value, value_len);
}

// Parse an Error Response. See att.h.
int att_parse_error(const uint8_t *pdu, size_t len, struct att_error *out) {
    if (pdu == NULL || out == NULL) { errno = EINVAL; return -1; }
    if (len < 5 || pdu[0] != ATT_OP_ERROR_RSP) { errno = EBADMSG; return -1; }
    out->request_opcode = pdu[1];
    out->handle = rd_le16(&pdu[2]);
    out->error_code = pdu[4];
    return 0;
}

// Parse an Exchange MTU Response. See att.h.
int att_parse_exchange_mtu_rsp(const uint8_t *pdu, size_t len, uint16_t *mtu) {
    if (pdu == NULL || mtu == NULL) { errno = EINVAL; return -1; }
    if (len < 3 || pdu[0] != ATT_OP_EXCHANGE_MTU_RSP) { errno = EBADMSG; return -1; }
    *mtu = rd_le16(&pdu[1]);
    return 0;
}

// Begin iterating a grouped list response. See att.h.
int att_list_begin(const uint8_t *pdu, size_t len, struct att_list *it) {
    if (pdu == NULL || it == NULL) { errno = EINVAL; return -1; }
    if (len < 2 || pdu[1] == 0) { errno = EBADMSG; return -1; }
    it->elem_len = pdu[1];
    it->data = &pdu[2];
    it->remaining = len - 2;
    it->pos = 0;
    return 0;
}

// Advance the iterator. See att.h.
int att_list_next(struct att_list *it, const uint8_t **elem) {
    if (it == NULL || elem == NULL) { return 0; }
    if (it->pos + it->elem_len > it->remaining) { return 0; }
    *elem = it->data + it->pos;
    it->pos += it->elem_len;
    return 1;
}
