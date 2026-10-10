// ========================================
//  nom du fichier: gatt.c
//  description courte: Implementation of the GATT client. Parses discovery
//  response elements into services/characteristics and drives the ATT
//  request/response loops (MTU exchange, service and characteristic walk).
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

#include "gatt.h"
#include "att.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <unistd.h>

// Read a little-endian 16-bit value.
static uint16_t rd_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

// Parse a service element. See gatt.h for the contract.
int gatt_parse_service(const uint8_t *elem, uint8_t elem_len,
                       struct gatt_service *out) {
    if (elem == NULL || out == NULL) { errno = EINVAL; return -1; }
    if (elem_len != 6 && elem_len != 20) { errno = EBADMSG; return -1; }

    memset(out, 0, sizeof *out);
    out->start_handle = rd_le16(&elem[0]);
    out->end_handle = rd_le16(&elem[2]);
    if (elem_len == 6) {
        out->uuid_is_128 = false;
        out->uuid16 = rd_le16(&elem[4]);
    } else {
        out->uuid_is_128 = true;
        memcpy(out->uuid128, &elem[4], 16);
    }
    return 0;
}

// Parse a characteristic element. See gatt.h for the contract.
int gatt_parse_characteristic(const uint8_t *elem, uint8_t elem_len,
                              struct gatt_char *out) {
    if (elem == NULL || out == NULL) { errno = EINVAL; return -1; }
    if (elem_len != 7 && elem_len != 21) { errno = EBADMSG; return -1; }

    memset(out, 0, sizeof *out);
    out->decl_handle = rd_le16(&elem[0]);
    out->properties = elem[2];
    out->value_handle = rd_le16(&elem[3]);
    if (elem_len == 7) {
        out->uuid_is_128 = false;
        out->uuid16 = rd_le16(&elem[5]);
    } else {
        out->uuid_is_128 = true;
        memcpy(out->uuid128, &elem[5], 16);
    }
    return 0;
}

// Send one ATT request and read the response, with a timeout.
static ssize_t gatt_txn(int fd, const uint8_t *req, size_t req_len,
                        uint8_t *rsp, size_t rsp_cap) {
    if (write(fd, req, req_len) < 0) {
        return -1;
    }
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    int pr = poll(&p, 1, 5000);
    if (pr <= 0) {
        if (pr == 0) errno = ETIMEDOUT;
        return -1;
    }
    return read(fd, rsp, rsp_cap);
}

// Exchange the ATT MTU. See gatt.h for the contract.
int gatt_exchange_mtu(int fd, uint16_t client_mtu, uint16_t *server_mtu) {
    uint8_t req[8];
    uint8_t rsp[8];
    ssize_t rl = att_build_exchange_mtu(req, sizeof req, client_mtu);
    if (rl < 0) return -1;
    ssize_t m = gatt_txn(fd, req, (size_t)rl, rsp, sizeof rsp);
    if (m < 0) return -1;
    uint16_t mtu;
    if (att_parse_exchange_mtu_rsp(rsp, (size_t)m, &mtu) < 0) return -1;
    if (server_mtu) *server_mtu = mtu;
    return 0;
}

// Discover primary services. See gatt.h for the contract.
int gatt_discover_services(int fd, struct gatt_service *out, size_t max,
                           size_t *count) {
    size_t n = 0;
    uint16_t start = 0x0001;
    uint8_t req[16];
    uint8_t rsp[512];

    for (;;) {
        ssize_t rl = att_build_read_by_group_type(req, sizeof req, start, 0xffff,
                                                  GATT_UUID_PRIMARY_SERVICE);
        if (rl < 0) return -1;
        ssize_t m = gatt_txn(fd, req, (size_t)rl, rsp, sizeof rsp);
        if (m < 1) return -1;
        if (rsp[0] == ATT_OP_ERROR_RSP) break; // Attribute Not Found: done
        if (rsp[0] != ATT_OP_READ_BY_GROUP_RSP) { errno = EBADMSG; return -1; }

        struct att_list it;
        if (att_list_begin(rsp, (size_t)m, &it) < 0) return -1;

        const uint8_t *el;
        uint16_t last_end = 0;
        while (att_list_next(&it, &el)) {
            struct gatt_service s;
            if (gatt_parse_service(el, it.elem_len, &s) == 0) {
                if (n < max) out[n] = s;
                n++;
                last_end = s.end_handle;
            }
        }
        if (last_end == 0 || last_end == 0xffff) break;
        start = (uint16_t)(last_end + 1);
    }

    if (count) *count = n;
    return 0;
}

// Parse a descriptor element. See gatt.h for the contract.
int gatt_parse_descriptor(const uint8_t *elem, uint8_t elem_len,
                          struct gatt_descriptor *out) {
    if (elem == NULL || out == NULL) { errno = EINVAL; return -1; }
    if (elem_len != 4 && elem_len != 18) { errno = EBADMSG; return -1; }

    memset(out, 0, sizeof *out);
    out->handle = rd_le16(&elem[0]);
    if (elem_len == 4) {
        out->uuid_is_128 = false;
        out->uuid16 = rd_le16(&elem[2]);
    } else {
        out->uuid_is_128 = true;
        memcpy(out->uuid128, &elem[2], 16);
    }
    return 0;
}

// Discover characteristics in a range. See gatt.h for the contract.
int gatt_discover_characteristics(int fd, uint16_t start, uint16_t end,
                                  struct gatt_char *out, size_t max,
                                  size_t *count) {
    size_t n = 0;
    uint16_t cur = start;
    uint8_t req[16];
    uint8_t rsp[512];

    for (;;) {
        if (cur > end) break;
        ssize_t rl = att_build_read_by_type(req, sizeof req, cur, end,
                                            GATT_UUID_CHARACTERISTIC);
        if (rl < 0) return -1;
        ssize_t m = gatt_txn(fd, req, (size_t)rl, rsp, sizeof rsp);
        if (m < 1) return -1;
        if (rsp[0] == ATT_OP_ERROR_RSP) break; // no more in range
        if (rsp[0] != ATT_OP_READ_BY_TYPE_RSP) { errno = EBADMSG; return -1; }

        struct att_list it;
        if (att_list_begin(rsp, (size_t)m, &it) < 0) return -1;

        const uint8_t *el;
        uint16_t last_handle = 0;
        while (att_list_next(&it, &el)) {
            struct gatt_char c;
            if (gatt_parse_characteristic(el, it.elem_len, &c) == 0) {
                if (n < max) out[n] = c;
                n++;
                last_handle = c.decl_handle;
            }
        }
        if (last_handle == 0 || last_handle >= end) break;
        cur = (uint16_t)(last_handle + 1);
    }

    if (count) *count = n;
    return 0;
}

// Discover descriptors in a range. See gatt.h for the contract.
int gatt_discover_descriptors(int fd, uint16_t start, uint16_t end,
                              struct gatt_descriptor *out, size_t max,
                              size_t *count) {
    size_t n = 0;
    uint16_t cur = start;
    uint8_t req[16];
    uint8_t rsp[512];

    for (;;) {
        if (cur > end) break;
        ssize_t rl = att_build_find_information(req, sizeof req, cur, end);
        if (rl < 0) return -1;
        ssize_t m = gatt_txn(fd, req, (size_t)rl, rsp, sizeof rsp);
        if (m < 1) return -1;
        if (rsp[0] == ATT_OP_ERROR_RSP) break;
        if (rsp[0] != ATT_OP_FIND_INFO_RSP) { errno = EBADMSG; return -1; }

        struct att_list it;
        if (att_findinfo_begin(rsp, (size_t)m, &it, NULL) < 0) return -1;

        const uint8_t *el;
        uint16_t last = 0;
        while (att_list_next(&it, &el)) {
            struct gatt_descriptor d;
            if (gatt_parse_descriptor(el, it.elem_len, &d) == 0) {
                if (n < max) out[n] = d;
                n++;
                last = d.handle;
            }
        }
        if (last == 0 || last >= end) break;
        cur = (uint16_t)(last + 1);
    }

    if (count) *count = n;
    return 0;
}

// Read a value by handle. See gatt.h for the contract.
int gatt_read(int fd, uint16_t handle, uint8_t *out, size_t cap,
              size_t *out_len, uint8_t *att_error) {
    if (att_error) *att_error = 0;
    uint8_t req[8];
    uint8_t rsp[600];
    ssize_t rl = att_build_read(req, sizeof req, handle);
    if (rl < 0) return -1;
    ssize_t m = gatt_txn(fd, req, (size_t)rl, rsp, sizeof rsp);
    if (m < 1) return -1;

    if (rsp[0] == ATT_OP_ERROR_RSP) {
        struct att_error e;
        if (att_parse_error(rsp, (size_t)m, &e) == 0 && att_error) *att_error = e.error_code;
        errno = EACCES;
        return -1;
    }
    if (rsp[0] != ATT_OP_READ_RSP) { errno = EBADMSG; return -1; }

    size_t vlen = (size_t)m - 1;
    if (out && cap > 0) {
        size_t copy = vlen < cap ? vlen : cap;
        memcpy(out, &rsp[1], copy);
    }
    if (out_len) *out_len = vlen;
    return 0;
}

// Write a value with acknowledgement. See gatt.h for the contract.
int gatt_write(int fd, uint16_t handle, const uint8_t *value, size_t len,
               uint8_t *att_error) {
    if (att_error) *att_error = 0;
    uint8_t req[600];
    uint8_t rsp[16];
    ssize_t rl = att_build_write(req, sizeof req, handle, value, len);
    if (rl < 0) return -1;
    ssize_t m = gatt_txn(fd, req, (size_t)rl, rsp, sizeof rsp);
    if (m < 1) return -1;

    if (rsp[0] == ATT_OP_ERROR_RSP) {
        struct att_error e;
        if (att_parse_error(rsp, (size_t)m, &e) == 0 && att_error) *att_error = e.error_code;
        errno = EACCES;
        return -1;
    }
    if (rsp[0] != ATT_OP_WRITE_RSP) { errno = EBADMSG; return -1; }
    return 0;
}

// Write a value without acknowledgement. See gatt.h for the contract.
int gatt_write_command(int fd, uint16_t handle, const uint8_t *value, size_t len) {
    uint8_t req[600];
    ssize_t rl = att_build_write_command(req, sizeof req, handle, value, len);
    if (rl < 0) return -1;
    return (write(fd, req, (size_t)rl) < 0) ? -1 : 0;
}

// Subscribe by writing the CCCD. See gatt.h for the contract.
int gatt_subscribe(int fd, uint16_t cccd_handle, bool indicate,
                   uint8_t *att_error) {
    uint8_t value[2];
    value[0] = indicate ? 0x02 : 0x01; // bit0 notify, bit1 indicate
    value[1] = 0x00;
    return gatt_write(fd, cccd_handle, value, sizeof value, att_error);
}

// Wait for a notification. See gatt.h for the contract.
int gatt_wait_notification(int fd, int timeout_ms, uint16_t *handle,
                           uint8_t *out, size_t cap, size_t *out_len) {
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    int pr = poll(&p, 1, timeout_ms);
    if (pr < 0) return -1;
    if (pr == 0) return 0; // timeout

    uint8_t rsp[600];
    ssize_t m = read(fd, rsp, sizeof rsp);
    if (m < 1) return -1;

    uint16_t h;
    const uint8_t *val;
    size_t vlen;
    if (att_parse_notification(rsp, (size_t)m, &h, &val, &vlen) < 0) {
        return 0; // not a notification (e.g. a response): ignore
    }
    if (handle) *handle = h;
    if (out && cap > 0 && val) {
        size_t copy = vlen < cap ? vlen : cap;
        memcpy(out, val, copy);
    }
    if (out_len) *out_len = vlen;
    return 1;
}
