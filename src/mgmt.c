// ========================================
//  nom du fichier: mgmt.c
//  description courte: Implementation of the mgmt packet layer. Serializes
//  and parses the little-endian mgmt header, and opens the kernel control
//  socket on HCI_CHANNEL_CONTROL (index MGMT_INDEX_NONE).
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE // for SOCK_CLOEXEC

#include "mgmt.h"
#include "hci_dev.h" // socket constants + struct sockaddr_hci

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

// Write a little-endian 16-bit value into a byte buffer.
static void wr_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0x00ff);
    p[1] = (uint8_t)((v >> 8) & 0x00ff);
}

// Read a little-endian 16-bit value from a byte buffer.
static uint16_t rd_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

// Read a little-endian 32-bit value from a byte buffer.
static uint32_t rd_le32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

// Copy a fixed-width, possibly non-terminated name field into a NUL-
// terminated destination of size `dst_size` (dst_size > field_len).
static void copy_name(char *dst, size_t dst_size,
                      const uint8_t *field, size_t field_len) {
    memcpy(dst, field, field_len);
    dst[field_len < dst_size ? field_len : dst_size - 1] = '\0';
}

// Build a mgmt command packet. See mgmt.h for the contract.
ssize_t mgmt_build_command(uint8_t *buf, size_t buf_len,
                           uint16_t opcode, uint16_t index,
                           const uint8_t *params, uint16_t param_len) {
    if (buf == NULL || (param_len > 0 && params == NULL)) {
        errno = EINVAL;
        return -1;
    }

    const size_t total = (size_t)MGMT_HDR_SIZE + param_len;
    if (buf_len < total) {
        errno = ENOSPC;
        return -1;
    }

    wr_le16(&buf[0], opcode);
    wr_le16(&buf[2], index);
    wr_le16(&buf[4], param_len);
    if (param_len > 0) {
        memcpy(&buf[6], params, param_len);
    }
    return (ssize_t)total;
}

// Parse a mgmt header. See mgmt.h for the contract.
int mgmt_parse_header(const uint8_t *buf, size_t len, struct mgmt_hdr *out) {
    if (buf == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (len < MGMT_HDR_SIZE) {
        errno = EBADMSG;
        return -1;
    }
    out->opcode = rd_le16(&buf[0]);
    out->index  = rd_le16(&buf[2]);
    out->len    = rd_le16(&buf[4]);
    return 0;
}

// Test a settings bitmask for a flag. See mgmt.h for the contract.
bool mgmt_has_setting(uint32_t settings, uint32_t flag) {
    return (settings & flag) != 0;
}

// Build a Start Discovery command. See mgmt.h for the contract.
ssize_t mgmt_build_start_discovery(uint8_t *buf, size_t buf_len,
                                   uint16_t index, uint8_t addr_type_mask) {
    uint8_t p[1] = { addr_type_mask };
    return mgmt_build_command(buf, buf_len, MGMT_OP_START_DISCOVERY,
                              index, p, sizeof p);
}

// Build a Stop Discovery command. See mgmt.h for the contract.
ssize_t mgmt_build_stop_discovery(uint8_t *buf, size_t buf_len,
                                  uint16_t index, uint8_t addr_type_mask) {
    uint8_t p[1] = { addr_type_mask };
    return mgmt_build_command(buf, buf_len, MGMT_OP_STOP_DISCOVERY,
                              index, p, sizeof p);
}

// Build a Set Static Address command. See mgmt.h for the contract.
ssize_t mgmt_build_set_static_address(uint8_t *buf, size_t buf_len,
                                      uint16_t index, const uint8_t addr[6]) {
    if (addr == NULL) {
        errno = EINVAL;
        return -1;
    }
    return mgmt_build_command(buf, buf_len, MGMT_OP_SET_STATIC_ADDRESS,
                              index, addr, 6);
}

// Parse a Device Found event. See mgmt.h for the contract.
int mgmt_parse_device_found(const uint8_t *evt, size_t len,
                            struct mgmt_device *out) {
    if (evt == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }

    struct mgmt_hdr h;
    if (mgmt_parse_header(evt, len, &h) < 0) {
        return -1; // errno already set
    }
    if (h.opcode != MGMT_EV_DEVICE_FOUND) {
        errno = EBADMSG;
        return -1;
    }
    if (h.len < MGMT_DEVICE_FOUND_MIN_PARAMS ||
        len < MGMT_HDR_SIZE + MGMT_DEVICE_FOUND_MIN_PARAMS) {
        errno = EBADMSG;
        return -1;
    }

    const uint8_t *p = evt + MGMT_HDR_SIZE;
    uint16_t eir_len = rd_le16(p + 12);

    // The declared EIR length must fit inside both the event and the buffer.
    if ((size_t)MGMT_DEVICE_FOUND_MIN_PARAMS + eir_len > h.len ||
        MGMT_HDR_SIZE + (size_t)MGMT_DEVICE_FOUND_MIN_PARAMS + eir_len > len) {
        errno = EBADMSG;
        return -1;
    }

    memcpy(out->address, p, 6);
    out->addr_type = p[6];
    out->rssi = (int8_t)p[7];
    out->flags = rd_le32(p + 8);
    out->eir_len = eir_len;
    out->eir = (eir_len > 0) ? (p + MGMT_DEVICE_FOUND_MIN_PARAMS) : NULL;
    return 0;
}

// Dispatch a device from one mgmt event. See mgmt.h for the contract.
int mgmt_dispatch_event(const uint8_t *evt, size_t len,
                        mgmt_device_cb cb, void *user) {
    if (evt == NULL || cb == NULL) {
        errno = EINVAL;
        return -1;
    }

    struct mgmt_hdr h;
    if (mgmt_parse_header(evt, len, &h) < 0) {
        return -1; // errno already set
    }
    if (h.opcode != MGMT_EV_DEVICE_FOUND) {
        return 0; // not a device event: ignore
    }

    struct mgmt_device dev;
    if (mgmt_parse_device_found(evt, len, &dev) < 0) {
        return -1;
    }
    cb(&dev, user);
    return 1;
}

// Parse a Read Controller Information reply. See mgmt.h for the contract.
int mgmt_parse_controller_info(const uint8_t *evt, size_t len,
                               struct mgmt_controller_info *out) {
    if (evt == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }

    struct mgmt_hdr h;
    if (mgmt_parse_header(evt, len, &h) < 0) {
        return -1; // errno already set
    }
    if (h.opcode != MGMT_EV_CMD_COMPLETE) {
        errno = EBADMSG;
        return -1;
    }

    // Command Complete params: cmd_opcode(2) status(1) return_params(280).
    const size_t body = 3 + (size_t)MGMT_CONTROLLER_INFO_PARAM_LEN;
    if (h.len < body || len < MGMT_HDR_SIZE + body) {
        errno = EBADMSG;
        return -1;
    }

    const uint8_t *p = evt + MGMT_HDR_SIZE;
    uint16_t cmd_opcode = rd_le16(p);
    uint8_t status = p[2];
    if (cmd_opcode != MGMT_OP_READ_CONTROLLER_INFO) {
        errno = EBADMSG;
        return -1;
    }
    if (status != 0x00) {
        errno = EIO; // controller reported a failure
        return -1;
    }

    const uint8_t *r = p + 3; // return parameters
    memcpy(out->address, r, 6);
    out->bluetooth_version  = r[6];
    out->manufacturer       = rd_le16(r + 7);
    out->supported_settings = rd_le32(r + 9);
    out->current_settings   = rd_le32(r + 13);
    memcpy(out->dev_class, r + 17, 3);
    copy_name(out->name, sizeof out->name, r + 20, 249);
    copy_name(out->short_name, sizeof out->short_name, r + 269, 11);
    return 0;
}

// Open the kernel mgmt control socket. See mgmt.h for the contract.
int mgmt_open(void) {
    struct sockaddr_hci addr;
    memset(&addr, 0, sizeof addr);
    addr.hci_family = BLEURP_AF_BLUETOOTH;
    addr.hci_dev = MGMT_INDEX_NONE; // control socket is not per-adapter
    addr.hci_channel = BLEURP_HCI_CHANNEL_CONTROL;

    int fd = socket(BLEURP_AF_BLUETOOTH, SOCK_RAW | SOCK_CLOEXEC,
                    BLEURP_BTPROTO_HCI);
    if (fd < 0) {
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

// Close a mgmt socket. See mgmt.h for the contract.
int mgmt_close(int fd) {
    return close(fd);
}
