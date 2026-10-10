// ========================================
//  nom du fichier: hci_user_channel.c
//  description courte: Implementation of the HCI_CHANNEL_USER lifecycle and
//  packet senders. See hci_user_channel.h for the contract.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

#include "hci_user_channel.h"
#include "hci_wire.h"
#include "../hci_cmd.h"
#include "../mgmt.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

// AF_BLUETOOTH / BTPROTO_HCI / HCI_CHANNEL_USER, and the sockaddr_hci wire
// layout, defined locally like the rest of BLEURP's HCI plumbing so no
// libbluetooth-dev header is needed.
#define AF_BLUETOOTH_VAL     31
#define BTPROTO_HCI_VAL      1
#define HCI_CHANNEL_USER_VAL 1

struct sockaddr_hci_raw {
    uint16_t hci_family;
    uint16_t hci_dev;
    uint16_t hci_channel;
};

// Power the adapter on or off through BlueZ mgmt. Returns 0 only once mgmt
// confirmed the change with status 0x00; -1 on any socket/write/timeout
// failure or non-zero controller status (errno set on the former, EIO on
// the latter).
static int mgmt_set_powered(int dev_id, uint8_t powered) {
    int mfd = mgmt_open();
    if (mfd < 0) return -1;

    uint8_t cmd[16];
    ssize_t n = mgmt_build_command(cmd, sizeof cmd, MGMT_OP_SET_POWERED,
                                   (uint16_t)dev_id, &powered, 1);
    int rc = -1;
    if (n > 0 && write(mfd, cmd, (size_t)n) == n) {
        // The reply may be preceded by unrelated events: read a few.
        for (int i = 0; i < 5; i++) {
            struct pollfd pfd = { .fd = mfd, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, 500) <= 0) break;
            uint8_t rsp[64];
            ssize_t r = read(mfd, rsp, sizeof rsp);
            if (r <= 0) continue;

            uint16_t completed_opcode;
            uint8_t status;
            if (mgmt_parse_cmd_complete(rsp, (size_t)r, &completed_opcode, &status) == 0 &&
                completed_opcode == MGMT_OP_SET_POWERED) {
                rc = (status == 0x00) ? 0 : -1;
                if (rc < 0) errno = EIO;
                break;
            }
        }
    }
    mgmt_close(mfd);
    return rc;
}

// Open an HCI_CHANNEL_USER socket. See hci_user_channel.h for the contract.
int hci_user_channel_open(int dev_id) {
    (void)mgmt_set_powered(dev_id, 0);
    usleep(50000);

    int fd = socket(AF_BLUETOOTH_VAL, SOCK_RAW, BTPROTO_HCI_VAL);
    if (fd < 0) {
        int err = errno;
        (void)mgmt_set_powered(dev_id, 1);
        errno = err;
        return -1;
    }

    struct sockaddr_hci_raw sa;
    memset(&sa, 0, sizeof sa);
    sa.hci_family = AF_BLUETOOTH_VAL;
    sa.hci_dev = (uint16_t)dev_id;
    sa.hci_channel = HCI_CHANNEL_USER_VAL;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        int err = errno;
        close(fd);
        (void)mgmt_set_powered(dev_id, 1);
        errno = err;
        return -1;
    }
    return fd;
}

// Close the socket and re-power the adapter. See hci_user_channel.h.
void hci_user_channel_close(int fd, int dev_id) {
    if (fd >= 0) close(fd);
    (void)mgmt_set_powered(dev_id, 1);
}

// Map an open() errno to a diagnostic. See hci_user_channel.h.
const char *hci_user_channel_strerror(int err) {
    switch (err) {
    case EPERM:
    case EACCES:
        return "permission denied opening the HCI user channel -- run with "
               "sudo, or grant the binary cap_net_raw/cap_net_admin via "
               "'make setcap'";
    case EBUSY:
        return "adapter busy -- the kernel Bluetooth stack (bluetoothd) "
               "would not release it; stop it or free the adapter first";
    default:
        return "could not open the HCI user channel (see errno for detail)";
    }
}

// Send a raw HCI command. See hci_user_channel.h for the contract.
int hci_user_channel_send_cmd(int fd, uint16_t opcode,
                              const uint8_t *param, uint8_t param_len) {
    uint8_t buf[260]; // 4-byte header + up to 255 bytes of params
    ssize_t total = hci_build_command(buf, sizeof buf, opcode, param, param_len);
    if (total < 0) return -1;
    return (write(fd, buf, (size_t)total) == total) ? 0 : -1;
}

// Send a raw HCI command and wait for its result. See hci_user_channel.h.
int hci_user_channel_send_cmd_sync(int fd, uint16_t opcode,
                                   const uint8_t *param, uint8_t param_len,
                                   uint8_t *out_status) {
    if (hci_user_channel_send_cmd(fd, opcode, param, param_len) < 0) return -1;

    struct timeval start, now;
    gettimeofday(&start, NULL);
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = 2000 - (int)elapsed;
        if (remaining <= 0) return -1;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) return -1;

        uint8_t rsp[256];
        ssize_t n = read(fd, rsp, sizeof rsp);
        if (n < 3 || rsp[0] != HCI_EVENT_PKT) continue;

        if (rsp[1] == HCI_EV_CMD_COMPLETE && n >= 6) {
            // code(1) plen(1) ncmd(1) opcode(2) status(1) ...
            uint16_t op = (uint16_t)(rsp[4] | (rsp[5] << 8));
            if (op != opcode) continue;
            uint8_t status = (n >= 7) ? rsp[6] : 0xff;
            if (out_status) *out_status = status;
            return (status == 0x00) ? 0 : -1;
        }
        if (rsp[1] == HCI_EV_CMD_STATUS && n >= 7) {
            // code(1) plen(1) status(1) ncmd(1) opcode(2)
            uint16_t op = (uint16_t)(rsp[5] | (rsp[6] << 8));
            if (op != opcode) continue;
            uint8_t status = rsp[3];
            if (out_status) *out_status = status;
            return (status == 0x00) ? 0 : -1;
        }
    }
}

// Build one ACL/L2CAP PDU. See hci_user_channel.h for the contract.
int hci_user_channel_build_acl(uint8_t *out, size_t out_len,
                               uint16_t conn_handle, uint16_t cid,
                               const uint8_t *payload, uint16_t payload_len) {
    if (!out || (!payload && payload_len > 0)) {
        errno = EINVAL;
        return -1;
    }
    // HCI ACL header(5) + L2CAP header(4) + payload.
    size_t total = 5 + 4 + (size_t)payload_len;
    if (out_len < total) {
        errno = ENOSPC;
        return -1;
    }

    uint16_t acl_len = (uint16_t)(4 + payload_len); // bytes following the HCI ACL header (L2CAP header + payload)

    out[0] = HCI_ACLDATA_PKT;
    out[1] = (uint8_t)(conn_handle & 0xff);
    out[2] = (uint8_t)((conn_handle >> 8) & 0x0f); // PB=00b (first non-flushable), BC=00b
    out[3] = (uint8_t)(acl_len & 0xff);
    out[4] = (uint8_t)(acl_len >> 8);

    out[5] = (uint8_t)(payload_len & 0xff); // L2CAP length: the payload alone, not the header
    out[6] = (uint8_t)(payload_len >> 8);
    out[7] = (uint8_t)(cid & 0xff);
    out[8] = (uint8_t)(cid >> 8);

    if (payload_len > 0) memcpy(&out[9], payload, payload_len);
    return (int)total;
}

// Send one ACL/L2CAP PDU. See hci_user_channel.h for the contract.
int hci_user_channel_send_acl(int fd, uint16_t conn_handle, uint16_t cid,
                              const uint8_t *payload, uint16_t payload_len) {
    uint8_t buf[9 + 512];
    int total = hci_user_channel_build_acl(buf, sizeof buf, conn_handle, cid,
                                           payload, payload_len);
    if (total < 0) return -1;
    return (write(fd, buf, (size_t)total) == total) ? 0 : -1;
}

// Read the controller's own BD_ADDR. See hci_user_channel.h for the contract.
int hci_user_channel_read_bdaddr(int fd, uint8_t out[6]) {
    if (!out) {
        errno = EINVAL;
        return -1;
    }
    if (hci_user_channel_send_cmd(fd, HCI_OP_READ_BD_ADDR, NULL, 0) < 0) return -1;

    struct timeval start, now;
    gettimeofday(&start, NULL);
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = 2000 - (int)elapsed;
        if (remaining <= 0) return -1;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) return -1;

        uint8_t rsp[256];
        ssize_t n = read(fd, rsp, sizeof rsp);
        if (n < 13 || rsp[0] != HCI_EVENT_PKT || rsp[1] != HCI_EV_CMD_COMPLETE) continue;

        uint16_t op = (uint16_t)(rsp[4] | (rsp[5] << 8));
        if (op != HCI_OP_READ_BD_ADDR || rsp[6] != 0x00) continue;
        memcpy(out, &rsp[7], 6);
        return 0;
    }
}
