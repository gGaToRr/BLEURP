// ========================================
//  nom du fichier: smp.c
//  description courte: Implementation of the SMP codec and the re-pairing
//  downgrade probe. See smp.h for the contract and its scope/limits.
//  dernière modification : 2026-09-27
//  auteur: GitHub/@gGaToRr
// ========================================

#include "smp.h"

#include <errno.h>
#include <poll.h>
#include <unistd.h>

// Build a Pairing Request. See smp.h for the contract.
ssize_t smp_build_pairing_request(uint8_t *buf, size_t buf_len,
                                  const struct smp_pairing_params *p) {
    if (buf == NULL || p == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (buf_len < 7) {
        errno = ENOSPC;
        return -1;
    }
    buf[0] = SMP_CODE_PAIRING_REQUEST;
    buf[1] = p->io_capability;
    buf[2] = p->oob_data_flag;
    buf[3] = p->auth_req;
    buf[4] = p->max_key_size;
    buf[5] = p->init_key_dist;
    buf[6] = p->resp_key_dist;
    return 7;
}

// Build a Security Request. See smp.h for the contract.
ssize_t smp_build_security_request(uint8_t *buf, size_t buf_len,
                                   uint8_t auth_req) {
    if (buf == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (buf_len < 2) {
        errno = ENOSPC;
        return -1;
    }
    buf[0] = SMP_CODE_SECURITY_REQUEST;
    buf[1] = auth_req;
    return 2;
}

// Parse a Pairing Response. See smp.h for the contract.
int smp_parse_pairing_response(const uint8_t *pdu, size_t len,
                               struct smp_pairing_params *out) {
    if (pdu == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (len < 7 || pdu[0] != SMP_CODE_PAIRING_RESPONSE) {
        errno = EBADMSG;
        return -1;
    }
    out->io_capability = pdu[1];
    out->oob_data_flag = pdu[2];
    out->auth_req      = pdu[3];
    out->max_key_size  = pdu[4];
    out->init_key_dist = pdu[5];
    out->resp_key_dist = pdu[6];
    return 0;
}

// Parse a Pairing Failed reason code. See smp.h for the contract.
int smp_parse_pairing_failed(const uint8_t *pdu, size_t len, uint8_t *reason) {
    if (pdu == NULL || reason == NULL) {
        errno = EINVAL;
        return -1;
    }
    if (len < 2 || pdu[0] != SMP_CODE_PAIRING_FAILED) {
        errno = EBADMSG;
        return -1;
    }
    *reason = pdu[1];
    return 0;
}

// Send `req` and wait up to `timeout_ms` for one reply. Same shape as
// gatt.c's internal gatt_txn, duplicated here since SMP and ATT are
// separate fixed channels with their own small codecs.
static ssize_t smp_txn(int fd, const uint8_t *req, size_t req_len,
                       uint8_t *rsp, size_t rsp_cap, int timeout_ms) {
    if (write(fd, req, req_len) < 0) {
        return -1;
    }
    struct pollfd p = { .fd = fd, .events = POLLIN, .revents = 0 };
    int pr = poll(&p, 1, timeout_ms);
    if (pr <= 0) {
        if (pr == 0) errno = ETIMEDOUT;
        return -1;
    }
    return read(fd, rsp, rsp_cap);
}

// Run the downgrade probe. See smp.h for the contract.
smp_probe_t smp_downgrade_probe(int fd, int timeout_ms,
                                struct smp_pairing_params *out_response) {
    const struct smp_pairing_params weak = {
        .io_capability = SMP_IO_CAP_NO_INPUT_NO_OUTPUT,
        .oob_data_flag = 0,
        .auth_req      = SMP_AUTHREQ_BONDING, // bonding only: no MITM, no SC
        .max_key_size  = 7,                   // weakest allowed key size
        .init_key_dist = 0,
        .resp_key_dist = 0,
    };

    uint8_t req[7];
    ssize_t rl = smp_build_pairing_request(req, sizeof req, &weak);
    if (rl < 0) {
        return SMP_PROBE_NO_RESPONSE;
    }

    uint8_t rsp[64];
    ssize_t m = smp_txn(fd, req, (size_t)rl, rsp, sizeof rsp, timeout_ms);
    if (m < 2) {
        return SMP_PROBE_NO_RESPONSE;
    }

    if (rsp[0] == SMP_CODE_PAIRING_RESPONSE) {
        if (out_response) {
            struct smp_pairing_params parsed;
            if (smp_parse_pairing_response(rsp, (size_t)m, &parsed) == 0) {
                *out_response = parsed;
            }
        }
        return SMP_PROBE_RESPONDED;
    }
    if (rsp[0] == SMP_CODE_PAIRING_FAILED) {
        return SMP_PROBE_REJECTED;
    }
    return SMP_PROBE_NO_RESPONSE;
}
