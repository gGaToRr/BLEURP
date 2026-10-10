// ========================================
//  nom du fichier: repair.c
//  description courte: Re-pairing check (BLERP, NDSS 2026). Parses the bond
//  BlueZ stores per device, lists bonded devices, and classifies the peer's
//  reply to a pairing weaker than that bond. Negotiation only, no key ever
//  leaves this module.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#include "repair.h"
#include "../mgmt.h"

#include <dirent.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Largest BlueZ info file we are willing to read (they are a few hundred bytes).
#define BOND_INFO_MAX 16384

// True when `line` starts with `key`. Used for "Key=value" lines.
static bool line_starts(const char *line, const char *key) {
    return strncmp(line, key, strlen(key)) == 0;
}

// Parse the text of a BlueZ info file. See repair.h for the contract.
int smp_bond_parse(const char *info_text, struct smp_bond_info *out) {
    if (!info_text || !out) {
        errno = EINVAL;
        return -1;
    }

    bool seen_ltk = false;   // an LE LTK section was found
    bool in_ltk = false;     // we are inside the first LTK section
    bool have_enc = false;   // its EncSize line was read
    bool authenticated = false;
    uint8_t enc_size = 0;

    const char *p = info_text;
    while (*p) {
        const char *eol = strchr(p, '\n');
        size_t len = eol ? (size_t)(eol - p) : strlen(p);
        char line[256];
        if (len >= sizeof line) len = sizeof line - 1;
        memcpy(line, p, len);
        line[len] = '\0';
        p = eol ? eol + 1 : p + len;

        if (line[0] == '[') {
            // New section: only the first LE LTK section is of interest.
            in_ltk = (!seen_ltk &&
                      (line_starts(line, "[LongTermKey]") ||
                       line_starts(line, "[SlaveLongTermKey]")));
            if (in_ltk) seen_ltk = true;
            continue;
        }
        if (!in_ltk) continue;

        if (line_starts(line, "Authenticated=")) {
            authenticated = line_starts(line, "Authenticated=1");
        } else if (line_starts(line, "EncSize=")) {
            long v = strtol(line + strlen("EncSize="), NULL, 10);
            if (v < 0 || v > 255) v = 0;
            enc_size = (uint8_t)v;
            have_enc = true;
        }
    }

    if (!seen_ltk) {
        errno = ENOENT;
        return -1;
    }
    if (!have_enc || enc_size < 7 || enc_size > 16) {
        errno = EBADMSG;
        return -1;
    }
    out->authenticated = authenticated;
    out->enc_size = enc_size;
    return 0;
}

// Build "<store>/<adapter>/<device>/info" into `path`. Returns 0 or -1 (ENAMETOOLONG).
static int bond_info_path(char *path, size_t cap, const char *store_dir,
                          const char *adapter_addr, const char *device_addr) {
    int n = snprintf(path, cap, "%s/%s/%s/info", store_dir, adapter_addr, device_addr);
    if (n < 0 || (size_t)n >= cap) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

// Load and parse a bond. See repair.h for the contract.
int smp_bond_load(const char *store_dir, const char *adapter_addr,
                  const char *device_addr, struct smp_bond_info *out) {
    if (!store_dir || !adapter_addr || !device_addr || !out) {
        errno = EINVAL;
        return -1;
    }

    char path[512];
    if (bond_info_path(path, sizeof path, store_dir, adapter_addr, device_addr) < 0) {
        return -1;
    }

    FILE *f = fopen(path, "r");
    if (!f) {
        return -1; // errno is already EACCES or ENOENT from fopen
    }
    char text[BOND_INFO_MAX];
    size_t n = fread(text, 1, sizeof text - 1, f);
    int saved = ferror(f) ? EIO : 0;
    fclose(f);
    if (saved) {
        errno = saved;
        return -1;
    }
    text[n] = '\0';
    return smp_bond_parse(text, out);
}

// True when `s` looks like a BlueZ directory name "AA:BB:CC:DD:EE:FF".
static bool is_bdaddr_dirname(const char *s) {
    if (strlen(s) != 17) return false;
    for (int i = 0; i < 17; i++) {
        if (i % 3 == 2) {
            if (s[i] != ':') return false;
        } else if (!((s[i] >= '0' && s[i] <= '9') ||
                     (s[i] >= 'A' && s[i] <= 'F'))) {
            return false;
        }
    }
    return true;
}

// List bonded device directories. See repair.h for the contract.
int smp_bond_list(const char *store_dir, const char *adapter_addr,
                  char (*out)[18], int max) {
    if (!store_dir || !adapter_addr || !out || max <= 0) {
        errno = EINVAL;
        return -1;
    }

    char path[512];
    int n = snprintf(path, sizeof path, "%s/%s", store_dir, adapter_addr);
    if (n < 0 || (size_t)n >= sizeof path) {
        errno = ENAMETOOLONG;
        return -1;
    }

    DIR *d = opendir(path);
    if (!d) {
        return -1; // errno from opendir (EACCES, ENOENT)
    }
    int count = 0;
    struct dirent *e;
    while (count < max && (e = readdir(d)) != NULL) {
        if (!is_bdaddr_dirname(e->d_name)) continue;
        memcpy(out[count], e->d_name, 18);
        count++;
    }
    closedir(d);
    return count;
}

// Read the adapter address with mgmt Read Controller Information. sysfs has
// no "address" file on current kernels, so the mgmt control socket is used.
// See repair.h for the contract.
int smp_adapter_addr(int dev_id, char out[18]) {
    if (!out || dev_id < 0) {
        errno = EINVAL;
        return -1;
    }
    int fd = mgmt_open();
    if (fd < 0) return -1;

    uint8_t cmd[8];
    ssize_t cl = mgmt_build_command(cmd, sizeof cmd, MGMT_OP_READ_CONTROLLER_INFO,
                                    (uint16_t)dev_id, NULL, 0);
    int rc = -1;
    if (cl > 0 && write(fd, cmd, (size_t)cl) == cl) {
        // The reply can follow unrelated events: read a few before giving up.
        for (int i = 0; i < 8; i++) {
            struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, 1000) <= 0) break;
            uint8_t rsp[512];
            ssize_t r = read(fd, rsp, sizeof rsp);
            if (r < 0) break;
            struct mgmt_controller_info info;
            if (mgmt_parse_controller_info(rsp, (size_t)r, &info) == 0) {
                // The parser returns the address in HCI (little-endian) order.
                snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
                         info.address[5], info.address[4], info.address[3],
                         info.address[2], info.address[1], info.address[0]);
                rc = 0;
                break;
            }
            if (errno == EIO) break; // mgmt refused the command
        }
    }
    mgmt_close(fd);
    if (rc < 0) errno = ENODEV;
    return rc;
}

// Classify the peer's reply. See repair.h for the contract.
void smp_repair_classify(const struct smp_bond_info *bond,
                         const struct smp_pairing_params *offer,
                         const struct smp_probe_result *res,
                         struct smp_repair_verdict *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    out->outcome = SMP_REPAIR_NO_REPLY;
    if (!bond || !offer || !res || !res->success) return;

    if (res->pairing_failed) {
        out->outcome = SMP_REPAIR_REFUSED;
        out->fail_reason = res->fail_reason;
        return;
    }

    // Negotiated MITM is the OR of both sides: an authenticated bond is
    // downgraded when neither side asks for MITM any more.
    bool mitm_negotiated = (offer->auth_req & SMP_AUTHREQ_MITM) != 0 ||
                           (res->auth_req & SMP_AUTHREQ_MITM) != 0;
    out->mitm_downgrade = bond->authenticated && !mitm_negotiated;

    // Negotiated key size is the minimum of both maxima. A peer that sends
    // no usable maximum is judged on our own offer alone.
    uint8_t peer_key = res->max_key_size ? res->max_key_size : offer->max_key_size;
    uint8_t negotiated_key = peer_key < offer->max_key_size ? peer_key : offer->max_key_size;
    out->entropy_downgrade = negotiated_key < bond->enc_size;

    out->outcome = (out->mitm_downgrade || out->entropy_downgrade)
                       ? SMP_REPAIR_ACCEPTED_DOWNGRADE
                       : SMP_REPAIR_ACCEPTED_SAFE;
}

// Verdicts. See repair.h for the contract.
const char *blerp_verdict_label(enum blerp_verdict v) {
    switch (v) {
    case BLERP_VERDICT_YES:  return "OUI";
    case BLERP_VERDICT_NO:   return "NON";
    case BLERP_VERDICT_INCONCLUSIVE: return "NON CONCLUANT";
    }
    return "NON CONCLUANT";
}

enum blerp_verdict smp_repair_verdict_v2(const struct smp_repair_verdict *v) {
    if (!v) return BLERP_VERDICT_INCONCLUSIVE;
    switch (v->outcome) {
    case SMP_REPAIR_ACCEPTED_DOWNGRADE:
    case SMP_REPAIR_ACCEPTED_SAFE:
        return BLERP_VERDICT_YES;
    case SMP_REPAIR_REFUSED:
    case SMP_REPAIR_NO_REPLY:
        return BLERP_VERDICT_INCONCLUSIVE;
    }
    return BLERP_VERDICT_INCONCLUSIVE;
}

enum blerp_verdict smp_repair_verdict_v4(bool bond_authenticated,
                                         const struct smp_repair_verdict *v) {
    if (!v || !bond_authenticated) return BLERP_VERDICT_INCONCLUSIVE;
    if (v->outcome == SMP_REPAIR_REFUSED) {
        return v->fail_reason == 0x03 ? BLERP_VERDICT_NO : BLERP_VERDICT_INCONCLUSIVE;
    }
    if (v->outcome == SMP_REPAIR_ACCEPTED_DOWNGRADE || v->outcome == SMP_REPAIR_ACCEPTED_SAFE) {
        return v->mitm_downgrade ? BLERP_VERDICT_YES : BLERP_VERDICT_NO;
    }
    return BLERP_VERDICT_INCONCLUSIVE;
}

enum blerp_verdict smp_repair_verdict_v6(const struct smp_repair_verdict *v) {
    if (!v) return BLERP_VERDICT_INCONCLUSIVE;
    if (v->outcome == SMP_REPAIR_REFUSED) {
        return v->fail_reason == 0x06 ? BLERP_VERDICT_NO : BLERP_VERDICT_INCONCLUSIVE;
    }
    if (v->outcome == SMP_REPAIR_ACCEPTED_DOWNGRADE || v->outcome == SMP_REPAIR_ACCEPTED_SAFE) {
        return v->entropy_downgrade ? BLERP_VERDICT_YES : BLERP_VERDICT_NO;
    }
    return BLERP_VERDICT_INCONCLUSIVE;
}
