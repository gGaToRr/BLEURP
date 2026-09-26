// ========================================
//  nom du fichier: hci_info.c
//  description courte: Implementation of controller-information helpers.
//  Validates and decodes the Read Local Version Command Complete event, and
//  derives extended advertising support from the reported HCI version.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "hci_info.h"
#include "hci.h"

#include <errno.h>

// Read a little-endian 16-bit value from a byte pointer.
static uint16_t rd_le16(const uint8_t *p) {
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

// Full Command Complete event for Read Local Version is 14 bytes:
// code(1) len(1) num_cmd(1) opcode(2) status(1) version(1) revision(2)
// lmp_version(1) manufacturer(2) lmp_subversion(2).
#define HCI_LOCAL_VERSION_EVT_LEN 14

// Parse a Read Local Version Command Complete event. See hci_info.h.
int hci_parse_local_version(const uint8_t *evt, size_t len,
                            struct hci_local_version *out) {
    if (evt == NULL || out == NULL) {
        errno = EINVAL;
        return -1;
    }

    // Reject anything that is not a complete, matching event.
    if (len < HCI_LOCAL_VERSION_EVT_LEN ||
        evt[0] != HCI_EVT_CMD_COMPLETE ||
        rd_le16(&evt[3]) != HCI_OP_READ_LOCAL_VERSION) {
        errno = EBADMSG;
        return -1;
    }

    out->status         = evt[5];
    out->hci_version    = evt[6];
    out->hci_revision   = rd_le16(&evt[7]);
    out->lmp_version    = evt[9];
    out->manufacturer   = rd_le16(&evt[10]);
    out->lmp_subversion = rd_le16(&evt[12]);
    return 0;
}

// Decide extended support from the HCI version. See hci_info.h.
bool hci_supports_extended(const struct hci_local_version *v) {
    if (v == NULL) {
        return false;
    }
    return v->hci_version >= HCI_VER_BT_5_0;
}
