// ==============================================================================
//  nom du fichier: smp_native.c
//  description courte: Implémentation du module natif SMP via HCI_CHANNEL_USER.
//  Permet de forger des requêtes SMP directement sur l'interface HCI sans
//  l'interférence du gestionnaire de sécurité du noyau Linux. Chaque étape
//  (connexion LE, réponse SMP) remonte un statut précis au lieu d'un timeout
//  générique, pour que l'utilisateur sache où la sonde s'est arrêtée.
// ==============================================================================

#define _GNU_SOURCE

#include "smp_native.h"
#include "secreq.h"
#include "../ui.h"
#include "../mgmt.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>

#define AF_BLUETOOTH_VAL   31
#define BTPROTO_HCI_VAL    1
#define HCI_CHANNEL_USER_VAL 1

// Adresses BLEURP (voir l2cap.h) : 1 = LE Public, 2 = LE Random
#define SMP_NATIVE_ATYPE_PUBLIC 1
#define SMP_NATIVE_ATYPE_RANDOM 2

#define HCI_COMMAND_PKT    0x01
#define HCI_ACLDATA_PKT    0x02
#define HCI_EVENT_PKT      0x04

#define HCI_EV_CMD_COMPLETE  0x0e
#define HCI_EV_CMD_STATUS    0x0f
#define HCI_EV_DISCONN_COMPL 0x05
#define HCI_EV_LE_META       0x3e

#define HCI_LE_EV_CONN_COMPL 0x01
#define HCI_LE_EV_CONN_COMPL_ENH 0x0a

#define HCI_OP_RESET                 0x0c03
#define HCI_OP_LE_SET_EVENT_MASK     0x2001
#define HCI_OP_LE_CREATE_CONN        0x200d
#define HCI_OP_LE_CREATE_CONN_CANCEL 0x200e
#define HCI_OP_DISCONNECT            0x0406
#define HCI_OP_LE_SET_ADV_PARAMS     0x2006
#define HCI_OP_LE_SET_ADV_DATA       0x2008
#define HCI_OP_LE_SET_ADV_ENABLE     0x200a

#define HCI_LE_EV_LTK_REQUEST        0x05

#define SMP_OP_SECURITY_REQ          0x0b

#define LE_CREATE_CONN_PARAM_LEN 25

#define SMP_CID_VAL         0x0006
#define SMP_OP_PAIRING_REQ  0x01
#define SMP_OP_PAIRING_RSP  0x02
#define SMP_OP_PAIRING_CONFIRM 0x03
#define SMP_OP_PAIRING_FAIL 0x05
#define SMP_OP_PUBLIC_KEY   0x0c

#define HCI_OP_LE_LTK_NEG_REPLY 0x201b

struct sockaddr_hci_raw {
    uint16_t hci_family;
    uint16_t hci_dev;
    uint16_t hci_channel;
};

// Power the adapter on or off through the BlueZ mgmt control socket. Returns
// 0 only when mgmt confirmed the change; -1 when the socket failed or mgmt
// refused (typically missing CAP_NET_ADMIN, i.e. run without sudo/setcap).
static int mgmt_set_powered(int dev_id, uint8_t powered) {
    int mfd = mgmt_open();
    if (mfd < 0) return -1;

    uint8_t cmd[16];
    ssize_t n = mgmt_build_command(cmd, sizeof(cmd), MGMT_OP_SET_POWERED,
                                   (uint16_t)dev_id, &powered, 1);
    int rc = -1;
    if (n > 0 && write(mfd, cmd, (size_t)n) == n) {
        // The reply may be preceded by unrelated events: read a few.
        for (int i = 0; i < 5; i++) {
            struct pollfd pfd = { .fd = mfd, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, 500) <= 0) break;
            uint8_t rsp[64];
            ssize_t r = read(mfd, rsp, sizeof rsp);
            if (r < 9) continue;
            // Header is 6 bytes (event, index, length), then opcode + status.
            uint16_t ev = (uint16_t)(rsp[0] | (rsp[1] << 8));
            uint16_t op = (uint16_t)(rsp[6] | (rsp[7] << 8));
            if (ev == MGMT_EV_CMD_COMPLETE && op == MGMT_OP_SET_POWERED) {
                rc = (rsp[8] == 0x00) ? 0 : -1;
                break;
            }
        }
    }
    mgmt_close(mfd);
    return rc;
}

// Close the HCI socket and power the adapter back on for the rest of the system.
static void probe_teardown(int fd, int dev_id) {
    close(fd);
    (void)mgmt_set_powered(dev_id, 1);
}

// Envoi d'une commande HCI brute (sans attendre l'acquittement)
static int hci_send_cmd(int fd, uint16_t opcode, const uint8_t *param, uint8_t plen) {
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
    return 0;
}

// Envoi d'un paquet ACL contenant une trame SMP
static int send_smp_packet(int fd, uint16_t conn_handle, const uint8_t *smp_payload, uint16_t smp_len) {
    uint8_t pkt[256];
    uint16_t l2cap_len = smp_len;
    uint16_t acl_len = (uint16_t)(4 + l2cap_len);

    pkt[0] = HCI_ACLDATA_PKT;
    // Handle (12 bits) + PB flag (2 bits = 00b First non-flushable) + BC (2 bits = 00b)
    pkt[1] = (uint8_t)(conn_handle & 0xff);
    pkt[2] = (uint8_t)(((conn_handle >> 8) & 0x0f) | 0x00); // PB=00b (first non-automatically-flushable, usual on LE)
    pkt[3] = (uint8_t)(acl_len & 0xff);
    pkt[4] = (uint8_t)(acl_len >> 8);

    // L2CAP Header (Length 2 bytes + CID 2 bytes)
    pkt[5] = (uint8_t)(l2cap_len & 0xff);
    pkt[6] = (uint8_t)(l2cap_len >> 8);
    pkt[7] = (uint8_t)(SMP_CID_VAL & 0xff);
    pkt[8] = (uint8_t)(SMP_CID_VAL >> 8);

    // SMP Payload
    memcpy(&pkt[9], smp_payload, smp_len);

    ssize_t total = 9 + smp_len;
    return (write(fd, pkt, (size_t)total) == total) ? 0 : -1;
}

// Parse an HCI Command Status event. See smp_native.h for the contract.
int smp_parse_cmd_status(const uint8_t *evt, size_t len,
                         uint16_t *opcode, uint8_t *status) {
    if (!evt || !opcode || !status) {
        errno = EINVAL;
        return -1;
    }
    // Layout: code (0x0f), parameter length, status, num cmd packets, opcode.
    if (len < 6 || evt[0] != HCI_EV_CMD_STATUS) {
        errno = EBADMSG;
        return -1;
    }
    *status = evt[2];
    *opcode = (uint16_t)(evt[4] | (evt[5] << 8));
    return 0;
}

// Build the LE Create Connection parameters. See smp_native.h for the contract.
int smp_le_create_conn_params(uint8_t out[25], uint8_t bleurp_atype,
                              const uint8_t addr[6]) {
    if (!out || !addr) {
        errno = EINVAL;
        return -1;
    }
    if (bleurp_atype != SMP_NATIVE_ATYPE_PUBLIC &&
        bleurp_atype != SMP_NATIVE_ATYPE_RANDOM) {
        errno = EINVAL;
        return -1;
    }
    memset(out, 0, LE_CREATE_CONN_PARAM_LEN);
    out[0] = 0x60; out[1] = 0x00; // Scan Interval (60ms)
    out[2] = 0x60; out[3] = 0x00; // Scan Window (60ms = 100% duty cycle, no dropped advs)
    out[4] = 0x00;                // Filter Policy: use the given address
    // HCI peer address type: 0x00 = public, 0x01 = random
    out[5] = (bleurp_atype == SMP_NATIVE_ATYPE_RANDOM) ? 0x01 : 0x00;
    memcpy(&out[6], addr, 6);     // Peer addr
    out[12] = 0x00;               // Own addr type (public)
    out[13] = 0x18; out[14] = 0x00; // Conn interval min (30ms)
    out[15] = 0x28; out[16] = 0x00; // Conn interval max (50ms)
    out[17] = 0x00; out[18] = 0x00; // Latency
    out[19] = 0xf4; out[20] = 0x01; // Supervision timeout (5000ms, avoids jitter disconnects)
    return 0;
}

// Default offer of the native probes: the weakest pairing, with LTK
// distribution on both sides (the bytes this module has always sent).
static void native_default_offer(struct smp_pairing_params *out) {
    smp_weak_offer(out);
    out->init_key_dist = 0x01;
    out->resp_key_dist = 0x01;
}

// Probe with the default offer. See smp_native.h for the contract.
int smp_native_probe_device(int dev_id, const uint8_t target_addr[6],
                            uint8_t addr_type, int timeout_ms,
                            struct smp_probe_result *out_result) {
    struct smp_pairing_params offer;
    native_default_offer(&offer);
    return smp_native_probe_offer(dev_id, target_addr, addr_type, timeout_ms,
                                  &offer, out_result);
}

// Default offer for callers that need the same bytes as the native probe.
void smp_native_default_offer(struct smp_pairing_params *out) {
    if (out) native_default_offer(out);
}

// Probe with a caller-chosen offer. See smp_native.h for the contract.
int smp_native_probe_offer(int dev_id, const uint8_t target_addr[6],
                           uint8_t addr_type, int timeout_ms,
                           const struct smp_pairing_params *offer,
                           struct smp_probe_result *out_result) {
    if (!target_addr || !offer || !out_result) {
        errno = EINVAL;
        return -1;
    }
    memset(out_result, 0, sizeof(*out_result));
    out_result->link = SMP_LINK_UNKNOWN;

    // Si l'adaptateur est actif dans le noyau Linux, bind(HCI_CHANNEL_USER) échoue avec EBUSY.
    // On met l'adaptateur temporairement en sommeil via BlueZ mgmt.
    if (mgmt_set_powered(dev_id, 0) < 0) {
        fprintf(stderr, "  [!] Extinction de hci%d refusée ou impossible via BlueZ mgmt : lancez avec sudo ou 'make setcap'.\n", dev_id);
    }
    usleep(50000);

    int fd = socket(AF_BLUETOOTH_VAL, SOCK_RAW, BTPROTO_HCI_VAL);
    if (fd < 0) {
        int err = errno;
        (void)mgmt_set_powered(dev_id, 1);
        if (err == EPERM || err == EACCES) {
            fprintf(stderr, "  [!] Permission refusée pour ouvrir la socket HCI. Exécutez 'make setcap' ou 'sudo ./build/bleurp ...'\n");
        }
        errno = err;
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
        (void)mgmt_set_powered(dev_id, 1);
        if (err == EPERM || err == EACCES) {
            fprintf(stderr, "  [!] Permission refusée pour bind(HCI_CHANNEL_USER). Exécutez 'make setcap' ou 'sudo ./build/bleurp ...'\n");
        } else if (err == EBUSY) {
            fprintf(stderr, "  [!] Adaptateur hci%d occupé par un autre processus ou verrouillé par le système.\n", dev_id);
        } else {
            fprintf(stderr, "  [!] Échec bind(HCI_CHANNEL_USER) sur hci%d: %s (code %d)\n", dev_id, strerror(err), err);
        }
        errno = err;
        return -1;
    }

    // 1. Initialisation du contrôleur (HCI Reset)
    printf("  [*] Initialisation du contrôleur hci%d (HCI Reset)...\n", dev_id);
    hci_send_cmd(fd, HCI_OP_RESET, NULL, 0);
    usleep(80000);

    // 2. Configuration des masques d'événements
    uint8_t le_mask[8] = {0xff, 0x1f, 0x0a, 0x03, 0, 0, 0, 0};
    hci_send_cmd(fd, HCI_OP_LE_SET_EVENT_MASK, le_mask, 8);

    // 3. Demande de connexion LE (LE Create Connection 0x200D)
    printf("  [*] Envoi de la requête de connexion Link Layer vers la cible...\n");
    uint8_t conn_param[LE_CREATE_CONN_PARAM_LEN];
    smp_le_create_conn_params(conn_param, addr_type, target_addr);

    if (hci_send_cmd(fd, HCI_OP_LE_CREATE_CONN, conn_param, LE_CREATE_CONN_PARAM_LEN) < 0) {
        out_result->link = SMP_LINK_HCI_ERROR;
        probe_teardown(fd, dev_id);
        return 0;
    }

    // 4. Attente de la connexion effective. Le contrôleur répond d'abord par
    //    un Command Status (refus immédiat possible), puis par un LE
    //    Connection Complete (legacy 0x01 ou enhanced 0x0A).
    uint16_t conn_handle = 0;
    bool connected = false;
    struct timeval cstart, cnow;
    gettimeofday(&cstart, NULL);

    while (!connected) {
        gettimeofday(&cnow, NULL);
        long elapsed = (cnow.tv_sec - cstart.tv_sec) * 1000 + (cnow.tv_usec - cstart.tv_usec) / 1000;
        int remaining = timeout_ms - (int)elapsed;
        if (remaining <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) break;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 3 || pkt[0] != HCI_EVENT_PKT) continue;

        if (pkt[1] == HCI_EV_CMD_STATUS) {
            uint16_t op = 0;
            uint8_t st = 0;
            if (smp_parse_cmd_status(&pkt[1], (size_t)n - 1, &op, &st) == 0 &&
                op == HCI_OP_LE_CREATE_CONN && st != 0x00) {
                out_result->link = SMP_LINK_HCI_ERROR;
                out_result->hci_status = st;
                break;
            }
            continue;
        }

        if (pkt[1] == HCI_EV_LE_META && n >= 5 &&
            (pkt[3] == HCI_LE_EV_CONN_COMPL || pkt[3] == HCI_LE_EV_CONN_COMPL_ENH)) {
            if (pkt[4] == 0x00 && n >= 7) {
                conn_handle = (uint16_t)((pkt[5] | (pkt[6] << 8)) & 0x0fff);
                connected = true;
            } else {
                out_result->link = SMP_LINK_HCI_ERROR;
                out_result->hci_status = pkt[4];
                break;
            }
        }
    }

    if (!connected) {
        if (out_result->link != SMP_LINK_HCI_ERROR) {
            // Stop the pending connection so the controller does not keep trying.
            (void)hci_send_cmd(fd, HCI_OP_LE_CREATE_CONN_CANCEL, NULL, 0);
            usleep(20000);
            out_result->link = SMP_LINK_NOT_FOUND;
        }
        probe_teardown(fd, dev_id);
        return 0;
    }

    out_result->link = SMP_LINK_UP;
    printf("  %s[+] Liaison Link Layer établie ! Handle = 0x%04x%s\n", UI_GREEN, conn_handle, UI_RESET);

    // 5. Envoi de la Pairing Request de l'offre choisie par l'appelant
    printf("  [*] Envoi du paquet SMP Pairing Request (AuthReq=0x%02x, KeySize=%u)...\n",
           offer->auth_req, offer->max_key_size);
    uint8_t pairing_req[7];
    ssize_t rl = smp_build_pairing_request(pairing_req, sizeof pairing_req, offer);
    if (rl < 0 || send_smp_packet(fd, conn_handle, pairing_req, (uint16_t)rl) < 0) {
        probe_teardown(fd, dev_id);
        return 0;
    }

    // 6. Attente de la réponse SMP de la cible (ACL Data packet)
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = timeout_ms - (int)elapsed;
        if (remaining <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) break;

        uint8_t acl_buf[1024];
        ssize_t n = read(fd, acl_buf, sizeof acl_buf);
        if (n < 9) continue;

        if (acl_buf[0] == HCI_ACLDATA_PKT) {
            uint16_t l2cap_cid = (uint16_t)(acl_buf[7] | (acl_buf[8] << 8));
            if (l2cap_cid == SMP_CID_VAL) {
                uint8_t smp_op = acl_buf[9];
                if (smp_op == SMP_OP_PAIRING_RSP && n >= 16) {
                    out_result->success = true;
                    out_result->io_capability = acl_buf[10];
                    out_result->oob_data_flag = acl_buf[11];
                    out_result->auth_req      = acl_buf[12];
                    out_result->max_key_size  = acl_buf[13];
                    out_result->init_key_dist = acl_buf[14];
                    out_result->resp_key_dist = acl_buf[15];
                    break;
                } else if (smp_op == SMP_OP_PAIRING_FAIL && n >= 11) {
                    out_result->success = true;
                    out_result->pairing_failed = true;
                    out_result->fail_reason = acl_buf[10];
                    break;
                }
            }
        }
    }

    // 7. Déconnexion propre
    uint8_t disconn_param[3] = { (uint8_t)(conn_handle & 0xff), (uint8_t)(conn_handle >> 8), 0x13 };
    hci_send_cmd(fd, HCI_OP_DISCONNECT, disconn_param, 3);
    usleep(20000);

    probe_teardown(fd, dev_id);
    return 0;
}

// Short French label for the HCI status codes a LE connection can return.
static const char *hci_status_label(uint8_t st) {
    switch (st) {
    case 0x08: return "Connection Timeout";
    case 0x0c: return "Command Disallowed (adaptateur occupé ou mal initialisé ?)";
    case 0x12: return "Invalid HCI Command Parameters";
    case 0x3e: return "Connection Failed to be Established";
    default:   return "voir Core Spec, Vol 2 Part D";
    }
}

// Peripheral-side Security Request test (BLERP, Apple finding). Advertises as
// connectable under our own public address with a plain name (no keyboard
// profile), waits for a Central to connect, sends one SMP Security Request
// with `arsr`, and records the first reaction: a Pairing Request, an LTK
// request, or nothing. The link is then closed: no key is exchanged and no
// pairing is completed. Returns 0 when the test ran, -1 when the adapter
// could not be used (errno set). See smp_native.h for the contract.
// Wait up to wait_ms for the controller's LE LTK Request on `handle`. Returns
// true when it arrives. Other events are skipped.
static bool wait_ltk_request(int fd, uint16_t handle, int wait_ms) {
    struct timeval start, now;
    gettimeofday(&start, NULL);
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = wait_ms - (int)elapsed;
        if (remaining <= 0) return false;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) return false;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 6 || pkt[0] != HCI_EVENT_PKT || pkt[1] != HCI_EV_LE_META) continue;
        if (pkt[3] == HCI_LE_EV_LTK_REQUEST && (uint16_t)(pkt[4] | (pkt[5] << 8)) == handle) {
            return true;
        }
    }
}

// Answer the Central's Pairing Request once with a weaker AuthReq than the
// Security Request asked for: bonding only, no MITM, no SC, key size 16. Only
// the response is sent; no public key or confirm value follows, so nothing is
// derived and no pairing completes.
static void send_downgraded_rsp(int fd, uint16_t handle) {
    uint8_t rsp[7] = {
        SMP_OP_PAIRING_RSP,
        0x03,   // IO capability: NoInputNoOutput
        0x00,   // OOB data: none
        0x01,   // AuthReq: bonding only (no MITM, no SC)
        0x10,   // max key size: 16
        0x00,   // initiator key distribution: none
        0x00,   // responder key distribution: none
    };
    send_smp_packet(fd, handle, rsp, sizeof rsp);
}

int smp_native_secreq_probe(int dev_id, uint8_t arsr, enum secreq_mode mode,
                            const char *adv_name, int wait_conn_ms, int wait_react_ms,
                            struct secreq_observation *obs) {
    if (!obs) {
        errno = EINVAL;
        return -1;
    }
    memset(obs, 0, sizeof *obs);

    // Advertising data: length byte, then up to 31 bytes of AD structures.
    uint8_t adv_buf[31];
    size_t alen = secreq_build_adv(adv_name, adv_buf, sizeof adv_buf);
    if (alen == 0) {
        errno = EINVAL;
        return -1;
    }
    uint8_t adv_data[32];
    memset(adv_data, 0, sizeof adv_data);
    adv_data[0] = (uint8_t)alen;
    memcpy(&adv_data[1], adv_buf, alen);

    if (mgmt_set_powered(dev_id, 0) < 0) {
        fprintf(stderr, "  [!] Extinction de hci%d refusée ou impossible via BlueZ mgmt : lancez avec sudo ou 'make setcap'.\n", dev_id);
    }
    usleep(50000);

    int fd = socket(AF_BLUETOOTH_VAL, SOCK_RAW, BTPROTO_HCI_VAL);
    if (fd < 0) {
        int err = errno;
        (void)mgmt_set_powered(dev_id, 1);
        errno = err;
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
        (void)mgmt_set_powered(dev_id, 1);
        fprintf(stderr, "  [!] bind(HCI_CHANNEL_USER) sur hci%d : %s\n", dev_id, strerror(err));
        errno = err;
        return -1;
    }

    // Controller setup: reset, then the LE event mask (connection complete
    // and LTK request must be reported).
    hci_send_cmd(fd, HCI_OP_RESET, NULL, 0);
    usleep(80000);
    uint8_t le_mask[8] = {0xff, 0x1f, 0x0a, 0x03, 0, 0, 0, 0};
    hci_send_cmd(fd, HCI_OP_LE_SET_EVENT_MASK, le_mask, 8);

    // Advertising parameters: ADV_IND (connectable, undirected), 40 ms
    // interval, public own address, all three channels.
    uint8_t adv_params[15] = {
        0x40, 0x00,             // interval min (40 ms)
        0x40, 0x00,             // interval max (40 ms)
        0x00,                   // ADV_IND
        0x00,                   // own address type: public
        0x00,                   // peer address type (unused for ADV_IND)
        0, 0, 0, 0, 0, 0,       // peer address (unused for ADV_IND)
        0x07,                   // channel map: 37, 38, 39
        0x00,                   // filter policy: none
    };
    hci_send_cmd(fd, HCI_OP_LE_SET_ADV_PARAMS, adv_params, sizeof adv_params);
    hci_send_cmd(fd, HCI_OP_LE_SET_ADV_DATA, adv_data, sizeof adv_data);
    uint8_t enable = 0x01;
    hci_send_cmd(fd, HCI_OP_LE_SET_ADV_ENABLE, &enable, 1);
    printf("  [*] Annonce connectable active sous l'adresse publique, attente d'une Central (%d s)...\n",
           wait_conn_ms / 1000);

    // Wait for a connection in the Peripheral role (role byte = 0x01).
    uint16_t handle = 0;
    bool connected = false;
    struct timeval cstart, cnow;
    gettimeofday(&cstart, NULL);
    while (!connected) {
        gettimeofday(&cnow, NULL);
        long elapsed = (cnow.tv_sec - cstart.tv_sec) * 1000 + (cnow.tv_usec - cstart.tv_usec) / 1000;
        int remaining = wait_conn_ms - (int)elapsed;
        if (remaining <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) break;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 8 || pkt[0] != HCI_EVENT_PKT || pkt[1] != HCI_EV_LE_META) continue;
        uint8_t sub = pkt[3];
        bool conn_event = (sub == HCI_LE_EV_CONN_COMPL || sub == HCI_LE_EV_CONN_COMPL_ENH);
        if (conn_event && pkt[4] == 0x00 && pkt[7] == 0x01) {
            handle = (uint16_t)((pkt[5] | (pkt[6] << 8)) & 0x0fff);
            connected = true;
        }
    }

    if (!connected) {
        uint8_t off = 0x00;
        hci_send_cmd(fd, HCI_OP_LE_SET_ADV_ENABLE, &off, 1);
        probe_teardown(fd, dev_id);
        return 0;
    }
    obs->linked = true;
    printf("  %s[+] Central connectée (handle 0x%04x). Envoi du SMP Security Request ARSR=0x%02x...%s\n",
           UI_GREEN, handle, arsr, UI_RESET);

    // V5: the Central's encryption request reaches the host as an LTK request.
    // The negative reply makes the controller send LL_REJECT_IND, the
    // interrupted session establishment that precedes the re-pairing trigger.
    if (mode == SECREQ_MODE_REJECT_ENC) {
        if (wait_ltk_request(fd, handle, wait_react_ms)) {
            uint8_t neg[2] = { (uint8_t)(handle & 0xff), (uint8_t)(handle >> 8) };
            hci_send_cmd(fd, HCI_OP_LE_LTK_NEG_REPLY, neg, sizeof neg);
            obs->enc_rejected = true;
            printf("  [*] Demande de chiffrement de la Central refusée (V5) : LL_REJECT_IND.\n");
        } else {
            printf("  [-] La Central n'a pas demandé de chiffrement dans le délai (V5 non testable).\n");
        }
    }

    uint8_t sec_req[2] = { SMP_OP_SECURITY_REQ, arsr };
    send_smp_packet(fd, handle, sec_req, sizeof sec_req);

    // Record the reaction. Plain and REJECT_ENC stop at the first one: a
    // Pairing Request, an LTK request, or the Central dropping the link.
    // DOWNGRADE_RSP answers the Pairing Request once with a weaker AuthReq,
    // then records what the Central does next.
    bool answered = false;
    struct timeval rstart, rnow;
    gettimeofday(&rstart, NULL);
    while (1) {
        gettimeofday(&rnow, NULL);
        long elapsed = (rnow.tv_sec - rstart.tv_sec) * 1000 + (rnow.tv_usec - rstart.tv_usec) / 1000;
        int remaining = wait_react_ms - (int)elapsed;
        if (remaining <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) break;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 2) continue;

        if (pkt[0] == HCI_ACLDATA_PKT && n >= 10) {
            uint16_t cid = (uint16_t)(pkt[7] | (pkt[8] << 8));
            if (cid != SMP_CID_VAL) continue;
            uint8_t op = pkt[9];
            if (op == SMP_OP_PAIRING_REQ && !answered) {
                obs->pairing_request = true;
                if (mode != SECREQ_MODE_DOWNGRADE_RSP) break;
                send_downgraded_rsp(fd, handle);
                obs->pairing_response_sent = true;
                answered = true;
                printf("  [*] Pairing Request reçue : réponse rétrogradée envoyée (AuthReq 0x01, V3).\n");
            } else if (answered && (op == SMP_OP_PAIRING_CONFIRM || op == SMP_OP_PUBLIC_KEY)) {
                obs->central_proceeded = true;
                break;
            } else if (answered && op == SMP_OP_PAIRING_FAIL) {
                obs->pairing_failed = true;
                obs->fail_reason = (n >= 11) ? pkt[10] : 0;
                break;
            }
        } else if (pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_LE_META && n >= 4 &&
                   pkt[3] == HCI_LE_EV_LTK_REQUEST) {
            obs->ltk_request = true;
            break;
        } else if (pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_DISCONN_COMPL) {
            break;
        }
    }

    uint8_t disc[3] = { (uint8_t)(handle & 0xff), (uint8_t)(handle >> 8), 0x13 };
    hci_send_cmd(fd, HCI_OP_DISCONNECT, disc, 3);
    usleep(20000);
    uint8_t off = 0x00;
    hci_send_cmd(fd, HCI_OP_LE_SET_ADV_ENABLE, &off, 1);
    probe_teardown(fd, dev_id);
    return 0;
}

// Print the probe result. See smp_native.h for the contract.
void smp_native_print_result(const struct smp_probe_result *res, const char *target_mac) {
    if (!res) return;

    switch (res->link) {
    case SMP_LINK_UNKNOWN:
        printf("  %s[-] La sonde n'a pas pu démarrer sur %s (voir les messages ci-dessus).%s\n",
               UI_RED, target_mac, UI_RESET);
        return;
    case SMP_LINK_NOT_FOUND:
        printf("  %s[-] Aucune liaison LE avec %s avant le timeout : la cible n'annonce pas, ou plus, à cette adresse (RPA périmée ?).%s\n",
               UI_RED, target_mac, UI_RESET);
        return;
    case SMP_LINK_HCI_ERROR:
        printf("  %s[-] Le contrôleur a refusé ou interrompu la connexion vers %s (HCI 0x%02x : %s).%s\n",
               UI_RED, target_mac, res->hci_status, hci_status_label(res->hci_status), UI_RESET);
        return;
    case SMP_LINK_UP:
        break;
    }

    if (!res->success) {
        printf("  %s[-] Liaison établie avec %s mais aucune réponse SMP : la cible ignore la Pairing Request.%s\n",
               UI_ORANGE, target_mac, UI_RESET);
        return;
    }

    if (res->pairing_failed) {
        printf("  %s[!] Cible %s a rejeté l'appairage (Pairing Failed, raison 0x%02x)%s\n",
               UI_GREEN, target_mac, res->fail_reason, UI_RESET);
        return;
    }

    bool mitm = (res->auth_req & 0x04) != 0;
    bool sc   = (res->auth_req & 0x08) != 0;
    bool bond = (res->auth_req & 0x01) != 0;

    printf("\n  %s=== Diagnostic SMP Native (Cible: %s) ===%s\n", UI_PINK, target_mac, UI_RESET);
    printf("  Capacité I/O cible  : 0x%02x\n", res->io_capability);
    printf("  Données OOB         : 0x%02x\n", res->oob_data_flag);
    printf("  AuthReq négocié     : %s0x%02x%s [MITM=%s, SC=%s, Bonding=%s]\n",
           UI_YELLOW, res->auth_req, UI_RESET,
           mitm ? "OUI" : "NON", sc ? "OUI" : "NON", bond ? "OUI" : "NON");
    printf("  Taille clé acceptée : %s%d octets (%d bits)%s\n",
           res->max_key_size <= 7 ? UI_ORANGE : UI_GREEN,
           res->max_key_size, res->max_key_size * 8, UI_RESET);
    printf("  Dist. Clés (Init/Rsp): 0x%02x / 0x%02x\n", res->init_key_dist, res->resp_key_dist);

    if (!mitm && !sc) {
        printf("  %s[i] La cible accepte un appairage initial sans MITM ni SC. Ce n'est pas la faille BLERP à elle seule :\n"
               "      le papier cible le re-pairing d'un appareil déjà appairé (voir 'bleurp repair').%s\n",
               UI_ORANGE, UI_RESET);
    }
    printf("\n");
}
