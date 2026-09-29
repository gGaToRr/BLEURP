// ==============================================================================
//  nom du fichier: smp_native.c
//  description courte: Implémentation du module natif SMP via HCI_CHANNEL_USER.
//  Permet de forger des requêtes SMP directement sur l'interface HCI sans
//  l'interférence du gestionnaire de sécurité du noyau Linux.
// ==============================================================================

#define _GNU_SOURCE

#include "smp_native.h"
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

#define HCI_COMMAND_PKT    0x01
#define HCI_ACLDATA_PKT    0x02
#define HCI_EVENT_PKT      0x04

#define HCI_EV_CMD_COMPLETE  0x0e
#define HCI_EV_CMD_STATUS    0x0f
#define HCI_EV_DISCONN_COMPL 0x05
#define HCI_EV_LE_META       0x3e

#define HCI_LE_EV_CONN_COMPL 0x01

#define SMP_CID_VAL         0x0006
#define SMP_OP_PAIRING_REQ  0x01
#define SMP_OP_PAIRING_RSP  0x02
#define SMP_OP_PAIRING_FAIL 0x05

struct sockaddr_hci_raw {
    uint16_t hci_family;
    uint16_t hci_dev;
    uint16_t hci_channel;
};

// Contrôle de l'alimentation de l'adaptateur via BlueZ Management API
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

// Envoi d'une commande HCI brute et attente de l'acquittement
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
    pkt[2] = (uint8_t)((conn_handle >> 8) & 0x0f);
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

int smp_native_probe_device(int dev_id, const uint8_t target_addr[6],
                            uint8_t addr_type, int timeout_ms,
                            struct smp_probe_result *out_result) {
    if (!target_addr || !out_result) return -1;
    memset(out_result, 0, sizeof(*out_result));

    // Si l'adaptateur est actif dans le noyau Linux, bind(HCI_CHANNEL_USER) échoue avec EBUSY.
    // On met l'adaptateur temporairement en sommeil via BlueZ mgmt.
    set_adapter_power_mgmt(dev_id, 0);
    usleep(50000);

    int fd = socket(AF_BLUETOOTH_VAL, SOCK_RAW, BTPROTO_HCI_VAL);
    if (fd < 0) {
        int err = errno;
        set_adapter_power_mgmt(dev_id, 1);
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
        set_adapter_power_mgmt(dev_id, 1);
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
    hci_send_cmd(fd, 0x0c03, NULL, 0); // Reset
    usleep(80000);

    // 2. Configuration des masques d'événements
    uint8_t le_mask[8] = {0xff, 0x1f, 0x0a, 0x03, 0, 0, 0, 0};
    hci_send_cmd(fd, 0x2001, le_mask, 8); // LE Set Event Mask

    // 3. Demande de connexion LE (LE Create Connection 0x200D)
    printf("  [*] Envoi de la requête de connexion Link Layer vers la cible...\n");
    uint8_t conn_param[25];
    memset(conn_param, 0, sizeof(conn_param));
    conn_param[0] = 0x60; conn_param[1] = 0x00; // Scan Interval (60ms)
    conn_param[2] = 0x30; conn_param[3] = 0x00; // Scan Window (30ms)
    conn_param[4] = 0x00;                       // Filter Policy
    conn_param[5] = (addr_type == 2) ? 0x01 : 0x00; // Peer addr type: 0=public, 1=random
    memcpy(&conn_param[6], target_addr, 6);     // Peer addr
    conn_param[12] = 0x00;                      // Own addr type (public)
    conn_param[13] = 0x18; conn_param[14] = 0x00; // Conn interval min (30ms)
    conn_param[15] = 0x28; conn_param[16] = 0x00; // Conn interval max (50ms)
    conn_param[17] = 0x00; conn_param[18] = 0x00; // Latency
    conn_param[19] = 0xc8; conn_param[20] = 0x00; // Supervision timeout (2000ms)

    if (hci_send_cmd(fd, 0x200d, conn_param, 25) < 0) {
        close(fd);
        set_adapter_power_mgmt(dev_id, 1);
        return -1;
    }

    // 4. Attente de la connexion effective (LE Connection Complete 0x01 ou Enhanced 0x0A)
    uint8_t evt_buf[256];
    int r = -1;
    struct timeval cstart, cnow;
    gettimeofday(&cstart, NULL);

    while (1) {
        gettimeofday(&cnow, NULL);
        long elapsed = (cnow.tv_sec - cstart.tv_sec) * 1000 + (cnow.tv_usec - cstart.tv_usec) / 1000;
        int remaining = timeout_ms - (int)elapsed;
        if (remaining <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) break;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 3) continue;

        if (pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_LE_META) {
            uint8_t sub = pkt[3];
            if (sub == HCI_LE_EV_CONN_COMPL || sub == 0x0a) { // 0x01 = Legacy, 0x0a = Enhanced
                if (pkt[4] == 0x00) { // Status Success
                    memcpy(evt_buf, pkt, (size_t)n < sizeof(evt_buf) ? (size_t)n : sizeof(evt_buf));
                    r = (int)n;
                    break;
                } else {
                    fprintf(stderr, "  [-] Échec de liaison Link Layer (HCI Status 0x%02x)\n", pkt[4]);
                    close(fd);
                    set_adapter_power_mgmt(dev_id, 1);
                    return -1;
                }
            }
        }
    }

    if (r < 7) {
        fprintf(stderr, "  [-] Timeout de connexion (la cible n'émet pas d'annonces ou a changé d'adresse)\n");
        close(fd);
        set_adapter_power_mgmt(dev_id, 1);
        return -1;
    }

    uint16_t conn_handle = (uint16_t)(evt_buf[5] | (evt_buf[6] << 8));
    printf("  %s[+] Liaison Link Layer établie ! Handle = 0x%04x%s\n", UI_GREEN, conn_handle, UI_RESET);

    // 5. Forge du Pairing Request affaibli (AuthReq = 0x01 Bonding, No MITM, No SC, KeySize = 7)
    printf("  [*] Envoi du paquet SMP Pairing Request affaibli (AuthReq=0x01, KeySize=7)...\n");
    uint8_t pairing_req[7];
    pairing_req[0] = SMP_OP_PAIRING_REQ;
    pairing_req[1] = 0x03; // NoInputNoOutput
    pairing_req[2] = 0x00; // No OOB
    pairing_req[3] = 0x01; // Bonding seul (Weak AuthReq)
    pairing_req[4] = 0x07; // 7 bytes key size (KNOB minimum)
    pairing_req[5] = 0x01; // Distribute LTK
    pairing_req[6] = 0x01; // Receive LTK

    send_smp_packet(fd, conn_handle, pairing_req, sizeof(pairing_req));

    // 6. Attente de la réponse SMP de la cible (ACL Data packet)
    struct timeval start, now;
    gettimeofday(&start, NULL);
    int got_reply = 0;

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
                    got_reply = 1;
                    break;
                } else if (smp_op == SMP_OP_PAIRING_FAIL && n >= 11) {
                    out_result->success = true;
                    out_result->pairing_failed = true;
                    out_result->fail_reason = acl_buf[10];
                    got_reply = 1;
                    break;
                }
            }
        }
    }

    // 7. Déconnexion propre
    uint8_t disconn_param[3] = { (uint8_t)(conn_handle & 0xff), (uint8_t)(conn_handle >> 8), 0x13 };
    hci_send_cmd(fd, 0x0406, disconn_param, 3);
    usleep(20000);

    close(fd);
    set_adapter_power_mgmt(dev_id, 1);
    return got_reply ? 0 : -1;
}

void smp_native_print_result(const struct smp_probe_result *res, const char *target_mac) {
    if (!res || !res->success) {
        printf("  %s[-] Aucune réponse SMP reçue de %s (Timeout ou liaison rejetée)%s\n",
               UI_RED, target_mac, UI_RESET);
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
        printf("  %s%s[+] Vulnérabilité d'affaiblissement observée : la cible accepte une négociation sans MITM ni SC !%s\n",
               UI_ORANGE, UI_BOLD, UI_RESET);
    }
    printf("\n");
}
