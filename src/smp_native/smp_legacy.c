// ========================================
//  nom du fichier: smp_legacy.c
//  description courte: Legacy LE pairing (Just Works, TK = 0): c1, s1 and the
//  initiator/responder state machines. See smp_legacy.h for the contract.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#include "smp_legacy.h"

#include <string.h>

#include <openssl/evp.h>

// Pairing Request/Response payload used for Just Works: NoInputNoOutput,
// no OOB, bonding only, 16-byte keys, EncKey distribution in both directions.
#define LEG_IOCAP      0x03
#define LEG_OOB        0x00
#define LEG_AUTHREQ    0x01
#define LEG_MAXKEY     0x10
#define LEG_KEYDIST    0x01

// AES-128 on the PDU byte order: the arrays are little-endian, AES wants the
// big-endian form, so the key and the block are reversed on the way in and out.
int smp_legacy_e(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t key_be[16], in_be[16], out_be[16];
    for (int i = 0; i < 16; i++) {
        key_be[i] = key[15 - i];
        in_be[i] = in[15 - i];
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return -1;
    int len = 0;
    int ok = EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key_be, NULL) == 1 &&
             EVP_CIPHER_CTX_set_padding(ctx, 0) == 1 &&
             EVP_EncryptUpdate(ctx, out_be, &len, in_be, 16) == 1 &&
             len == 16;
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) return -1;

    for (int i = 0; i < 16; i++) {
        out[i] = out_be[15 - i];
    }
    return 0;
}

// c1(k, r, preq, pres, iat, ia, rat, ra) = e(k, e(k, r ^ p1) ^ p2)
// p1 = pres || preq || rat' || iat', p2 = padding || ia || ra (LE arrays).
int smp_legacy_c1(const uint8_t k[16], const uint8_t r[16],
                  const uint8_t preq[7], const uint8_t pres[7],
                  uint8_t iat, const uint8_t ia[6],
                  uint8_t rat, const uint8_t ra[6],
                  uint8_t out[16]) {
    uint8_t p1[16], p2[16], step[16];

    p1[0] = iat;
    p1[1] = rat;
    memcpy(&p1[2], preq, 7);
    memcpy(&p1[9], pres, 7);

    memcpy(&p2[0], ra, 6);
    memcpy(&p2[6], ia, 6);
    memset(&p2[12], 0, 4);

    for (int i = 0; i < 16; i++) step[i] = r[i] ^ p1[i];
    if (smp_legacy_e(k, step, step) < 0) return -1;

    for (int i = 0; i < 16; i++) step[i] ^= p2[i];
    return smp_legacy_e(k, step, out);
}

// s1(k, r1, r2) = e(k, r'), r' = 64 LSB of r2 || 64 LSB of r1. In the
// standard, r1 is the responder's random and r2 the initiator's (STK).
int smp_legacy_s1(const uint8_t k[16], const uint8_t mrand[16],
                  const uint8_t srand[16], uint8_t out[16]) {
    uint8_t r_prime[16];
    memcpy(&r_prime[0], mrand, 8);
    memcpy(&r_prime[8], srand, 8);
    return smp_legacy_e(k, r_prime, out);
}

void smp_legacy_init(struct smp_legacy *p, bool initiator,
                     uint8_t iat, const uint8_t ia[6],
                     uint8_t rat, const uint8_t ra[6],
                     const uint8_t my_rand[16]) {
    memset(p, 0, sizeof *p);
    p->initiator = initiator;
    p->iat = iat;
    p->rat = rat;
    memcpy(p->ia, ia, 6);
    memcpy(p->ra, ra, 6);
    memcpy(p->my_rand, my_rand, 16);
}

void smp_legacy_set_params(struct smp_legacy *p, uint8_t authreq, uint8_t max_keysize) {
    if (!p) return;
    p->custom_authreq = authreq;
    p->custom_maxkey = max_keysize;
}

int smp_legacy_make_req(struct smp_legacy *p, uint8_t out[7]) {
    if (!p || !p->initiator) return -1;
    uint8_t auth = p->custom_authreq ? p->custom_authreq : LEG_AUTHREQ;
    uint8_t mkey = p->custom_maxkey ? p->custom_maxkey : LEG_MAXKEY;
    uint8_t pdu[7] = {
        SMP_LEG_OP_PAIRING_REQ, LEG_IOCAP, LEG_OOB, auth,
        mkey, LEG_KEYDIST, LEG_KEYDIST,
    };
    memcpy(p->preq, pdu, 7);
    memcpy(out, pdu, 7);
    return 7;
}

int smp_legacy_on_rsp(struct smp_legacy *p, const uint8_t pdu[7]) {
    if (!p || !p->initiator || pdu[0] != SMP_LEG_OP_PAIRING_RSP) return -1;
    memcpy(p->pres, pdu, 7);
    return 0;
}

int smp_legacy_on_req(struct smp_legacy *p, const uint8_t pdu[7]) {
    if (!p || p->initiator || pdu[0] != SMP_LEG_OP_PAIRING_REQ) return -1;
    memcpy(p->preq, pdu, 7);
    return 0;
}

int smp_legacy_make_rsp(struct smp_legacy *p, uint8_t out[7]) {
    if (!p || p->initiator) return -1;
    uint8_t auth = p->custom_authreq ? p->custom_authreq : LEG_AUTHREQ;
    uint8_t mkey = p->custom_maxkey ? p->custom_maxkey : LEG_MAXKEY;
    uint8_t pdu[7] = {
        SMP_LEG_OP_PAIRING_RSP, LEG_IOCAP, LEG_OOB, auth,
        mkey, LEG_KEYDIST, LEG_KEYDIST,
    };
    memcpy(p->pres, pdu, 7);
    memcpy(out, pdu, 7);
    return 7;
}

int smp_legacy_make_confirm(struct smp_legacy *p, uint8_t out[17]) {
    if (!p) return -1;
    uint8_t tk[16] = {0};
    uint8_t value[16];
    if (smp_legacy_c1(tk, p->my_rand, p->preq, p->pres,
                      p->iat, p->ia, p->rat, p->ra, value) < 0) {
        return -1;
    }
    out[0] = SMP_LEG_OP_PAIRING_CONFIRM;
    memcpy(&out[1], value, 16);
    return 17;
}

int smp_legacy_on_confirm(struct smp_legacy *p, const uint8_t pdu[17]) {
    if (!p || pdu[0] != SMP_LEG_OP_PAIRING_CONFIRM) return -1;
    memcpy(p->peer_confirm, &pdu[1], 16);
    return 0;
}

int smp_legacy_make_random(struct smp_legacy *p, uint8_t out[17]) {
    if (!p) return -1;
    out[0] = SMP_LEG_OP_PAIRING_RANDOM;
    memcpy(&out[1], p->my_rand, 16);
    return 17;
}

int smp_legacy_on_random(struct smp_legacy *p, const uint8_t pdu[17]) {
    if (!p || pdu[0] != SMP_LEG_OP_PAIRING_RANDOM) return -1;
    memcpy(p->peer_rand, &pdu[1], 16);

    // The peer's confirm must be reproducible from its random: the check that
    // stops a man in the middle from swapping its own random in.
    uint8_t tk[16] = {0};
    uint8_t check[16];
    if (smp_legacy_c1(tk, p->peer_rand, p->preq, p->pres,
                      p->iat, p->ia, p->rat, p->ra, check) < 0) {
        return -1;
    }
    if (memcmp(check, p->peer_confirm, 16) != 0) {
        p->failed = true;
        p->reason = 0x04; // Confirm Value Failed
        return 0;
    }

    // STK = s1(TK, Srand, Mrand): the responder's random is the r1 argument.
    const uint8_t *mrand = p->initiator ? p->my_rand : p->peer_rand;
    const uint8_t *srand = p->initiator ? p->peer_rand : p->my_rand;
    if (smp_legacy_s1(tk, mrand, srand, p->stk) < 0) return -1;
    p->done = true;
    return 0;
}
