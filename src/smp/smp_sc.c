// ========================================
//  nom du fichier: smp_sc.c
//  description courte: Implementation of the LE Secure Connections crypto
//  toolbox. See smp_sc.h for the contract and the byte-order/f5-constant
//  caveats.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "smp_sc.h"

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

struct smp_sc_keypair {
    EVP_PKEY *pkey;
};

// Reverse `len` bytes from `in` into `out` (SMP wire order <-> the Core
// Spec crypto-toolbox's big-endian order). `out` and `in` may NOT overlap,
// except for the identity case in == out with len <= 1.
static void reverse_bytes(const uint8_t *in, size_t len, uint8_t *out) {
    for (size_t i = 0; i < len; i++) out[i] = in[len - 1 - i];
}

// AES-128 CMAC (RFC 4493) over an already-big-endian key/message, producing
// a big-endian 16-byte tag. No byte-order conversion here -- callers built
// `key`/`msg` in the Core Spec's math order already (see reverse_bytes()
// call sites below). Returns 0 on success, -1 on an OpenSSL failure.
static int aes_cmac_be(const uint8_t key[16], const uint8_t *msg, size_t msg_len,
                       uint8_t out[16]) {
    int rc = -1;
    EVP_MAC *mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
    if (!mac) return -1;
    EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
    if (!ctx) { EVP_MAC_free(mac); return -1; }

    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string("cipher", (char *)"AES-128-CBC", 0);
    params[1] = OSSL_PARAM_construct_end();

    size_t outlen = 0;
    if (EVP_MAC_init(ctx, key, 16, params) == 1 &&
        EVP_MAC_update(ctx, msg, msg_len) == 1 &&
        EVP_MAC_final(ctx, out, &outlen, 16) == 1 &&
        outlen == 16) {
        rc = 0;
    }

    EVP_MAC_CTX_free(ctx);
    EVP_MAC_free(mac);
    return rc;
}

// Generate a key pair. See smp_sc.h for the contract.
struct smp_sc_keypair *smp_sc_keygen(void) {
    struct smp_sc_keypair *kp = calloc(1, sizeof *kp);
    if (!kp) return NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!ctx) { free(kp); return NULL; }

    int ok = EVP_PKEY_keygen_init(ctx) == 1 &&
             EVP_PKEY_CTX_set_group_name(ctx, "P-256") == 1 &&
             EVP_PKEY_keygen(ctx, &kp->pkey) == 1;
    EVP_PKEY_CTX_free(ctx);

    if (!ok) { free(kp); return NULL; }
    return kp;
}

// Free a key pair. See smp_sc.h for the contract.
void smp_sc_keypair_free(struct smp_sc_keypair *kp) {
    if (!kp) return;
    EVP_PKEY_free(kp->pkey);
    free(kp);
}

// Extract the public key. See smp_sc.h for the contract.
int smp_sc_public_key(const struct smp_sc_keypair *kp, uint8_t out[64]) {
    if (!kp || !kp->pkey || !out) return -1;

    uint8_t raw[65]; // 0x04 || X(32, big-endian) || Y(32, big-endian)
    size_t raw_len = sizeof raw;
    if (EVP_PKEY_get_octet_string_param(kp->pkey, OSSL_PKEY_PARAM_PUB_KEY,
                                        raw, sizeof raw, &raw_len) != 1 ||
        raw_len != 65 || raw[0] != 0x04) {
        return -1;
    }

    reverse_bytes(&raw[1], 32, &out[0]);   // X: big-endian -> wire order
    reverse_bytes(&raw[33], 32, &out[32]); // Y: big-endian -> wire order
    return 0;
}

// Compute the shared DHKey. See smp_sc.h for the contract.
int smp_sc_dhkey(const struct smp_sc_keypair *kp, const uint8_t peer_pubkey[64],
                 uint8_t out[32]) {
    if (!kp || !kp->pkey || !peer_pubkey || !out) return -1;

    uint8_t raw[65];
    raw[0] = 0x04;
    reverse_bytes(&peer_pubkey[0], 32, &raw[1]);  // X: wire order -> big-endian
    reverse_bytes(&peer_pubkey[32], 32, &raw[33]); // Y: wire order -> big-endian

    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    if (!bld) return -1;
    int built = OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME, "P-256", 0) &&
                OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY, raw, sizeof raw);
    OSSL_PARAM *params = built ? OSSL_PARAM_BLD_to_param(bld) : NULL;
    OSSL_PARAM_BLD_free(bld);
    if (!params) return -1;

    EVP_PKEY_CTX *fctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    EVP_PKEY *peer = NULL;
    int rc = -1;
    if (fctx && EVP_PKEY_fromdata_init(fctx) == 1 &&
        EVP_PKEY_fromdata(fctx, &peer, EVP_PKEY_PUBLIC_KEY, params) == 1 && peer) {
        // fromdata already rejects a point that is not on the P-256 curve
        // (an invalid-curve attack input), so reaching here means `peer`
        // is a valid point.
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(kp->pkey, NULL);
        if (dctx && EVP_PKEY_derive_init(dctx) == 1 &&
            EVP_PKEY_derive_set_peer(dctx, peer) == 1) {
            uint8_t secret_be[32];
            size_t slen = sizeof secret_be;
            if (EVP_PKEY_derive(dctx, secret_be, &slen) == 1 && slen == 32) {
                reverse_bytes(secret_be, 32, out); // big-endian -> wire order
                rc = 0;
            }
        }
        EVP_PKEY_CTX_free(dctx);
    }
    EVP_PKEY_free(peer);
    EVP_PKEY_CTX_free(fctx);
    OSSL_PARAM_free(params);
    return rc;
}

// f4(U, V, X, Z) = AES-CMAC_X(U || V || Z). See smp_sc.h for the contract.
int smp_sc_f4(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
             uint8_t z, uint8_t out[16]) {
    if (!u || !v || !x || !out) return -1;

    uint8_t key_be[16];
    reverse_bytes(x, 16, key_be);

    uint8_t msg_be[32 + 32 + 1];
    reverse_bytes(u, 32, &msg_be[0]);
    reverse_bytes(v, 32, &msg_be[32]);
    msg_be[64] = z; // single byte, no order to reverse

    uint8_t out_be[16];
    if (aes_cmac_be(key_be, msg_be, sizeof msg_be, out_be) < 0) return -1;
    reverse_bytes(out_be, 16, out);
    return 0;
}

// f5(w, n1, n2, a1, a2): MacKey/LTK derivation. See smp_sc.h for the
// contract, and the module-level comment for the SALT/keyID caveat.
int smp_sc_f5(const uint8_t w[32], const uint8_t n1[16], const uint8_t n2[16],
             const uint8_t a1[7], const uint8_t a2[7],
             uint8_t out_mackey[16], uint8_t out_ltk[16]) {
    if (!w || !n1 || !n2 || !a1 || !a2 || !out_mackey || !out_ltk) return -1;

    // SALT (128-bit fixed constant) and keyID ("btle" in ASCII) from Core
    // Spec Vol 3, Part H, Table 2.8 -- see the module-level caveat in
    // smp_sc.h about verifying these against the spec text.
    static const uint8_t salt_be[16] = {
        0x6C, 0x88, 0x83, 0x91, 0xAA, 0xF5, 0xA5, 0x38,
        0x60, 0x37, 0x0B, 0xDB, 0x5A, 0x1F, 0xB0, 0xFF,
    };
    static const uint8_t keyid_be[4] = { 0x62, 0x74, 0x6C, 0x65 }; // "btle"

    uint8_t w_be[32];
    reverse_bytes(w, 32, w_be);

    uint8_t t_be[16];
    if (aes_cmac_be(salt_be, w_be, sizeof w_be, t_be) < 0) return -1;

    // M0 = Counter(1) || keyID(4) || N1(16) || N2(16) || A1(7) || A2(7) || Length(2)
    // Length = 256 (bits), little-endian in the Core Spec's own field
    // layout for this message (0x0100), i.e. {0x00, 0x01} big-endian-math
    // order once placed in the CMAC input.
    uint8_t msg_be[1 + 4 + 16 + 16 + 7 + 7 + 2];
    size_t off;

    for (int counter = 0; counter < 2; counter++) {
        off = 0;
        msg_be[off++] = (uint8_t)counter;
        memcpy(&msg_be[off], keyid_be, 4); off += 4;
        reverse_bytes(n1, 16, &msg_be[off]); off += 16;
        reverse_bytes(n2, 16, &msg_be[off]); off += 16;
        reverse_bytes(a1, 7, &msg_be[off]); off += 7;
        reverse_bytes(a2, 7, &msg_be[off]); off += 7;
        msg_be[off++] = 0x01; msg_be[off++] = 0x00; // Length = 256

        uint8_t out_be[16];
        if (aes_cmac_be(t_be, msg_be, sizeof msg_be, out_be) < 0) return -1;
        reverse_bytes(out_be, 16, counter == 0 ? out_mackey : out_ltk);
    }
    return 0;
}

// f6(w, n1, n2, r, iocap, a1, a2). See smp_sc.h for the contract.
int smp_sc_f6(const uint8_t w[16], const uint8_t n1[16], const uint8_t n2[16],
             const uint8_t r[16], const uint8_t iocap[3],
             const uint8_t a1[7], const uint8_t a2[7], uint8_t out[16]) {
    if (!w || !n1 || !n2 || !r || !iocap || !a1 || !a2 || !out) return -1;

    uint8_t key_be[16];
    reverse_bytes(w, 16, key_be);

    uint8_t msg_be[16 + 16 + 16 + 3 + 7 + 7];
    size_t off = 0;
    reverse_bytes(n1, 16, &msg_be[off]); off += 16;
    reverse_bytes(n2, 16, &msg_be[off]); off += 16;
    reverse_bytes(r, 16, &msg_be[off]); off += 16;
    reverse_bytes(iocap, 3, &msg_be[off]); off += 3;
    reverse_bytes(a1, 7, &msg_be[off]); off += 7;
    reverse_bytes(a2, 7, &msg_be[off]); off += 7;

    uint8_t out_be[16];
    if (aes_cmac_be(key_be, msg_be, sizeof msg_be, out_be) < 0) return -1;
    reverse_bytes(out_be, 16, out);
    return 0;
}

// g2(u, v, x, y) = AES-CMAC_X(U || V || Y) mod 2^32. See smp_sc.h.
int smp_sc_g2(const uint8_t u[32], const uint8_t v[32], const uint8_t x[16],
             const uint8_t y[16], uint32_t *out) {
    if (!u || !v || !x || !y || !out) return -1;

    uint8_t key_be[16];
    reverse_bytes(x, 16, key_be);

    uint8_t msg_be[32 + 32 + 16];
    reverse_bytes(u, 32, &msg_be[0]);
    reverse_bytes(v, 32, &msg_be[32]);
    reverse_bytes(y, 16, &msg_be[64]);

    uint8_t tag_be[16];
    if (aes_cmac_be(key_be, msg_be, sizeof msg_be, tag_be) < 0) return -1;

    // The display value is the 32 LEAST significant bits of the CMAC
    // output, taken from its big-endian (spec) representation, mod 10^6.
    uint32_t low32 = ((uint32_t)tag_be[12] << 24) | ((uint32_t)tag_be[13] << 16) |
                     ((uint32_t)tag_be[14] << 8) | (uint32_t)tag_be[15];
    *out = low32 % 1000000u;
    return 0;
}
