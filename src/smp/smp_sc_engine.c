// ========================================
//  nom du fichier: smp_sc_engine.c
//  description courte: Implementation of the SC Just Works/Numeric
//  Comparison Phase 2 state machine. See smp_sc_engine.h for the contract
//  and the caveats on message ordering/field ordering.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "smp_sc_engine.h"

#include <string.h>

// Pairing Request/Response payload: NoInputNoOutput, no OOB, bonding + SC
// (0x09), 16-byte keys, EncKey distribution in both directions. The SC bit
// is what makes this engine reachable at all -- forced on even if a caller
// supplies a custom AuthReq without it.
#define SC_IOCAP    0x03
#define SC_OOB      0x00
#define SC_AUTHREQ  0x09 // Bonding | SC
#define SC_MAXKEY   0x10
#define SC_KEYDIST  0x01
#define SC_AUTHREQ_SC_BIT 0x08

// Set up the role/addresses/nonce and generate an ECDH key pair. See
// smp_sc_engine.h for the contract.
int smp_sc_init(struct smp_sc *p, bool initiator,
                uint8_t iat, const uint8_t ia[6],
                uint8_t rat, const uint8_t ra[6],
                const uint8_t my_nonce[16]) {
    if (!p) return -1;
    memset(p, 0, sizeof *p);
    p->initiator = initiator;
    p->iat = iat;
    p->rat = rat;
    memcpy(p->ia, ia, 6);
    memcpy(p->ra, ra, 6);
    memcpy(p->my_nonce, my_nonce, 16);

    p->keypair = smp_sc_keygen();
    if (!p->keypair) return -1;
    if (smp_sc_public_key(p->keypair, p->my_pubkey) < 0) {
        smp_sc_keypair_free(p->keypair);
        p->keypair = NULL;
        return -1;
    }
    return 0;
}

// Release the key pair. See smp_sc_engine.h for the contract.
void smp_sc_free(struct smp_sc *p) {
    if (!p) return;
    smp_sc_keypair_free(p->keypair);
    p->keypair = NULL;
}

// Set custom AuthReq/max key size. See smp_sc_engine.h for the contract.
void smp_sc_set_params(struct smp_sc *p, uint8_t authreq, uint8_t max_keysize) {
    if (!p) return;
    p->custom_authreq = authreq ? (uint8_t)(authreq | SC_AUTHREQ_SC_BIT) : 0;
    p->custom_maxkey = max_keysize;
}

int smp_sc_make_req(struct smp_sc *p, uint8_t out[7]) {
    if (!p || !p->initiator) return -1;
    uint8_t auth = p->custom_authreq ? p->custom_authreq : SC_AUTHREQ;
    uint8_t mkey = p->custom_maxkey ? p->custom_maxkey : SC_MAXKEY;
    uint8_t pdu[7] = {
        SMP_SC_OP_PAIRING_REQ, SC_IOCAP, SC_OOB, auth,
        mkey, SC_KEYDIST, SC_KEYDIST,
    };
    memcpy(p->preq, pdu, 7);
    memcpy(out, pdu, 7);
    return 7;
}

int smp_sc_on_rsp(struct smp_sc *p, const uint8_t pdu[7]) {
    if (!p || !p->initiator || pdu[0] != SMP_SC_OP_PAIRING_RSP) return -1;
    memcpy(p->pres, pdu, 7);
    return 0;
}

int smp_sc_on_req(struct smp_sc *p, const uint8_t pdu[7]) {
    if (!p || p->initiator || pdu[0] != SMP_SC_OP_PAIRING_REQ) return -1;
    memcpy(p->preq, pdu, 7);
    return 0;
}

int smp_sc_make_rsp(struct smp_sc *p, uint8_t out[7]) {
    if (!p || p->initiator) return -1;
    uint8_t auth = p->custom_authreq ? p->custom_authreq : SC_AUTHREQ;
    uint8_t mkey = p->custom_maxkey ? p->custom_maxkey : SC_MAXKEY;
    uint8_t pdu[7] = {
        SMP_SC_OP_PAIRING_RSP, SC_IOCAP, SC_OOB, auth,
        mkey, SC_KEYDIST, SC_KEYDIST,
    };
    memcpy(p->pres, pdu, 7);
    memcpy(out, pdu, 7);
    return 7;
}

int smp_sc_make_pubkey(struct smp_sc *p, uint8_t out[65]) {
    if (!p) return -1;
    out[0] = SMP_SC_OP_PUBLIC_KEY;
    memcpy(&out[1], p->my_pubkey, 64);
    return 65;
}

int smp_sc_on_pubkey(struct smp_sc *p, const uint8_t pdu[65]) {
    if (!p || pdu[0] != SMP_SC_OP_PUBLIC_KEY) return -1;
    memcpy(p->peer_pubkey, &pdu[1], 64);
    return smp_sc_dhkey(p->keypair, p->peer_pubkey, p->dhkey);
}

// Confirm value: responder commits to its own nonce before either side
// reveals a Pairing Random. U = responder's own public key X, V =
// initiator's public key X (see smp_sc_engine.h's ordering caveat).
int smp_sc_make_confirm(struct smp_sc *p, uint8_t out[17]) {
    if (!p || p->initiator) return -1;
    const uint8_t *pkb = &p->my_pubkey[0];   // our (responder) X coordinate
    const uint8_t *pka = &p->peer_pubkey[0]; // initiator's X coordinate
    uint8_t cb[16];
    if (smp_sc_f4(pkb, pka, p->my_nonce, 0x00, cb) < 0) return -1;
    out[0] = SMP_SC_OP_PAIRING_CONFIRM;
    memcpy(&out[1], cb, 16);
    return 17;
}

int smp_sc_on_confirm(struct smp_sc *p, const uint8_t pdu[17]) {
    if (!p || !p->initiator || pdu[0] != SMP_SC_OP_PAIRING_CONFIRM) return -1;
    memcpy(p->peer_confirm, &pdu[1], 16);
    return 0;
}

int smp_sc_make_random(struct smp_sc *p, uint8_t out[17]) {
    if (!p) return -1;
    out[0] = SMP_SC_OP_PAIRING_RANDOM;
    memcpy(&out[1], p->my_nonce, 16);
    return 17;
}

int smp_sc_on_random(struct smp_sc *p, const uint8_t pdu[17]) {
    if (!p || pdu[0] != SMP_SC_OP_PAIRING_RANDOM) return -1;
    memcpy(p->peer_nonce, &pdu[1], 16);

    if (p->initiator) {
        // Verify the responder's Nb reproduces the Cb it committed to
        // earlier -- the check that stops the responder (or a relay)
        // swapping its nonce in after seeing Na.
        const uint8_t *pkb = &p->peer_pubkey[0]; // responder's X coordinate
        const uint8_t *pka = &p->my_pubkey[0];   // our (initiator) X coordinate
        uint8_t check[16];
        if (smp_sc_f4(pkb, pka, p->peer_nonce, 0x00, check) < 0) return -1;
        if (memcmp(check, p->peer_confirm, 16) != 0) {
            p->failed = true;
            p->reason = 0x04; // Confirm Value Failed
            return 0;
        }
    }
    // Responder: nothing to verify yet -- it committed first, so there is
    // no confirm value from the initiator to check against.
    return 0;
}

// Build the 7-byte "address || type" value f5/f6 expect for one side.
static void build_a(const uint8_t addr[6], uint8_t type, uint8_t out[7]) {
    memcpy(out, addr, 6);
    out[6] = type;
}

// Build the 3-byte "AuthReq || OOB || IOCap" value f6 expects, from a
// 7-byte Pairing Request/Response PDU (opcode, iocap, oob, authreq, ...).
static void build_iocap(const uint8_t pdu[7], uint8_t out[3]) {
    out[0] = pdu[3]; // AuthReq
    out[1] = pdu[2]; // OOB data flag
    out[2] = pdu[1]; // IO Capability
}

// MacKey/LTK derivation. See smp_sc_engine.h for the contract.
int smp_sc_derive_keys(struct smp_sc *p) {
    if (!p) return -1;
    const uint8_t *na = p->initiator ? p->my_nonce : p->peer_nonce;
    const uint8_t *nb = p->initiator ? p->peer_nonce : p->my_nonce;
    uint8_t a_ia[7], a_ra[7];
    build_a(p->ia, p->iat, a_ia);
    build_a(p->ra, p->rat, a_ra);
    return smp_sc_f5(p->dhkey, na, nb, a_ia, a_ra, p->mackey, p->ltk);
}

int smp_sc_make_dhkey_check(struct smp_sc *p, uint8_t out[17]) {
    if (!p) return -1;
    uint8_t a_ia[7], a_ra[7];
    build_a(p->ia, p->iat, a_ia);
    build_a(p->ra, p->rat, a_ra);

    uint8_t iocap_a[3], iocap_b[3];
    build_iocap(p->preq, iocap_a);
    build_iocap(p->pres, iocap_b);

    static const uint8_t zero_r[16] = {0}; // Just Works/NC: r is always 0
    uint8_t check[16];
    int rc;
    if (p->initiator) {
        // Ea = f6(MacKey, Na, Nb, rb=0, IOcapA, A_ia, A_ra)
        rc = smp_sc_f6(p->mackey, p->my_nonce, p->peer_nonce, zero_r, iocap_a, a_ia, a_ra, check);
    } else {
        // Eb = f6(MacKey, Nb, Na, ra=0, IOcapB, A_ra, A_ia)
        rc = smp_sc_f6(p->mackey, p->my_nonce, p->peer_nonce, zero_r, iocap_b, a_ra, a_ia, check);
    }
    if (rc < 0) return -1;

    out[0] = SMP_SC_OP_DHKEY_CHECK;
    memcpy(&out[1], check, 16);
    return 17;
}

int smp_sc_on_dhkey_check(struct smp_sc *p, const uint8_t pdu[17]) {
    if (!p || pdu[0] != SMP_SC_OP_DHKEY_CHECK) return -1;

    uint8_t a_ia[7], a_ra[7];
    build_a(p->ia, p->iat, a_ia);
    build_a(p->ra, p->rat, a_ra);

    uint8_t iocap_a[3], iocap_b[3];
    build_iocap(p->preq, iocap_a);
    build_iocap(p->pres, iocap_b);

    static const uint8_t zero_r[16] = {0};
    uint8_t expect[16];
    int rc;
    if (p->initiator) {
        // We are checking the responder's Eb.
        rc = smp_sc_f6(p->mackey, p->peer_nonce, p->my_nonce, zero_r, iocap_b, a_ra, a_ia, expect);
    } else {
        // We are checking the initiator's Ea.
        rc = smp_sc_f6(p->mackey, p->peer_nonce, p->my_nonce, zero_r, iocap_a, a_ia, a_ra, expect);
    }
    if (rc < 0) return -1;

    if (memcmp(expect, &pdu[1], 16) != 0) {
        p->failed = true;
        p->reason = 0x04; // Confirm Value Failed (reused for DHKey Check failure)
        return 0;
    }
    p->done = true;
    return 0;
}
