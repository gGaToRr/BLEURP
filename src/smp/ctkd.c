// ========================================
//  nom du fichier: ctkd.c
//  description courte: Implementation of Cross-Transport Key Derivation
//  (h6/h7 KDFs) and vulnerability diagnostic for BR/EDR link key downgrade.
//  auteur: GitHub/@gGaToRr
// ========================================

#include "ctkd.h"
#include "smp_sc.h"
#include <string.h>
#include <stdio.h>

static void reverse_bytes(const uint8_t *in, size_t len, uint8_t *out) {
    for (size_t i = 0; i < len; i++) {
        out[i] = in[len - 1 - i];
    }
}

int ctkd_h6(const uint8_t w[16], const char keyid[4], uint8_t out[16]) {
    if (!w || !keyid || !out) return -1;

    uint8_t w_be[16];
    reverse_bytes(w, 16, w_be);

    // keyID on the wire / in big-endian order
    uint8_t keyid_be[4];
    memcpy(keyid_be, keyid, 4);

    uint8_t out_be[16];
    if (smp_sc_cmac(w_be, keyid_be, 4, out_be) < 0) return -1;

    reverse_bytes(out_be, 16, out);
    return 0;
}

int ctkd_h7(const uint8_t salt[16], const uint8_t w[16], uint8_t out[16]) {
    if (!salt || !w || !out) return -1;

    uint8_t salt_be[16];
    reverse_bytes(salt, 16, salt_be);

    uint8_t w_be[16];
    reverse_bytes(w, 16, w_be);

    uint8_t out_be[16];
    if (smp_sc_cmac(salt_be, w_be, 16, out_be) < 0) return -1;

    reverse_bytes(out_be, 16, out);
    return 0;
}

// Fixed 16-byte salts for h7 per Bluetooth Core Specification
static const uint8_t s_salt_tmp1[16] = {
    't', 'm', 'p', '1', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const uint8_t s_salt_lebr[16] = {
    'l', 'e', 'b', 'r', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const uint8_t s_salt_tmp2[16] = {
    't', 'm', 'p', '2', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};
static const uint8_t s_salt_brle[16] = {
    'b', 'r', 'l', 'e', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

int ctkd_derive_link_key_from_ltk(const uint8_t ltk[16], bool use_ct2, uint8_t out_lk[16]) {
    if (!ltk || !out_lk) return -1;

    uint8_t ilk[16];
    if (use_ct2) {
        if (ctkd_h7(s_salt_tmp1, ltk, ilk) < 0) return -1;
        return ctkd_h7(s_salt_lebr, ilk, out_lk);
    } else {
        if (ctkd_h6(ltk, CTKD_KEYID_TMP1, ilk) < 0) return -1;
        return ctkd_h6(ilk, CTKD_KEYID_LEBR, out_lk);
    }
}

int ctkd_derive_ltk_from_link_key(const uint8_t lk[16], bool use_ct2, uint8_t out_ltk[16]) {
    if (!lk || !out_ltk) return -1;

    uint8_t iltk[16];
    if (use_ct2) {
        if (ctkd_h7(s_salt_tmp2, lk, iltk) < 0) return -1;
        return ctkd_h7(s_salt_brle, iltk, out_ltk);
    } else {
        if (ctkd_h6(lk, CTKD_KEYID_TMP2, iltk) < 0) return -1;
        return ctkd_h6(iltk, CTKD_KEYID_BRLE, out_ltk);
    }
}

void ctkd_classify_response(const struct smp_pairing_params *req,
                            const struct smp_pairing_params *rsp,
                            const struct smp_bond_info *existing_bredr_bond,
                            struct ctkd_report *rep) {
    if (!rep) return;
    memset(rep, 0, sizeof(*rep));

    if (!req || !rsp) {
        rep->verdict = CTKD_VERDICT_UNSUPPORTED;
        snprintf(rep->details, sizeof(rep->details), "Missing pairing negotiation parameters");
        return;
    }

    rep->req_linkkey = (req->init_key_dist & SMP_KEYDIST_LINKKEY) ||
                       (req->resp_key_dist & SMP_KEYDIST_LINKKEY);
    rep->rsp_linkkey = (rsp->resp_key_dist & SMP_KEYDIST_LINKKEY) ||
                       (rsp->init_key_dist & SMP_KEYDIST_LINKKEY);

    if (!rep->rsp_linkkey) {
        rep->supported = false;
        rep->verdict = CTKD_VERDICT_UNSUPPORTED;
        snprintf(rep->details, sizeof(rep->details), "Peer stripped LinkKey bit (CTKD disabled or unsupported)");
        return;
    }

    rep->supported = true;
    rep->negotiated_keysize = rsp->max_key_size;
    rep->authenticated = (rsp->auth_req & SMP_AUTHREQ_MITM) != 0;
    rep->sc_enabled = (rsp->auth_req & SMP_AUTHREQ_SC) != 0;

    // Check entropy reduction (< 16 bytes)
    if (rsp->max_key_size < 16) {
        rep->verdict = CTKD_VERDICT_VULN_ENTROPY;
        snprintf(rep->details, sizeof(rep->details),
                 "VULNERABLE: LinkKey derived from truncated key size (%u bytes < 16)",
                 (unsigned)rsp->max_key_size);
        return;
    }

    // Check unauthenticated Just Works overwrite of an authenticated bond
    if (!rep->authenticated || !rep->sc_enabled) {
        if (existing_bredr_bond && existing_bredr_bond->authenticated) {
            rep->verdict = CTKD_VERDICT_VULN_UNAUTH;
            snprintf(rep->details, sizeof(rep->details),
                     "VULNERABLE: Unauthenticated Just Works LE pairing permitted to overwrite authenticated BR/EDR bond");
            return;
        }

        // Even without an existing bond on record, accepting LinkKey over Just Works violates Bluetooth 5.1+ CTKD security rules
        rep->verdict = CTKD_VERDICT_VULN_UNAUTH;
        snprintf(rep->details, sizeof(rep->details),
                 "SUSCEPTIBLE: Target accepts LinkKey generation over unauthenticated (Just Works) channel");
        return;
    }

    // Authenticated Secure Connections
    rep->verdict = CTKD_VERDICT_PROTECTED_SC;
    snprintf(rep->details, sizeof(rep->details),
             "PROTECTED: CTKD LinkKey requires authenticated LE Secure Connections");
}

const char *ctkd_verdict_label(enum ctkd_verdict v) {
    switch (v) {
    case CTKD_VERDICT_UNSUPPORTED:   return "UNSUPPORTED";
    case CTKD_VERDICT_PROTECTED_SC:  return "PROTECTED";
    case CTKD_VERDICT_VULN_UNAUTH:   return "VULN_UNAUTH";
    case CTKD_VERDICT_VULN_ENTROPY:  return "VULN_ENTROPY";
    }
    return "UNKNOWN";
}
