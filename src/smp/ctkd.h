// ========================================
//  nom du fichier: ctkd.h
//  description courte: Cross-Transport Key Derivation (CTKD) crypto conversion
//  and security policy assessment (Bluetooth Core Specification Vol 3, Part H).
//  Implements h6/h7 KDFs and checks for cross-transport downgrade / key overwrite.
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_SMP_CTKD_H
#define BLEURP_SMP_CTKD_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "smp.h"
#include "repair.h"

// Key Distribution flag bits in SMP Pairing Request/Response
#define SMP_KEYDIST_ENCKEY   0x01
#define SMP_KEYDIST_IDKEY    0x02
#define SMP_KEYDIST_SIGNKEY  0x04
#define SMP_KEYDIST_LINKKEY  0x08 // Cross-Transport Key Derivation (CTKD) flag

// CTKD keyID values (Bluetooth Core Specification Vol 3, Part H, 2.4.2.4)
#define CTKD_KEYID_TMP1 "tmp1" // 0x746D7031: LE LTK -> Intermediate LK
#define CTKD_KEYID_LEBR "lebr" // 0x6C656272: Intermediate LK -> BR/EDR Link Key
#define CTKD_KEYID_TMP2 "tmp2" // 0x746D7032: BR/EDR Link Key -> Intermediate LTK
#define CTKD_KEYID_BRLE "brle" // 0x62726C65: Intermediate LTK -> LE LTK

// Evaluation verdict for CTKD security policy
enum ctkd_verdict {
    CTKD_VERDICT_UNSUPPORTED = 0,    // Peer strips LinkKey bit (0x08) or rejects
    CTKD_VERDICT_PROTECTED_SC,       // Peer accepts LinkKey only with authenticated SC (Parity OK)
    CTKD_VERDICT_VULN_UNAUTH,        // Peer accepts LinkKey over unauthenticated Just Works (BLURtooth / CVE-2020-15802 pattern)
    CTKD_VERDICT_VULN_ENTROPY        // Peer accepts LinkKey with downgraded entropy (key_size < 16)
};

struct ctkd_report {
    bool supported;
    bool req_linkkey;
    bool rsp_linkkey;
    bool authenticated;
    bool sc_enabled;
    uint8_t negotiated_keysize;
    enum ctkd_verdict verdict;
    char details[128];
};

// Conversion function h6(W, keyID) = AES-CMAC_W(keyID).
// W is 16 bytes (wire order); keyID is 4 bytes ASCII; out is 16 bytes (wire order).
int ctkd_h6(const uint8_t w[16], const char keyid[4], uint8_t out[16]);

// Conversion function h7(SALT, W) = AES-CMAC_SALT(W).
// SALT is 16 bytes (wire order); W is 16 bytes (wire order); out is 16 bytes (wire order).
int ctkd_h7(const uint8_t salt[16], const uint8_t w[16], uint8_t out[16]);

// Derive BR/EDR Link Key from LE Long Term Key (LTK) using CTKD (LE -> BR/EDR).
// Returns 0 on success, -1 on crypto failure.
int ctkd_derive_link_key_from_ltk(const uint8_t ltk[16], bool use_ct2, uint8_t out_lk[16]);

// Derive LE Long Term Key (LTK) from BR/EDR Link Key using CTKD (BR/EDR -> LE).
// Returns 0 on success, -1 on crypto failure.
int ctkd_derive_ltk_from_link_key(const uint8_t lk[16], bool use_ct2, uint8_t out_ltk[16]);

// Classify CTKD security response against the security level of an existing BR/EDR bond.
void ctkd_classify_response(const struct smp_pairing_params *req,
                            const struct smp_pairing_params *rsp,
                            const struct smp_bond_info *existing_bredr_bond,
                            struct ctkd_report *rep);

// Helper to return verdict label
const char *ctkd_verdict_label(enum ctkd_verdict v);

#endif // BLEURP_SMP_CTKD_H
