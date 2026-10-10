// ========================================
//  nom du fichier: test_repair.c
//  description courte: Unit tests for the re-pairing check: BlueZ info-file
//  parsing, bond loading errors, and the downgrade classification.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "repair.h"

#include <errno.h>
#include <string.h>

// Typical BlueZ info file written after a Just Works pairing (no MITM).
static const char info_unauth[] =
    "[General]\n"
    "Name=Living Room TV\n"
    "\n"
    "[LongTermKey]\n"
    "Key=00112233445566778899AABBCCDDEEFF\n"
    "Authenticated=0\n"
    "EncSize=16\n"
    "EDiv=0\n"
    "Rand=0\n";

// Passkey pairing (authenticated) stored under the peripheral-side section.
static const char info_auth_slave[] =
    "[SlaveLongTermKey]\n"
    "Key=FFEEDDCCBBAA99887766554433221100\n"
    "Authenticated=1\n"
    "EncSize=7\n";

// LE bond present but its EncSize line is missing: unusable.
static const char info_no_encsize[] =
    "[LongTermKey]\n"
    "Key=00\n"
    "Authenticated=1\n";

// Only a BR/EDR link key: no LE bond.
static const char info_classic_only[] =
    "[LinkKey]\n"
    "Key=00112233445566778899AABBCCDDEEFF\n"
    "Type=4\n";

// Parse the LTK section and read Authenticated / EncSize.
static void test_bond_parse_ltk(void) {
    struct smp_bond_info b;
    memset(&b, 0, sizeof b);
    CHECK(smp_bond_parse(info_unauth, &b) == 0);
    CHECK(b.authenticated == false);
    CHECK(b.enc_size == 16);
}

// The peripheral-side section is accepted too.
static void test_bond_parse_slave_ltk(void) {
    struct smp_bond_info b;
    memset(&b, 0, sizeof b);
    CHECK(smp_bond_parse(info_auth_slave, &b) == 0);
    CHECK(b.authenticated == true);
    CHECK(b.enc_size == 7);
}

// No LE section: -1 with ENOENT. A BR/EDR link key is not an LE bond.
static void test_bond_parse_no_le_bond(void) {
    struct smp_bond_info b;
    errno = 0;
    CHECK(smp_bond_parse(info_classic_only, &b) == -1);
    CHECK(errno == ENOENT);
}

// LE section without EncSize: -1 with EBADMSG.
static void test_bond_parse_missing_encsize(void) {
    struct smp_bond_info b;
    errno = 0;
    CHECK(smp_bond_parse(info_no_encsize, &b) == -1);
    CHECK(errno == EBADMSG);
}

// NULL arguments are rejected with EINVAL.
static void test_bond_parse_null(void) {
    struct smp_bond_info b;
    errno = 0;
    CHECK(smp_bond_parse(NULL, &b) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(smp_bond_parse(info_unauth, NULL) == -1);
    CHECK(errno == EINVAL);
}

// A store that does not exist means no bond: -1 with ENOENT.
static void test_bond_load_missing_store(void) {
    struct smp_bond_info b;
    errno = 0;
    CHECK(smp_bond_load("/nonexistent/bleurp-store", "C0:FF:EE:00:00:01",
                        "AA:BB:CC:DD:EE:FF", &b) == -1);
    CHECK(errno == ENOENT);
}

// Helper: a reply from the peer with the given AuthReq and max key size.
static struct smp_probe_result reply(uint8_t auth_req, uint8_t max_key) {
    struct smp_probe_result r;
    memset(&r, 0, sizeof r);
    r.success = true;
    r.auth_req = auth_req;
    r.max_key_size = max_key;
    return r;
}

// Helper: the weak offer the probe sends (bonding only, no MITM, 7 bytes).
static struct smp_pairing_params weak_offer(void) {
    struct smp_pairing_params o;
    memset(&o, 0, sizeof o);
    o.io_capability = SMP_IO_CAP_NO_INPUT_NO_OUTPUT;
    o.auth_req = SMP_AUTHREQ_BONDING;
    o.max_key_size = 7;
    return o;
}

// No SMP answer at all: inconclusive, no flag raised.
static void test_classify_no_reply(void) {
    struct smp_bond_info b = { .authenticated = true, .enc_size = 16 };
    struct smp_probe_result r;
    struct smp_repair_verdict v;
    memset(&r, 0, sizeof r);
    struct smp_pairing_params o = weak_offer();
    smp_repair_classify(&b, &o, &r, &v);
    CHECK(v.outcome == SMP_REPAIR_NO_REPLY);
    CHECK(v.mitm_downgrade == false);
    CHECK(v.entropy_downgrade == false);
}

// Pairing Failed: the peer refused the weak offer (anti-downgrade seen).
// The reason code is kept so the report can say which check fired.
static void test_classify_refused(void) {
    struct smp_bond_info b = { .authenticated = true, .enc_size = 16 };
    struct smp_probe_result r;
    struct smp_repair_verdict v;
    memset(&r, 0, sizeof r);
    r.success = true;
    r.pairing_failed = true;
    r.fail_reason = 0x06; // Encryption Key Size
    struct smp_pairing_params o = weak_offer();
    smp_repair_classify(&b, &o, &r, &v);
    CHECK(v.outcome == SMP_REPAIR_REFUSED);
    CHECK(v.fail_reason == 0x06);
    CHECK(v.mitm_downgrade == false);
    CHECK(v.entropy_downgrade == false);
}

// Authenticated bond, peer answers without MITM: downgrade of the level.
// The 7-byte offer is also below the 16-byte bond: entropy flag too.
static void test_classify_mitm_downgrade(void) {
    struct smp_bond_info b = { .authenticated = true, .enc_size = 16 };
    struct smp_repair_verdict v;
    struct smp_probe_result r = reply(SMP_AUTHREQ_BONDING, 16);
    struct smp_pairing_params o = weak_offer();
    smp_repair_classify(&b, &o, &r, &v);
    CHECK(v.outcome == SMP_REPAIR_ACCEPTED_DOWNGRADE);
    CHECK(v.mitm_downgrade == true);
    CHECK(v.entropy_downgrade == true);
}

// Authenticated bond, peer insists on MITM: no MITM downgrade.
// Entropy still lower because we offered 7 bytes against a 16-byte bond.
static void test_classify_mitm_kept(void) {
    struct smp_bond_info b = { .authenticated = true, .enc_size = 16 };
    struct smp_repair_verdict v;
    struct smp_probe_result r = reply(SMP_AUTHREQ_BONDING | SMP_AUTHREQ_MITM, 16);
    struct smp_pairing_params o = weak_offer();
    smp_repair_classify(&b, &o, &r, &v);
    CHECK(v.outcome == SMP_REPAIR_ACCEPTED_DOWNGRADE);
    CHECK(v.mitm_downgrade == false);
    CHECK(v.entropy_downgrade == true);
}

// Unauthenticated bond with 7-byte key: nothing lower than the bond.
static void test_classify_safe(void) {
    struct smp_bond_info b = { .authenticated = false, .enc_size = 7 };
    struct smp_repair_verdict v;
    struct smp_probe_result r = reply(SMP_AUTHREQ_BONDING, 7);
    struct smp_pairing_params o = weak_offer();
    smp_repair_classify(&b, &o, &r, &v);
    CHECK(v.outcome == SMP_REPAIR_ACCEPTED_SAFE);
    CHECK(v.mitm_downgrade == false);
    CHECK(v.entropy_downgrade == false);
}

// The negotiated size is the minimum of both sides: a peer that only
// supports 7 bytes is an entropy downgrade against a 16-byte bond even when
// our own offer were larger.
static void test_classify_entropy_uses_min(void) {
    struct smp_bond_info b = { .authenticated = false, .enc_size = 12 };
    struct smp_repair_verdict v;
    struct smp_probe_result r = reply(SMP_AUTHREQ_BONDING, 7);
    struct smp_pairing_params o = weak_offer();
    o.max_key_size = 16; // we offer 16, peer caps at 7
    smp_repair_classify(&b, &o, &r, &v);
    CHECK(v.entropy_downgrade == true);
    CHECK(v.outcome == SMP_REPAIR_ACCEPTED_DOWNGRADE);
}

// V2: an accepted offer not tied to the bond is YES; a refusal does not
// prove the sender was checked, so it stays inconclusive.
static void test_verdict_v2(void) {
    struct smp_repair_verdict v = {0};
    v.outcome = SMP_REPAIR_ACCEPTED_SAFE;
    CHECK(smp_repair_verdict_v2(&v) == BLERP_VERDICT_YES);
    v.outcome = SMP_REPAIR_ACCEPTED_DOWNGRADE;
    CHECK(smp_repair_verdict_v2(&v) == BLERP_VERDICT_YES);
    v.outcome = SMP_REPAIR_REFUSED;
    v.fail_reason = 0x03;
    CHECK(smp_repair_verdict_v2(&v) == BLERP_VERDICT_INCONCLUSIVE);
    v.outcome = SMP_REPAIR_NO_REPLY;
    CHECK(smp_repair_verdict_v2(&v) == BLERP_VERDICT_INCONCLUSIVE);
}

// V4: only meaningful for an authenticated bond. The MITM bit dropped is YES;
// refused with 0x03 or kept is NO; an entropy-only downgrade is not V4.
static void test_verdict_v4(void) {
    struct smp_repair_verdict v = {0};
    v.outcome = SMP_REPAIR_ACCEPTED_DOWNGRADE;
    v.mitm_downgrade = true;
    CHECK(smp_repair_verdict_v4(false, &v) == BLERP_VERDICT_INCONCLUSIVE);
    CHECK(smp_repair_verdict_v4(true, &v) == BLERP_VERDICT_YES);
    v.outcome = SMP_REPAIR_REFUSED;
    v.fail_reason = 0x03;
    CHECK(smp_repair_verdict_v4(true, &v) == BLERP_VERDICT_NO);
    v.outcome = SMP_REPAIR_ACCEPTED_SAFE;
    v.mitm_downgrade = false;
    CHECK(smp_repair_verdict_v4(true, &v) == BLERP_VERDICT_NO);
    v.outcome = SMP_REPAIR_ACCEPTED_DOWNGRADE;
    v.entropy_downgrade = true;
    CHECK(smp_repair_verdict_v4(true, &v) == BLERP_VERDICT_NO);
}

// V6: a key size below the bond is YES; refused with 0x06 or kept is NO.
static void test_verdict_v6(void) {
    struct smp_repair_verdict v = {0};
    v.outcome = SMP_REPAIR_ACCEPTED_DOWNGRADE;
    v.entropy_downgrade = true;
    CHECK(smp_repair_verdict_v6(&v) == BLERP_VERDICT_YES);
    v.outcome = SMP_REPAIR_REFUSED;
    v.fail_reason = 0x06;
    CHECK(smp_repair_verdict_v6(&v) == BLERP_VERDICT_NO);
    v.outcome = SMP_REPAIR_REFUSED;
    v.fail_reason = 0x03;
    CHECK(smp_repair_verdict_v6(&v) == BLERP_VERDICT_INCONCLUSIVE);
    v.outcome = SMP_REPAIR_ACCEPTED_SAFE;
    v.entropy_downgrade = false;
    CHECK(smp_repair_verdict_v6(&v) == BLERP_VERDICT_NO);
}

// Labels are the fixed words the [VERDICT] lines and the audit script use.
static void test_verdict_labels(void) {
    CHECK(strcmp(blerp_verdict_label(BLERP_VERDICT_YES), "OUI") == 0);
    CHECK(strcmp(blerp_verdict_label(BLERP_VERDICT_NO), "NON") == 0);
    CHECK(strcmp(blerp_verdict_label(BLERP_VERDICT_INCONCLUSIVE), "NON CONCLUANT") == 0);
}

int main(void) {
    printf("test_repair\n");
    test_bond_parse_ltk();
    test_bond_parse_slave_ltk();
    test_bond_parse_no_le_bond();
    test_bond_parse_missing_encsize();
    test_bond_parse_null();
    test_bond_load_missing_store();
    test_classify_no_reply();
    test_classify_refused();
    test_classify_mitm_downgrade();
    test_classify_mitm_kept();
    test_classify_safe();
    test_classify_entropy_uses_min();
    test_verdict_v2();
    test_verdict_v4();
    test_verdict_v6();
    test_verdict_labels();
    return TEST_REPORT();
}
