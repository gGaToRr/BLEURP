// ========================================
//  nom du fichier: test_hardened_audit.c
//  description courte: Unit tests for the VII-A hardened re-pairing rule
//  classification. Pure relabeling of an already-classified
//  blerp_attack_report, no I/O.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "hardened_audit.h"

#include <string.h>

static void set_verdicts(struct blerp_attack_report *rep,
                         enum blerp_verdict v3, enum blerp_verdict v4,
                         enum blerp_verdict v5, enum blerp_verdict v6) {
    memset(rep, 0, sizeof *rep);
    for (int i = 0; i < BLERP_VULN_COUNT; i++) rep->verdicts[i] = BLERP_VERDICT_INCONCLUSIVE;
    rep->verdicts[BLERP_V3_PERIPHERAL_DOWNGRADE] = v3;
    rep->verdicts[BLERP_V4_LEVEL_DOWNGRADE] = v4;
    rep->verdicts[BLERP_V5_SESSION_BREAK] = v5;
    rep->verdicts[BLERP_V6_ENTROPY_DOWNGRADE] = v6;
}

// A target that resists every BLERP vulnerability passes all three rules.
static void test_fully_hardened(void) {
    struct blerp_attack_report rep;
    set_verdicts(&rep, BLERP_VERDICT_NO, BLERP_VERDICT_NO, BLERP_VERDICT_NO, BLERP_VERDICT_NO);

    struct hardened_audit_report out;
    hardened_audit_classify(&rep, &out);

    CHECK(out.rule_verdicts[HARDENED_CONSISTENCY_CHECK] == BLERP_VERDICT_YES);
    CHECK(out.rule_verdicts[HARDENED_ANTI_DOWNGRADE] == BLERP_VERDICT_YES);
    CHECK(out.rule_verdicts[HARDENED_ENC_FAILURE_TERMINATION] == BLERP_VERDICT_YES);
}

// A target vulnerable to every BLERP vulnerability fails all three rules.
static void test_fully_vulnerable(void) {
    struct blerp_attack_report rep;
    set_verdicts(&rep, BLERP_VERDICT_YES, BLERP_VERDICT_YES, BLERP_VERDICT_YES, BLERP_VERDICT_YES);

    struct hardened_audit_report out;
    hardened_audit_classify(&rep, &out);

    CHECK(out.rule_verdicts[HARDENED_CONSISTENCY_CHECK] == BLERP_VERDICT_NO);
    CHECK(out.rule_verdicts[HARDENED_ANTI_DOWNGRADE] == BLERP_VERDICT_NO);
    CHECK(out.rule_verdicts[HARDENED_ENC_FAILURE_TERMINATION] == BLERP_VERDICT_NO);
}

// Anti-Downgrade requires BOTH V4 and V6 to be NO to count as present; a
// single YES on either one fails the rule, and this must not be confused
// with inconclusive.
static void test_anti_downgrade_requires_both(void) {
    struct blerp_attack_report rep;

    set_verdicts(&rep, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_YES, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_NO);
    struct hardened_audit_report out;
    hardened_audit_classify(&rep, &out);
    CHECK(out.rule_verdicts[HARDENED_ANTI_DOWNGRADE] == BLERP_VERDICT_NO);

    set_verdicts(&rep, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_NO, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_YES);
    hardened_audit_classify(&rep, &out);
    CHECK(out.rule_verdicts[HARDENED_ANTI_DOWNGRADE] == BLERP_VERDICT_NO);

    // Both NO: present, even though they come from two different tests.
    set_verdicts(&rep, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_NO, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_NO);
    hardened_audit_classify(&rep, &out);
    CHECK(out.rule_verdicts[HARDENED_ANTI_DOWNGRADE] == BLERP_VERDICT_YES);

    // One NO, one untested: can't claim the rule holds.
    set_verdicts(&rep, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_NO, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_INCONCLUSIVE);
    hardened_audit_classify(&rep, &out);
    CHECK(out.rule_verdicts[HARDENED_ANTI_DOWNGRADE] == BLERP_VERDICT_INCONCLUSIVE);
}

// A report that never reached a given V-test (e.g. a lone `pi` run never
// exercises V2) reports that rule inconclusive, not a guess either way.
static void test_untested_stays_inconclusive(void) {
    struct blerp_attack_report rep;
    set_verdicts(&rep, BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_INCONCLUSIVE,
                BLERP_VERDICT_INCONCLUSIVE, BLERP_VERDICT_INCONCLUSIVE);

    struct hardened_audit_report out;
    hardened_audit_classify(&rep, &out);
    for (int i = 0; i < HARDENED_RULE_COUNT; i++) {
        CHECK(out.rule_verdicts[i] == BLERP_VERDICT_INCONCLUSIVE);
        CHECK(out.rule_details[i][0] != '\0'); // always says something, never blank
    }
}

// NULL report is handled without crashing, and reports every rule
// inconclusive.
static void test_null_report(void) {
    struct hardened_audit_report out;
    hardened_audit_classify(NULL, &out);
    for (int i = 0; i < HARDENED_RULE_COUNT; i++) {
        CHECK(out.rule_verdicts[i] == BLERP_VERDICT_INCONCLUSIVE);
    }
}

// Every rule has a non-empty name and a non-empty "fixes" string.
static void test_rule_names_and_fixes(void) {
    for (int i = 0; i < HARDENED_RULE_COUNT; i++) {
        enum hardened_rule r = (enum hardened_rule)i;
        CHECK(hardened_rule_name(r)[0] != '\0');
        CHECK(hardened_rule_fixes(r)[0] != '\0');
    }
    CHECK(strcmp(hardened_rule_fixes(HARDENED_ANTI_DOWNGRADE), "V4, V6") == 0);
}

int main(void) {
    printf("test_hardened_audit\n");
    test_fully_hardened();
    test_fully_vulnerable();
    test_anti_downgrade_requires_both();
    test_untested_stays_inconclusive();
    test_null_report();
    test_rule_names_and_fixes();
    return TEST_REPORT();
}
