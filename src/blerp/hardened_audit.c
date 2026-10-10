// ========================================
//  nom du fichier: hardened_audit.c
//  description courte: Implementation of the VII-A hardened re-pairing
//  rule classification. See hardened_audit.h for the contract.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "hardened_audit.h"
#include "../ui.h"

#include <stdio.h>
#include <string.h>

const char *hardened_rule_name(enum hardened_rule r) {
    switch (r) {
    case HARDENED_CONSISTENCY_CHECK:        return "Consistency Check";
    case HARDENED_ANTI_DOWNGRADE:           return "Anti-Downgrade";
    case HARDENED_ENC_FAILURE_TERMINATION:  return "Encryption Failure Termination";
    default:                                return "Unknown rule";
    }
}

const char *hardened_rule_fixes(enum hardened_rule r) {
    switch (r) {
    case HARDENED_CONSISTENCY_CHECK:        return "V3";
    case HARDENED_ANTI_DOWNGRADE:           return "V4, V6";
    case HARDENED_ENC_FAILURE_TERMINATION:  return "V5";
    default:                                return "";
    }
}

// Combine two vulnerability verdicts into one "is this pair of
// vulnerabilities both absent" rule verdict: NO (rule absent, vulnerable)
// if either underlying verdict is YES; YES (rule present) only if both are
// NO; INCONCLUSIVE otherwise (anything short of that).
static enum blerp_verdict combine_both_no(enum blerp_verdict a, enum blerp_verdict b) {
    if (a == BLERP_VERDICT_YES || b == BLERP_VERDICT_YES) return BLERP_VERDICT_NO;
    if (a == BLERP_VERDICT_NO && b == BLERP_VERDICT_NO) return BLERP_VERDICT_YES;
    return BLERP_VERDICT_INCONCLUSIVE;
}

// A single vulnerability verdict inverted into "is the mitigating rule
// present": YES<->NO swap, INCONCLUSIVE stays INCONCLUSIVE.
static enum blerp_verdict invert(enum blerp_verdict v) {
    if (v == BLERP_VERDICT_YES) return BLERP_VERDICT_NO;
    if (v == BLERP_VERDICT_NO) return BLERP_VERDICT_YES;
    return BLERP_VERDICT_INCONCLUSIVE;
}

void hardened_audit_classify(const struct blerp_attack_report *rep,
                             struct hardened_audit_report *out) {
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!rep) {
        for (int i = 0; i < HARDENED_RULE_COUNT; i++) {
            out->rule_verdicts[i] = BLERP_VERDICT_INCONCLUSIVE;
            snprintf(out->rule_details[i], sizeof out->rule_details[i], "No report provided");
        }
        return;
    }

    enum blerp_verdict v3 = rep->verdicts[BLERP_V3_PERIPHERAL_DOWNGRADE];
    enum blerp_verdict v4 = rep->verdicts[BLERP_V4_LEVEL_DOWNGRADE];
    enum blerp_verdict v5 = rep->verdicts[BLERP_V5_SESSION_BREAK];
    enum blerp_verdict v6 = rep->verdicts[BLERP_V6_ENTROPY_DOWNGRADE];

    out->rule_verdicts[HARDENED_CONSISTENCY_CHECK] = invert(v3);
    snprintf(out->rule_details[HARDENED_CONSISTENCY_CHECK], sizeof out->rule_details[0],
            v3 == BLERP_VERDICT_YES ?
                "Absent: the peer accepted a Pairing Response weaker than what it asked for (V3)." :
            v3 == BLERP_VERDICT_NO ?
                "Present: the peer rejected a Pairing Response inconsistent with its own request." :
                "Not tested: V3 was not evaluated in this run.");

    out->rule_verdicts[HARDENED_ANTI_DOWNGRADE] = combine_both_no(v4, v6);
    snprintf(out->rule_details[HARDENED_ANTI_DOWNGRADE], sizeof out->rule_details[0],
            (v4 == BLERP_VERDICT_YES && v6 == BLERP_VERDICT_YES) ?
                "Absent: the peer accepted both a lower security level (V4) and lower key entropy (V6)." :
            v4 == BLERP_VERDICT_YES ?
                "Absent: the peer accepted a security level below its stored bond (V4)." :
            v6 == BLERP_VERDICT_YES ?
                "Absent: the peer accepted a key size below its stored bond (V6)." :
            (v4 == BLERP_VERDICT_NO && v6 == BLERP_VERDICT_NO) ?
                "Present: the peer refused both the security level and key entropy downgrade." :
                "Not fully tested: V4 and/or V6 were not conclusively evaluated in this run.");

    out->rule_verdicts[HARDENED_ENC_FAILURE_TERMINATION] = invert(v5);
    snprintf(out->rule_details[HARDENED_ENC_FAILURE_TERMINATION], sizeof out->rule_details[0],
            v5 == BLERP_VERDICT_YES ?
                "Absent: the peer fell back to unauthenticated re-pairing after a rejected encryption request (V5)." :
            v5 == BLERP_VERDICT_NO ?
                "Present: the peer disconnected instead of falling back to re-pairing." :
                "Not tested: V5 was not evaluated in this run.");
}

void hardened_audit_print(const struct hardened_audit_report *rep) {
    if (!rep) return;

    printf("\n  %s================================================================%s\n", UI_PINK, UI_RESET);
    printf("  %s         HARDENED RE-PAIRING CHECK (NDSS 2026, Section VII-A)   %s\n", UI_BOLD, UI_RESET);
    printf("  %s================================================================%s\n\n", UI_PINK, UI_RESET);

    printf("  +----------------------------------+--------+-------------+\n");
    printf("  | Rule                             | Fixes  | Verdict     |\n");
    printf("  +----------------------------------+--------+-------------+\n");
    for (int i = 0; i < HARDENED_RULE_COUNT; i++) {
        enum hardened_rule r = (enum hardened_rule)i;
        enum blerp_verdict verd = rep->rule_verdicts[r];
        const char *vcolor = (verd == BLERP_VERDICT_YES) ? UI_GREEN  // rule present = good
                           : (verd == BLERP_VERDICT_NO)  ? UI_RED    // rule absent = vulnerable
                           : UI_ORANGE;
        printf("  | %-33.33s | %-6s | %s%-11s%s |\n",
               hardened_rule_name(r), hardened_rule_fixes(r),
               vcolor, blerp_verdict_label(verd), UI_RESET);
    }
    printf("  +----------------------------------+--------+-------------+\n\n");

    for (int i = 0; i < HARDENED_RULE_COUNT; i++) {
        enum hardened_rule r = (enum hardened_rule)i;
        printf("  [%s] %s\n", hardened_rule_name(r), rep->rule_details[r]);
    }
    printf("\n");
}
