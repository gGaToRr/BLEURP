// ========================================
//  nom du fichier: hardened_audit.h
//  description courte: Maps a blerp_attack_report (already run through
//  blerp_classify_vulnerabilities) onto the three named rules of the
//  paper's "hardened re-pairing" mitigation (Section VII-A): Consistency
//  Check, Anti-Downgrade, and Encryption Failure Termination. A target
//  that passes all three resists the BLERP attacks by construction, even
//  without the stronger (and standard-incompatible) authenticated
//  re-pairing protocol from Section VII-B.
//
//  This is a pure relabeling layer, not a new test: every rule's verdict
//  is derived entirely from the V1-V6 verdicts blerp_classify_vulnerabilities
//  already computed, so this module carries no new attack-surface or I/O.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_HARDENED_AUDIT_H
#define BLEURP_HARDENED_AUDIT_H

#include "blerp_attack.h"

// The three hardened re-pairing rules (NDSS 2026, Section VII-A).
enum hardened_rule {
    // Enforce consistency between the security level in the Security
    // Request (ARSR) and the subsequent re-pairing request: fixes V3
    // (a Peripheral can request high security then downgrade its own
    // Pairing Response without the Central noticing).
    HARDENED_CONSISTENCY_CHECK = 0,
    // Verify that neither the re-pairing security level nor the PK entropy
    // ever drops below the currently stored bond: fixes V4 (security level
    // downgrade) and V6 (key entropy downgrade) together, since both are
    // the same "never accept less than what we already had" rule applied
    // to two different fields.
    HARDENED_ANTI_DOWNGRADE,
    // Mandate disconnection when an encryption procedure fails, instead of
    // silently falling back to unauthenticated re-pairing: fixes V5.
    HARDENED_ENC_FAILURE_TERMINATION,
    HARDENED_RULE_COUNT
};

// Per-rule outcome: BLERP_VERDICT_YES means the rule is PRESENT (the
// corresponding vulnerability is NOT exploitable), BLERP_VERDICT_NO means
// the rule is ABSENT (the target is vulnerable), matching
// blerp_classify_vulnerabilities' own verdict semantics -- note this is
// the opposite sense of "YES = vulnerable" that BLERP_V1..V6 use, since a
// hardened-rule verdict answers a different question ("is the defense
// there?") than a vulnerability verdict ("is the attack possible?").
struct hardened_audit_report {
    enum blerp_verdict rule_verdicts[HARDENED_RULE_COUNT];
    char rule_details[HARDENED_RULE_COUNT][160];
};

// Return the standard short name for a rule (e.g. "Consistency Check").
const char *hardened_rule_name(enum hardened_rule r);

// Return the vulnerability this rule mitigates, as the V-codes string
// (e.g. "V4, V6").
const char *hardened_rule_fixes(enum hardened_rule r);

// Derive the three rule verdicts from an already-classified
// blerp_attack_report (i.e. one that has been through
// blerp_classify_vulnerabilities()). Safe to call with a report that only
// covers part of V1-V6 (e.g. from a single PI or CI run rather than a full
// `audit`): a rule whose underlying V-verdict(s) are inconclusive is
// itself reported inconclusive, not guessed.
void hardened_audit_classify(const struct blerp_attack_report *rep,
                             struct hardened_audit_report *out);

// Print the formatted hardened-rule verdict table to stdout, in the same
// style as blerp_print_report()'s V1-V6 matrix.
void hardened_audit_print(const struct hardened_audit_report *rep);

#endif // BLEURP_HARDENED_AUDIT_H
