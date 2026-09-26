// ========================================
//  nom du fichier: test_audit.c
//  description courte: Unit tests for the GATT access-audit classifier. Maps
//  the outcome of a characteristic read (success or an ATT error code) to a
//  verdict (open / protected / denied / other) and checks the labels.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "audit.h"

#include <string.h>

// A successful read means the value came back without pairing: OPEN.
static void test_open(void) {
    CHECK(audit_classify_read(true, 0x00) == AUDIT_OPEN);
    // att_error is ignored when the read succeeded.
    CHECK(audit_classify_read(true, 0x05) == AUDIT_OPEN);
}

// The four "insufficient security" ATT codes mean the value exists but needs
// pairing/encryption: PROTECTED.
static void test_protected(void) {
    CHECK(audit_classify_read(false, ATT_ERR_INSUFFICIENT_AUTHENTICATION) == AUDIT_PROTECTED);
    CHECK(audit_classify_read(false, ATT_ERR_INSUFFICIENT_AUTHORIZATION) == AUDIT_PROTECTED);
    CHECK(audit_classify_read(false, ATT_ERR_INSUFFICIENT_ENCRYPTION) == AUDIT_PROTECTED);
    CHECK(audit_classify_read(false, ATT_ERR_INSUFFICIENT_ENC_KEY_SIZE) == AUDIT_PROTECTED);
}

// Read Not Permitted: the attribute simply cannot be read (despite a READ
// property being advertised): DENIED.
static void test_denied(void) {
    CHECK(audit_classify_read(false, ATT_ERR_READ_NOT_PERMITTED) == AUDIT_DENIED);
}

// Any other failure (unexpected ATT code, or a transport failure with no code)
// is reported verbatim as OTHER.
static void test_other(void) {
    CHECK(audit_classify_read(false, 0x0a) == AUDIT_OTHER); // Attribute Not Found
    CHECK(audit_classify_read(false, 0x00) == AUDIT_OTHER); // no ATT code (e.g. timeout)
}

// Labels are short, stable, upper-case tokens for the report column.
static void test_labels(void) {
    CHECK(strcmp(audit_verdict_label(AUDIT_OPEN), "OPEN") == 0);
    CHECK(strcmp(audit_verdict_label(AUDIT_PROTECTED), "PROTECTED") == 0);
    CHECK(strcmp(audit_verdict_label(AUDIT_DENIED), "DENIED") == 0);
    CHECK(strcmp(audit_verdict_label(AUDIT_OTHER), "OTHER") == 0);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_audit\n");
    test_open();
    test_protected();
    test_denied();
    test_other();
    test_labels();
    return TEST_REPORT();
}
