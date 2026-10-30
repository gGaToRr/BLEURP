// ========================================
//  nom du fichier: test_export.c
//  description courte: Unit tests for CSV and JSON device table exporters.
//  Tests field escaping, formatting, and null safety.
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "export.h"
#include "dev_table.h"

#include <string.h>

static void test_csv_escaping(void) {
    char out[128];

    // Simple string without special chars
    export_escape_csv("HelloDevice", out, sizeof(out));
    CHECK(strcmp(out, "HelloDevice") == 0);

    // String with comma
    export_escape_csv("Device, Inc", out, sizeof(out));
    CHECK(strcmp(out, "\"Device, Inc\"") == 0);

    // String with quote
    export_escape_csv("Device \"Pro\"", out, sizeof(out));
    CHECK(strcmp(out, "\"Device \"\"Pro\"\"\"") == 0);

    // Null safety
    export_escape_csv(NULL, out, sizeof(out));
    CHECK(strcmp(out, "") == 0);
}

static void test_json_escaping(void) {
    char out[128];

    // Simple string
    export_escape_json("PlainDevice", out, sizeof(out));
    CHECK(strcmp(out, "PlainDevice") == 0);

    // Quotes and backslashes
    export_escape_json("Line1\nLine2 \"Quote\" \\slash", out, sizeof(out));
    CHECK(strstr(out, "\\n") != NULL);
    CHECK(strstr(out, "\\\"Quote\\\"") != NULL);
    CHECK(strstr(out, "\\\\slash") != NULL);

    // Null safety
    export_escape_json(NULL, out, sizeof(out));
    CHECK(strcmp(out, "") == 0);
}

static void test_table_export(void) {
    struct dev_table t;
    dev_table_init(&t);

    uint8_t a1[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    struct dev_entry *e1 = dev_table_upsert(&t, a1, 1, -60, "Device, One", 1000);
    CHECK(e1 != NULL);
    snprintf(e1->category, sizeof(e1->category), "phone");
    e1->exposure = 75;

    uint8_t a2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    struct dev_entry *e2 = dev_table_upsert(&t, a2, 2, -80, "Smart \"Beacon\"", 1005);
    CHECK(e2 != NULL);
    snprintf(e2->category, sizeof(e2->category), "sensor");
    e2->exposure = 30;

    // Test CSV export to memory buffer
    char csv_buf[2048] = {0};
    FILE *f_csv = fmemopen(csv_buf, sizeof(csv_buf), "w");
    CHECK(f_csv != NULL);
    CHECK(export_csv(&t, f_csv) == 0);
    fclose(f_csv);

    CHECK(strstr(csv_buf, "address,address_type,privacy,trackable") != NULL);
    CHECK(strstr(csv_buf, "06:05:04:03:02:01,public") != NULL);
    CHECK(strstr(csv_buf, "\"Device, One\",phone,75,1") != NULL);
    CHECK(strstr(csv_buf, "\"Smart \"\"Beacon\"\"\",sensor,30,1") != NULL);

    // Test JSON export to memory buffer
    char json_buf[2048] = {0};
    FILE *f_json = fmemopen(json_buf, sizeof(json_buf), "w");
    CHECK(f_json != NULL);
    CHECK(export_json(&t, f_json) == 0);
    fclose(f_json);

    CHECK(strstr(json_buf, "[\n  {\n") != NULL);
    CHECK(strstr(json_buf, "\"address\": \"06:05:04:03:02:01\"") != NULL);
    CHECK(strstr(json_buf, "\"name\": \"Device, One\"") != NULL);
    CHECK(strstr(json_buf, "\"exposure\": 75") != NULL);
    CHECK(strstr(json_buf, "\"name\": \"Smart \\\"Beacon\\\"\"") != NULL);
    CHECK(strstr(json_buf, "}\n]") != NULL);

    // Null checks
    CHECK(export_csv(NULL, stdout) == -1);
    CHECK(export_csv(&t, NULL) == -1);
    CHECK(export_json(NULL, stdout) == -1);
    CHECK(export_json(&t, NULL) == -1);

    dev_table_free(&t);
}

int main(void) {
    printf("test_export\n");
    test_csv_escaping();
    test_json_escaping();
    test_table_export();
    return TEST_REPORT();
}
