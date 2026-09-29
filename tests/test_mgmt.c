// ========================================
//  nom du fichier: test_mgmt.c
//  description courte: Unit tests for the mgmt packet layer. Verifies the
//  exact command packet bytes (little-endian header + params) and header
//  parsing, including rejection of truncated or NULL input.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#include "test.h"
#include "mgmt.h"

#include <errno.h>
#include <string.h>

// A parameterless command is a 6-byte little-endian header.
static void test_build_no_params(void) {
    uint8_t buf[16];
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_READ_CONTROLLER_INFO, 0, NULL, 0);
    const uint8_t want[] = {
        0x04, 0x00, // opcode 0x0004 (LE)
        0x00, 0x00, // index 0
        0x00, 0x00, // param length 0
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// Start Discovery on controller 0 with the LE address-type bitmask.
static void test_build_start_discovery(void) {
    uint8_t buf[16];
    const uint8_t p[] = {MGMT_ADDR_LE}; // 0x06
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_START_DISCOVERY, 0, p, sizeof p);
    const uint8_t want[] = {
        0x23, 0x00, // opcode 0x0023
        0x00, 0x00, // index 0
        0x01, 0x00, // param length 1
        0x06,       // address type = LE public | LE random
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// Set Static Address on controller 0: opcode + index + the 6-byte address.
static void test_build_set_static_address(void) {
    uint8_t buf[16];
    const uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0xC6};
    ssize_t n = mgmt_build_set_static_address(buf, sizeof buf, 0, addr);
    const uint8_t want[] = {
        0x2c, 0x00, // opcode 0x002c
        0x00, 0x00, // index 0
        0x06, 0x00, // param length 6
        0x11, 0x22, 0x33, 0x44, 0x55, 0xC6,
    };
    CHECK(n == (ssize_t)sizeof want);
    for (size_t i = 0; i < sizeof want; i++) CHECK(buf[i] == want[i]);
}

// A NULL address is rejected with EINVAL.
static void test_build_set_static_address_null(void) {
    uint8_t buf[16];
    errno = 0;
    CHECK(mgmt_build_set_static_address(buf, sizeof buf, 0, NULL) == -1);
    CHECK(errno == EINVAL);
}

// The controller index is encoded little-endian.
static void test_build_index_le(void) {
    uint8_t buf[16];
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_STOP_DISCOVERY, 0x0102, NULL, 0);
    CHECK(n == 6);
    CHECK(buf[2] == 0x02); // index LSB
    CHECK(buf[3] == 0x01); // index MSB
}

// A buffer too small is rejected with ENOSPC.
static void test_build_too_small(void) {
    uint8_t buf[4];
    errno = 0;
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_READ_CONTROLLER_INFO, 0, NULL, 0);
    CHECK(n == -1);
    CHECK(errno == ENOSPC);
}

// NULL params with a non-zero length is rejected with EINVAL.
static void test_build_null_params(void) {
    uint8_t buf[16];
    errno = 0;
    ssize_t n = mgmt_build_command(buf, sizeof buf,
                                   MGMT_OP_START_DISCOVERY, 0, NULL, 3);
    CHECK(n == -1);
    CHECK(errno == EINVAL);
}

// A full header is decoded into opcode, index and length.
static void test_parse_header_ok(void) {
    // Command Complete event, controller 0, 4 param bytes.
    const uint8_t evt[] = {0x01, 0x00, 0x00, 0x00, 0x04, 0x00,
                           0x04, 0x00, 0x00, 0x00};
    struct mgmt_hdr h;
    int r = mgmt_parse_header(evt, sizeof evt, &h);
    CHECK(r == 0);
    CHECK(h.opcode == MGMT_EV_CMD_COMPLETE);
    CHECK(h.index == 0x0000);
    CHECK(h.len == 0x0004);
}

// The index field parses little-endian, including MGMT_INDEX_NONE.
static void test_parse_header_index_none(void) {
    const uint8_t evt[] = {0x02, 0x00, 0xff, 0xff, 0x00, 0x00};
    struct mgmt_hdr h;
    CHECK(mgmt_parse_header(evt, sizeof evt, &h) == 0);
    CHECK(h.opcode == MGMT_EV_CMD_STATUS);
    CHECK(h.index == MGMT_INDEX_NONE);
    CHECK(h.len == 0);
}

// A short buffer and NULL arguments are rejected.
static void test_parse_header_bad(void) {
    const uint8_t evt[] = {0x01, 0x00, 0x00};
    struct mgmt_hdr h;
    errno = 0;
    CHECK(mgmt_parse_header(evt, sizeof evt, &h) == -1);
    CHECK(errno == EBADMSG);
    errno = 0;
    CHECK(mgmt_parse_header(NULL, 6, &h) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(mgmt_parse_header(evt, 6, NULL) == -1);
    CHECK(errno == EINVAL);
}

// --- Read Controller Info parsing ---

// Little-endian writers used to build fixtures.
static void put16(uint8_t *p, uint16_t v) { p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8); }
static void put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

// Build a Read Controller Info "Command Complete" event. Returns its length.
static size_t make_ctrl_info(uint8_t *b, uint8_t status,
                             uint32_t supported, uint32_t current,
                             const char *name) {
    size_t o = 0;
    put16(&b[o], MGMT_EV_CMD_COMPLETE); o += 2;   // event code
    put16(&b[o], 0x0000); o += 2;                 // index 0
    put16(&b[o], (uint16_t)(3 + MGMT_CONTROLLER_INFO_PARAM_LEN)); o += 2;
    put16(&b[o], MGMT_OP_READ_CONTROLLER_INFO); o += 2; // cmd opcode
    b[o++] = status;                              // status
    const uint8_t addr[6] = {0x82, 0x76, 0xc9, 0x56, 0x9e, 0x84};
    memcpy(&b[o], addr, 6); o += 6;               // address
    b[o++] = 0x0c;                                // bluetooth version = 12
    put16(&b[o], 0x000f); o += 2;                 // manufacturer
    put32(&b[o], supported); o += 4;              // supported settings
    put32(&b[o], current); o += 4;                // current settings
    b[o++] = 0; b[o++] = 0; b[o++] = 0;           // class of device
    memset(&b[o], 0, 249);
    strncpy((char *)&b[o], name, 248); o += 249;  // complete name
    memset(&b[o], 0, 11); o += 11;                // short name
    return o;
}

// A valid reply decodes address, version, manufacturer, settings and name.
static void test_ctrl_info_ok(void) {
    uint8_t buf[320];
    uint32_t supported = MGMT_SETTING_LE | MGMT_SETTING_BREDR |
                         MGMT_SETTING_POWERED | MGMT_SETTING_ADVERTISING;
    uint32_t current = MGMT_SETTING_LE | MGMT_SETTING_POWERED;
    size_t n = make_ctrl_info(buf, 0x00, supported, current, "BLEURP-Test");

    struct mgmt_controller_info info;
    int r = mgmt_parse_controller_info(buf, n, &info);
    CHECK(r == 0);
    CHECK(info.bluetooth_version == 12);
    CHECK(info.manufacturer == 0x000f);
    const uint8_t want_addr[6] = {0x82, 0x76, 0xc9, 0x56, 0x9e, 0x84};
    CHECK(memcmp(info.address, want_addr, 6) == 0);
    CHECK(mgmt_has_setting(info.supported_settings, MGMT_SETTING_LE) == true);
    CHECK(mgmt_has_setting(info.current_settings, MGMT_SETTING_POWERED) == true);
    CHECK(mgmt_has_setting(info.current_settings, MGMT_SETTING_ADVERTISING) == false);
    CHECK(strcmp(info.name, "BLEURP-Test") == 0);
    CHECK(info.short_name[0] == '\0');
}

// A non-zero status is reported as EIO.
static void test_ctrl_info_status_fail(void) {
    uint8_t buf[320];
    size_t n = make_ctrl_info(buf, 0x01, 0, 0, "x");
    struct mgmt_controller_info info;
    errno = 0;
    CHECK(mgmt_parse_controller_info(buf, n, &info) == -1);
    CHECK(errno == EIO);
}

// A Command Complete for a different opcode is rejected with EBADMSG.
static void test_ctrl_info_wrong_opcode(void) {
    uint8_t buf[320];
    size_t n = make_ctrl_info(buf, 0x00, MGMT_SETTING_LE, MGMT_SETTING_LE, "x");
    put16(&buf[6], MGMT_OP_SET_POWERED); // tamper the command opcode
    struct mgmt_controller_info info;
    errno = 0;
    CHECK(mgmt_parse_controller_info(buf, n, &info) == -1);
    CHECK(errno == EBADMSG);
}

// A truncated buffer and NULL arguments are rejected.
static void test_ctrl_info_bad(void) {
    uint8_t buf[320];
    size_t n = make_ctrl_info(buf, 0x00, MGMT_SETTING_LE, MGMT_SETTING_LE, "x");
    struct mgmt_controller_info info;
    errno = 0;
    CHECK(mgmt_parse_controller_info(buf, n - 1, &info) == -1);
    CHECK(errno == EBADMSG);
    errno = 0;
    CHECK(mgmt_parse_controller_info(NULL, n, &info) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(mgmt_parse_controller_info(buf, n, NULL) == -1);
    CHECK(errno == EINVAL);
}

// --- Discovery commands and Device Found parsing ---

// Start/Stop Discovery build the right opcode with the LE address bitmask.
static void test_build_discovery(void) {
    uint8_t buf[16];
    ssize_t n = mgmt_build_start_discovery(buf, sizeof buf, 0, MGMT_ADDR_LE);
    const uint8_t start_want[] = {0x23, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06};
    CHECK(n == (ssize_t)sizeof start_want);
    for (size_t i = 0; i < sizeof start_want; i++) CHECK(buf[i] == start_want[i]);

    n = mgmt_build_stop_discovery(buf, sizeof buf, 0, MGMT_ADDR_LE);
    const uint8_t stop_want[] = {0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06};
    CHECK(n == (ssize_t)sizeof stop_want);
    for (size_t i = 0; i < sizeof stop_want; i++) CHECK(buf[i] == stop_want[i]);
}

// Build a Device Found event. Returns its length.
static size_t make_device_found(uint8_t *b, const uint8_t addr[6],
                                uint8_t addr_type, int8_t rssi, uint32_t flags,
                                const uint8_t *eir, uint16_t eir_len) {
    size_t o = 0;
    put16(&b[o], MGMT_EV_DEVICE_FOUND); o += 2;
    put16(&b[o], 0x0000); o += 2;
    put16(&b[o], (uint16_t)(MGMT_DEVICE_FOUND_MIN_PARAMS + eir_len)); o += 2;
    memcpy(&b[o], addr, 6); o += 6;
    b[o++] = addr_type;
    b[o++] = (uint8_t)rssi;
    put32(&b[o], flags); o += 4;
    put16(&b[o], eir_len); o += 2;
    if (eir_len) { memcpy(&b[o], eir, eir_len); o += eir_len; }
    return o;
}

// A Device Found event decodes address, type, RSSI, flags and EIR.
static void test_device_found_ok(void) {
    const uint8_t addr[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    const uint8_t eir[] = {0x02, 0x01, 0x06, 0x04, 0x09, 'B', 'L', 'E'};
    uint8_t buf[64];
    size_t n = make_device_found(buf, addr, MGMT_ADDR_TYPE_LE_RANDOM,
                                 -55, 0x00000004, eir, sizeof eir);
    struct mgmt_device d;
    CHECK(mgmt_parse_device_found(buf, n, &d) == 0);
    CHECK(memcmp(d.address, addr, 6) == 0);
    CHECK(d.addr_type == MGMT_ADDR_TYPE_LE_RANDOM);
    CHECK(d.rssi == -55);
    CHECK(d.flags == 0x00000004);
    CHECK(d.eir_len == sizeof eir);
    CHECK(d.eir != NULL && d.eir[0] == 0x02 && d.eir[4] == 0x09);
}

// A device with no EIR yields a NULL data pointer and zero length.
static void test_device_found_empty_eir(void) {
    const uint8_t addr[6] = {1, 2, 3, 4, 5, 6};
    uint8_t buf[64];
    size_t n = make_device_found(buf, addr, MGMT_ADDR_TYPE_LE_PUBLIC,
                                 -90, 0, NULL, 0);
    struct mgmt_device d;
    CHECK(mgmt_parse_device_found(buf, n, &d) == 0);
    CHECK(d.eir == NULL);
    CHECK(d.eir_len == 0);
    CHECK(d.rssi == -90);
}

// A truncated EIR and a wrong event code are rejected with EBADMSG.
static void test_device_found_bad(void) {
    const uint8_t addr[6] = {1, 2, 3, 4, 5, 6};
    const uint8_t eir[] = {0x02, 0x01, 0x06};
    uint8_t buf[64];
    size_t n = make_device_found(buf, addr, MGMT_ADDR_TYPE_LE_PUBLIC,
                                 -70, 0, eir, sizeof eir);
    struct mgmt_device d;
    errno = 0;
    CHECK(mgmt_parse_device_found(buf, n - 1, &d) == -1);
    CHECK(errno == EBADMSG);
    put16(&buf[0], MGMT_EV_CMD_STATUS); // wrong event code
    errno = 0;
    CHECK(mgmt_parse_device_found(buf, n, &d) == -1);
    CHECK(errno == EBADMSG);
}

// Dispatch capture.
static struct mgmt_device g_dev;
static int g_dev_n;
static void dev_cb(const struct mgmt_device *d, void *user) {
    (void)user;
    g_dev = *d;
    g_dev_n++;
}

// Dispatch invokes the callback for a Device Found and ignores other events.
static void test_dispatch(void) {
    g_dev_n = 0;
    const uint8_t addr[6] = {0xa, 0xb, 0xc, 0xd, 0xe, 0xf};
    uint8_t buf[64];
    size_t n = make_device_found(buf, addr, MGMT_ADDR_TYPE_LE_PUBLIC, -33, 0, NULL, 0);
    CHECK(mgmt_dispatch_event(buf, n, dev_cb, NULL) == 1);
    CHECK(g_dev_n == 1);
    CHECK(g_dev.rssi == -33);

    // A Command Complete event is ignored (returns 0, no callback).
    const uint8_t ev[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00};
    CHECK(mgmt_dispatch_event(ev, sizeof ev, dev_cb, NULL) == 0);
    CHECK(g_dev_n == 1);

    errno = 0;
    CHECK(mgmt_dispatch_event(NULL, 6, dev_cb, NULL) == -1);
    CHECK(errno == EINVAL);
    errno = 0;
    CHECK(mgmt_dispatch_event(buf, n, NULL, NULL) == -1);
    CHECK(errno == EINVAL);
}

// Entry point: run every test case and report the aggregate result.
int main(void) {
    printf("test_mgmt\n");
    test_build_no_params();
    test_build_start_discovery();
    test_build_set_static_address();
    test_build_set_static_address_null();
    test_build_index_le();
    test_build_too_small();
    test_build_null_params();
    test_parse_header_ok();
    test_parse_header_index_none();
    test_parse_header_bad();
    test_ctrl_info_ok();
    test_ctrl_info_status_fail();
    test_ctrl_info_wrong_opcode();
    test_ctrl_info_bad();
    test_build_discovery();
    test_device_found_ok();
    test_device_found_empty_eir();
    test_device_found_bad();
    test_dispatch();
    return TEST_REPORT();
}
