// ========================================
//  nom du fichier: gatt_cmd.c
//  description courte: Implementation of the `enum`/`audit`/`read`/`write`
//  subcommands. Extracted from src/main.c during the v2 rewrite's Phase 8
//  breakup. See gatt_cmd.h for the contract.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#include "gatt_cmd.h"
#include "common.h"
#include "ad_parse.h"
#include "addr_priv.h"
#include "audit.h"
#include "gatt.h"
#include "l2cap.h"

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Format characteristic properties as short flags, e.g. "R W N".
static void props_str(uint8_t p, char *buf, size_t n) {
    buf[0] = '\0';
    struct { uint8_t bit; const char *s; } m[] = {
        {GATT_PROP_READ, "R"}, {GATT_PROP_WRITE, "W"},
        {GATT_PROP_WRITE_NR, "w"}, {GATT_PROP_NOTIFY, "N"},
        {GATT_PROP_INDICATE, "I"},
    };
    for (size_t i = 0; i < sizeof m / sizeof m[0]; i++) {
        if (p & m[i].bit) {
            if (buf[0] != '\0') strncat(buf, " ", n - strlen(buf) - 1);
            strncat(buf, m[i].s, n - strlen(buf) - 1);
        }
    }
}

// Connect to a device and print its GATT tree. Address is in HCI byte order.
int do_enum(const uint8_t addr[6], uint8_t atype) {
    char as[18];
    snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);

    fprintf(stderr, "Authorized targets only. Connecting to %s ...\n", as);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    uint16_t mtu = 0;
    (void)gatt_exchange_mtu(fd, 517, &mtu);
    printf("Connected to %s (ATT MTU=%u)\n\n", as, mtu ? mtu : 23);

    struct gatt_service svcs[64];
    size_t nsvc = 0;
    if (gatt_discover_services(fd, svcs, 64, &nsvc) < 0) {
        perror("discover services");
        bleurp_l2_close(fd);
        return 1;
    }

    size_t shown = nsvc < 64 ? nsvc : 64;
    printf("GATT tree (%zu service(s)):\n", nsvc);
    for (size_t i = 0; i < shown; i++) {
        const struct gatt_service *s = &svcs[i];
        if (s->uuid_is_128) {
            printf("[SVC] 0x%04X-0x%04X  128-bit UUID\n", s->start_handle, s->end_handle);
        } else {
            const char *name = ad_service_name(s->uuid16);
            printf("[SVC] 0x%04X-0x%04X  0x%04X%s%s\n", s->start_handle,
                   s->end_handle, s->uuid16, name ? "  " : "", name ? name : "");
        }
        struct gatt_char chs[64];
        size_t nch = 0;
        gatt_discover_characteristics(fd, s->start_handle, s->end_handle, chs, 64, &nch);
        size_t cshown = nch < 64 ? nch : 64;
        for (size_t j = 0; j < cshown; j++) {
            const struct gatt_char *c = &chs[j];
            char pr[16];
            props_str(c->properties, pr, sizeof pr);
            if (c->uuid_is_128) {
                printf("   [CHR] val 0x%04X  [%s]  128-bit UUID\n", c->value_handle, pr);
            } else {
                printf("   [CHR] val 0x%04X  [%s]  0x%04X\n", c->value_handle, pr, c->uuid16);
            }
        }
    }

    bleurp_l2_close(fd);
    return 0;
}

// Probe one readable characteristic and print its audit verdict. Reads the
// value handle and classifies the outcome; never writes. `atype` is unused
// beyond the already-open socket but kept for signature symmetry.
static void audit_probe_char(int fd, const struct gatt_char *c) {
    char pr[16];
    props_str(c->properties, pr, sizeof pr);

    char uuid[24];
    if (c->uuid_is_128) snprintf(uuid, sizeof uuid, "128-bit");
    else                snprintf(uuid, sizeof uuid, "0x%04X", c->uuid16);

    const char *svc_name = c->uuid_is_128 ? NULL : ad_service_name(c->uuid16);

    if (c->properties & GATT_PROP_READ) {
        uint8_t buf[517];
        size_t len = 0;
        uint8_t err = 0;
        int rc = gatt_read(fd, c->value_handle, buf, sizeof buf, &len, &err);
        audit_verdict_t v = audit_classify_read(rc == 0, err);
        printf("  0x%04X  [%-6s]  %-8s %-10s", c->value_handle, pr, uuid,
               audit_verdict_label(v));
        if (v == AUDIT_OPEN)           printf(" %zu byte(s) readable unauthenticated", len);
        else if (v == AUDIT_PROTECTED) printf(" needs pairing (ATT 0x%02x)", err);
        else if (v == AUDIT_OTHER && err) printf(" ATT 0x%02x", err);
        if (svc_name) printf("  (%s)", svc_name);
        printf("\n");
    } else {
        // Not readable: report the capability, do not touch the value.
        printf("  0x%04X  [%-6s]  %-8s %-10s", c->value_handle, pr, uuid, "-");
        if (c->properties & (GATT_PROP_WRITE | GATT_PROP_WRITE_NR | GATT_PROP_SIGNED_WRITE))
            printf(" write-capable (not tested)");
        if (svc_name) printf("  (%s)", svc_name);
        printf("\n");
    }
}

// Connect to an authorized device and audit which characteristics are
// accessible without pairing. Reads readable values only; write-capable
// characteristics are reported but never written. Address is in HCI order.
int do_audit(const uint8_t addr[6], uint8_t atype) {
    char as[18];
    snprintf(as, sizeof as, "%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);

    addr_privacy_t p = addr_privacy(addr, atype);
    fprintf(stderr, "Authorized targets only. Connecting to %s ...\n", as);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    uint16_t mtu = 0;
    (void)gatt_exchange_mtu(fd, 517, &mtu);
    printf("GATT access audit for %s (priv=%s%s, ATT MTU=%u)\n\n", as,
           addr_privacy_label(p), addr_is_trackable(p) ? " [trackable]" : "",
           mtu ? mtu : 23);

    struct gatt_service svcs[64];
    size_t nsvc = 0;
    if (gatt_discover_services(fd, svcs, 64, &nsvc) < 0) {
        perror("discover services");
        bleurp_l2_close(fd);
        return 1;
    }

    printf("  handle  props       uuid     verdict    detail\n");
    printf("  ------  ----------  -------- ---------- ------\n");
    size_t shown = nsvc < 64 ? nsvc : 64;
    for (size_t i = 0; i < shown; i++) {
        struct gatt_char chs[64];
        size_t nch = 0;
        gatt_discover_characteristics(fd, svcs[i].start_handle,
                                      svcs[i].end_handle, chs, 64, &nch);
        size_t cshown = nch < 64 ? nch : 64;
        for (size_t j = 0; j < cshown; j++)
            audit_probe_char(fd, &chs[j]);
    }

    printf("\nLegend: OPEN=readable without pairing  PROTECTED=needs pairing"
           "  DENIED=read not permitted  OTHER=other ATT error\n");
    bleurp_l2_close(fd);
    return 0;
}

// enum subcommand: parse the address/type then dump the GATT tree.
int cmd_enum(int argc, char **argv) {
    uint8_t atype = BLEURP_BDADDR_LE_PUBLIC;
    int opt;
    while ((opt = getopt(argc, argv, "t:h")) != -1) {
        switch (opt) {
        case 't':
            atype = (strcmp(optarg, "random") == 0) ? BLEURP_BDADDR_LE_RANDOM
                                                     : BLEURP_BDADDR_LE_PUBLIC;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: bleurp enum <ADDR> [-t public|random]\n");
            return (opt == 'h') ? 0 : 2;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Usage: bleurp enum <ADDR> [-t public|random]\n");
        return 2;
    }
    uint8_t addr[6];
    if (parse_addr(argv[optind], addr) < 0) {
        fprintf(stderr, "invalid address: %s\n", argv[optind]);
        return 2;
    }
    return do_enum(addr, atype);
}

// audit subcommand: parse the address/type then audit unauthenticated access.
int cmd_audit(int argc, char **argv) {
    uint8_t atype = BLEURP_BDADDR_LE_PUBLIC;
    int opt;
    while ((opt = getopt(argc, argv, "t:h")) != -1) {
        switch (opt) {
        case 't':
            atype = (strcmp(optarg, "random") == 0) ? BLEURP_BDADDR_LE_RANDOM
                                                     : BLEURP_BDADDR_LE_PUBLIC;
            break;
        case 'h':
        default:
            fprintf(stderr, "Usage: bleurp audit <ADDR> [-t public|random]\n");
            return (opt == 'h') ? 0 : 2;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "Usage: bleurp audit <ADDR> [-t public|random]\n");
        return 2;
    }
    uint8_t addr[6];
    if (parse_addr(argv[optind], addr) < 0) {
        fprintf(stderr, "invalid address: %s\n", argv[optind]);
        return 2;
    }
    return do_audit(addr, atype);
}

// Hex digit value, or -1.
static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

// Parse a 16-bit number (accepts 0x-prefixed). Returns 0 or -1.
static int parse_u16(const char *s, uint16_t *out) {
    char *end;
    long v = strtol(s, &end, 0);
    if (*end != '\0' || v < 0 || v > 0xffff) return -1;
    *out = (uint16_t)v;
    return 0;
}

// Parse a hex string (optional ':'/' ' separators) into bytes. Returns len or -1.
static ssize_t parse_hex(const char *s, uint8_t *out, size_t cap) {
    size_t n = 0;
    while (*s) {
        if (*s == ':' || *s == ' ') { s++; continue; }
        int hi = hexval(*s++);
        int lo = (*s) ? hexval(*s++) : -1;
        if (hi < 0 || lo < 0 || n >= cap) return -1;
        out[n++] = (uint8_t)((hi << 4) | lo);
    }
    return (ssize_t)n;
}

// Shared option/positional parse for read/write: address + handle (+ value).
static int connect_target(int argc, char **argv, uint8_t addr[6],
                          uint8_t *atype, int *pos) {
    *atype = BLEURP_BDADDR_LE_PUBLIC;
    int opt;
    while ((opt = getopt(argc, argv, "t:h")) != -1) {
        if (opt == 't') {
            *atype = (strcmp(optarg, "random") == 0) ? BLEURP_BDADDR_LE_RANDOM
                                                      : BLEURP_BDADDR_LE_PUBLIC;
        } else {
            return -1;
        }
    }
    if (optind >= argc || parse_addr(argv[optind], addr) < 0) return -1;
    *pos = optind + 1;
    return 0;
}

// read subcommand: read a characteristic/descriptor value by handle.
int cmd_read(int argc, char **argv) {
    uint8_t addr[6], atype;
    int pos;
    if (connect_target(argc, argv, addr, &atype, &pos) < 0 || pos >= argc) {
        fprintf(stderr, "Usage: bleurp read <ADDR> <handle> [-t public|random]\n");
        return 2;
    }
    uint16_t handle;
    if (parse_u16(argv[pos], &handle) < 0) {
        fprintf(stderr, "invalid handle: %s\n", argv[pos]);
        return 2;
    }

    fprintf(stderr, "Authorized targets only. Connecting to %s ...\n", argv[optind]);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) { perror("connect"); return 1; }
    (void)gatt_exchange_mtu(fd, 517, NULL);

    uint8_t buf[512];
    size_t len = 0;
    uint8_t err = 0;
    if (gatt_read(fd, handle, buf, sizeof buf, &len, &err) < 0) {
        if (err) fprintf(stderr, "read denied (ATT error 0x%02x)\n", err);
        else perror("read");
        bleurp_l2_close(fd);
        return 1;
    }
    printf("handle 0x%04X = %zu byte(s):\n  hex:", handle, len);
    for (size_t i = 0; i < len; i++) printf(" %02x", buf[i]);
    printf("\n  txt: ");
    for (size_t i = 0; i < len; i++) putchar((buf[i] >= 32 && buf[i] < 127) ? buf[i] : '.');
    printf("\n");
    bleurp_l2_close(fd);
    return 0;
}

// write subcommand: write bytes to a characteristic by handle.
int cmd_write(int argc, char **argv) {
    uint8_t addr[6], atype;
    int pos;
    if (connect_target(argc, argv, addr, &atype, &pos) < 0 || pos + 1 >= argc) {
        fprintf(stderr, "Usage: bleurp write <ADDR> <handle> <hexbytes> [-t public|random]\n");
        return 2;
    }
    uint16_t handle;
    if (parse_u16(argv[pos], &handle) < 0) {
        fprintf(stderr, "invalid handle: %s\n", argv[pos]);
        return 2;
    }
    uint8_t value[512];
    ssize_t vlen = parse_hex(argv[pos + 1], value, sizeof value);
    if (vlen < 0) {
        fprintf(stderr, "invalid hex value: %s\n", argv[pos + 1]);
        return 2;
    }

    fprintf(stderr, "Authorized targets only. Writing %zd byte(s) to handle 0x%04X ...\n",
            (ssize_t)vlen, handle);
    int fd = bleurp_l2_connect(addr, atype);
    if (fd < 0) { perror("connect"); return 1; }
    (void)gatt_exchange_mtu(fd, 517, NULL);

    uint8_t err = 0;
    if (gatt_write(fd, handle, value, (size_t)vlen, &err) < 0) {
        if (err) fprintf(stderr, "write denied (ATT error 0x%02x)\n", err);
        else perror("write");
        bleurp_l2_close(fd);
        return 1;
    }
    printf("write ok (handle 0x%04X)\n", handle);
    bleurp_l2_close(fd);
    return 0;
}
