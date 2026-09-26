// ========================================
//  nom du fichier: hci.h
//  description courte: HCI wire constants (packet types and LE scan
//  opcodes) defined locally, so BLEURP needs no libbluetooth-dev. Covers
//  both legacy (BT 4.x) and extended (BT 5.x) scanning commands, plus the
//  informational command used to detect controller capabilities.
//  dernière modification : 2026-09-26
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_HCI_H
#define BLEURP_HCI_H

#include <stdint.h>

// HCI packet type indicators — the first byte written on the HCI transport.
#define HCI_COMMAND_PKT 0x01
#define HCI_ACLDATA_PKT 0x02
#define HCI_EVENT_PKT   0x04

// Opcode Group Fields (OGF): the high 6 bits of an HCI opcode.
#define HCI_OGF_INFO_PARAMS 0x04
#define HCI_OGF_LE_CTL      0x08

// Compose a 16-bit HCI opcode from its OGF and OCF (Opcode Command Field).
#define HCI_OPCODE(ogf, ocf) ((uint16_t)(((ogf) << 10) | ((ocf) & 0x03ff)))

// Informational parameters — used to read the controller's BT version and
// decide between legacy and extended scanning.
#define HCI_OP_READ_LOCAL_VERSION HCI_OPCODE(HCI_OGF_INFO_PARAMS, 0x0001) // 0x1001

// LE controller — legacy advertising/scanning (BT 4.0 -> 4.2).
#define HCI_OP_LE_SET_SCAN_PARAMS HCI_OPCODE(HCI_OGF_LE_CTL, 0x000b) // 0x200b
#define HCI_OP_LE_SET_SCAN_ENABLE HCI_OPCODE(HCI_OGF_LE_CTL, 0x000c) // 0x200c

// LE controller — extended advertising/scanning (BT 5.0+).
#define HCI_OP_LE_SET_EXT_SCAN_PARAMS HCI_OPCODE(HCI_OGF_LE_CTL, 0x0041) // 0x2041
#define HCI_OP_LE_SET_EXT_SCAN_ENABLE HCI_OPCODE(HCI_OGF_LE_CTL, 0x0042) // 0x2042

// LE scan type values used by the Set Scan Parameters commands.
#define HCI_LE_SCAN_PASSIVE 0x00 // listen only (stealthy, no scan requests)
#define HCI_LE_SCAN_ACTIVE  0x01 // send SCAN_REQ to solicit SCAN_RSP (more data)

// HCI event codes (first byte of an HCI event, after the packet type).
#define HCI_EVT_CMD_COMPLETE 0x0e
#define HCI_EVT_LE_META      0x3e

// LE Meta sub-event codes carried inside an HCI_EVT_LE_META event.
#define HCI_SUBEVT_LE_ADV_REPORT     0x02 // legacy advertising report
#define HCI_SUBEVT_LE_EXT_ADV_REPORT 0x0d // extended advertising report (BT5)

// HCI_Version field values (Bluetooth Assigned Numbers, "Host Controller
// Interface" version). Extended advertising/scanning arrives with BT 5.0.
#define HCI_VER_BT_4_0 6
#define HCI_VER_BT_4_1 7
#define HCI_VER_BT_4_2 8
#define HCI_VER_BT_5_0 9

#endif // BLEURP_HCI_H
