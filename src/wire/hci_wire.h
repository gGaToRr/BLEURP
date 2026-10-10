// ========================================
//  nom du fichier: hci_wire.h
//  description courte: HCI wire constants (packet types, opcodes, event and
//  LE Meta sub-event codes), defined locally so BLEURP needs no
//  libbluetooth-dev. Single source of truth: before this file existed, the
//  kernel-mgmt scan path (hci_scan.c/hci_cmd.c/hci_info.c) and the three
//  independent HCI_CHANNEL_USER engines (smp_native.c, blerp_attack.c,
//  peripheral_native.c) each defined their own, sometimes inconsistently
//  named (e.g. HCI_LE_EV_LTK_REQ vs HCI_LE_EV_LTK_REQUEST for the same
//  0x05), copy of these opcodes. Everything HCI-opcode-shaped belongs here.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_HCI_WIRE_H
#define BLEURP_HCI_WIRE_H

#include <stdint.h>

// HCI packet type indicators — the first byte written on the HCI transport.
#define HCI_COMMAND_PKT 0x01
#define HCI_ACLDATA_PKT 0x02
#define HCI_EVENT_PKT   0x04

// Opcode Group Fields (OGF): the high 6 bits of an HCI opcode.
#define HCI_OGF_LINK_CTL     0x01
#define HCI_OGF_CTL_BASEBAND 0x03
#define HCI_OGF_INFO_PARAMS  0x04
#define HCI_OGF_LE_CTL       0x08

// Compose a 16-bit HCI opcode from its OGF and OCF (Opcode Command Field).
#define HCI_OPCODE(ogf, ocf) ((uint16_t)(((ogf) << 10) | ((ocf) & 0x03ff)))

// Link Control — used to tear down an HCI_CHANNEL_USER ACL connection.
#define HCI_OP_DISCONNECT HCI_OPCODE(HCI_OGF_LINK_CTL, 0x0006) // 0x0406

// Controller & Baseband.
#define HCI_OP_SET_EVENT_MASK HCI_OPCODE(HCI_OGF_CTL_BASEBAND, 0x0001) // 0x0c01
#define HCI_OP_RESET          HCI_OPCODE(HCI_OGF_CTL_BASEBAND, 0x0003) // 0x0c03

// Informational parameters.
#define HCI_OP_READ_LOCAL_VERSION HCI_OPCODE(HCI_OGF_INFO_PARAMS, 0x0001) // 0x1001
#define HCI_OP_READ_BD_ADDR       HCI_OPCODE(HCI_OGF_INFO_PARAMS, 0x0009) // 0x1009

// LE controller — legacy advertising/scanning (BT 4.0 -> 4.2), used by the
// kernel-mgmt scan path.
#define HCI_OP_LE_SET_SCAN_PARAMS HCI_OPCODE(HCI_OGF_LE_CTL, 0x000b) // 0x200b
#define HCI_OP_LE_SET_SCAN_ENABLE HCI_OPCODE(HCI_OGF_LE_CTL, 0x000c) // 0x200c

// LE controller — extended advertising/scanning (BT 5.0+).
#define HCI_OP_LE_SET_EXT_SCAN_PARAMS HCI_OPCODE(HCI_OGF_LE_CTL, 0x0041) // 0x2041
#define HCI_OP_LE_SET_EXT_SCAN_ENABLE HCI_OPCODE(HCI_OGF_LE_CTL, 0x0042) // 0x2042

// LE controller — HCI_CHANNEL_USER engines: advertising (Peripheral role),
// connecting (Central role), and LTK delivery for Phase 3 encryption.
#define HCI_OP_LE_SET_EVENT_MASK     HCI_OPCODE(HCI_OGF_LE_CTL, 0x0001) // 0x2001
#define HCI_OP_LE_SET_RANDOM_ADDR    HCI_OPCODE(HCI_OGF_LE_CTL, 0x0005) // 0x2005
#define HCI_OP_LE_SET_ADV_PARAMS     HCI_OPCODE(HCI_OGF_LE_CTL, 0x0006) // 0x2006
#define HCI_OP_LE_SET_ADV_DATA       HCI_OPCODE(HCI_OGF_LE_CTL, 0x0008) // 0x2008
#define HCI_OP_LE_SET_SCAN_RSP_DATA  HCI_OPCODE(HCI_OGF_LE_CTL, 0x0009) // 0x2009
#define HCI_OP_LE_SET_ADV_ENABLE     HCI_OPCODE(HCI_OGF_LE_CTL, 0x000a) // 0x200a
#define HCI_OP_LE_CREATE_CONN        HCI_OPCODE(HCI_OGF_LE_CTL, 0x000d) // 0x200d
#define HCI_OP_LE_CREATE_CONN_CANCEL HCI_OPCODE(HCI_OGF_LE_CTL, 0x000e) // 0x200e
#define HCI_OP_LE_LTK_REPLY          HCI_OPCODE(HCI_OGF_LE_CTL, 0x001a) // 0x201a
#define HCI_OP_LE_LTK_NEG_REPLY      HCI_OPCODE(HCI_OGF_LE_CTL, 0x001b) // 0x201b

// LE scan type values used by the Set Scan Parameters commands.
#define HCI_LE_SCAN_PASSIVE 0x00 // listen only (stealthy, no scan requests)
#define HCI_LE_SCAN_ACTIVE  0x01 // send SCAN_REQ to solicit SCAN_RSP (more data)

// HCI event codes (first byte of an HCI event, after the packet type).
#define HCI_EV_DISCONN_COMPL  0x05
#define HCI_EV_ENCRYPT_CHANGE 0x08
#define HCI_EV_CMD_COMPLETE   0x0e
#define HCI_EV_CMD_STATUS     0x0f
#define HCI_EV_LE_META        0x3e

// LE Meta sub-event codes carried inside an HCI_EV_LE_META event.
#define HCI_SUBEVT_LE_CONN_COMPLETE     0x01 // legacy LE Connection Complete
#define HCI_SUBEVT_LE_ADV_REPORT        0x02 // legacy advertising report
#define HCI_SUBEVT_LE_LTK_REQUEST       0x05 // controller needs an LTK/STK (Phase 3)
#define HCI_SUBEVT_LE_CONN_COMPLETE_ENH 0x0a // Enhanced LE Connection Complete (BT5)
#define HCI_SUBEVT_LE_EXT_ADV_REPORT    0x0d // extended advertising report (BT5)

// HCI_Version field values (Bluetooth Assigned Numbers, "Host Controller
// Interface" version). Extended advertising/scanning arrives with BT 5.0.
#define HCI_VER_BT_4_0 6
#define HCI_VER_BT_4_1 7
#define HCI_VER_BT_4_2 8
#define HCI_VER_BT_5_0 9

#endif // BLEURP_HCI_WIRE_H
