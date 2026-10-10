// ========================================
//  nom du fichier: hci_user_channel.h
//  description courte: Single implementation of the HCI_CHANNEL_USER raw
//  socket lifecycle (open/close, with the mandatory BlueZ mgmt power
//  toggle) and the two packet shapes every attack/probe engine sends over
//  it (raw HCI command, one-shot ACL/L2CAP PDU). Before this module
//  existed, src/smp_native/smp_native.c, src/smp_native/blerp_attack.c and
//  src/peripheral_native.c each carried their own copy of this ~40-line
//  block.
//  dernière modification : 2026-10-10
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_HCI_USER_CHANNEL_H
#define BLEURP_HCI_USER_CHANNEL_H

#include <stddef.h>
#include <stdint.h>

// Open an HCI_CHANNEL_USER raw socket on hci<dev_id>.
//
// Powers the adapter down first via BlueZ mgmt: bind(HCI_CHANNEL_USER)
// fails with EBUSY while the kernel Bluetooth stack still owns the
// adapter, which is the normal state whenever bluetoothd is running. The
// mgmt power-down is best-effort -- if it fails (e.g. missing
// CAP_NET_ADMIN), the socket() + bind() attempt still proceeds, since a
// manually-stopped bluetoothd leaves the channel free regardless.
//
// On failure, returns -1 with errno set to whatever socket()/bind() left
// (typically EPERM/EACCES without CAP_NET_RAW, or EBUSY if the adapter
// could not be freed), and the adapter is powered back on before
// returning. Use hci_user_channel_strerror(errno) for a one-line,
// user-facing diagnostic.
int hci_user_channel_open(int dev_id);

// Close `fd` and power the adapter back on via mgmt, for the rest of the
// system (bluetoothd, other tools). Safe to call with fd < 0 (skips the
// close). Always returns to the caller -- the mgmt power-on is
// best-effort, matching hci_user_channel_open()'s own power-down.
void hci_user_channel_close(int fd, int dev_id);

// Map an errno left by hci_user_channel_open() to a one-line, user-facing
// diagnostic ("run with sudo or 'make setcap'", "adapter busy", ...).
// Pure function: no I/O, safe to unit test. Never returns NULL.
const char *hci_user_channel_strerror(int err);

// Write a raw HCI command packet (see hci_build_command() in hci_cmd.h for
// the exact wire layout). Returns 0 on success, -1 on a short or failed
// write.
int hci_user_channel_send_cmd(int fd, uint16_t opcode,
                              const uint8_t *param, uint8_t param_len);

// Same as hci_user_channel_send_cmd(), but polls up to ~2s for the
// matching Command Complete or Command Status event instead of firing and
// forgetting. *out_status (if non-NULL) receives the controller's HCI
// status byte once a matching event arrives. Returns 0 when the command
// completed with status 0x00, -1 otherwise -- including on timeout, in
// which case *out_status is left untouched.
int hci_user_channel_send_cmd_sync(int fd, uint16_t opcode,
                                   const uint8_t *param, uint8_t param_len,
                                   uint8_t *out_status);

// Build an ACL Data packet carrying one non-fragmented, non-flushable
// (PB=00b) L2CAP PDU -- the shape every SMP/ATT PDU in this codebase fits
// in a single packet. Returns the number of bytes written to `out`, or -1
// with errno set (EINVAL for NULL args, ENOSPC when `out`/`len` can't hold
// the 9-byte framing plus `payload`).
//
// Exposed separately from hci_user_channel_send_acl() so the framing
// itself can be unit tested without a socket.
int hci_user_channel_build_acl(uint8_t *out, size_t out_len,
                               uint16_t conn_handle, uint16_t cid,
                               const uint8_t *payload, uint16_t payload_len);

// Build (see hci_user_channel_build_acl()) and write one ACL/L2CAP PDU.
// Returns 0 on success, -1 on a build or write failure.
int hci_user_channel_send_acl(int fd, uint16_t conn_handle, uint16_t cid,
                              const uint8_t *payload, uint16_t payload_len);

// Read the controller's own public address via HCI_Read_BD_ADDR (opcode
// 0x1009), polling up to ~2s for the reply. Returns 0 and fills `out`
// (HCI/LE byte order, LSB first) on success, -1 on timeout or failure.
int hci_user_channel_read_bdaddr(int fd, uint8_t out[6]);

#endif // BLEURP_HCI_USER_CHANNEL_H
