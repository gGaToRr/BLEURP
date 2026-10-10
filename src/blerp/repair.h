// ========================================
//  nom du fichier: repair.h
//  description courte: Re-pairing check (BLERP, NDSS 2026). Reads the bond
//  this adapter already holds with a device (BlueZ "info" file), offers a
//  pairing weaker than that bond, and classifies the peer's reply: refused
//  (anti-downgrade), accepted with a lower level (downgrade candidate), or
//  no reply. Feature negotiation only: no key is ever exchanged.
//  dernière modification : 2026-10-03
//  auteur: GitHub/@gGaToRr
// ========================================

#ifndef BLEURP_REPAIR_H
#define BLEURP_REPAIR_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "smp.h"
#include "smp_native.h"

// Where BlueZ keeps its bonds. Root-only on most distributions.
#define BLEURP_BLUEZ_STORE_DIR "/var/lib/bluetooth"

// Security level stored in the bond (ARPK in the BLERP paper).
struct smp_bond_info {
    bool authenticated; // MITM protection was used when the bond was made
    uint8_t enc_size;   // Encryption key size of the stored LTK (7..16)
};

// Parse the text of a BlueZ "info" file and extract the LTK section
// ([LongTermKey] or [SlaveLongTermKey]). Returns 0 on success, -1 with
// errno = EINVAL (NULL args), ENOENT (no LE bond in the text) or EBADMSG
// (LE bond found but without a usable EncSize).
int smp_bond_parse(const char *info_text, struct smp_bond_info *out);

// Load the bond between the adapter `adapter_addr` and the device
// `device_addr` (both "AA:BB:CC:DD:EE:FF", upper case, as BlueZ names its
// directories). Reads <store_dir>/<adapter>/<device>/info. Returns 0 or -1
// with errno set (EACCES when the store is root-only, ENOENT when no bond).
int smp_bond_load(const char *store_dir, const char *adapter_addr,
                  const char *device_addr, struct smp_bond_info *out);

// List the device addresses bonded with `adapter_addr`. Writes up to
// `max` addresses of 18 bytes each into `out` and returns their count, or
// -1 with errno set.
int smp_bond_list(const char *store_dir, const char *adapter_addr,
                  char (*out)[18], int max);

// Read the adapter address of hci<dev_id> through the mgmt control socket
// ("AA:BB:..." upper case, written into `out` of 18 bytes). Needs the same
// rights as the other mgmt calls. Returns 0 or -1 with errno set.
int smp_adapter_addr(int dev_id, char out[18]);

// What the peer did with a pairing weaker than the stored bond.
enum smp_repair_outcome {
    SMP_REPAIR_NO_REPLY,            // no SMP answer: inconclusive
    SMP_REPAIR_REFUSED,             // Pairing Failed: anti-downgrade seen
    SMP_REPAIR_ACCEPTED_DOWNGRADE,  // peer proceeds below the stored bond
    SMP_REPAIR_ACCEPTED_SAFE,       // peer proceeds without going lower
};

// Verdict of one vulnerability test, as printed in the [VERDICT] lines.
// Shared by the re-pairing and Security Request tests.
enum blerp_verdict {
    BLERP_VERDICT_YES,           // vulnerable
    BLERP_VERDICT_NO,            // not vulnerable (or mitigated)
    BLERP_VERDICT_INCONCLUSIVE,  // the test did not reach the point that decides
};

struct smp_repair_verdict {
    enum smp_repair_outcome outcome;
    bool mitm_downgrade;    // bond was authenticated, the new level is not
    bool entropy_downgrade; // negotiated key size is below the stored one
    uint8_t fail_reason;    // Pairing Failed reason when REFUSED
};

// Classify the probe result against the stored bond. `offer` is what we
// sent. Pure function: no I/O, safe to unit test.
void smp_repair_classify(const struct smp_bond_info *bond,
                         const struct smp_pairing_params *offer,
                         const struct smp_probe_result *res,
                         struct smp_repair_verdict *out);

// Label used in the [VERDICT] lines: "OUI", "NON" or "NON CONCLUANT".
const char *blerp_verdict_label(enum blerp_verdict v);

// V2, unauthenticated Peripheral re-pairing: the peer proceeds with an offer
// that is not tied to the bond. A refusal of a weaker offer does not prove the
// sender was checked, so it stays inconclusive.
enum blerp_verdict smp_repair_verdict_v2(const struct smp_repair_verdict *v);

// V4, re-pairing level downgrade: only meaningful for an authenticated bond.
// The peer proceeds without MITM (YES), refuses it with 0x03 (NO), or
// proceeds without going lower (NO).
enum blerp_verdict smp_repair_verdict_v4(bool bond_authenticated,
                                         const struct smp_repair_verdict *v);

// V6, PK entropy downgrade: the peer proceeds with a key size below the bond
// (YES), refuses it with 0x06 or proceeds at the bond size (NO).
enum blerp_verdict smp_repair_verdict_v6(const struct smp_repair_verdict *v);

#endif // BLEURP_REPAIR_H
