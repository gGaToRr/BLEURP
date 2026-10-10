// ==============================================================================
//  nom du fichier: smp_native.h
//  description courte: Module natif Linux pour l'interaction bas niveau SMP
//  (Security Manager Protocol) via HCI User Channel ou sockets directes.
//  Permet de forger des trames d'appairage et d'inspecter les réponses sans
//  dépendance de pile lourde (étude du BLE bas niveau).
// ==============================================================================

#ifndef BLEURP_SMP_NATIVE_H
#define BLEURP_SMP_NATIVE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include "smp.h"

// État de la liaison Link Layer obtenue par la sonde
enum smp_link_status {
    SMP_LINK_UNKNOWN,    // La sonde n'a pas atteint l'étape de connexion
    SMP_LINK_UP,         // Liaison LE établie, la cible est joignable
    SMP_LINK_NOT_FOUND,  // Pas de liaison avant le timeout (cible absente)
    SMP_LINK_HCI_ERROR,  // Le contrôleur a refusé ou échoué (hci_status)
};

// Résultat du diagnostic SMP
struct smp_probe_result {
    bool success;              // Réponse SMP reçue (Pairing Response ou Failed)
    bool pairing_failed;       // Réponse "Pairing Failed" (code de refus)
    uint8_t fail_reason;       // Raison du refus si pairing_failed == true
    uint8_t io_capability;     // Capacités I/O déclarées par la cible
    uint8_t oob_data_flag;     // Présence de données OOB
    uint8_t auth_req;          // Octet AuthReq retourné par la cible
    uint8_t max_key_size;      // Taille maximale de clé acceptée (octets)
    uint8_t init_key_dist;     // Distribution clés Initiator
    uint8_t resp_key_dist;     // Distribution clés Responder
    enum smp_link_status link; // Où la sonde s'est arrêtée
    uint8_t hci_status;        // Code HCI si link == SMP_LINK_HCI_ERROR
};

// Parse un événement HCI Command Status (code 0x0f). `evt` pointe sur le
// code de l'événement (indicateur de paquet déjà retiré). Renvoie 0 et
// remplit opcode/status, ou -1 avec errno = EBADMSG.
int smp_parse_cmd_status(const uint8_t *evt, size_t len,
                         uint16_t *opcode, uint8_t *status);

// Remplit les 25 octets de paramètres de LE Create Connection (0x200d) pour
// la cible. `bleurp_atype` vaut BLEURP_BDADDR_LE_PUBLIC (1) ou
// BLEURP_BDADDR_LE_RANDOM (2) et est traduit en 0x00 / 0x01 pour HCI.
// Renvoie 0, ou -1 avec errno = EINVAL.
int smp_le_create_conn_params(uint8_t out[25], uint8_t bleurp_atype,
                              const uint8_t addr[6]);

// Exécute la sonde SMP native sur un adaptateur HCI (ex: hci0 = dev_id 0)
// vers l'adresse MAC spécifiée (6 octets LSB first), avec l'offre faible
// par défaut (bonding seul, pas de MITM, 7 octets).
// addr_type: 1 = LE Public, 2 = LE Random
// Renvoie 0 quand la sonde a tourné (lire out_result->link et ->success),
// -1 si l'adaptateur n'a pas pu être utilisé (errno renseigné).
int smp_native_probe_device(int dev_id, const uint8_t target_addr[6],
                            uint8_t addr_type, int timeout_ms,
                            struct smp_probe_result *out_result);

// Même sonde, avec une offre de Pairing Request choisie par l'appelant
// (utilisée par le test de re-pairing). `offer` ne doit pas être NULL.
int smp_native_probe_offer(int dev_id, const uint8_t target_addr[6],
                           uint8_t addr_type, int timeout_ms,
                           const struct smp_pairing_params *offer,
                           struct smp_probe_result *out_result);

// Offre utilisée par la sonde par défaut (bonding seul, 7 octets, LTK
// distribué des deux côtés). Le re-pairing part de la même offre.
void smp_native_default_offer(struct smp_pairing_params *out);

// Test de Security Request côté Périphérique (papier BLERP, constat Apple) :
// annonce connectable, attente d'une Central, envoi d'un SMP Security Request
// avec le niveau `arsr`, puis enregistrement de la première réaction.
// `adv_name` est le nom annoncé. Ne calcule ni n'échange aucune clé.
// Renvoie 0 quand le test a tourné, -1 si l'adaptateur n'a pas pu être utilisé.
// What the Security Request probe does on top of the plain request.
enum secreq_mode {
    SECREQ_MODE_PLAIN,         // SEC REQ on connect, nothing answered (Listing 1)
    SECREQ_MODE_REJECT_ENC,    // V5: reject the Central's encryption request, then SEC REQ
    SECREQ_MODE_DOWNGRADE_RSP, // V3: answer its Pairing Request with a weaker AuthReq
};

struct secreq_observation;
int smp_native_secreq_probe(int dev_id, uint8_t arsr, enum secreq_mode mode,
                            const char *adv_name, int wait_conn_ms, int wait_react_ms,
                            struct secreq_observation *obs);

// Affiche de manière formatée et lisible les résultats de la sonde
void smp_native_print_result(const struct smp_probe_result *res, const char *target_mac);

#endif // BLEURP_SMP_NATIVE_H
