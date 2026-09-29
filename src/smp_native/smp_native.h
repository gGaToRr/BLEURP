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

// Résultat du diagnostic SMP
struct smp_probe_result {
    bool success;              // Réponse reçue avec succès
    bool pairing_failed;       // Réponse "Pairing Failed" (code de refus)
    uint8_t fail_reason;       // Raison du refus si pairing_failed == true
    uint8_t io_capability;     // Capacités I/O déclarées par la cible
    uint8_t oob_data_flag;     // Présence de données OOB
    uint8_t auth_req;          // Octet AuthReq retourné par la cible
    uint8_t max_key_size;      // Taille maximale de clé acceptée (octets)
    uint8_t init_key_dist;     // Distribution clés Initiator
    uint8_t resp_key_dist;     // Distribution clés Responder
};

// Exécute la sonde SMP native sur un adaptateur HCI (ex: hci0 = dev_id 0)
// vers l'adresse MAC spécifiée (6 octets LSB first).
// addr_type: 1 = LE Public, 2 = LE Random
int smp_native_probe_device(int dev_id, const uint8_t target_addr[6],
                            uint8_t addr_type, int timeout_ms,
                            struct smp_probe_result *out_result);

// Affiche de manière formatée et lisible les résultats de la sonde
void smp_native_print_result(const struct smp_probe_result *res, const char *target_mac);

#endif // BLEURP_SMP_NATIVE_H
