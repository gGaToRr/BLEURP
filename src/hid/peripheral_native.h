// ==============================================================================
//  nom du fichier: peripheral_native.h
//  description courte: Émulateur natif Linux de périphérique BLE Clavier HID
//  (HOGP - HID over GATT Profile) via HCI User Channel.
//  Permet au PC d'émettre des annonces en tant que Clavier Bluetooth, d'accepter
//  les connexions de smartphones (iOS, Android), de négocier l'appairage SMP,
//  d'inspecter les échanges de clés et d'injecter des frappes clavier.
// ==============================================================================

#ifndef BLEURP_PERIPHERAL_NATIVE_H
#define BLEURP_PERIPHERAL_NATIVE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Configuration du périphérique clavier BLE
struct peripheral_config {
    int dev_id;                  // Adaptateur HCI (0 = hci0)
    const char *device_name;     // Nom annoncé (ex: "BLEURP Keyboard")
    uint8_t io_capability;       // Capacité I/O (0x02 = KeyboardOnly, 0x03 = NoInputNoOutput)
    uint8_t auth_req;            // Drapeaux AuthReq (0x01 Bonding, 0x05 MITM+Bonding, 0x0D SC+MITM+Bonding)
    uint8_t max_key_size;        // Taille max de clé acceptée (7..16)
    bool trigger_sec_req;        // Émettre un SMP Security Request à la connexion
    const char *payload_file;    // Fichier DuckyScript à exécuter automatiquement (optionnel)
};

// Statistiques et état d'une session périphérique
struct peripheral_stats {
    int connections_count;       // Nombre de connexions reçues
    int smp_requests_count;      // Nombre de requêtes SMP traitées
    int smp_pairings_success;    // Appairages SMP réussis
    int att_requests_count;      // Requêtes ATT / GATT traitées
    int keystrokes_sent;         // Frappes de touches envoyées
    char peer_addr_str[18];      // Adresse MAC du smartphone connecté
    uint8_t peer_addr_type;      // 0 = Public, 1 = Random
    bool notifications_enabled;  // Client a souscrit aux notifications HID (CCCD)
};

// Construction des paquets d'annonces (Advertising Data & Scan Response Data)
int peripheral_build_adv_data(const char *name, uint8_t *out_buf, size_t max_len);
int peripheral_build_scan_rsp(const char *name, uint8_t *out_buf, size_t max_len);

// Moteur de base de données GATT (HOGP HID Keyboard)
int gatt_server_handle_att_packet(uint16_t conn_handle,
                                 const uint8_t *req, size_t req_len,
                                 uint8_t *rsp, size_t rsp_max,
                                 const char *dev_name,
                                 bool *out_notifications_enabled);

// Gestionnaire du protocole de sécurité SMP pour le rôle Périphérique (Slave)
int smp_server_handle_packet(uint16_t conn_handle,
                             const uint8_t *req, size_t req_len,
                             uint8_t *rsp, size_t rsp_max,
                             const struct peripheral_config *cfg,
                             struct peripheral_stats *stats);

// Fonctions cryptographiques BLE SMP (Confirm c1 et STK s1)
void smp_c1_calc(const uint8_t k[16], const uint8_t r[16],
                 const uint8_t pres[7], const uint8_t preq[7],
                 uint8_t iat, uint8_t rat,
                 const uint8_t ia[6], const uint8_t ra[6],
                 uint8_t out_c[16]);

void smp_s1_calc(const uint8_t k[16], const uint8_t r1[16], const uint8_t r2[16], uint8_t out[16]);

// Envoi d'un rapport HID clavier (Input Report) via notification ATT sur le Handle 0x0018
int peripheral_send_hid_report(int fd, uint16_t conn_handle, uint8_t modifiers, const uint8_t keys[6]);

// Envoi d'une frappe de touche (appui + relâchement)
int peripheral_send_keystroke(int fd, uint16_t conn_handle, uint8_t modifier, uint8_t keycode);

// Envoi d'une chaîne de texte ASCII convertie en frappes HID
int peripheral_send_text(int fd, uint16_t conn_handle, const char *text);

// Exécution de la boucle principale du serveur Périphérique Clavier BLE
int peripheral_keyboard_run(const struct peripheral_config *cfg);

#endif // BLEURP_PERIPHERAL_NATIVE_H
