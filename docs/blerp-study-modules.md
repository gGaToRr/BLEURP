# Modules d'étude BLERP : ce qui est implémenté, et pourquoi

Ce document liste les modules ajoutés pour étudier le papier *BLERP: BLE Re-Pairing Attacks and Defenses* (NDSS 2026, copie locale dans `scratch/paper.pdf`). Pour chaque module : son rôle, les choix faits, et la raison de ces choix.

> ⚠️ **Périmètre.** BLEURP mesure, il n'attaque pas. Aucun module ne calcule ni n'échange de clé, aucun ne termine un appairage, aucun ne se fait passer pour un autre appareil. Tests réservés aux appareils que tu possèdes ou pour lesquels tu as une autorisation écrite.

---

## 1. Ce que le papier demande, et ce qu'on peut mesurer

Le papier étudie le **re-pairing** : deux appareils qui partagent déjà une clé (PK) et son niveau de sécurité (ARPK). Quatre des six vulnérabilités sont nouvelles (V1 à V4), deux sont des extensions (V5, V6).

| ID | Problème | Mesurable par BLEURP ? | Module |
| :--- | :--- | :--- | :--- |
| V1 | Central accepte un Security Request non authentifié | Partiellement (réaction à un SEC REQ) | `secreq` |
| V2 | Peripheral accepte un re-pairing sans authentifier le Central | Indice (réponse à une Pairing Request sur un bond) | `repair` |
| V3 | Peripheral annonce un niveau haut puis le baisse | Non (demande la phase 2) | — |
| V4 | Re-pairing accepte un niveau sous ARPK | Indice (MITM retiré d'un bond authentifié) | `repair` |
| V5 | Re-pairing forcé en interrompant la session | Non (exige de couper une session chiffrée) | — |
| V6 | Entropie de clé réduite pendant le re-pairing | Indice (taille de clé négociée sous le bond) | `repair` |

Deux constats du papier ne sont pas des vulnérabilités au sens strict, mais ils structurent les tests :

- **Listing 1** : `ARSR > ARPK` déclenche un re-pairing, sinon le Central lance la reprise de session. C'est la règle que `secreq` vérifie.
- **Constat Apple (section VI-C)** : les iPhone testés **en tant que Central** lancent un re-pairing quand `ARSR ≥ ARPK`. C'est le cas d'égalité que teste `secreq`.

---

## 2. Carte des modules

| Fichier | Rôle | Pourquoi ce module existe |
| :--- | :--- | :--- |
| `src/smp.c`, `src/smp.h` | Codec SMP (Pairing Request, Response, Failed, Security Request), et l'offre faible partagée | Une seule source pour les octets envoyés. Les deux sondes envoient la même offre, donc leurs résultats sont comparables. |
| `src/smp/smp_native.c`, `smp_native.h` | Accès bas niveau à l'adaptateur (HCI User Channel) : sonde d'appairage initial, sonde de Security Request côté Peripheral | Il faut le canal USER pour envoyer des trames SMP sans que la pile BlueZ intervienne. |
| `src/blerp/repair.c`, `repair.h` | Lecture du bond BlueZ, liste des appareils appairés, adresse de l'adaptateur, classification du re-pairing | Le bond est le « ARPK » du papier : sans lui, rien à comparer. |
| `src/blerp/secreq.c`, `secreq.h` | Logique pure du test Security Request : annonce minimale, estimation d'ARPK, réaction attendue, non-conformité | Séparée de l'I/O pour pouvoir être testée sans adaptateur. |
| `src/main.c` | Sous-commandes `smp`, `repair`, `secreq` et affichage des verdicts | Point d'entrée utilisateur. Aucune logique de protocole n'est écrite ici. |
| `tests/test_smp.c`, `test_smp_native.c`, `test_repair.c`, `test_secreq.c` | Tests unitaires | Règle `rules.txt` : TDD. Les tests ne demandent ni adaptateur ni root. |

---

## 3. Détail par module

### 3.1 Codec SMP et offre faible (`smp.c`, `smp.h`)

- `smp_weak_offer()` remplit l'offre utilisée partout : NoInputNoOutput, bonding seul (pas de MITM, pas de SC), taille de clé 7 octets.
- **Pourquoi 7 octets** : c'est la valeur minimale autorisée. Une cible qui l'accepte est un candidat V6 (ou KNOB) dans le cas d'un appairage initial, et un candidat V6 dans le cas d'un bond plus long.
- **Pourquoi partagée** : auparavant chaque sonde codait ses propres octets. Une seule fonction évite les divergences entre `smp`, `repair` et `secreq`.

### 3.2 Sondes HCI (`smp_native.c`)

**Sonde d'appairage initial** (`smp_native_probe_offer`, `smp_native_probe_device`)
- Éteint l'adaptateur via mgmt, l'ouvre en canal USER, envoie HCI Reset, puis LE Create Connection, puis une Pairing Request. Renvoie le **statut de liaison** : pas de liaison, refus du contrôleur (code HCI), connecté sans réponse, ou réponse SMP.
- **Pourquoi un statut** : avant, toute absence de réponse donnait « Timeout ». Un refus du contrôleur, une cible absente et une cible qui ignore sont trois résultats différents.
- **Pourquoi annuler la connexion au timeout** (LE Create Connection Cancel, `0x200e`) : sans cela, le contrôleur continue d'essayer en arrière-plan.

**Sonde de Security Request côté Peripheral** (`smp_native_secreq_probe`)
- Annonce connectable sous l'adresse publique de l'adaptateur, attend une connexion dont le rôle est Peripheral, envoie un SMP Security Request (`0x0b`) avec le niveau `ARSR`, puis enregistre la première réaction :
  - une **Pairing Request** venant de la Central (`SECREQ_PAIRING_STARTED`) ;
  - une **demande de LTK** (événement LE, sous-événement `0x05`) : établissement de session (`SECREQ_SESSION_STARTED`) ;
  - rien, ou une déconnexion (`SECREQ_NO_REACTION`).
- **Pourquoi l'annonce minimale** : le constructeur de publicité existant (`peripheral_build_adv_data`) annonce un **clavier HID** (profil 0x1812, apparence clavier). Pour un test SMP, ce n'est pas le bon profil : une Central verrait un clavier et pourrait lancer une autre procédure. `secreq_build_adv` n'annonce que Flags et nom.
- **Pourquoi on s'arrête à la première réaction** : le papier montre que la suite (phase 2, dérivation de clés) aboutit à l'usurpation. Cet outil s'arrête avant : il n'envoie pas de réponse à la demande de LTK, et ne répond pas à la Pairing Request.

### 3.3 Re-pairing et bonds (`repair.c`, `repair.h`)

- **`smp_bond_parse`** lit le fichier `info` de BlueZ et extrait la section LTK (`[LongTermKey]` ou `[SlaveLongTermKey]`) : `Authenticated` et `EncSize`.
  - **Pourquoi** : ces deux champs donnent un ARPK partiel. BlueZ ne stocke pas le bit SC, donc ARPK ne peut pas être reconstruit entièrement.
- **`smp_bond_load`** charge le fichier d'un appareil. Le dossier `/var/lib/bluetooth` appartient à root : la lecture renvoie `EACCES` sans `sudo`, ce qui est affiché tel quel.
- **`smp_bond_list`** liste les adresses d'identité appairées avec un adaptateur. C'est ce qui permet de retrouver l'adresse d'identité d'un iPhone, qui ne se voit pas au scan.
- **`smp_adapter_addr`** lit l'adresse de l'adaptateur par la commande mgmt `READ_CONTROLLER_INFO`.
  - **Pourquoi pas sysfs** : le fichier `/sys/class/bluetooth/hciN/address` n'existe pas sur le noyau de test. La première version échouait.
- **`smp_repair_classify`** (fonction pure) : compare la réponse à l'offre et au bond.
  - MITM retiré (`mitm_downgrade`) si le bond est authentifié et que la négociation finale n'a pas de MITM. Le MITM négocié est le OU logique des deux côtés.
  - Taille de clé négociée (`entropy_downgrade`) : `min(offre, réponse de la cible)` comparée au bond.
  - Un refus `Pairing Failed` donne `REFUSED`, avec la raison conservée.
  - **Point important** : seules les raisons `0x03` (authentification) et `0x06` (taille de clé) signalent un contrôle anti-downgrade. Les autres (`0x08` Unspecified Reason, par exemple) ne disent rien : l'affichage les marque `RÉSULTAT NON CONCLUANT`. Une première version confondait les deux, d'où la correction.

### 3.4 Test Security Request (`secreq.c`, `secreq.h`)

Fonctions pures, sans I/O :

- **`secreq_arpk_guess`** : `ARPK = 0x01 | (0x04 si bond authentifié)`. Le bit bonding est toujours présent puisque le bond existe. SC (`0x08`) n'est pas estimable.
- **`secreq_expected`** : `ARSR > ARPK` attend un re-pairing, sinon une session (Listing 1).
- **`secreq_classify`** : transforme les faits bruts en résultat. Une Pairing Request l'emporte sur une demande de LTK.
- **`secreq_is_nonconform`** : une réaction est non conforme si elle est l'un des deux chemins attendus, mais pas le bon. Cas Apple : `ARSR = ARPK` et réaction = Pairing Request. Cas inverse : `ARSR > ARPK` et réaction = session.
  - **Pourquoi ces deux cas** : le papier ne traite que le premier. Le second sert de contrôle, pour vérifier que l'iPhone répond bien quand la règle l'exige.

### 3.5 Interface (`main.c`)

- `bleurp repair` : sans adresse, liste les appareils appairés. Avec adresse, lit le bond et lance le test de re-pairing. `-c` donne l'adresse courante (RPA) sur laquelle se connecter, parce que le bond est indexé par l'adresse d'identité, alors que la connexion se fait sur l'adresse que l'appareil utilise en ce moment.
- `bleurp secreq <ADRESSE_IDENTITE>` : lit le bond, calcule ARPK, envoie le test. `-r` fixe ARSR (par défaut ARPK). `-c` et `-w` règlent les délais d'attente de connexion et de réaction.
- Les verdicts sont en français, et chaque verdict rappelle qu'il s'agit d'un indice.

---

## 4. Décisions et leurs raisons

| Décision | Raison |
| :--- | :--- |
| Séparer la logique pure (`secreq.c`, `repair.c`) de l'I/O | Testable sans adaptateur ni root, et conforme au TDD de `rules.txt`. |
| Ne jamais terminer un appairage ni échanger de clé | Le papier démontre l'attaque à partir de la clé dérivée. Mesurer la négociation suffit pour l'audit. |
| Annonce sans profil clavier | Éviter de se faire passer pour un clavier pendant un test SMP. |
| Adresse d'identité pour le bond, RPA pour la connexion (`-c`) | Le bond est indexé par l'identité. La connexion exige l'adresse que l'appareil utilise maintenant. |
| Lecture de l'adresse adaptateur via mgmt | sysfs ne l'expose pas sur le noyau de test. |
| `PB=00b` pour les trames SMP ACL | `PB=10b` (flush automatique) empêchait le contrôleur d'émettre la trame, confirmé par l'absence de `Number of Completed Packets` dans `btmon`. `00b` corrige ce point. |
| Statut de liaison distinct d'un simple `-1` | Un refus, une absence et un silence ont des causes différentes, et des corrections différentes. |
| Refus `0x08` marqué non concluant | Une raison générique ne signale pas un contrôle anti-downgrade. |

---

## 5. Correspondance avec le papier

| Élément du papier | Où dans BLEURP | État |
| :--- | :--- | :--- |
| Listing 1 (décision sur SEC REQ) | `secreq_expected`, `secreq_is_nonconform` | Implémenté, testé unitairement |
| Constat Apple, VI-C (`ARSR ≥ ARPK`) | `secreq_is_nonconform`, cas `ARSR = ARPK` | Implémenté ; à valider sur matériel |
| V4 / V6 (négociation sous le bond) | `smp_repair_classify` | Implémenté ; indice seulement (phase 1) |
| Anti-downgrade, VII-A | Raisons `0x03` et `0x06` dans l'affichage | Implémenté |
| V2 (re-pairing non authentifié) | `repair` (une Pairing Request sur bond) | Indice |
| V1, V3, V5 | — | Non implémenté : exige la phase 2 ou une session coupée |
| Attaques PI, CI, MitM | — | Hors périmètre (attaque, pas audit) |

---

## 6. Procédures de test

Pré-requis : `make build/bleurp` (ou `make test && make all`), `sudo` ou `make setcap`, un bond existant (voir `docs/smp-security-audit.md`, section 3.1).

```sh
# Liste des appareils appairés (adresses d'identité)
sudo ./build/bleurp repair

# Test de re-pairing : RPA courante via -c
sudo ./build/bleurp repair <IDENTITE> -c <RPA_COURANTE> -t random

# Security Request : cas d'égalité (ARSR = ARPK estimé)
sudo ./build/bleurp secreq <IDENTITE> -c 60 -w 10

# Security Request : contrôle (ARSR > ARPK)
sudo ./build/bleurp secreq <IDENTITE> -r 0x05 -c 60 -w 10
```

Pour `secreq`, l'appareil doit **se connecter à nous** : Bluetooth activé sur l'appareil, et une reconnexion à un accessoire déjà appairé doit être déclenchée côté appareil. Rien ne garantit que l'iPhone se reconnecte à un adaptateur Linux dans la fenêtre de test. Un « Aucune connexion » n'est donc pas une conclusion.

---

## 7. Limites et points à valider

- **Code non compilé ni exécuté au moment de la rédaction** pour les dernières modifications (`secreq`, `smp_native_secreq_probe`, `cmd_secreq`). Les tests unitaires `test_secreq.c` sont écrits mais pas encore lancés.
- **Bit `Authenticated` du bond iPhone** : la sortie de `repair` indique « non authentifié », alors que l'appairage a demandé une confirmation numérique. À vérifier avec le fichier `info`, en masquant les clés (`sudo grep -v -E "^(Key|Rand|EDiv)=" <fichier>`).
- **SC invisible** : BlueZ ne stocke pas le bit SC dans `info`. ARPK est donc partiel, et un cas SC→LSC ne peut pas être testé.
- **Mode clavier (`peripheral_native.c`)** : même correction `PB=00b` appliquée à `send_l2cap_packet`, pour la même raison que la sonde. Non encore vérifié sur matériel.
- **Réaction non garantie** : l'iPhone peut ne pas réagir à une Pairing Request hors contexte, ni se reconnecter à un adaptateur qui annonce. Un « aucune réaction » est donc un résultat à interpréter avec prudence.
- **Adresse RPA** : elle change toutes les ~15 min. Les commandes qui en dépendent doivent suivre un scan récent.

---

## 8. Ce que les tests ont appris

- Une trace `btmon` (filtrée sur `Number of Completed Packets`) a permis de voir que le contrôleur n'émettait pas la trame avec `PB=10b`, et de le confirmer avec `PB=00b`.
- `btmon` montre ce que l'hôte envoie, pas ce que la cible reçoit. Une réponse absente ne prouve donc pas que la cible a reçu la requête.
- L'adresse d'un iPhone change en permanence (RPA). Le bond, lui, est stable et indexé par l'identité.
- Une raison `Pairing Failed` n'a de sens que si elle correspond à un contrôle précis. Un code générique ne doit pas être interprété comme une défense.
