<div align="center">
  <img src="assets/banner.svg" alt="BLEURP — Version 2 en travaux, contributeur·rices bienvenu·es" width="100%">
</div>

# BLEURP

**Bluetooth Low Energy Unauthenticated Reconnaissance &amp; Probing** — un toolkit C modulaire et sans dépendances lourdes, pour la reconnaissance et l'audit de sécurité Bluetooth Low Energy sous Linux.

> ⚠️ **Usage autorisé uniquement.** N'utilisez BLEURP que sur des appareils et réseaux que vous possédez ou que vous êtes explicitement autorisé·e à tester. Interagir avec des appareils BLE tiers sans autorisation peut enfreindre la loi.

> 🚧 **Version 2 en cours de réécriture — pas encore fiable à 100 %.** De larges pans du code bougent encore (refactor en modules `src/recon`, `src/gatt`, `src/smp`, `src/blerp`, …), des bugs et des changements d'API sont à prévoir. **Avis aux contributeur·rices : toute aide pour continuer le travail est chaleureusement acceptée** — voir [Contribution](#-contribution).

## Table des matières

- [🪧 À propos](#-à-propos)
- [📦 Prérequis](#-prérequis)
- [🚀 Installation](#-installation)
- [🛠️ Utilisation](#️-utilisation)
- [🤝 Contribution](#-contribution)
- [🏗️ Construit avec](#️-construit-avec)
- [📚 Documentation](#-documentation)
- [🏷️ Gestion des versions](#️-gestion-des-versions)
- [📝 Licence](#-licence)

## 🪧 À propos

BLEURP est né d'un besoin d'**apprendre et d'auditer concrètement la sécurité du Bluetooth Low Energy** sans dépendre d'une lourde pile logicielle : il parle directement au noyau Linux (API *mgmt*, HCI User Channel, L2CAP/ATT, SMP) pour observer et sonder les appareils BLE.

Il couvre toute la chaîne : reconnaissance passive et fingerprinting, énumération GATT et audit des caractéristiques accessibles sans appairage, diagnostic de sécurité de l'appairage SMP, émulation d'un clavier BLE (HOGP) et injection de frappe, jusqu'à la reproduction des attaques **BLERP** (NDSS 2026 : impersonation de périphérique/central, MitM double canal). Le but est autant **pédagogique** (comprendre la surface d'attaque BLE) que pratique (auditer ses propres équipements).

## 📦 Prérequis

- **Linux avec la pile BlueZ** (côté noyau) — [BlueZ](http://www.bluez.org/)
- **Un adaptateur Bluetooth Low Energy** (ex. `hci0`)
- **gcc** et **make** — [GCC](https://gcc.gnu.org/), [GNU Make](https://www.gnu.org/software/make/)
- **libbluetooth-dev** — en-têtes BlueZ (`-lbluetooth`)
- **libssl-dev** (libcrypto) — crypto AES-128 pour SMP/BLERP — [OpenSSL](https://www.openssl.org/)
- **libdbus-1-dev** — helper HID via D-Bus — [D-Bus](https://www.freedesktop.org/wiki/Software/dbus/)
- **Capacités réseau** : `CAP_NET_ADMIN` + sockets bruts (via `make setcap`) ou exécution en `sudo`

Installation des dépendances sur Debian/Ubuntu :

```sh
sudo apt install build-essential libbluetooth-dev libssl-dev libdbus-1-dev pkg-config
```

## 🚀 Installation

```sh
# Cloner le dépôt et se placer sur la version 2
git clone git@github.com:gGaToRr/BLEURP.git
cd BLEURP
git checkout v2/rewrite

# Compiler
make

# Lancer la suite de tests
make test

# (Optionnel) Donner les capacités réseau au binaire pour un usage non-root
make setcap

# Le binaire est dans ./build/bleurp
```

## 🛠️ Utilisation

> Sans `make setcap`, préfixez les commandes par `sudo`.

### Menu interactif & assistant guidé

```sh
./build/bleurp            # Menu interactif (bannière ASCII)
./build/bleurp wizard     # Pipeline d'audit guidé, tout-en-un
```

### Reconnaissance & scan

```sh
./build/bleurp scan        # Scan en direct jusqu'à Ctrl-C
./build/bleurp scan -t 10  # Scan pendant 10 secondes
./build/bleurp scan -v     # Scan verbeux (EIR constructeur & services annoncés)
```

### Chaîne d'attaque automatisée de bout en bout (`attack`)

```sh
# Chaîne complète sur cible : profilage -> surface GATT -> sonde SMP -> exploit BLERP -> payload
sudo ./build/bleurp attack AA:BB:CC:DD:EE:FF -t random -p src/hid/send_attack/payloads/linux-terminal.txt

# Audit offensif sans écrasement de session, sortie JSON structurée
./build/bleurp attack AA:BB:CC:DD:EE:FF --audit-only --json

# Scan automatique de l'environnement (15s) et sélection de la cible la plus exposée
sudo ./build/bleurp attack --scan 15 -i 0
```

### Énumération GATT & audit d'accès non authentifié

```sh
# Dump de l'arbre GATT (services, caractéristiques, descripteurs)
./build/bleurp enum AA:BB:CC:DD:EE:FF -t random

# Quelles caractéristiques sont lisibles sans appairage
./build/bleurp audit AA:BB:CC:DD:EE:FF -t public

# Lecture / écriture directe par handle
./build/bleurp read  AA:BB:CC:DD:EE:FF 0x0012 -t random
./build/bleurp write AA:BB:CC:DD:EE:FF 0x0012 01ff -t random
```

### Diagnostic de sécurité de l'appairage (SMP / BLERP)

```sh
# Sonde de downgrade SMP (première liaison, sans bond)
./build/bleurp smp AA:BB:CC:DD:EE:FF -i 0 -t random

# Test de ré-appairage (BLERP) contre un appareil déjà bondé avec hci0
sudo ./build/bleurp repair                        # liste les identités bondées
sudo ./build/bleurp repair AA:BB:CC:DD:EE:FF -i 0 -t public

# Attaques natives BLERP (NDSS 2026) : PI, CI, MitM double/simple canal, audit complet
sudo ./build/bleurp blerp pi    AA:BB:CC:DD:EE:FF -s 11:22:33:44:55:66 -n "Keyboard" -e -k 7
sudo ./build/bleurp blerp ci    11:22:33:44:55:66 -s AA:BB:CC:DD:EE:FF -k 7 -r 0x01
sudo ./build/bleurp blerp mitm  AA:BB:CC:DD:EE:FF -i 0 -j 1
sudo ./build/bleurp blerp audit AA:BB:CC:DD:EE:FF -t public -i 0
```

### Clavier BLE natif & injection de frappe

```sh
# Périphérique clavier BLE natif (annonce HOGP, gère l'appairage SMP)
./build/bleurp keyboard -i 0 -n "BLEURP Keyboard" -d src/hid/send_attack/payloads/demo-hello.txt

# Injection d'un payload DuckyScript via D-Bus BlueZ
./build/bleurp hid -i hci0 -t AA:BB:CC:DD:EE:FF -f src/hid/send_attack/payloads/linux-terminal.txt
```

## 🤝 Contribution

**Les contributions sont les bienvenues** — la v2 est un chantier ouvert, il y a de la place pour tout le monde (code, tests, docs, relecture). Flux proposé :

```sh
# 1. Forkez le dépôt sur GitHub, puis :
git clone git@github.com:<votre-pseudo>/BLEURP.git
cd BLEURP
git checkout v2/rewrite

# 2. Créez une branche de travail
git checkout -b feat/<ma-fonctionnalite>

# 3. Développez, puis vérifiez que tout compile et que les tests passent
make && make test

# 4. Commitez (style conventionnel : feat:, fix:, refactor:, docs:)
git commit -m "feat: <description concise>"

# 5. Poussez et ouvrez une Pull Request vers la branche v2/rewrite
git push origin feat/<ma-fonctionnalite>
```

Merci de garder le code sans warning (`-Wall -Wextra -Werror`) et d'accompagner toute nouvelle fonctionnalité d'un test dans `tests/`. Les discussions et signalements passent par les [Issues](https://github.com/gGaToRr/BLEURP/issues).

## 🏗️ Construit avec

### Langages &amp; bibliothèques

- **[C (C11)](https://en.cppreference.com/w/c)** — cœur du projet, sans framework
- **[BlueZ](http://www.bluez.org/) / HCI User Channel / L2CAP / API mgmt** — accès direct à la pile Bluetooth du noyau Linux
- **[OpenSSL — libcrypto](https://www.openssl.org/)** — primitives AES-128 (`c1`/`s1`, SMP)
- **[D-Bus — libdbus-1](https://www.freedesktop.org/wiki/Software/dbus/)** — helper d'injection HID via BlueZ

### Outils

- **[GCC](https://gcc.gnu.org/)** + **[GNU Make](https://www.gnu.org/software/make/)** — compilation (`make`, `make test`, `make setcap`, `make clean`)
- **[pkg-config](https://www.freedesktop.org/wiki/Software/pkg-config/)** — résolution des flags D-Bus
- **Framework de test maison** — un binaire par fichier `tests/test_*.c`

### CI

> _Aucune intégration continue n'est encore configurée._ **Bonne première contribution :** ajouter un workflow [GitHub Actions](https://docs.github.com/actions) lançant `make && make test` à chaque push / PR.

### Déploiement

Outil en ligne de commande : pas de déploiement serveur. La distribution se fait via les binaires compilés localement et la [page des Releases](https://github.com/gGaToRr/BLEURP/releases).

## 📚 Documentation

Guides techniques détaillés dans le répertoire [`docs/`](docs/) :

- 📋 [Architecture &amp; vue d'ensemble des modules](docs/architecture.md)
- ⚡ [Attaques &amp; audit BLERP (NDSS 2026, V1–V6, PI, CI, MitM)](docs/blerp-attacks.md)
- 🔍 [Fingerprinting passif &amp; score d'exposition](docs/device-fingerprinting.md)
- 🔒 [Audit SMP &amp; sondage de downgrade](docs/smp-security-audit.md)
- ⌨️ [Émulation de périphérique HID &amp; injection de frappe](docs/hid-peripheral-injection.md)
- 🧭 [Pipeline d'audit guidé &amp; menu interactif](docs/guided-audit-pipeline.md)
- 🛡️ [Audit d'accès GATT](docs/gatt-access-audit.md)
- 🎯 [Référence de la surface d'attaque BLE](docs/ble-attack-surface.md)
- ⚙️ [Référence des arguments CLI](docs/cli-args.md)
- 📡 [Architecture du scan](docs/scan-overview.md)
- 🔗 [Conception de la connexion GATT (phase 2)](docs/phase2-gatt-connection.md)
- 📚 [Modules d'étude BLERP : ce qui est implémenté et pourquoi](docs/blerp-study-modules.md)

## 🏷️ Gestion des versions

Afin de maintenir un cycle de publication clair et de favoriser la rétrocompatibilité, la dénomination des versions suit la spécification [Gestion sémantique de version (SemVer)](https://semver.org/lang/fr/).

Les versions disponibles ainsi que les journaux de changements sont sur la [page des Releases](https://github.com/gGaToRr/BLEURP/releases).

## 📝 Licence

> ⚠️ **Aucun fichier `LICENSE` n'est encore défini.** En l'absence de licence, le code reste sous le copyright de son auteur et les droits de réutilisation/contribution ne sont pas formellement accordés. Une licence (p. ex. MIT ou GPLv3) **devrait être ajoutée** — c'est un point ouvert, idéal pour une première contribution ou une décision de l'auteur.
