# Protocole : re-appairage depuis l'émulateur clavier (PI, appareil personnel)

Objectif : mesurer si le smartphone accepte un nouvel appairage initié par l'émulateur, et par quel chemin (rejet du chiffrement ou SEC REQ seul).

## Matériel et état
- Carte Bluetooth du PC (`hci0`, adresse `DE:AD:BE:EF:00:01`).
- Smartphone appairé à « BLEURP Keyboard » (ne pas oublier l'appareil entre les essais).
- Note le modèle et la version de l'OS du téléphone : le papier attribue des comportements différents à Apple et Android.

## Un essai
1. `sudo ./build/bleurp`, puis `6`, puis Entrée pour les valeurs par défaut (mode 1, Just Works).
2. Attends la connexion du téléphone (ouvre Réglages > Bluetooth si besoin).
3. Note ce qui s'affiche sur le téléphone : demande de jumelage (oui/non), nombre de clics.
4. Quand la ligne `[TRACE]` apparaît, note-la et fais Ctrl-C.

La ligne `[TRACE]` est écrite à chaque déconnexion :

```
[TRACE] peer=<adresse> enc_req=<oui|non> ltk_rejet=<oui|non> pairing_req=<oui|non> bonding=<oui|non> disc=<raison>
```

## Trois essais minimum
Répète au moins trois fois. Le chemin observé dépend du téléphone (il envoie ou non une demande de chiffrement avec l'ancienne clé), donc on compte les issues, on ne les force pas.

## Résultats à coller
Pour chaque essai : la ligne `[TRACE]`, le modèle du téléphone, et ce qui s'est affiché sur l'écran du téléphone.

## Lecture
- `enc_req=oui ltk_rejet=oui pairing_req=non` : le téléphone se déconnecte après le rejet, V5 non reproduit sur cet appareil.
- `pairing_req=oui bonding=oui` : le téléphone a accepté un nouvel appairage avec l'émulateur, la clé stockée est remplacée.
- `pairing_req=oui bonding=non` : appairage commencé puis abandonné.

Ces résultats ne sont que des observations sur un appareil. Ils ne prouvent pas une attaque complète.
