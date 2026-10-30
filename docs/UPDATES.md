# Journal des mises à jour

## 2026-10-10 — hci0 absent + rapport trompeur sur `blerp pi -i 0`

### Le bug matériel/système (pas un bug BLEURP)

`rfkill list bluetooth` montre deux switches :
- `ideapad_bluetooth` (contrôleur BT interne, combo Wi-Fi/BT Foxconn/Hon Hai
  USB `0489:e111`) — soft/hard **unblocked**
- `hci1` (dongle USB MediaTek externe) — soft/hard **unblocked**

Mais `hciconfig -a` ne liste **que** `hci1`. `hci0` n'existe pas du tout
dans le kernel (`Can't get device info: No such device`), même après :
```
sudo rfkill unblock bluetooth
sudo hciconfig hci0 up
```
C'est normal que ça ne change rien : `rfkill unblock` ne fait que lever le
kill-switch logiciel/matériel (l'alimentation radio). Il ne crée pas
l'interface HCI. Si le kernel n'a jamais bindé un driver Bluetooth
(`btusb`/`btrtl`/`btmtk`/`btintel`) sur le périphérique USB interne,
`hci0` n'apparaîtra **jamais**, qu'il soit "unblocked" ou pas.

Confirmé sur cette machine :
- `lsusb` voit bien le périphérique interne : `0489:e111 Foxconn / Hon Hai
  Wireless_Device` (le combo Wi-Fi/BT du ideapad).
- Aucun module `hci0` ne se crée dessus → le driver ne le réclame pas
  (firmware manquant pour la fonction BT du combo, ou PID non supporté par
  `btusb` sur ce noyau).
- `dmesg`/`journalctl -k` étaient inaccessibles sans mot de passe root
  dans cette session pour confirmer la raison exacte côté kernel.

**À faire sur la machine réelle (pas depuis cette session) :**
```
sudo dmesg | grep -iE 'bluetooth|btusb|btrtl|btmtk|0489'
sudo journalctl -k -b | grep -iE 'bluetooth|0489'
```
S'il n'y a strictement rien sur `0489:e111`, le driver ne voit même pas la
fonction BT du combo (firmware manquant côté `linux-firmware` ou chipset
non supporté) — ce n'est pas quelque chose que `rfkill`/`hciconfig`
peuvent réparer. Pour avancer sur l'audit : **utiliser le dongle USB
externe (`hci1`, `-i 1`)**, qui fonctionne et qui est justement celui qui
apparaît dans `smp -i 1`.

### Le bug BLEURP trouvé en creusant pourquoi la matrice sortait "NON CONCLUANT" partout

`bleurp blerp pi -i 0 ...` tournait **quand même**, affichait la matrice
V1-V6 complète, et marquait tout "NON CONCLUANT" / "No Link Layer
connection established" comme si l'attaque avait tourné et n'avait rien
trouvé. En réalité l'adaptateur `hci0` n'existe pas : l'ouverture du
socket HCI User Channel échoue (`bind()` → `ENODEV`), `blerp_run_pi()`
retourne `-1` immédiatement sans avoir rien tenté — et ce retour était
**silencieusement ignoré**.

Code concerné (même bug dupliqué par le refactor v2, dans
`src/smp_native/blerp_attack.c` → `src/cmd/blerp_cmd.c`) :
```c
case BLERP_ATTACK_PI:
    rc = blerp_run_pi(&cfg, &rep);          // rc == -1 si hci0 inexistant
    blerp_classify_vulnerabilities(...);     // tourne quand même sur un rapport vide
    blerp_print_report(...);                 // imprime la fausse matrice "NON CONCLUANT"
    ...
```
`blerp_run_pi`/`blerp_run_ci`/`blerp_run_audit` ne renvoient `< 0` que
dans deux cas : arguments invalides, ou `blerp_hci_open()` n'a pas pu
ouvrir/bind le socket sur l'adaptateur demandé. Dans tous les autres cas
ils renvoient `0`, peu importe le verdict trouvé. Donc `rc != 0` est un
signal fiable de "l'attaque n'a même pas pu démarrer".

**Fix appliqué** (`src/main.c` dans BLEURP, `src/cmd/blerp_cmd.c` dans
BLEURP-v2, cas `PI`/`CI`/`AUDIT`) : si `rc != 0` après l'appel, on
n'affiche plus la matrice — on imprime directement :
```
[-] Could not run the attack on hci<N>: <strerror(errno)>
    (adapter missing/down, or still owned by bluetoothd)
```
et on sort avec le code 1. Compilé et vérifié (`make`) dans les deux
dépôts (`~/Desktop/BLEURP` et `~/Desktop/BLEURP-v2`). Pas encore rejoué en
live avec `sudo` dans cette session (le sudo non-interactif a demandé un
mot de passe) — à revérifier à la main avec `-i 0` pour voir le nouveau
message d'erreur, et avec `-i 1` pour confirmer que l'attaque tourne
toujours normalement sur le vrai adaptateur.

### Point à surveiller (non confirmé)

Dans la session collée par l'utilisateur, `bleurp smp 28:05:A5:5B:AD:92 -i 1`
n'a produit **aucune sortie du tout** entre le prompt et le prompt
suivant — alors que `cmd_smp_native()`/`cmd_smp_cmd()` doit toujours
imprimer au moins la ligne `Connecting to ... (hci1, type=public)...`
avant de sonder. Soit c'est une troncature du copier-coller, soit il y a
un vrai problème de buffering/flush à reproduire. À reconfirmer en
relançant la commande seule, sans la chaîner avec une autre.
