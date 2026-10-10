#!/usr/bin/env bash
# ========================================
#  nom du fichier: audit_ble.sh
#  description courte: Chaîne d'audit BLERP de bout en bout (mesure seulement).
#  Enchaîne l'identification de la cible (scan on/off), le contrôle du bond,
#  la sonde de première appairage (optionnelle), le test de re-pairing et le
#  test Security Request (cas d'égalité ARSR = ARPK, puis contrôle ARSR > ARPK,
#  puis V1 bits rfu, V5 rejet du chiffrement, V3 réponse plus faible),
#  et écrit un rapport Markdown avec la matrice V1-V6 (tableau I du papier BLERP). Aucune clé n'est dérivée ni échangée, et aucun
#  appairage n'est terminé.
#  dernière modification : 2026-10-03
#  auteur: GitHub/@gGaToRr
# ========================================
#
# Usage (depuis la racine du projet, après 'make build/bleurp') :
#   sudo scripts/audit_ble.sh                          menu interactif
#   sudo scripts/audit_ble.sh -t <IDENTITE> -r <RPA> [options]
#
# Options :
#   -t ADDR  adresse d'identité du bond (BlueZ), ex: AA:BB:CC:DD:EE:FF   (obligatoire)
#   -r ADDR  adresse courante (RPA) de l'appareil, ex: 11:22:33:44:55:66 (recommandée ; obligatoire avec -a)
#   -T TYPE  type d'adresse pour la connexion : public ou random (défaut : random)
#   -i N     index de l'adaptateur (défaut : 0, donc hci0)
#   -o DIR   dossier de sortie (défaut : audit_AAAAMMJJ_HHMMSS)
#   -a       tout d'un coup : pas d'Entrée à taper, chaque action manuelle est
#            remplacée par un compte à rebours ; active aussi la sonde (-s)
#   -d S     durée du compte à rebours avec -a, en secondes (défaut : 10)
#   -s       lancer aussi la sonde de première appairage (désactivée par défaut)
#   -c S     attente de connexion pour secreq, en secondes (défaut : 60)
#   -w S     attente de réaction pour secreq, en secondes (défaut : 10)
#   -h       afficher cette aide
#
# Codes de sortie : 0 si toutes les étapes ont réussi, 1 sinon.
# Chaque étape est lancée même si une précédente a échoué, pour que le
# rapport contienne toutes les mesures possibles.

set -u
set -o pipefail

# ----- Configuration par défaut -----
BLEURP="${BLEURP:-./build/bleurp}"
STORE_DIR="/var/lib/bluetooth"
TARGET_ID=""
TARGET_RPA=""
TARGET_TYPE="random"
HCI_INDEX=0
OUT_DIR=""
RUN_SMP=0
WAIT_CONN=60
WAIT_REACT=10
SCAN_SEC=15
AUTO=0
PAUSE_SEC=10
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Couleurs du menu, reprises de src/ui.h.
C_RESET=$'\033[0m'
C_GREEN=$'\033[32m'
C_YELLOW=$'\033[33m'
C_PINK=$'\033[38;5;213m'
C_PURPLE=$'\033[38;5;141m'

# Format attendu d'une adresse Bluetooth en majuscules.
ADDR_RE='^([0-9A-F]{2}:){5}[0-9A-F]{2}$'

# Tableaux remplis par run_step, lus par write_report.
STEP_NAMES=()
STEP_RC=()
STEP_LOG=()

# ----- Utilitaires -----

# Affiche un message sur la sortie standard et l'ajoute au journal d'audit.
# Le journal n'existe pas encore pendant l'analyse des options : on l'ignore alors.
log() {
    printf '%s\n' "$*"
    if [[ -n "$OUT_DIR" && -d "$OUT_DIR" ]]; then
        printf '%s\n' "$*" >> "$OUT_DIR/audit.log"
    fi
}

# Affiche une erreur et quitte avec le code 1.
die() {
    log "[-] $*"
    exit 1
}

# Attend une action manuelle sur l'appareil. Interactif : attend Entrée.
# Avec -a : compte à rebours de PAUSE_SEC secondes, sans rien à taper.
# Appel : pause_for <action>
pause_for() {
    local action="$1" n
    if [[ $AUTO -ne 1 ]]; then
        read -r -p "${action}, puis Entrée : " _
        return 0
    fi
    log "[*] ${action} dans ${PAUSE_SEC} s"
    for ((n = PAUSE_SEC; n > 0; n--)); do
        printf '\r    %2d s ' "$n"
        sleep 1
    done
    printf '\r[*] %s : maintenant.   \n' "$action"
}

# Retire les séquences de couleur ANSI de l'entrée standard.
strip_ansi() {
    sed -e 's/\x1b\[[0-9;]*m//g'
}

# Affiche l'aide, extraite du bloc de commentaires "Usage ... Codes" en tête de script.
usage() {
    sed -n '/^# Usage/,/^# Codes/{p;/^# Codes/q}' "$0" | sed -e 's/^# \{0,1\}//'
}

# Lance une commande, affiche sa sortie en direct, garde une copie brute et
# une copie sans couleur, et retient le code retour pour le rapport.
# Usage : run_step <nom> <commande> [arguments...]
run_step() {
    local name="$1"
    shift
    local logfile="$OUT_DIR/logs/${name}.log"
    local cleanfile="$OUT_DIR/logs/${name}.txt"

    log "[*] Étape ${name} : $*"
    "$@" 2>&1 | tee "$logfile"
    local rc=${PIPESTATUS[0]}
    strip_ansi < "$logfile" > "$cleanfile"

    STEP_NAMES+=("$name")
    STEP_RC+=("$rc")
    STEP_LOG+=("$cleanfile")
    log "[*] Fin de ${name} (code ${rc})"
    return "$rc"
}

# ----- Analyse des options -----

parse_args() {
    while getopts ":t:r:T:i:o:c:w:d:sah" opt; do
        case "$opt" in
            t) TARGET_ID="${OPTARG^^}" ;;
            r) TARGET_RPA="${OPTARG^^}" ;;
            T) TARGET_TYPE="$OPTARG" ;;
            i) HCI_INDEX="$OPTARG" ;;
            o) OUT_DIR="$OPTARG" ;;
            c) WAIT_CONN="$OPTARG" ;;
            w) WAIT_REACT="$OPTARG" ;;
            d) PAUSE_SEC="$OPTARG" ;;
            a) AUTO=1 ;;
            s) RUN_SMP=1 ;;
            h) usage; exit 0 ;;
            :) die "l'option -$OPTARG attend une valeur" ;;
            *) die "option inconnue : -$OPTARG (voir -h)" ;;
        esac
    done

    if [[ -z "$TARGET_ID" ]]; then
        die "adresse d'identité manquante (-t). Liste des bonds : sudo $BLEURP repair"
    fi
    if ! [[ "$TARGET_ID" =~ $ADDR_RE ]]; then
        die "adresse d'identité invalide : $TARGET_ID (format AA:BB:CC:DD:EE:FF)"
    fi
    if [[ -n "$TARGET_RPA" ]] && ! [[ "$TARGET_RPA" =~ $ADDR_RE ]]; then
        die "adresse courante invalide : $TARGET_RPA (format AA:BB:CC:DD:EE:FF)"
    fi
    if [[ "$TARGET_TYPE" != "public" && "$TARGET_TYPE" != "random" ]]; then
        die "type d'adresse invalide : $TARGET_TYPE (public ou random)"
    fi
    if ! [[ "$HCI_INDEX" =~ ^[0-9]+$ ]]; then
        die "index d'adaptateur invalide : $HCI_INDEX"
    fi
    if ! [[ "$WAIT_CONN" =~ ^[0-9]+$ && "$WAIT_REACT" =~ ^[0-9]+$ && "$PAUSE_SEC" =~ ^[0-9]+$ ]]; then
        die "les durées (-c, -w, -d) doivent être des entiers en secondes"
    fi
    if [[ $AUTO -eq 1 ]]; then
        # Sans Entrée, l'adresse courante ne peut pas être saisie pendant le scan.
        [[ -n "$TARGET_RPA" ]] || die "le mode -a exige l'adresse courante (-r)"
        RUN_SMP=1
    fi

    : "${OUT_DIR:=audit_$(date +%Y%m%d_%H%M%S)}"
}

# ----- Étapes -----

# Vérifie le binaire, les droits et l'adaptateur.
check_prereqs() {
    log "== 1. Contrôles préalables =="
    [[ -x "$BLEURP" ]] || die "binaire introuvable : $BLEURP (lance 'make build/bleurp' ou définis BLEURP=...)"
    if [[ $EUID -ne 0 ]]; then
        die "lance le script avec sudo : lecture de $STORE_DIR, canal USER HCI et mgmt"
    fi
    if ! command -v btmon >/dev/null 2>&1; then
        log "[!] btmon absent : pas de trace (facultatif, utile pour le débogage)"
    fi
    # Un appel sans adresse liste les bonds : il valide aussi l'adaptateur.
    run_step bond_list "$BLEURP" repair -i "$HCI_INDEX" \
        || die "adaptateur hci${HCI_INDEX} indisponible ou bond illisible (voir logs/bond_list.txt)"
}

# Vérifie que l'appareil est bien celui qu'on veut auditer : scan avec puis sans
# son Bluetooth. La vérification porte sur l'adresse courante (RPA), seule visible
# au scan ; l'adresse d'identité du bond n'apparaît pas dans les annonces.
identify_target() {
    log "== 2. Identification de la cible =="
    log "Cette étape demande une action sur l'appareil : son Bluetooth doit être activé, puis désactivé."

    pause_for "[1/2] Bluetooth de l'appareil ACTIVÉ"
    run_step scan_on "$BLEURP" scan -i "$HCI_INDEX" -t "$SCAN_SEC" -v

    if [[ -z "$TARGET_RPA" ]]; then
        log "[!] Adresse courante (-r) non fournie. Copie celle de l'appareil depuis logs/scan_on.txt."
        read -r -p "Adresse courante (AA:BB:CC:DD:EE:FF) : " TARGET_RPA
        TARGET_RPA="${TARGET_RPA^^}"
        if ! [[ "$TARGET_RPA" =~ $ADDR_RE ]]; then
            die "adresse courante invalide : $TARGET_RPA"
        fi
    fi

    pause_for "[2/2] Bluetooth de l'appareil DÉSACTIVÉ"
    run_step scan_off "$BLEURP" scan -i "$HCI_INDEX" -t "$SCAN_SEC" -v

    local on_file="$OUT_DIR/logs/scan_on.txt"
    local off_file="$OUT_DIR/logs/scan_off.txt"
    if grep -qi "$TARGET_RPA" "$on_file" && ! grep -qi "$TARGET_RPA" "$off_file"; then
        log "[+] Identification confirmée : $TARGET_RPA est présente quand le Bluetooth est actif, absente sinon."
    else
        log "[!] Identification NON confirmée pour $TARGET_RPA."
        log "    Présente à l'activation : $(grep -qi "$TARGET_RPA" "$on_file" && echo oui || echo non)"
        log "    Présente à la désactivation : $(grep -qi "$TARGET_RPA" "$off_file" && echo oui || echo non)"
        # En mode -a, pas de question : on s'arrête, par prudence.
        [[ $AUTO -eq 1 ]] && die "arrêt : identification non confirmée (mode -a)"
        read -r -p "Continuer quand même ? (o/N) : " answer
        [[ "$answer" == "o" || "$answer" == "O" ]] || die "arrêt : identification non confirmée"
    fi
}

# Vérifie qu'un bond existe pour l'adresse d'identité donnée.
check_bond() {
    log "== 3. Contrôle du bond =="
    if grep -qi "$TARGET_ID" "$OUT_DIR/logs/bond_list.txt"; then
        log "[+] Bond présent pour $TARGET_ID."
    else
        die "aucun bond pour $TARGET_ID. Appaire d'abord l'appareil (bluetoothctl pair), puis relance."
    fi
}

# Sonde de première appairage (optionnelle, option -s) : envoie une Pairing
# Request sans bond et lit la première réponse.
run_smp() {
    log "== 4. Sonde de première appairage =="
    if [[ $RUN_SMP -ne 1 ]]; then
        log "[*] Désactivée (ajoute -s pour l'activer)."
        return 0
    fi
    run_step smp_first_pairing "$BLEURP" smp "$TARGET_RPA" -i "$HCI_INDEX" -t "$TARGET_TYPE"
}

# Test de re-pairing : lit le bond, offre un appairage plus faible, classe la réponse.
run_repair() {
    log "== 5. Test de re-pairing =="
    run_step repair_test "$BLEURP" repair "$TARGET_ID" -c "$TARGET_RPA" -t "$TARGET_TYPE" -i "$HCI_INDEX"
}

# Test Security Request en deux temps : cas d'égalité (ARSR = ARPK) puis contrôle
# (ARSR > ARPK). L'appareil doit se connecter pendant l'attente.
run_secreq() {
    log "== 6. Test Security Request =="

    pause_for "[1/5] Cas d'égalité ARSR = ARPK. Appareil prêt à se connecter"
    run_step secreq_equal "$BLEURP" secreq "$TARGET_ID" -i "$HCI_INDEX" -c "$WAIT_CONN" -w "$WAIT_REACT"

    # Contrôle : un ARSR strictement supérieur à l'ARPK estimé. Si le bond est
    # authentifié (MITM), l'ARPK vaut 0x05 et il faut 0x0d ; sinon 0x05 suffit.
    local control_arsr="0x05"
    if grep -q "authentifié (MITM)" "$OUT_DIR/logs/secreq_equal.txt" 2>/dev/null; then
        control_arsr="0x0d"
    fi
    pause_for "[2/5] Contrôle ARSR = ${control_arsr} (> ARPK). Appareil prêt à se connecter"
    run_step secreq_control "$BLEURP" secreq "$TARGET_ID" -r "$control_arsr" -i "$HCI_INDEX" \
        -c "$WAIT_CONN" -w "$WAIT_REACT"

    # V1 : bits rfu à 1 dans l'ARSR (0xc0), sans authentification.
    pause_for "[3/5] V1 : ARSR à bits rfu 0xc0. Appareil prêt à se connecter"
    run_step secreq_v1 "$BLEURP" secreq "$TARGET_ID" -r 0xc0 -i "$HCI_INDEX" \
        -c "$WAIT_CONN" -w "$WAIT_REACT"

    # V5 : la demande de chiffrement est rejetée, puis SEC REQ 0x0d (> ARPK).
    pause_for "[4/5] V5 : rejet du chiffrement puis SEC REQ 0x0d. Appareil prêt à se connecter"
    run_step secreq_v5 "$BLEURP" secreq "$TARGET_ID" -m v5 -r 0x0d -i "$HCI_INDEX" \
        -c "$WAIT_CONN" -w "$WAIT_REACT"

    # V3 : la Pairing Request reçoit une réponse plus faible que l'ARSR 0x0d.
    pause_for "[5/5] V3 : réponse d'appairage plus faible. Appareil prêt à se connecter"
    run_step secreq_v3 "$BLEURP" secreq "$TARGET_ID" -m v3 -r 0x0d -i "$HCI_INDEX" \
        -c "$WAIT_CONN" -w "$WAIT_REACT"
}

# Verdict d'une vulnérabilité, lu dans les journaux des étapes (lignes
# "[VERDICT] V<n> : <verdict> - <détail>" écrites par bleurp). Renvoie
# "<verdict>|<détail>|<étape>", ou rien si la vulnérabilité n'a pas été testée.
read_verdict() {
    local id="$1" line rest file
    line="$(grep -h "^\[VERDICT\] ${id} : " "$OUT_DIR"/logs/*.txt 2>/dev/null | head -n 1)"
    [[ -n "$line" ]] || return 0
    rest="${line#"[VERDICT] ${id} : "}"
    file="$(grep -l -F -- "$line" "$OUT_DIR"/logs/*.txt 2>/dev/null | head -n 1)"
    printf '%s|%s|%s\n' "${rest%% - *}" "${rest#* - }" "$(basename "$file" .txt)"
}

# Prérequis d'une attaque d'après la table II : "prérequis présents" si tous
# les verdicts donnés sont OUI, "prérequis absent" si l'un est NON, sinon
# "non déterminée". Ce n'est pas une attaque, seulement une estimation.
exposure() {
    local v
    for v in "$@"; do
        case "$v" in
            OUI) ;;
            NON) echo "prérequis absent"; return 0 ;;
            *) echo "non déterminée"; return 0 ;;
        esac
    done
    echo "prérequis présents"
}

# Écrit le rapport Markdown : résumé, extraits de verdicts, journaux complets, limites.
write_report() {
    log "== 7. Rapport =="
    local report="$OUT_DIR/rapport.md"
    local i verdict

    {
        echo "# Rapport d'audit BLERP"
        echo
        echo "- Date : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "- Adresse d'identité du bond : \`$TARGET_ID\`"
        echo "- Adresse courante (RPA) : \`${TARGET_RPA:-non fournie}\`"
        echo "- Type d'adresse pour la connexion : $TARGET_TYPE"
        echo "- Adaptateur : hci$HCI_INDEX"
        echo "- Outil : \`$BLEURP\`"
        echo
        echo "> Mesure seulement : aucune clé n'est dérivée ni échangée, et aucun appairage n'est terminé."
        echo
        echo "## Résumé des étapes"
        echo
        echo "| Étape | Code retour | Verdicts (extrait) |"
        echo "| :--- | :---: | :--- |"
        for i in "${!STEP_NAMES[@]}"; do
            verdict="$(grep -E '\[\+\]|\[!\]|\[-\]|\[i\]|Conforme|Refus|Bond trouvé|réaction|Connectée|Aucune|RÉSULTAT' "${STEP_LOG[$i]}" 2>/dev/null | head -n 3 | tr '\n' ' ' | sed -e 's/|/\\|/g')"
            echo "| ${STEP_NAMES[$i]} | ${STEP_RC[$i]} | ${verdict:-—} |"
        done
        echo
        echo "## Matrice V1-V6 (tableau I du papier BLERP)"
        echo
        echo "| Vulnérabilité | Verdict | Étape | Détail |"
        echo "| :--- | :---: | :--- | :--- |"
        local vid vname res v d st
        for vid in V1 V2 V3 V4 V5 V6; do
            case "$vid" in
                V1) vname="Re-pairing non authentifié (ARSR à bits rfu)" ;;
                V2) vname="Re-pairing non authentifié (Peripheral)" ;;
                V3) vname="Downgrade du niveau côté Central" ;;
                V4) vname="Downgrade du niveau au re-pairing" ;;
                V5) vname="Re-pairing depuis l'établissement de session" ;;
                V6) vname="Entropie de clé réduite au re-pairing" ;;
            esac
            res="$(read_verdict "$vid")"
            if [[ -z "$res" ]]; then
                echo "| ${vid} ${vname} | non mesuré | — | — |"
            else
                IFS='|' read -r v d st <<< "$res"
                echo "| ${vid} ${vname} | ${v} | ${st} | ${d} |"
            fi
        done
        echo
        echo "### Prérequis d'attaque estimés (table II)"
        echo
        echo "Ce ne sont que des prérequis : aucune attaque n'est exécutée."
        echo
        echo "- Peripheral Impersonation (V1 et V5) : $(exposure "$(read_verdict V1 | cut -d'|' -f1)" "$(read_verdict V5 | cut -d'|' -f1)")"
        echo "- Central Impersonation (V2) : $(exposure "$(read_verdict V2 | cut -d'|' -f1)")"
        echo
        echo "## Journaux complets"
        for i in "${!STEP_NAMES[@]}"; do
            echo
            echo "### ${STEP_NAMES[$i]}"
            echo
            echo '```'
            cat "${STEP_LOG[$i]}"
            echo '```'
        done
        echo
        echo "## Limites"
        echo
        echo "- La mesure porte sur la phase de négociation : une acceptation est un indice, pas une preuve de BLERP complet."
        echo "- ARPK est estimé à partir du fichier \`info\` de BlueZ : le bit SC n'y figure pas."
        echo "- Un refus \`0x08\` (Unspecified Reason) n'est pas un contrôle anti-downgrade : il est classé non concluant."
        echo "- Un appareil qui ne se connecte pas dans la fenêtre d'attente ne prouve rien."
        echo "- V3 n'est mesurée que côté Central, avec une seule réponse plus faible."
        echo "- V5 suppose que la Central demande le chiffrement : sinon le verdict est non concluant."
        echo "- Les prérequis PI et CI sont estimés d'après la table II, aucune impersonation n'est exécutée."
    } > "$report"

    log "[+] Rapport écrit : $report"
}

# ----- Menu interactif -----

# Remet à zéro l'état d'un audit, pour qu'un second passage dans le menu
# ne reprenne ni le dossier, ni les étapes, ni les options du précédent.
reset_run() {
    OUT_DIR=""
    TARGET_ID=""
    TARGET_RPA=""
    TARGET_TYPE="random"
    AUTO=0
    RUN_SMP=0
    STEP_NAMES=()
    STEP_RC=()
    STEP_LOG=()
}

# Demande une adresse Bluetooth jusqu'à obtenir un format valide. Résultat dans ANSWER.
# Avec optional=1, une réponse vide est acceptée.
ask_addr() {
    local label="$1" optional="${2:-0}" value
    while true; do
        printf '  %s%s%s : ' "$C_PINK" "$label" "$C_RESET"
        read -r value || exit 0
        value="${value^^}"
        if [[ -z "$value" && $optional -eq 1 ]] || [[ "$value" =~ $ADDR_RE ]]; then
            ANSWER="$value"
            return 0
        fi
        printf '  %sformat attendu : AA:BB:CC:DD:EE:FF%s\n' "$C_YELLOW" "$C_RESET"
    done
}

# Demande une question oui/non. Résultat dans ANSWER (1 = oui, 0 = non), défaut selon $2.
ask_yes_no() {
    local label="$1" default="$2" value hint="o/N"
    [[ "$default" -eq 1 ]] && hint="O/n"
    printf '  %s%s%s [%s] : ' "$C_PINK" "$label" "$C_RESET" "$hint"
    read -r value || exit 0
    case "$value" in
        o|O|y|Y) ANSWER=1 ;;
        n|N) ANSWER=0 ;;
        *) ANSWER="$default" ;;
    esac
}

# Assistant de l'audit complet : pose les questions, puis lance run_audit.
menu_audit() {
    reset_run
    [[ -x "$BLEURP" ]] || { log "[-] binaire introuvable : $BLEURP"; return 1; }

    printf '\n  %sListe des bonds :%s\n' "$C_PURPLE" "$C_RESET"
    "$BLEURP" repair -i "$HCI_INDEX" 2>&1 | strip_ansi | sed -e 's/^/    /' || true
    echo

    ask_addr "Adresse d'identité du bond (-t)"
    local id="$ANSWER"

    echo
    printf '  %s1)%s pas à pas : une Entrée à taper à chaque étape\n' "$C_GREEN" "$C_RESET"
    printf '  %s2)%s automatique : compte à rebours, sans rien taper (-a)\n' "$C_GREEN" "$C_RESET"
    local mode
    while true; do
        printf '  %sMode%s [1] : ' "$C_PINK" "$C_RESET"
        read -r mode || exit 0
        case "${mode:-1}" in
            1) AUTO=0; break ;;
            2) AUTO=1; break ;;
        esac
    done

    echo
    if [[ $AUTO -eq 1 ]]; then
        ask_addr "Adresse courante RPA (-r, obligatoire en automatique)"
    else
        ask_addr "Adresse courante RPA (-r, vide si inconnue)" 1
    fi
    local rpa="$ANSWER"

    printf "  %sType d'adresse%s (public/random) [random] : " "$C_PINK" "$C_RESET"
    local addr_type
    read -r addr_type || exit 0
    addr_type="${addr_type:-random}"

    if [[ $AUTO -eq 0 ]]; then
        ask_yes_no "Lancer aussi la sonde de première appairage (-s) ?" 0
        RUN_SMP="$ANSWER"
    fi

    local args=(-t "$id" -T "$addr_type")
    [[ -n "$rpa" ]] && args+=(-r "$rpa")
    [[ $AUTO -eq 1 ]] && args+=(-a)
    [[ $RUN_SMP -eq 1 ]] && args+=(-s)

    echo
    printf '  %sCommande :%s sudo %s %s\n' "$C_PURPLE" "$C_RESET" "$0" "${args[*]}"
    printf "  %sLes étapes envoient des requêtes à l'appareil. Vérifie que c'est bien le tien.%s\n" \
        "$C_YELLOW" "$C_RESET"
    ask_yes_no "Lancer l'audit ?" 0
    [[ "$ANSWER" -eq 1 ]] || { echo "  annulé."; return 0; }

    reset_run
    OPTIND=1
    parse_args "${args[@]}"
    run_audit
    return $?
}

# Demande un entier strictement positif. Résultat dans ANSWER, défaut si vide.
ask_positive() {
    local label="$1" default="$2" value
    while true; do
        printf '  %s%s%s [%s] : ' "$C_PINK" "$label" "$C_RESET" "$default"
        read -r value || exit 0
        value="${value:-$default}"
        if [[ "$value" =~ ^[0-9]+$ ]] && (( value > 0 )); then
            ANSWER="$value"
            return 0
        fi
        printf '  %sentier positif attendu%s\n' "$C_YELLOW" "$C_RESET"
    done
}

# Option [-4-] : scan, puis connexion et lecture GATT sur chaque appareil
# découvert (bleurp autotry). Touche tous les appareils à portée, pas seulement
# ceux de l'utilisateur : d'où la confirmation écrite.
menu_autotry() {
    reset_run
    [[ -x "$BLEURP" ]] || { log "[-] binaire introuvable : $BLEURP"; return 1; }

    printf '\n  %sTester tous les appareils découverts%s\n' "$C_PINK" "$C_RESET"
    printf "  %sLe scan puis une connexion sur chaque appareil à portée (le tien et les autres).%s\n" \
        "$C_YELLOW" "$C_RESET"
    printf '  %sLes lectures GATT ne sont faites que là où tu es autorisé à tester.%s\n\n' \
        "$C_YELLOW" "$C_RESET"

    ask_positive "Durée du scan (s)" 15
    local scan_sec="$ANSWER"
    ask_positive "Timeout par appareil (ms)" 4000
    local timeout_ms="$ANSWER"

    printf "\n  %sTape oui pour lancer (autre chose = annuler) : %s" "$C_PINK" "$C_RESET"
    local confirm
    read -r confirm || exit 0
    [[ "$confirm" == "oui" ]] || { echo "  annulé."; return 0; }

    OUT_DIR="autotry_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$OUT_DIR/logs"
    log "== Tester tout : scan ${scan_sec}s, timeout ${timeout_ms} ms, hci${HCI_INDEX} =="
    run_step autotry "$BLEURP" autotry -i "$HCI_INDEX" -t "$scan_sec" -T "$timeout_ms"
    log "[+] Résultats : $OUT_DIR/logs/autotry.txt"
}

# Menu principal, affiché quand le script est lancé sans option.
menu() {
    local choice
    while true; do
        printf '\033[2J\033[H'
        printf '%s  BLERP : audit BLE (mesure seulement)%s\n' "$C_PINK" "$C_RESET"
        printf '%s  ------------------------------------------------------------%s\n' "$C_PURPLE" "$C_RESET"
        printf '  %s[-1-]%s Audit complet    %sidentification, SMP, re-pairing, Security Request, rapport%s\n' \
            "$C_GREEN" "$C_RESET" "$C_PURPLE" "$C_RESET"
        printf '  %s[-2-]%s Lister les bonds %sappareils déjà appairés (BlueZ)%s\n' \
            "$C_YELLOW" "$C_RESET" "$C_PURPLE" "$C_RESET"
        printf "  %s[-3-]%s Reset Bluetooth  %srestaure l'adaptateur (reset_bluetooth.sh)%s\n" \
            "$C_YELLOW" "$C_RESET" "$C_PURPLE" "$C_RESET"
        printf '  %s[-4-]%s Tout tester      %sscan, puis connexion + lecture GATT sur chaque appareil%s\n' \
            "$C_YELLOW" "$C_RESET" "$C_PURPLE" "$C_RESET"
        printf '  %s[-Q-]%s Quitter\n\n> ' "$C_PINK" "$C_RESET"

        read -r choice || return 0
        case "$choice" in
            1)
                menu_audit
                printf '\n(Entrée pour revenir au menu) '
                read -r _ || return 0
                ;;
            2)
                echo
                "$BLEURP" repair -i "$HCI_INDEX" 2>&1 | strip_ansi || true
                printf '\n(Entrée pour revenir au menu) '
                read -r _ || return 0
                ;;
            3)
                echo
                "$SCRIPT_DIR/reset_bluetooth.sh" "hci${HCI_INDEX}" || true
                printf '\n(Entrée pour revenir au menu) '
                read -r _ || return 0
                ;;
            4)
                menu_autotry
                printf '\n(Entrée pour revenir au menu) '
                read -r _ || return 0
                ;;
            q|Q) return 0 ;;
        esac
    done
}

# ----- Programme principal -----

# Lance l'audit à partir de la configuration déjà analysée. Renvoie 0 si toutes
# les étapes ont réussi, 1 sinon.
run_audit() {
    mkdir -p "$OUT_DIR/logs"
    log "== Audit BLERP : $(date '+%Y-%m-%d %H:%M:%S') =="
    log "Cible : $TARGET_ID (RPA : ${TARGET_RPA:-non fournie}), hci$HCI_INDEX, dossier : $OUT_DIR"

    check_prereqs
    identify_target
    check_bond
    run_smp
    run_repair
    run_secreq
    write_report

    local failed=0 rc
    for rc in ${STEP_RC[@]+"${STEP_RC[@]}"}; do
        [[ "$rc" -ne 0 ]] && failed=1
    done
    if [[ $failed -eq 0 ]]; then
        log "[+] Audit terminé : toutes les étapes ont réussi."
    else
        log "[!] Audit terminé : au moins une étape a échoué (voir le rapport)."
    fi
    return "$failed"
}

main() {
    trap 'log "[!] Interruption. Si hci${HCI_INDEX} reste éteint : ./scripts/reset_bluetooth.sh"; exit 130' INT TERM

    if [[ $# -eq 0 ]]; then
        [[ $EUID -eq 0 ]] || die "lance le menu avec sudo : lecture de $STORE_DIR, canal USER HCI et mgmt"
        menu
        exit 0
    fi
    parse_args "$@"
    run_audit
    exit $?
}

main "$@"
