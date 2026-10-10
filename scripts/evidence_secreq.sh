#!/usr/bin/env bash
# ========================================
#  nom du fichier: evidence_secreq.sh
#  description courte: Répète le test Security Request (bleurp secreq) sur un bond
#  BlueZ et consigne chaque essai : trace brute, tableau TSV et rapport Markdown.
#  Mesure seulement : une Security Request est envoyée, la première réaction est
#  notée. Aucune clé n'est dérivée et aucun appairage n'est mené à terme.
#  dernière modification : 2026-10-03
#  auteur: GitHub/@gGaToRr
# ========================================
#
# Usage (depuis la racine du projet, après 'make build/bleurp') :
#   sudo scripts/evidence_secreq.sh -t <IDENTITE> [options]
#
# Options :
#   -t ADDR  adresse d'identité du bond (BlueZ), obligatoire
#   -n N     nombre d'essais (défaut : 3)
#   -r ARSR  niveau envoyé (défaut : ARPK estimé du bond, le cas d'égalité)
#   -i N     index de l'adaptateur (défaut : 0)
#   -m TXT   modèle et version de l'appareil, reportés (ex. "iPhone 15, iOS 18.5")
#   -o DIR   dossier de sortie (défaut : evidence_AAAAMMJJ_HHMMSS)
#   -h       afficher cette aide
#
# Codes de sortie : 0 si au moins un essai a été consigné, 1 sinon.

set -u
set -o pipefail

BLEURP="${BLEURP:-./build/bleurp}"
TARGET=""
TRIALS=3
ARSR_ARG=""
HCI_INDEX=0
DEVICE_INFO="non renseigné"
OUT_DIR=""

# Format attendu d'une adresse Bluetooth en majuscules.
ADDR_RE='^([0-9A-F]{2}:){5}[0-9A-F]{2}$'

log() {
    printf '%s\n' "$*"
}

die() {
    log "[-] $*"
    exit 1
}

# Retire les séquences de couleur ANSI de l'entrée standard.
strip_ansi() {
    sed -e 's/\x1b\[[0-9;]*m//g'
}

usage() {
    sed -n '/^# Usage/,/^# Codes/{p;/^# Codes/q}' "$0" | sed -e 's/^# \{0,1\}//'
}

parse_args() {
    while getopts ":t:n:r:i:m:o:h" opt; do
        case "$opt" in
            t) TARGET="${OPTARG^^}" ;;
            n) TRIALS="$OPTARG" ;;
            r) ARSR_ARG="$OPTARG" ;;
            i) HCI_INDEX="$OPTARG" ;;
            m) DEVICE_INFO="$OPTARG" ;;
            o) OUT_DIR="$OPTARG" ;;
            h) usage; exit 0 ;;
            :) die "l'option -$OPTARG attend une valeur" ;;
            *) die "option inconnue : -$OPTARG (voir -h)" ;;
        esac
    done

    [[ -n "$TARGET" ]] || die "adresse d'identité manquante (-t). Liste des bonds : sudo $BLEURP repair"
    [[ "$TARGET" =~ $ADDR_RE ]] || die "adresse d'identité invalide : $TARGET (format AA:BB:CC:DD:EE:FF)"
    [[ "$TRIALS" =~ ^[1-9][0-9]*$ ]] || die "nombre d'essais invalide : $TRIALS"
    [[ "$HCI_INDEX" =~ ^[0-9]+$ ]] || die "index d'adaptateur invalide : $HCI_INDEX"
    if [[ -n "$ARSR_ARG" ]]; then
        [[ "$ARSR_ARG" =~ ^(0x[0-9A-Fa-f]{1,2}|[0-9]{1,3})$ ]] || die "ARSR invalide : $ARSR_ARG (ex. 0x01)"
    fi

    : "${OUT_DIR:=evidence_$(date +%Y%m%d_%H%M%S)}"
}

# Lit la réaction de la Central dans la sortie d'un essai.
reaction_of() {
    local f="$1"
    if grep -q "lance un re-pairing" "$f"; then echo "pairing_request"
    elif grep -q "demande le LTK" "$f"; then echo "ltk_request"
    elif grep -q "Aucune connexion de la Central" "$f"; then echo "pas_de_connexion"
    elif grep -q "aucune réaction pendant" "$f"; then echo "pas_de_reaction"
    else echo "inconnu"
    fi
}

# Lance les essais, un par un, en attendant la reconnexion de l'appareil.
run_trials() {
    local k log_raw log_txt stamp rc arpk arsr reaction conform
    printf 'essai\theure\tARPK\tARSR\treaction\tconforme\tcode\n' > "$OUT_DIR/essais.tsv"

    for ((k = 1; k <= TRIALS; k++)); do
        printf '\n[%d/%d] Essai : l'"'"'appareil doit se reconnecter (Bluetooth activé). Entrée pour lancer, q pour arrêter : ' "$k" "$TRIALS"
        local answer
        read -r answer || break
        [[ "$answer" == "q" || "$answer" == "Q" ]] && break

        log_raw="$OUT_DIR/logs/essai_$k.log"
        log_txt="$OUT_DIR/logs/essai_$k.txt"
        stamp="$(date '+%Y-%m-%d %H:%M:%S')"

        local args=(secreq "$TARGET" -i "$HCI_INDEX" -c 60 -w 10)
        [[ -n "$ARSR_ARG" ]] && args+=(-r "$ARSR_ARG")

        "$BLEURP" "${args[@]}" 2>&1 | tee "$log_raw"
        rc=${PIPESTATUS[0]}
        strip_ansi < "$log_raw" > "$log_txt"

        arpk="$(grep -o 'ARPK estimé (bond) : 0x[0-9A-Fa-f]*' "$log_txt" | head -n 1 | awk '{print $NF}')"
        arsr="$(grep -o 'ARSR envoyé : 0x[0-9A-Fa-f]*' "$log_txt" | head -n 1 | awk '{print $NF}')"
        reaction="$(reaction_of "$log_txt")"
        if grep -q "NON CONFORME" "$log_txt"; then conform="non"
        elif grep -q "Conforme à Listing 1" "$log_txt"; then conform="oui"
        else conform="n/a"
        fi
        [[ "$rc" -ne 0 ]] && reaction="erreur"

        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "$k" "$stamp" "${arpk:-?}" "${arsr:-?}" "$reaction" "$conform" "$rc" >> "$OUT_DIR/essais.tsv"
    done
}

# Rapport Markdown : contexte, tableau des essais, comptes par réaction, limites.
write_report() {
    local report="$OUT_DIR/rapport.md"
    local done_count
    done_count="$(($(wc -l < "$OUT_DIR/essais.tsv") - 1))"

    {
        echo "# Preuves : Security Request sur un bond BlueZ"
        echo
        echo "- Date de génération : $(date '+%Y-%m-%d %H:%M:%S')"
        echo "- Adresse d'identité du bond : \`$TARGET\`"
        echo "- Appareil : $DEVICE_INFO"
        echo "- Adaptateur : hci$HCI_INDEX"
        echo "- Outil : \`$BLEURP secreq\` (mesure seulement)"
        echo "- Essais consignés : $done_count sur $TRIALS demandés"
        echo
        echo "## Essais"
        echo
        echo "| Essai | Heure | ARPK | ARSR envoyé | Réaction | Conforme à Listing 1 | Code |"
        echo "| :---: | :--- | :---: | :---: | :--- | :---: | :---: |"
        tail -n +2 "$OUT_DIR/essais.tsv" | awk -F'\t' '{printf "| %s | %s | %s | %s | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, $7}'
        echo
        echo "## Comptes par réaction"
        echo
        tail -n +2 "$OUT_DIR/essais.tsv" | awk -F'\t' '{c[$5]++} END {for (r in c) printf "- %s : %d\n", r, c[r]}' | sort
        echo
        echo "## Méthode et limites"
        echo
        echo "- Une Security Request est envoyée à chaque essai, puis la première réaction de la Central est notée."
        echo "- L'outil n'envoie aucune réponse d'appairage, ne dérive aucune clé et ne termine aucun appairage."
        echo "- Le test couvre le chemin Security Request seul. Il n'inclut pas le rejet d'une demande de chiffrement."
        echo "- Les essais dépendent de la reconnexion de l'appareil : une absence de connexion ne prouve rien."
        echo "- Les traces brutes sont dans \`logs/\` (une par essai)."
    } > "$report"

    log "[+] Rapport écrit : $report"
}

main() {
    parse_args "$@"
    [[ -x "$BLEURP" ]] || die "binaire introuvable : $BLEURP (lance 'make build/bleurp' ou définis BLEURP=...)"
    if [[ $EUID -ne 0 ]]; then
        die "lance le script avec sudo : accès à /var/lib/bluetooth et au canal HCI"
    fi

    mkdir -p "$OUT_DIR/logs"
    log "== Preuves Security Request : $TARGET, $TRIALS essai(s), dossier : $OUT_DIR =="

    run_trials
    if [[ "$(wc -l < "$OUT_DIR/essais.tsv")" -le 1 ]]; then
        die "aucun essai consigné"
    fi
    write_report
    log "[+] Terminé. Joins $OUT_DIR/rapport.md et logs/ à ton envoi."
}

main "$@"
