#!/bin/bash
# ==============================================================================
# Script de restauration / réinitialisation de l'adaptateur Bluetooth (Linux/BlueZ)
# ==============================================================================

set -e

ADAPTER="${1:-hci0}"

echo "=== [BLEURP] Réinitialisation de l'adaptateur Bluetooth ($ADAPTER) ==="

# 1. Vérifier si l'adaptateur existe
if ! hciconfig "$ADAPTER" >/dev/null 2>&1 && ! btmgmt info 2>/dev/null | grep -q "$ADAPTER"; then
    echo "[!] Attention: L'adaptateur $ADAPTER n'a pas été trouvé."
fi

# 2. Débloquer rfkill si bloqué
echo "[*] Déblocage de rfkill..."
sudo rfkill unblock bluetooth || true

# 3. Redémarrer le service BlueZ pour réassigner le contrôle au système
echo "[*] Redémarrage du démon bluetoothd..."
if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl restart bluetooth || true
fi

# 4. Réactiver l'interface Bluetooth
echo "[*] Réactivation de l'interface $ADAPTER..."
if command -v hciconfig >/dev/null 2>&1; then
    sudo hciconfig "$ADAPTER" reset || true
    sudo hciconfig "$ADAPTER" up || true
fi

# 5. Allumer l'adaptateur via bluetoothctl / btmgmt
echo "[*] Allumage de l'adaptateur..."
bluetoothctl power on 2>/dev/null || true

echo "=== [OK] Adaptateur $ADAPTER restauré avec succès dans sa configuration standard ==="
hciconfig "$ADAPTER" || true
