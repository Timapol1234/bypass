#!/usr/bin/env bash
# Чистая переустановка Hysteria 2 на всех 4 серверах BYPASS.
# Запускать на Амстердаме (у которого SSH-доступ ко всем остальным).
# Использование: bash reinstall_hysteria_all.sh

set -uo pipefail

SERVERS=(
    "109.248.162.180"   # amsterdam
    "31.56.229.94"      # usa
    "109.248.161.20"    # finland
    "45.38.23.141"      # france
)

INSTALLER_URL="https://raw.githubusercontent.com/Timapol1234/bypass/main/site/install_hysteria.sh"

echo "=========================================="
echo "  BYPASS: переустановка Hysteria на 4 серверах"
echo "=========================================="
echo ""

# === Шаг 1: снос ===
echo ">>> ШАГ 1: удаляю Hysteria со всех серверов"
echo ""
for s in "${SERVERS[@]}"; do
    echo "--- CLEAN $s ---"
    ssh -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 "root@$s" '
        systemctl stop hysteria-server 2>/dev/null || true
        systemctl disable hysteria-server 2>/dev/null || true
        systemctl stop hysteria 2>/dev/null || true
        systemctl disable hysteria 2>/dev/null || true
        rm -rf /etc/hysteria
        rm -f /etc/systemd/system/hysteria-server.service
        rm -f /etc/systemd/system/hysteria.service
        rm -f /etc/systemd/system/multi-user.target.wants/hysteria-server.service
        rm -f /etc/systemd/system/multi-user.target.wants/hysteria.service
        systemctl daemon-reload
        systemctl reset-failed 2>/dev/null || true
        echo "cleaned"
    '
    echo ""
done

# === Шаг 2: установка ===
echo ""
echo ">>> ШАГ 2: ставлю Hysteria заново"
echo ""
declare -A OBFS_PASSWORDS
for s in "${SERVERS[@]}"; do
    echo "--- INSTALL $s ---"
    OUTPUT=$(ssh -o StrictHostKeyChecking=accept-new "root@$s" "curl -fsSL $INSTALLER_URL | bash" 2>&1)
    echo "$OUTPUT" | tail -25
    # Вытаскиваем obfs password из вывода installer'а
    PW=$(echo "$OUTPUT" | grep -oP 'Obfs password:\s+\K\S+' | head -1)
    if [ -n "$PW" ]; then
        OBFS_PASSWORDS[$s]=$PW
    fi
    echo ""
done

# === Шаг 3: финальная проверка ===
echo ""
echo ">>> ШАГ 3: финальная проверка"
echo ""
ALL_OK=1
for s in "${SERVERS[@]}"; do
    STATUS=$(ssh "root@$s" 'systemctl is-active hysteria-server' 2>/dev/null)
    MARKERS=$(ssh "root@$s" 'grep -c "BYPASS-USERS" /etc/hysteria/config.yaml 2>/dev/null || echo 0')
    if [ "$STATUS" = "active" ] && [ "$MARKERS" -ge 2 ]; then
        echo "  [OK]  $s : active, markers=$MARKERS"
    else
        echo "  [FAIL] $s : status=$STATUS, markers=$MARKERS"
        ALL_OK=0
    fi
done

# === Итог + obfs passwords ===
echo ""
echo "=========================================="
if [ $ALL_OK -eq 1 ]; then
    echo "  УСПЕХ: все 4 сервера работают"
else
    echo "  ОШИБКА: не все сервера поднялись — смотри вывод выше"
fi
echo "=========================================="
echo ""
echo "OBFS PASSWORDS (для /opt/vpn-site/secrets.json):"
echo ""
echo '  "hysteria": {'
IP_TO_KEY=(
    "109.248.162.180:amsterdam"
    "31.56.229.94:usa"
    "109.248.161.20:finland"
    "45.38.23.141:france"
)
LAST_IDX=$((${#IP_TO_KEY[@]} - 1))
for i in "${!IP_TO_KEY[@]}"; do
    pair="${IP_TO_KEY[$i]}"
    ip="${pair%:*}"
    key="${pair#*:}"
    pw="${OBFS_PASSWORDS[$ip]:-???}"
    comma=","
    [ $i -eq $LAST_IDX ] && comma=""
    printf '    "%s": { "obfs_password": "%s" }%s\n' "$key" "$pw" "$comma"
done
echo '  }'
echo ""
