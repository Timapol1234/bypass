#!/usr/bin/env bash
# Глубокий дебаг hysteria-сервера:
# 1. Ставит tcpdump, включает logLevel=debug в /etc/hysteria/config.yaml
# 2. Сбрасывает счётчик iptables на UDP 8443
# 3. Даёт юзеру 15 секунд на Connect в клиенте
# 4. Показывает: tcpdump (первые 10 пакетов), изменение счётчика, debug логи hysteria
# 5. Откатывает logLevel обратно

set -uo pipefail

declare -A IPS=(
    [amsterdam]="109.248.162.180"
    [usa]="31.56.229.94"
    [finland]="109.248.161.20"
    [france]="45.38.23.141"
)

SERVER=$(python3 -c "import json; print(json.load(open('/opt/vpn-site/users.json'))[-1]['server'])")
SERVER_IP="${IPS[$SERVER]}"
UN=$(python3 -c "import json; print(json.load(open('/opt/vpn-site/users.json'))[-1]['username'])")

echo "=== Последний юзер: $UN на $SERVER ($SERVER_IP) ==="
echo ""

ssh -n "root@$SERVER_IP" 'bash -s' <<'REMOTE_EOF'
set -e
echo "--- устанавливаю tcpdump ---"
apt-get install -y tcpdump >/dev/null 2>&1 && echo "tcpdump установлен" || echo "tcpdump уже был"

echo "--- включаю debug log в hysteria-server ---"
if ! grep -q "^logLevel:" /etc/hysteria/config.yaml; then
    echo "" >> /etc/hysteria/config.yaml
    echo "logLevel: debug" >> /etc/hysteria/config.yaml
else
    sed -i 's/^logLevel:.*/logLevel: debug/' /etc/hysteria/config.yaml
fi
systemctl restart hysteria-server
sleep 2
systemctl is-active hysteria-server

echo "--- сбрасываю счётчик iptables ---"
iptables -Z INPUT
REMOTE_EOF

echo ""
echo "======================================================"
echo "ПРЯМО СЕЙЧАС в V2Box нажми Connect и держи 15 секунд!"
echo "======================================================"
echo ""
sleep 3
echo "10..."
sleep 2
echo "8..."
sleep 2
echo "6..."
sleep 2
echo "4..."
sleep 2
echo "2..."
sleep 2
echo "0 — собираю данные"

ssh -n "root@$SERVER_IP" 'bash -s' <<'REMOTE_EOF'
set -uo pipefail

echo ""
echo "--- счётчик iptables UDP 8443 ПОСЛЕ попытки ---"
iptables -L INPUT -v -n | grep -E "8443|Chain INPUT"

echo ""
echo "--- tcpdump 10 первых UDP пакетов на 8443 (8 сек) ---"
timeout 8 tcpdump -ni any -c 10 -X "udp port 8443" 2>&1 || true

echo ""
echo "--- логи hysteria-server за последнюю минуту (debug) ---"
journalctl -u hysteria-server --since "1 minute ago" --no-pager

echo ""
echo "--- возвращаю logLevel обратно ---"
sed -i '/^logLevel:/d' /etc/hysteria/config.yaml
# убираем пустую строку в конце если она появилась
sed -i -e :a -e '/^$/{$d;N;ba' -e '}' /etc/hysteria/config.yaml
systemctl restart hysteria-server
sleep 1
systemctl is-active hysteria-server
REMOTE_EOF
