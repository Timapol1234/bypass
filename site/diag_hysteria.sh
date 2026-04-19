#!/usr/bin/env bash
# Диагностика подключения к Hysteria для последнего созданного ключа.
# Запускать на Амстердаме.

set -uo pipefail

echo "=== последний юзер ==="
python3 <<'PYEOF'
import json
u = json.load(open("/opt/vpn-site/users.json"))
last = u[-1]
print(f"username: {last['username']}")
print(f"server:   {last['server']}")
print(f"hy_pw:    {last.get('hysteria_password')}")
PYEOF

SERVER_IP=$(python3 <<'PYEOF'
import json
with open("/opt/vpn-site/users.json") as f:
    u = json.load(f)[-1]
ips = {
    "amsterdam": "109.248.162.180",
    "usa":       "31.56.229.94",
    "finland":   "109.248.161.20",
    "france":    "45.38.23.141",
}
print(ips[u["server"]])
PYEOF
)

echo ""
echo "=== server IP: $SERVER_IP ==="
echo ""

echo "=== 1. hysteria-server status ==="
ssh -n "root@$SERVER_IP" 'systemctl status hysteria-server --no-pager | head -10'
echo ""

echo "=== 2. последние логи hysteria ==="
ssh -n "root@$SERVER_IP" 'journalctl -u hysteria-server -n 25 --no-pager'
echo ""

echo "=== 3. UDP 8443 слушает? ==="
ssh -n "root@$SERVER_IP" 'ss -ulnp | grep 8443 || echo "NOT LISTENING"'
echo ""

echo "=== 4. iptables/ufw на 8443 ==="
ssh -n "root@$SERVER_IP" 'iptables -L INPUT -n | grep 8443 || echo "нет правила iptables для 8443"; echo "---ufw---"; ufw status 2>/dev/null | grep 8443 || echo "ufw не активен или нет правила"'
echo ""

echo "=== 5. юзеры в конфиге ==="
ssh -n "root@$SERVER_IP" 'sed -n "/BYPASS-USERS-BEGIN/,/BYPASS-USERS-END/p" /etc/hysteria/config.yaml'
echo ""

echo "=== 6. obfs password: сервер vs secrets.json ==="
REMOTE_OBFS=$(ssh -n "root@$SERVER_IP" 'cat /etc/hysteria/.obfs_password')
SECRETS_OBFS=$(python3 <<'PYEOF'
import json
with open("/opt/vpn-site/secrets.json") as f: d = json.load(f)
with open("/opt/vpn-site/users.json") as f: u = json.load(f)[-1]
print(d["hysteria"][u["server"]]["obfs_password"])
PYEOF
)
echo "remote:  $REMOTE_OBFS"
echo "secrets: $SECRETS_OBFS"
if [ "$REMOTE_OBFS" = "$SECRETS_OBFS" ]; then
    echo "[OK] совпадает"
else
    echo "[FAIL] НЕ СОВПАДАЕТ! Клиент обфусцирует пакеты паролем из secrets.json, а сервер ждёт другой."
fi
echo ""

echo "=== 7. проверка что UDP 8443 снаружи отвечает (с Амстердама) ==="
timeout 3 bash -c "echo test | nc -u -w2 $SERVER_IP 8443 >/dev/null 2>&1"
if [ $? -eq 0 ] || [ $? -eq 124 ]; then
    echo "порт достижим (пакет отправлен, ответа ждать не надо — QUIC не отвечает на мусор)"
else
    echo "порт НЕ достижим с Амстердама!"
fi
