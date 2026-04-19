#!/usr/bin/env bash
# Глубокая диагностика Hysteria-клиента: есть ли юзер в конфиге сервера
# после последней очистки, совпадает ли его пароль с тем, что в users.json,
# какой URI генерит backend, и проходит ли UDP до сервера.

set -uo pipefail

declare -A IPS=(
    [amsterdam]="109.248.162.180"
    [usa]="31.56.229.94"
    [finland]="109.248.161.20"
    [france]="45.38.23.141"
)

echo "=== 1. Последний юзер в users.json ==="
python3 <<'PYEOF'
import json
u = json.load(open("/opt/vpn-site/users.json"))
last = u[-1]
print(json.dumps(last, indent=2, ensure_ascii=False))
PYEOF

# Вытаскиваем данные для дальнейших шагов
eval "$(python3 <<'PYEOF'
import json
u = json.load(open("/opt/vpn-site/users.json"))[-1]
print(f"UN={u['username']}")
print(f"SERVER={u['server']}")
print(f"HYPW={u.get('hysteria_password', '')}")
PYEOF
)"

SERVER_IP="${IPS[$SERVER]}"
echo ""
echo "=== 2. Данные для проверки ==="
echo "username: $UN"
echo "server:   $SERVER ($SERVER_IP)"
echo "hy_pw в users.json:    '$HYPW'"

echo ""
echo "=== 3. ПОЛНЫЙ конфиг Hysteria на $SERVER ==="
ssh -n "root@$SERVER_IP" 'cat /etc/hysteria/config.yaml'

echo ""
echo "=== 4. Есть ли $UN в блоке BEGIN/END на сервере? ==="
HY_PW_REMOTE=$(ssh -n "root@$SERVER_IP" "awk '/^[[:space:]]*# BYPASS-USERS-BEGIN[[:space:]]*\$/{flag=1;next} /^[[:space:]]*# BYPASS-USERS-END[[:space:]]*\$/{flag=0} flag' /etc/hysteria/config.yaml | grep -E '^[[:space:]]+$UN:' | awk -F': ' '{print \$2}' | tr -d ' '")
if [ -z "$HY_PW_REMOTE" ]; then
    echo "[FAIL] Юзера $UN НЕТ в конфиге сервера!"
else
    echo "hy_pw на сервере:      '$HY_PW_REMOTE'"
    if [ "$HY_PW_REMOTE" = "$HYPW" ]; then
        echo "[OK] пароли совпадают"
    else
        echo "[FAIL] пароли НЕ совпадают! Клиент будет слать не тот пароль"
    fi
fi

echo ""
echo "=== 5. obfs password на сервере vs secrets.json ==="
REMOTE_OBFS=$(ssh -n "root@$SERVER_IP" 'cat /etc/hysteria/.obfs_password')
SECRETS_OBFS=$(python3 <<PYEOF
import json
with open("/opt/vpn-site/secrets.json") as f: d = json.load(f)
print(d["hysteria"]["$SERVER"]["obfs_password"])
PYEOF
)
echo "obfs на сервере:         '$REMOTE_OBFS'"
echo "obfs в secrets.json:     '$SECRETS_OBFS'"
if [ "$REMOTE_OBFS" = "$SECRETS_OBFS" ]; then
    echo "[OK] совпадает"
else
    echo "[FAIL] обфускация паролем из secrets.json не совпадает — QUIC пакеты будут мусором для сервера"
fi

echo ""
echo "=== 6. Статус hysteria на $SERVER ==="
ssh -n "root@$SERVER_IP" 'systemctl is-active hysteria-server; ss -ulnp | grep 8443 || echo NOT_LISTENING'

echo ""
echo "=== 7. Какой URI сейчас сгенерил бы backend ==="
python3 <<PYEOF
import sys
sys.path.insert(0, "/opt/vpn-site")
import json
with open("/opt/vpn-site/secrets.json") as f:
    secrets = json.load(f)
with open("/opt/vpn-site/users.json") as f:
    users = json.load(f)
u = users[-1]
server_key = u["server"]
server_ips = {
    "amsterdam": "109.248.162.180",
    "usa":       "31.56.229.94",
    "finland":   "109.248.161.20",
    "france":    "45.38.23.141",
}
from hysteria_config import build_uri
server = {
    "ip": server_ips[server_key],
    "name": server_key.upper(),
    "remote": server_key != "amsterdam",
    "ssh": f"root@{server_ips[server_key]}",
}
try:
    uri = build_uri(server_key, server, u["username"], u.get("hysteria_password", ""))
    print(uri)
except Exception as e:
    print(f"[FAIL] build_uri упал: {e}")
PYEOF

echo ""
echo "=== 8. UDP 8443 достижимость ==="
timeout 3 bash -c "echo x | nc -u -w2 $SERVER_IP 8443 >/dev/null 2>&1" && echo "отправка прошла" || echo "отправка не прошла ($?)"

echo ""
echo "=== 9. Последние 10 логов hysteria-server на $SERVER ==="
ssh -n "root@$SERVER_IP" 'journalctl -u hysteria-server -n 10 --no-pager'
