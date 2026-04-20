#!/usr/bin/env bash
# Тест без salamander obfs: отключает obfs на Финляндии, генерит URI без obfs.
# Если V2Box подключится по этому URI — значит проблема в salamander.

set -uo pipefail

FIN_IP="109.248.161.20"
UN=$(python3 -c "import json; print(json.load(open('/opt/vpn-site/users.json'))[-1]['username'])")

echo "=== Отключаю salamander на Финляндии ==="
ssh -o BatchMode=yes "root@$FIN_IP" bash <<'REMOTE_EOF'
set -e
# Бэкап
cp /etc/hysteria/config.yaml /etc/hysteria/config.yaml.bak

# Вырезаем obfs блок (4 строки: obfs:, '  type:', '  salamander:', '    password:')
python3 <<'PYEOF'
import re
with open('/etc/hysteria/config.yaml') as f:
    cfg = f.read()
# Убираем блок obfs: ... (до следующего top-level ключа)
cfg = re.sub(r'\nobfs:\n(?:[ \t]+[^\n]*\n)+', '\n', cfg)
with open('/etc/hysteria/config.yaml', 'w') as f:
    f.write(cfg)
PYEOF

echo "--- новый конфиг (проверка) ---"
cat /etc/hysteria/config.yaml

echo "--- рестарт ---"
systemctl restart hysteria-server
sleep 2
systemctl is-active hysteria-server
REMOTE_EOF

echo ""
echo "=== Получаю пароль юзера $UN на Финляндии ==="
# Сначала проверим есть ли юзер на Финляндии. Если нет — добавим его с тем же паролем
# что в users.json (если сервер юзера был finland) или сгенерим новый.

HY_PW=$(ssh "root@$FIN_IP" "awk '/^[[:space:]]*# BYPASS-USERS-BEGIN[[:space:]]*\$/{flag=1;next} /^[[:space:]]*# BYPASS-USERS-END[[:space:]]*\$/{flag=0} flag' /etc/hysteria/config.yaml | grep -E '^[[:space:]]+$UN:' | awk -F': ' '{print \$2}' | tr -d ' '")

if [ -z "$HY_PW" ]; then
    echo "Юзера $UN нет на Финляндии — добавляю через Flask API"
    # Генерим пароль, добавляем через Python+hysteria_config
    HY_PW=$(python3 <<PYEOF
import sys
sys.path.insert(0, '/opt/vpn-site')
import hysteria_config
server = {"ip": "$FIN_IP", "name": "FINLAND", "remote": True, "ssh": "root@$FIN_IP"}
pw = hysteria_config.generate_password()
hysteria_config.add_user(server, "$UN", pw)
print(pw)
PYEOF
)
fi

echo "hysteria password для $UN на Финляндии: $HY_PW"

echo ""
echo "======================================================="
echo "URI БЕЗ obfs (Финляндия) — вставь в V2Box как новый профиль:"
echo ""
echo "hysteria2://$UN:$HY_PW@$FIN_IP:8443/?sni=www.microsoft.com&insecure=1#BYPASS-FIN-TEST"
echo ""
echo "======================================================="
echo ""
echo "1. Скопируй ссылку выше"
echo "2. В V2Box нажми + → 'Import from Clipboard'"
echo "3. Попробуй подключиться"
echo "4. Отпиши — работает или нет"
echo ""
echo "Чтобы откатить obfs на Финляндии обратно:"
echo "  ssh root@$FIN_IP 'mv /etc/hysteria/config.yaml.bak /etc/hysteria/config.yaml && systemctl restart hysteria-server'"
