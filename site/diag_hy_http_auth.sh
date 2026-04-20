#!/usr/bin/env bash
# Диагностика hysteria + http-auth после перехода на /api/hy-auth.
# Запускать на Амстердаме.

set -uo pipefail

AMS_IP="109.248.162.180"
declare -A SERVERS=(
    [usa]="31.56.229.94"
    [finland]="109.248.161.20"
    [france]="45.38.23.141"
)

echo "########## 1. /api/hy-auth отвечает локально? ##########"
curl -sv -X POST -H 'Content-Type: application/json' \
    -d '{"addr":"diag","auth":"","tx":0}' \
    http://127.0.0.1:8080/api/hy-auth 2>&1 | tail -15
echo ""

echo "########## 2. Flask слушает 8080 на публичном интерфейсе? ##########"
ss -tlnp | grep ':8080 ' || echo "  НЕ СЛУШАЕТ 8080"
echo ""

echo "########## 3. iptables INPUT для 8080 на Амстердаме ##########"
iptables -nL INPUT | grep -E '8080|DROP|ACCEPT' | head -20
echo ""

echo "########## 4. Пробую достучаться до 8080 извне (через USA) ##########"
ssh -n -o BatchMode=yes root@${SERVERS[usa]} \
    "curl -s -o /tmp/resp.json -w 'HTTP=%{http_code} time=%{time_total}s\n' -m 5 \
     -X POST -H 'Content-Type: application/json' \
     -d '{\"addr\":\"diag\",\"auth\":\"\",\"tx\":0}' \
     http://$AMS_IP:8080/api/hy-auth 2>&1; echo '  body:'; cat /tmp/resp.json 2>/dev/null; echo ''"
echo ""

echo "########## 5. Последние записи hysteria-server на Амстердаме ##########"
journalctl -u hysteria-server -n 30 --no-pager
echo ""

echo "########## 6. Последние записи hysteria-server на Финляндии ##########"
ssh -n -o BatchMode=yes root@${SERVERS[finland]} \
    "journalctl -u hysteria-server -n 30 --no-pager"
echo ""

echo "########## 7. Выписки пользователей из users.json (без секретов) ##########"
python3 - <<'PY'
import json
try:
    with open("/opt/vpn-site/users.json") as f:
        users = json.load(f)
except Exception as e:
    print(f"  read failed: {e}")
    raise SystemExit
for u in users[-5:]:
    hp = u.get("hysteria_password") or ""
    hp_preview = (hp[:4] + "..." + hp[-4:]) if hp else "MISSING"
    print(f"  user={u.get('username'):<25} server={u.get('server'):<10} "
          f"in_xray={u.get('in_xray')} hy_pw={hp_preview}")
PY
echo ""

echo "########## 8. Проверка /api/hy-auth с реальным паролем последнего юзера ##########"
python3 - <<'PY'
import json, subprocess
with open("/opt/vpn-site/users.json") as f:
    users = json.load(f)
target = None
for u in users[::-1]:
    if u.get("in_xray") and u.get("hysteria_password"):
        target = u
        break
if not target:
    print("  нет ни одного юзера с hysteria_password + in_xray=True")
    raise SystemExit
pw = target["hysteria_password"]
print(f"  тестирую юзера '{target['username']}' сервер={target['server']}")
r = subprocess.run(
    ["curl", "-s", "-w", "\\nHTTP=%{http_code}\\n", "-m", "5",
     "-X", "POST", "-H", "Content-Type: application/json",
     "-d", json.dumps({"addr": "diag", "auth": pw, "tx": 0}),
     "http://127.0.0.1:8080/api/hy-auth"],
    capture_output=True, text=True,
)
print(f"  response: {r.stdout}")
PY
echo ""

echo "########## 9. Какой URI сайт отдаёт для этого юзера? ##########"
python3 - <<'PY'
import sys
sys.path.insert(0, "/opt/vpn-site")
import json
from hysteria_config import build_uri

with open("/opt/vpn-site/users.json") as f:
    users = json.load(f)
with open("/opt/vpn-site/app.py") as f:
    # Вытащим SERVERS dict
    pass

# Упрощённо — подгрузим напрямую
import importlib.util
spec = importlib.util.spec_from_file_location("app_mod", "/opt/vpn-site/app.py")
# Не выполняем app.py целиком — это запустит Flask. Вместо этого парсим SERVERS:
import re, ast
text = open("/opt/vpn-site/app.py").read()
m = re.search(r'SERVERS\s*=\s*(\{.*?\n\})\s*\n', text, re.DOTALL)
if not m:
    print("  SERVERS dict не нашёл в app.py")
    raise SystemExit
SERVERS = ast.literal_eval(m.group(1))

target = None
for u in users[::-1]:
    if u.get("in_xray") and u.get("hysteria_password"):
        target = u; break
if not target:
    print("  нет юзера с hy_pw"); raise SystemExit

uri = build_uri(target["server"], SERVERS[target["server"]],
                target["username"], target["hysteria_password"])
print(f"  {uri}")
print("")
print("  ^ именно это должно быть в V2Box. Если у тебя там hysteria2://USERNAME:...@")
print("    — значит V2Box держит старый ключ, надо удалить и заново импортировать.")
PY
