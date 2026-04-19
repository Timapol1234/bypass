#!/usr/bin/env bash
# Принудительный деплой: снос /tmp/bypass-deploy, свежий clone, копирование,
# обновление secrets.json, рестарт. Запускать на Амстердаме.

set -e

REPO=https://github.com/Timapol1234/bypass.git
DEPLOY_DIR=/tmp/bypass-deploy

echo ">>> 1. Смотрю что было в /tmp/bypass-deploy"
if [ -d "$DEPLOY_DIR/.git" ]; then
    (cd "$DEPLOY_DIR" && git log --oneline -3 2>/dev/null) || true
    (cd "$DEPLOY_DIR" && git status -s 2>/dev/null) || true
fi

echo ""
echo ">>> 2. Сношу и клонирую заново"
rm -rf "$DEPLOY_DIR"
git clone "$REPO" "$DEPLOY_DIR"
cd "$DEPLOY_DIR"
echo "  последний коммит:"
git log --oneline -1

echo ""
echo ">>> 3. Проверяю что в новом index.html есть hy2-tab-btn"
if grep -q "hy2-tab-btn" site/index.html; then
    echo "  [OK] hy2-tab-btn найден"
else
    echo "  [FAIL] hy2-tab-btn НЕ найден в клонированном index.html — проблема в git"
    exit 1
fi

echo ""
echo ">>> 4. Обновляю secrets.json"
python3 <<'PYEOF'
import json
p = "/opt/vpn-site/secrets.json"
d = json.load(open(p))
d["hysteria"] = {
    "amsterdam": {"obfs_password": "RpIc8oNqLhMse0HqFQBfeGrwC372Vws4"},
    "usa":       {"obfs_password": "SpP9WQ5RKvjC5NSPNFTEFeVxuQ6W7lTd"},
    "finland":   {"obfs_password": "BKuBFtgom2dGm2AoMqN4JH72oEthnoj3"},
    "france":    {"obfs_password": "4QFtuNsl6Ghq2lsoyaTaJOmtOw70PJWD"},
}
json.dump(d, open(p, "w"), indent=2, ensure_ascii=False)
print("  secrets.json updated")
PYEOF

echo ""
echo ">>> 5. Копирую свежий код"
mkdir -p /opt/vpn-site/static
cp "$DEPLOY_DIR/site/app.py" /opt/vpn-site/
cp "$DEPLOY_DIR/site/hysteria_config.py" /opt/vpn-site/
# Flask сервит из /opt/vpn-site/static/, не из /opt/vpn-site/!
cp "$DEPLOY_DIR/site/index.html" /opt/vpn-site/static/index.html
echo "  скопировано в /opt/vpn-site/static/index.html"

echo ""
echo ">>> 6. Проверяю md5 (должны совпасть)"
md5sum "$DEPLOY_DIR/site/index.html" /opt/vpn-site/static/index.html

echo ""
echo ">>> 7. Перезапускаю vpn-site"
systemctl restart vpn-site
sleep 2
systemctl status vpn-site --no-pager | head -5

echo ""
echo ">>> 8. Проверяю что в живом index.html есть hy2-tab-btn"
if curl -s http://127.0.0.1:8080/ | grep -q "hy2-tab-btn"; then
    echo "  [OK] фронт отдаёт hy2-tab-btn"
else
    echo "  [FAIL] фронт НЕ отдаёт hy2-tab-btn"
fi

echo ""
echo "=== ГОТОВО. Теперь в браузере нажми Ctrl+Shift+R и создай новый ключ ==="
