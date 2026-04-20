#!/usr/bin/env bash
# Быстрый деплой только Flask-сайта: обновляет /opt/vpn-site из репозитория,
# рестартит vpn-site, проверяет что /api/health и /api/hy-auth живы.
# НЕ трогает Hysteria/Xray конфиги на серверах — для этого fix_hysteria_corruption.sh.
# Запускать на Амстердаме.

set -e

REPO=https://github.com/Timapol1234/bypass.git
DEPLOY_DIR=/tmp/bypass-deploy
APP_DIR=/opt/vpn-site

echo ">>> 1. Клон свежего репо"
rm -rf "$DEPLOY_DIR"
git clone --depth 1 "$REPO" "$DEPLOY_DIR"
echo "  коммит: $(cd "$DEPLOY_DIR" && git log --oneline -1)"

echo ""
echo ">>> 2. Копирую исходники в $APP_DIR"
cp "$DEPLOY_DIR/site/app.py"              "$APP_DIR/app.py"
cp "$DEPLOY_DIR/site/hysteria_config.py"  "$APP_DIR/hysteria_config.py"
mkdir -p "$APP_DIR/static"
cp "$DEPLOY_DIR/site/index.html"          "$APP_DIR/static/index.html"
cp "$DEPLOY_DIR/site/admin.html"          "$APP_DIR/static/admin.html"

echo ""
echo ">>> 3. Рестарт vpn-site"
systemctl restart vpn-site
sleep 2
systemctl is-active vpn-site || { echo "  vpn-site НЕ активен"; journalctl -u vpn-site -n 20 --no-pager; exit 1; }
echo "  vpn-site активен"

echo ""
echo ">>> 4. Healthcheck"
hc=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/health)
hy=$(curl -s -o /dev/null -w '%{http_code}' -X POST -H 'Content-Type: application/json' \
     -d '{"addr":"deploy","auth":"","tx":0}' http://127.0.0.1:8080/api/hy-auth)
echo "  /api/health   → HTTP $hc (ожидаем 200)"
echo "  /api/hy-auth  → HTTP $hy (ожидаем 401)"
if [ "$hc" != "200" ] || [ "$hy" != "401" ]; then
    echo "  !!! один из endpoint'ов ответил не так, смотри journalctl -u vpn-site"
    exit 1
fi

echo ""
echo "=== Деплой ОК ==="
