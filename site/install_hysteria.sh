#!/usr/bin/env bash
# Установщик Hysteria 2 для WIREX.
# Запуск: bash install_hysteria.sh
# Работает на каждом из 4 серверов (Амстердам/USA/Финляндия/Франция).
# Идемпотентный.
#
# Авторизация: auth.type = http. Hysteria дёргает Flask на Амстердаме
# (http://109.248.162.180:8080/api/hy-auth), передавая туда пароль из клиента.
# Flask сверяет его со списком юзеров в users.json. Один пароль = один юзер.
# Плюс такого подхода: URI получается вида hysteria2://PASSWORD@host:port/...,
# без `user:pass@` — такой формат корректно парсит V2Box.

set -euo pipefail

PORT=443
CONFIG_DIR=/etc/hysteria
CERT=$CONFIG_DIR/cert.crt
KEY=$CONFIG_DIR/private.key
CONFIG=$CONFIG_DIR/config.yaml
OBFS_FILE=$CONFIG_DIR/.obfs_password
SNI="www.microsoft.com"
AUTH_URL="http://109.248.162.180:8080/api/hy-auth"

echo "=== WIREX Hysteria 2 installer ==="

# 0. Зависимости apt (на свежем сервере кэш может быть пустой;
#    openssl нужен для самоподписанного серта, curl/ca-certificates — для get.hy2.sh).
if command -v apt-get >/dev/null 2>&1; then
    echo "[0/7] apt-get update + базовые зависимости (openssl/curl/ca-certificates)..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y || { echo "apt-get update упал — проверь DNS/сеть на сервере"; exit 1; }
    apt-get install -y --no-install-recommends openssl curl ca-certificates || {
        echo "apt-get install openssl/curl упал — смотри вывод выше"; exit 1;
    }
fi

# 1. Бинарник
if ! command -v hysteria >/dev/null 2>&1; then
    echo "[1/7] Устанавливаю hysteria..."
    bash <(curl -fsSL https://get.hy2.sh/)
else
    echo "[1/7] hysteria уже установлен: $(hysteria version 2>&1 | head -1 || true)"
fi

mkdir -p $CONFIG_DIR
chmod 700 $CONFIG_DIR

# 2. Сертификат
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[2/7] Генерирую самоподписанный TLS-сертификат..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$KEY" -out "$CERT" -subj "/CN=$SNI" -days 3650 >/dev/null 2>&1
    chmod 600 "$KEY"
else
    echo "[2/7] Сертификат уже существует"
fi

# 3. Obfs password
if [ ! -f "$OBFS_FILE" ]; then
    echo "[3/7] Генерирую obfs password..."
    OBFS_PASSWORD=$(openssl rand -base64 32 | tr -d '=/+\n' | head -c 32)
    echo -n "$OBFS_PASSWORD" > "$OBFS_FILE"
    chmod 600 "$OBFS_FILE"
else
    OBFS_PASSWORD=$(cat "$OBFS_FILE")
    echo "[3/7] Obfs password загружен из $OBFS_FILE"
fi

# 4. Пишем канонический конфиг
echo "[4/7] Записываю $CONFIG..."
cat > "$CONFIG" <<EOF
# WIREX Hysteria 2 config — управляется install_hysteria.sh + /opt/vpn-site/app.py
# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ. Авторизация юзеров — через HTTP-колбэк на Flask.

listen: :$PORT

tls:
  cert: $CERT
  key: $KEY

obfs:
  type: salamander
  salamander:
    password: "$OBFS_PASSWORD"

auth:
  type: http
  http:
    url: $AUTH_URL
    insecure: false

masquerade:
  type: proxy
  proxy:
    url: https://$SNI
    rewriteHost: true

quic:
  initStreamReceiveWindow: 16777216
  maxStreamReceiveWindow: 16777216
  initConnReceiveWindow: 33554432
  maxConnReceiveWindow: 33554432

bandwidth:
  up: 50 mbps
  down: 50 mbps
EOF
chmod 600 "$CONFIG"

# 5. systemd unit
echo "[5/7] Настраиваю systemd..."
cat > /etc/systemd/system/hysteria-server.service <<'UNIT'
[Unit]
Description=Hysteria 2 Server (WIREX)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/hysteria server -c /etc/hysteria/config.yaml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535
User=root

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable hysteria-server >/dev/null 2>&1

# 6. Firewall
echo "[6/7] Открываю UDP $PORT..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow $PORT/udp >/dev/null 2>&1 || true
    echo "    ufw: $PORT/udp разрешён"
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p udp --dport $PORT -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p udp --dport $PORT -j ACCEPT
    echo "    iptables: $PORT/udp разрешён"
fi

# 7. Старт / перезагрузка (всегда restart, так как auth-блок поменялся)
echo "[7/7] Перезапускаю hysteria-server..."
systemctl restart hysteria-server

sleep 2
if systemctl is-active --quiet hysteria-server; then
    echo ""
    echo "=== УСПЕХ ==="
    systemctl --no-pager status hysteria-server | head -5
else
    echo ""
    echo "=== ОШИБКА ==="
    systemctl --no-pager status hysteria-server | head -15
    echo ""
    journalctl -u hysteria-server -n 20 --no-pager
    exit 1
fi

echo ""
echo "======================================================"
echo "  Порт:          $PORT/udp"
echo "  SNI:           $SNI"
echo "  Auth:          http → $AUTH_URL"
echo "  Obfs password: $OBFS_PASSWORD"
echo "======================================================"
echo ""
echo "СКОПИРУЙ obfs password В secrets.json на Амстердаме:"
echo ""
echo '  "hysteria": {'
echo '      "<server_key>": { "obfs_password": "'"$OBFS_PASSWORD"'" }'
echo '  }'
echo ""
echo "где <server_key> = amsterdam / usa / finland / france"
