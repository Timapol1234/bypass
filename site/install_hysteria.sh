#!/usr/bin/env bash
# Установщик Hysteria 2 для BYPASS VPN.
# Запуск: bash install_hysteria.sh
# Должен работать на каждом из 4 серверов (Амстердам/USA/Финляндия/Франция).
# Идемпотентный: повторный запуск не ломает уже настроенный сервер.
#
# Что делает:
#   1. Ставит бинарник hysteria (официальный установщик get.hy2.sh)
#   2. Генерирует самоподписанный сертификат (если нет)
#   3. Генерирует obfs password (если нет) — сохраняет в /etc/hysteria/.obfs_password
#   4. Сохраняет существующих userpass-юзеров, если конфиг уже был
#   5. Перезаписывает /etc/hysteria/config.yaml в каноническом формате BYPASS
#   6. Создаёт systemd unit hysteria-server.service
#   7. Открывает UDP 8443 в файрволе
#   8. Запускает / перезагружает сервис
#
# ВАЖНО: Если сервер уже использовал auth.type=password (общий пароль),
# он заменяется на auth.type=userpass (пустой список). Старые клиенты отвалятся.

set -euo pipefail

PORT=8443
CONFIG_DIR=/etc/hysteria
CERT=$CONFIG_DIR/cert.crt
KEY=$CONFIG_DIR/private.key
CONFIG=$CONFIG_DIR/config.yaml
OBFS_FILE=$CONFIG_DIR/.obfs_password
SNI="www.microsoft.com"

echo "=== BYPASS Hysteria 2 installer ==="

# 1. Бинарник
if ! command -v hysteria >/dev/null 2>&1; then
    echo "[1/8] Устанавливаю hysteria..."
    bash <(curl -fsSL https://get.hy2.sh/)
else
    echo "[1/8] hysteria уже установлен: $(hysteria version 2>&1 | head -1 || true)"
fi

mkdir -p $CONFIG_DIR
chmod 700 $CONFIG_DIR

# 2. Сертификат
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[2/8] Генерирую самоподписанный TLS-сертификат..."
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$KEY" -out "$CERT" -subj "/CN=$SNI" -days 3650 >/dev/null 2>&1
    chmod 600 "$KEY"
else
    echo "[2/8] Сертификат уже существует"
fi

# 3. Obfs password
if [ ! -f "$OBFS_FILE" ]; then
    echo "[3/8] Генерирую obfs password..."
    OBFS_PASSWORD=$(openssl rand -base64 32 | tr -d '=/+\n' | head -c 32)
    echo -n "$OBFS_PASSWORD" > "$OBFS_FILE"
    chmod 600 "$OBFS_FILE"
else
    OBFS_PASSWORD=$(cat "$OBFS_FILE")
    echo "[3/8] Obfs password загружен из $OBFS_FILE"
fi

# 4. Сохраняем существующих userpass-юзеров (если конфиг уже в каноническом формате BYPASS)
EXISTING_USERS=""
# Маркер — это строка, равная ровно "# BYPASS-USERS-BEGIN" (с любым отступом).
# Подстрочное сравнение ломается на шапке-комментарии, где эти слова тоже встречаются.
if [ -f "$CONFIG" ] && grep -qE '^[[:space:]]*# BYPASS-USERS-BEGIN[[:space:]]*$' "$CONFIG"; then
    echo "[4/8] Извлекаю существующих BYPASS-юзеров..."
    # Извлекаем блок между маркерами и фильтруем мусор, который мог туда попасть
    # из-за старого бага (__seed__/password обфускации).
    EXISTING_USERS=$(awk '
        /^[[:space:]]*# BYPASS-USERS-BEGIN[[:space:]]*$/ {flag=1; next}
        /^[[:space:]]*# BYPASS-USERS-END[[:space:]]*$/   {flag=0}
        flag
    ' "$CONFIG" | grep -vE '^[[:space:]]+(__seed__|password)[[:space:]]*:' || true)
    USER_COUNT=$(echo "$EXISTING_USERS" | grep -c ":" || true)
    echo "    Найдено юзеров: $USER_COUNT"
else
    echo "[4/8] Старый конфиг не в формате BYPASS — начинаем с пустого списка юзеров"
fi

# 5. Пишем канонический конфиг
echo "[5/8] Записываю $CONFIG..."
{
cat <<EOF
# BYPASS Hysteria 2 config — управляется /opt/vpn-site/app.py
# НЕ РЕДАКТИРОВАТЬ ВРУЧНУЮ блок между BYPASS-USERS-BEGIN/END.

listen: :$PORT

tls:
  cert: $CERT
  key: $KEY

obfs:
  type: salamander
  salamander:
    password: "$OBFS_PASSWORD"

auth:
  type: userpass
  userpass:
    # Seed-запись: Hysteria требует хотя бы одного юзера, иначе не стартует.
    # Пароль случайный, никем не используется — только чтобы конфиг был валиден
    # когда список BYPASS-юзеров пустой.
    __seed__: $(openssl rand -hex 24)
    # BYPASS-USERS-BEGIN
EOF
if [ -n "$EXISTING_USERS" ]; then
    echo "$EXISTING_USERS"
fi
cat <<EOF
    # BYPASS-USERS-END

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
} > "$CONFIG"
chmod 600 "$CONFIG"

# 6. systemd unit
echo "[6/8] Настраиваю systemd..."
cat > /etc/systemd/system/hysteria-server.service <<'UNIT'
[Unit]
Description=Hysteria 2 Server (BYPASS)
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

# 7. Firewall
echo "[7/8] Открываю UDP $PORT..."
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow $PORT/udp >/dev/null 2>&1 || true
    echo "    ufw: $PORT/udp разрешён"
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p udp --dport $PORT -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p udp --dport $PORT -j ACCEPT
    echo "    iptables: $PORT/udp разрешён"
fi

# 8. Старт / перезагрузка
if systemctl is-active --quiet hysteria-server; then
    systemctl reload hysteria-server 2>/dev/null || systemctl restart hysteria-server
    echo "[8/8] hysteria-server перезагружен"
else
    systemctl start hysteria-server
    echo "[8/8] hysteria-server запущен"
fi

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
