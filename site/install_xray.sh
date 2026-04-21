#!/usr/bin/env bash
# Установщик Xray (VLESS + Reality) для BYPASS VPN.
# Запускается на свежем сервере при добавлении через админку.
# Идемпотентный: при повторном запуске не перезаписывает уже сгенерированные ключи.
#
# В stdout в конце печатает JSON-блок { "pbk": "...", "sid": "...", "sni": "...", "port": 443 }
# — Flask его парсит и сохраняет в servers.json.

set -euo pipefail

PORT=443
XRAY_CONFIG=/usr/local/etc/xray/config.json
SNI="www.microsoft.com"
DEST="$SNI:443"
SID_DEFAULT="abcd1234"

echo "=== BYPASS Xray installer ===" >&2

# 0. Зависимости apt (на свежем сервере кэш apt может быть пустой,
#    и официальный Xray-install падает на `apt install unzip`).
if command -v apt-get >/dev/null 2>&1; then
    echo "[0/5] apt-get update + базовые зависимости (unzip/curl/ca-certificates)..." >&2
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y >&2 || { echo "apt-get update упал — проверь DNS/сеть на сервере" >&2; exit 1; }
    apt-get install -y --no-install-recommends unzip curl ca-certificates >&2 || {
        echo "apt-get install unzip/curl упал — смотри вывод выше" >&2; exit 1;
    }
fi

# 1. Бинарник
if ! command -v xray >/dev/null 2>&1; then
    echo "[1/5] Устанавливаю xray..." >&2
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install >&2
else
    echo "[1/5] xray уже установлен: $(xray version 2>&1 | head -1)" >&2
fi

mkdir -p /usr/local/etc/xray

# 2. Reality keypair (если ещё нет — генерим, иначе читаем из /etc/xray/.reality_keys)
KEYS_FILE=/etc/xray/.reality_keys
mkdir -p /etc/xray
chmod 700 /etc/xray
PRIV=""
PBK=""
if [ -f "$KEYS_FILE" ]; then
    echo "[2/5] Reality keypair уже есть, читаю из $KEYS_FILE" >&2
    PRIV=$(grep '^private:' "$KEYS_FILE" | awk '{print $2}')
    PBK=$(grep '^public:' "$KEYS_FILE" | awk '{print $2}')
fi
if [ -z "$PRIV" ] || [ -z "$PBK" ]; then
    echo "[2/5] Генерирую Reality keypair..." >&2
    rm -f "$KEYS_FILE"
    OUT=$(xray x25519)
    # Xray <=24 выводит "Private key: <v>" / "Public key: <v>".
    # Xray 26+ выводит "PrivateKey: <v>" / "Password (PublicKey): <v>".
    # Берём всё после ": " на строке, содержащей "private key" / "public key"
    # без учёта регистра и пробела между словами.
    PRIV=$(echo "$OUT" | awk -F': *' 'tolower($0) ~ /private *key/ {print $2; exit}')
    PBK=$(echo "$OUT"  | awk -F': *' 'tolower($0) ~ /public *key/  {print $2; exit}')
    if [ -z "$PRIV" ] || [ -z "$PBK" ]; then
        echo "xray x25519 вернул пустые ключи — смотри вывод:" >&2
        echo "$OUT" >&2
        exit 1
    fi
    echo "private: $PRIV"  > "$KEYS_FILE"
    echo "public:  $PBK"  >> "$KEYS_FILE"
    chmod 600 "$KEYS_FILE"
fi

SID="$SID_DEFAULT"

# 3. Конфиг
if [ -f "$XRAY_CONFIG" ] && python3 -c "import json; json.load(open('$XRAY_CONFIG'))" 2>/dev/null; then
    echo "[3/5] Конфиг уже есть — оставляю как есть, только подменю приватный ключ/порт/dest если надо" >&2
    python3 - "$XRAY_CONFIG" "$PRIV" "$PBK" "$SID" "$DEST" "$PORT" <<'PY' >&2
import json, sys
path, priv, pbk, sid, dest, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], int(sys.argv[6])
with open(path) as f: c = json.load(f)
ib = next((i for i in c.get("inbounds", []) if i.get("protocol") == "vless"), None)
if ib:
    ib["port"] = port
    rs = ib.setdefault("streamSettings", {}).setdefault("realitySettings", {})
    rs["privateKey"] = priv
    rs["shortIds"] = [sid]
    rs["dest"] = dest
    rs["serverNames"] = [dest.split(":")[0]]
with open(path, "w") as f: json.dump(c, f, indent=2)
PY
else
    echo "[3/5] Пишу новый конфиг $XRAY_CONFIG..." >&2
    cat > "$XRAY_CONFIG" <<EOF
{
  "log": { "loglevel": "warning" },
  "api": {
    "tag": "api",
    "services": ["HandlerService", "LoggerService", "StatsService"]
  },
  "stats": {},
  "policy": {
    "levels": { "0": { "statsUserUplink": true, "statsUserDownlink": true } },
    "system": { "statsInboundUplink": true, "statsInboundDownlink": true }
  },
  "inbounds": [
    {
      "tag": "api",
      "listen": "127.0.0.1",
      "port": 10085,
      "protocol": "dokodemo-door",
      "settings": { "address": "127.0.0.1" }
    },
    {
      "port": $PORT,
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "$DEST",
          "xver": 0,
          "serverNames": ["$SNI"],
          "privateKey": "$PRIV",
          "shortIds": ["$SID"]
        }
      },
      "sniffing": { "enabled": true, "destOverride": ["http", "tls"] }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ],
  "routing": {
    "rules": [
      { "type": "field", "inboundTag": ["api"], "outboundTag": "api" }
    ]
  }
}
EOF
fi

# 4. Firewall
echo "[4/5] Открываю TCP $PORT..." >&2
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    ufw allow $PORT/tcp >/dev/null 2>&1 || true
fi
if command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport $PORT -j ACCEPT 2>/dev/null || \
        iptables -I INPUT -p tcp --dport $PORT -j ACCEPT
fi

# 5. systemd enable + restart
echo "[5/5] Запускаю xray..." >&2
systemctl enable xray >/dev/null 2>&1 || true
systemctl restart xray
sleep 2
if ! systemctl is-active --quiet xray; then
    echo "xray не стартанул" >&2
    journalctl -u xray -n 20 --no-pager >&2
    exit 1
fi

# Финальный JSON в stdout — его парсит Flask
cat <<EOF
{"pbk": "$PBK", "sid": "$SID", "sni": "$SNI", "port": $PORT}
EOF
