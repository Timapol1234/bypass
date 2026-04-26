#!/usr/bin/env bash
# Поднимает nginx + Let's Encrypt сертификат для api.wirex.online на бэкенде.
# Проксирует https://api.wirex.online → 127.0.0.1:8080 (Flask).
# Запускать один раз на сервере 109.248.162.180 как root.
#
# Предусловие: A-запись api.wirex.online → 109.248.162.180 уже распространилась.
# Проверь: dig +short api.wirex.online должно вернуть 109.248.162.180.

set -e

DOMAIN="api.wirex.online"
EMAIL="bigamkavinsjcmibs@outlook.com"   # для Let's Encrypt уведомлений

echo "=== 1. Ставлю nginx + certbot ==="
apt update
apt install -y nginx certbot python3-certbot-nginx ufw

echo "=== 2. Открываю 80/443 в ufw (если ufw активен) ==="
if ufw status | grep -q "Status: active"; then
    ufw allow 80/tcp
    ufw allow 443/tcp
fi

echo "=== 3. Базовый http-конфиг для certbot challenge ==="
cat > /etc/nginx/sites-available/api-wirex.conf <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    # certbot вебрут (создастся при выпуске cert'а)
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # пока http — отдадим redirect; certbot позже перепишет.
    location / {
        return 301 https://\$host\$request_uri;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/api-wirex.conf /etc/nginx/sites-enabled/api-wirex.conf
# дефолт убрать — он висит на :80 и ловит наш Host
rm -f /etc/nginx/sites-enabled/default

mkdir -p /var/www/html
nginx -t
systemctl reload nginx

echo "=== 4. Выпуск Let's Encrypt cert'а ==="
certbot --nginx -d "${DOMAIN}" \
    --non-interactive --agree-tos -m "${EMAIL}" --redirect

echo "=== 5. Финальный конфиг с reverse-proxy на Flask ==="
# certbot уже добавил блок listen 443 ssl. Перезапишем целиком, чтобы добавить proxy_pass.
cat > /etc/nginx/sites-available/api-wirex.conf <<NGINX
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate     /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Большие подписки/QR — поднимем лимит до 2 МБ
    client_max_body_size 2m;

    # API + всё остальное проксируется в Flask
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Connection        "";
        proxy_read_timeout 300s;
    }
}
NGINX

nginx -t
systemctl reload nginx

echo "=== 6. Cron auto-renew (certbot ставит сам, проверяем) ==="
systemctl list-timers | grep -i certbot || echo "  (certbot.timer должен быть активен — проверь systemctl status certbot.timer)"

echo ""
echo "=========================================="
echo "  ГОТОВО. Проверь:"
echo "    curl -I https://${DOMAIN}/api/health"
echo "    → HTTP 200 + правильный TLS"
echo ""
echo "  В Flask 8080 уже не надо держать наружу — закрой порт:"
echo "    ufw deny 8080/tcp"
echo "=========================================="
