#!/usr/bin/env bash
# Ежедневный бэкап данных BYPASS VPN.
# Что бэкапится:
#   - JSON-файлы из /opt/vpn-site/ (users, subscriptions, secrets, промокоды и т.д.)
#   - Xray-конфиги со всех 4 серверов (содержат UUID-ы клиентов)
# Куда:
#   - Локально: /opt/vpn-site/backups/
#   - Удалённо: root@31.56.229.94:/root/bypass-backups/ (USA сервер)
# Хранение: 30 дней, старее — удаляются автоматически.
#
# Запуск: /opt/vpn-site/backup.sh
# Cron:   0 4 * * * /opt/vpn-site/backup.sh >> /var/log/vpn-site-backup.log 2>&1

set -u

DATE="$(date +%Y-%m-%d_%H-%M)"
APP_DIR="/opt/vpn-site"
LOCAL_BACKUP_DIR="$APP_DIR/backups"
REMOTE_HOST="root@31.56.229.94"
REMOTE_DIR="/root/bypass-backups"
RETENTION_DAYS=30
WORK_DIR="$(mktemp -d)"
ARCHIVE_NAME="bypass-backup-${DATE}.tar.gz"
ARCHIVE_PATH="$LOCAL_BACKUP_DIR/$ARCHIVE_NAME"

log() { echo "[$(date -Iseconds)] $*"; }

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

mkdir -p "$LOCAL_BACKUP_DIR"

log "=== BYPASS backup START ==="

# 1. Копируем локальные JSON
STAGING="$WORK_DIR/bypass-${DATE}"
mkdir -p "$STAGING/site-data" "$STAGING/xray"

for f in users.json verification_codes.json sessions.json secrets.json \
         traffic_snapshot.json subscriptions.json payment_requests.json \
         promo_codes.json; do
    if [ -f "$APP_DIR/$f" ]; then
        cp -p "$APP_DIR/$f" "$STAGING/site-data/"
    fi
done
log "local JSONs copied: $(ls "$STAGING/site-data" | wc -l) файлов"

# 2. Xray-конфиги по SSH. Локальный Xray (Амстердам) — напрямую.
if [ -f /usr/local/etc/xray/config.json ]; then
    cp -p /usr/local/etc/xray/config.json "$STAGING/xray/amsterdam.json"
fi

for entry in "usa:31.56.229.94" "finland:109.248.161.20" "france:45.38.23.141"; do
    name="${entry%%:*}"
    ip="${entry##*:}"
    if timeout 10 ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
           "root@${ip}" 'cat /usr/local/etc/xray/config.json' \
           > "$STAGING/xray/${name}.json" 2>/dev/null; then
        log "xray config fetched: $name"
    else
        log "WARN: не удалось получить xray config с $name ($ip)"
        rm -f "$STAGING/xray/${name}.json"
    fi
done

# 3. Архив
tar -czf "$ARCHIVE_PATH" -C "$WORK_DIR" "bypass-${DATE}"
SIZE=$(du -h "$ARCHIVE_PATH" | cut -f1)
chmod 600 "$ARCHIVE_PATH"
log "архив создан: $ARCHIVE_PATH ($SIZE)"

# 4. Пуш на USA
if timeout 30 scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
       "$ARCHIVE_PATH" "${REMOTE_HOST}:${REMOTE_DIR}/" 2>&1; then
    ssh -o BatchMode=yes "${REMOTE_HOST}" "chmod 600 ${REMOTE_DIR}/${ARCHIVE_NAME}" 2>/dev/null || true
    log "удалённая копия OK: ${REMOTE_HOST}:${REMOTE_DIR}/${ARCHIVE_NAME}"
else
    log "WARN: не удалось скопировать на ${REMOTE_HOST} (проверь mkdir -p ${REMOTE_DIR} на USA)"
fi

# 5. Ротация — удаляем локальные старше RETENTION_DAYS
DELETED=$(find "$LOCAL_BACKUP_DIR" -name 'bypass-backup-*.tar.gz' -type f -mtime +${RETENTION_DAYS} -print -delete | wc -l)
log "ротация локально: удалено $DELETED старых архивов (>${RETENTION_DAYS} дней)"

# 6. Ротация удалённо
ssh -o BatchMode=yes "${REMOTE_HOST}" \
    "find ${REMOTE_DIR} -name 'bypass-backup-*.tar.gz' -type f -mtime +${RETENTION_DAYS} -delete" 2>/dev/null \
    && log "ротация на ${REMOTE_HOST}: OK" \
    || log "WARN: не смог проротировать на ${REMOTE_HOST}"

log "=== BYPASS backup DONE ==="
