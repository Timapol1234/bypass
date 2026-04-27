from flask import Flask, jsonify, request, send_from_directory, Response
import uuid
import json
import subprocess
import qrcode
import base64
import io
import os
import smtplib
import secrets
import re
import threading
import time
import hmac
from functools import wraps
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError

import sys
import traceback
import hysteria_config

app = Flask(__name__, static_folder='static')

XRAY_CONFIG = "/usr/local/etc/xray/config.json"
SUB_DIR = "/var/www/sub"
USERS_DB = "/opt/vpn-site/users.json"
VERIFICATION_CODES_DB = "/opt/vpn-site/verification_codes.json"
SESSIONS_DB = "/opt/vpn-site/sessions.json"
SECRETS_FILE = "/opt/vpn-site/secrets.json"
TRAFFIC_SNAPSHOT_FILE = "/opt/vpn-site/traffic_snapshot.json"
SUBSCRIPTIONS_DB = "/opt/vpn-site/subscriptions.json"
PAYMENT_REQUESTS_DB = "/opt/vpn-site/payment_requests.json"
PROMO_CODES_DB = "/opt/vpn-site/promo_codes.json"
LAVA_PAYMENTS_DB = "/opt/vpn-site/lava_payments.json"

# lava.top API endpoints
LAVA_API_BASE = "https://gate.lava.top"
LAVA_INVOICE_CREATE = "/api/v3/invoice"
LAVA_INVOICE_GET = "/api/v1/invoices/{id}"

# Тарифы: дни → цена в рублях
TARIFFS = {
    "1mo":  {"days": 30,  "price": 99,  "label": "1 месяц"},
    "3mo":  {"days": 90,  "price": 269, "label": "3 месяца"},
    "6mo":  {"days": 180, "price": 499, "label": "6 месяцев"},
    "12mo": {"days": 365, "price": 899, "label": "12 месяцев"},
}

# Хост, с которого раздаются файлы подписок (файлы лежат только на NL-сервере)
SUB_HOST = "api.wirex.online:8443"

# Время жизни сессии
SESSION_TTL_DAYS = 30
# Минимальный интервал между запросами кода на один email (секунды)
OTP_RESEND_COOLDOWN = 60
# Юзер считается online, если трафик рос в последние N секунд
ONLINE_THRESHOLD_SECONDS = 120

# Название бренда в имени ключа (показывается в VPN-клиенте как Remarks).
# При переименовании сервиса достаточно поменять здесь.
BRAND_NAME = "WIREX"


def key_tag(server_key_or_obj, protocol: str) -> str:
    """Имя ключа в клиенте: `<BRAND>-<Сервер>-<Protocol>`.
    `protocol` — человекочитаемое: "Reality" / "Hysteria"."""
    s = server_key_or_obj if isinstance(server_key_or_obj, dict) \
        else SERVERS.get(server_key_or_obj, {})
    name = (s.get("name") or "").strip() or "server"
    return f"{BRAND_NAME}-{name}-{protocol}"

# Домены одноразовых почт — блокируем регистрацию, чтобы не засоряли серверы.
# Список основных публичных temp-mail сервисов; MX-домены тоже включены.
DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "guerrillamail.net", "guerrillamail.org",
    "guerrillamail.biz", "guerrillamail.de", "sharklasers.com", "grr.la",
    "10minutemail.com", "10minutemail.net", "20minutemail.com", "30minutemail.com",
    "tempmail.com", "temp-mail.org", "temp-mail.ru", "tempmail.io", "tempmail.net",
    "tempmailaddress.com", "tempmail.email", "tempmail.dev", "tempmailo.com",
    "trashmail.com", "trashmail.net", "trashmail.de", "trashmail.io",
    "getnada.com", "nada.email", "getairmail.com", "dispostable.com",
    "yopmail.com", "yopmail.fr", "yopmail.net", "yopmail.org",
    "maildrop.cc", "mintemail.com", "mohmal.com", "moakt.com", "mytemp.email",
    "throwawaymail.com", "throwaway.email", "fakeinbox.com", "fakemailgenerator.com",
    "mailnesia.com", "mailcatch.com", "mailbox.org", "mail.tm", "vuxvux.ru",
    "emailondeck.com", "email-fake.com", "fake-email.com", "dropmail.me",
    "inboxbear.com", "inboxkitten.com", "harakirimail.com", "spambox.us",
    "spam4.me", "spambog.com", "spambog.ru", "spambog.de",
    "mailsac.com", "mail7.io", "linshiyouxiang.net", "tmail.ws",
    "mvrht.net", "armyspy.com", "cuvox.de", "einrot.com", "fleckens.hu",
    "gustr.com", "jourrapide.com", "rhyta.com", "superrito.com", "teleworm.us",
    "dayrep.com", "byom.de", "spambog.net", "luxusmail.org",
    "1secmail.com", "1secmail.net", "1secmail.org", "esiix.com", "wwjmp.com",
    "getairmail.com", "my10minutemail.com", "minutemail.com", "burnermail.io",
    "anonaddy.me", "relay.firefox.com", "duck.com",
}


def is_disposable_email(email: str) -> bool:
    try:
        domain = email.rsplit("@", 1)[1].strip().lower()
    except IndexError:
        return False
    return domain in DISPOSABLE_EMAIL_DOMAINS


def load_secrets():
    """Загружает секреты из /opt/vpn-site/secrets.json.
    На dev-машине файла нет — читаем из переменных окружения."""
    if os.path.exists(SECRETS_FILE):
        with open(SECRETS_FILE, "r") as f:
            return json.load(f)
    return {
        "smtp_username": os.environ.get("SMTP_USERNAME", ""),
        "smtp_password": os.environ.get("SMTP_PASSWORD", ""),
        "admin_password": os.environ.get("ADMIN_PASSWORD", ""),
    }


_secrets = load_secrets()

SMTP_CONFIG = {
    "server": "smtp.mail.ru",
    "port": 587,
    "username": _secrets.get("smtp_username", ""),
    "password": _secrets.get("smtp_password", "")
}

ADMIN_EMAIL = _secrets.get("admin_email", "")

# lava.top: API-ключ берётся из кабинета (Profile → Integration → Public API).
# `lava_offers` маппит наш id тарифа → uuid товара в кабинете lava
# (товар на 99₽ создаётся отдельно в кабинете и должен совпадать с PRICING).
# `lava_webhook_secret` — случайный токен в URL вебхука, защита от подделки.
# `lava_success_url` — куда lava редиректит юзера после оплаты.
LAVA_API_KEY = _secrets.get("lava_api_key", "")
LAVA_WEBHOOK_SECRET = _secrets.get("lava_webhook_secret", "")
LAVA_OFFERS = _secrets.get("lava_offers", {})  # {tariff_id: offer_uuid}
LAVA_SUCCESS_URL = _secrets.get("lava_success_url", "https://wirex.online/?payment=success")

ALERTS_STATE_FILE = "/opt/vpn-site/alerts_state.json"
ALERTS_LOG_FILE = "/opt/vpn-site/alerts_log.json"
ALERTS_COOLDOWN_SEC = 1800  # 30 мин между повторами того же набора проблем
ALERTS_CHECK_INTERVAL_SEC = 300  # 5 мин между проверками
ALERTS_LOG_MAX = 200
ALERT_LOAD_RATIO = 2.0   # load_1m / cpu_count > 2.0 → перегруз
ALERT_MEM_PCT = 90       # mem_used / mem_total > 90% → тревога

# Seed-конфиг серверов. Рантайм-правки (add_server/remove_server, backup_for, max_users,
# disabled) лежат в SERVERS_FILE и накладываются поверх при старте — см. load_servers_store().
_SEED_SERVERS = {
    "amsterdam": {
        "name": "Амстердам",
        "country": "NL",
        "flag": "🇳🇱",
        "ip": "109.248.162.180",
        "port": 443,
        "security": "reality",
        "sni": "www.microsoft.com",
        "pbk": "YfQM06_AHria4kt_wURFu1CfWtoytNDUgakGp5NelhY",
        "sid": "abcd1234",
        "fp": "chrome",
        "xray_config": "/usr/local/etc/xray/config.json",
        "remote": False,
        "bandwidth_mbps": 50,
    },
    "usa": {
        "name": "США",
        "country": "US",
        "flag": "🇺🇸",
        "ip": "31.56.229.94",
        "port": 443,
        "security": "reality",
        "sni": "www.microsoft.com",
        "pbk": "iamZFPJ6Husi6hWB3zig8qEZ-0jAIF2_RumsQst58lM",
        "sid": "abcd1234",
        "fp": "chrome",
        "xray_config": "/usr/local/etc/xray/config.json",
        "remote": True,
        "ssh": "root@31.56.229.94",
        "bandwidth_mbps": 50,
    },
    "finland": {
        "name": "Финляндия",
        "country": "FI",
        "flag": "🇫🇮",
        "ip": "109.248.161.20",
        "port": 443,
        "security": "reality",
        "sni": "www.microsoft.com",
        "pbk": "_wlrPN0rdbwpclS3HS3-Fyq6d4eJ_i5pMG7zLhNf2WA",
        "sid": "abcd1234",
        "fp": "chrome",
        "xray_config": "/usr/local/etc/xray/config.json",
        "remote": True,
        "ssh": "root@109.248.161.20",
        "bandwidth_mbps": 50,
    },
    "france": {
        "name": "Франция",
        "country": "FR",
        "flag": "🇫🇷",
        "ip": "45.38.23.141",
        "port": 443,
        "security": "reality",
        "sni": "www.microsoft.com",
        "pbk": "sgaUpQqdqM8m5JGzEA9z3r-cC4qVaSXC9tCfu9ZILiA",
        "sid": "abcd1234",
        "fp": "chrome",
        "xray_config": "/usr/local/etc/xray/config.json",
        "remote": True,
        "ssh": "root@45.38.23.141",
        "bandwidth_mbps": 50,
    }
}

SERVERS_FILE = "/opt/vpn-site/servers.json"
SERVER_STATUS_FILE = "/opt/vpn-site/server_status.json"
_servers_lock = threading.Lock()


def load_servers_store():
    """Читает /opt/vpn-site/servers.json. Формат:
      {"servers": {<key>: {<field>: <value>, ...}, ...},
       "deleted": [<key>, ...]}
    Если файла нет — {}. Мы только читаем, не мержим с _SEED — это делает build_servers().
    """
    if not os.path.exists(SERVERS_FILE):
        return {"servers": {}, "deleted": []}
    try:
        with open(SERVERS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            data.setdefault("servers", {})
            data.setdefault("deleted", [])
            return data
    except Exception as e:
        print(f"[servers] load failed: {e}")
        return {"servers": {}, "deleted": []}


def save_servers_store(store):
    os.makedirs(os.path.dirname(SERVERS_FILE), exist_ok=True)
    with open(SERVERS_FILE, "w", encoding="utf-8") as f:
        json.dump(store, f, indent=2, ensure_ascii=False)


def build_servers():
    """Собирает итоговый SERVERS-dict: seed + overrides из servers.json,
    минус те ключи, что перечислены в store['deleted']."""
    store = load_servers_store()
    overrides = store.get("servers", {}) or {}
    deleted = set(store.get("deleted", []) or [])
    result = {}
    for key, cfg in _SEED_SERVERS.items():
        if key in deleted:
            continue
        merged = dict(cfg)
        if key in overrides:
            merged.update(overrides[key])
        result[key] = merged
    # новые сервера, добавленные через админку, живут только в overrides
    for key, cfg in overrides.items():
        if key in _SEED_SERVERS or key in deleted:
            continue
        result[key] = dict(cfg)
    return result


SERVERS = build_servers()


def reload_servers():
    """Пересобирает SERVERS из seed+servers.json. Вызывается после admin-изменений."""
    global SERVERS
    with _servers_lock:
        SERVERS = build_servers()
    return SERVERS


DEFAULT_MAX_USERS = 30
# Расчёт ёмкости: bandwidth_mbps ÷ пиковый трафик на юзера ÷ доля одновременно активных.
# Для 50 Мбит/с: 50 / 5 / 0.3 ≈ 33 юзера; для 1 Гбит/с: 1000 / 5 / 0.3 ≈ 666.
CAPACITY_PEAK_MBPS = 5
CAPACITY_CONCURRENCY = 0.3


def compute_max_users(bandwidth_mbps):
    if not bandwidth_mbps or bandwidth_mbps <= 0:
        return DEFAULT_MAX_USERS
    return max(1, int(bandwidth_mbps / CAPACITY_PEAK_MBPS / CAPACITY_CONCURRENCY))


def capacity_for_server(s):
    """max_users сервера: override из конфига, иначе формула от bandwidth_mbps."""
    override = s.get("max_users")
    if isinstance(override, (int, float)) and override > 0:
        return int(override)
    return compute_max_users(s.get("bandwidth_mbps"))


# ---- Health-check + failover (Phase 3c) ----
import socket as _socket

HEALTH_CHECK_INTERVAL_SEC = 120   # 2 минуты между проверками
HEALTH_FAIL_THRESHOLD = 3         # 3 подряд фэйла = сервер упал (6 мин)
HEALTH_OK_THRESHOLD = 2           # 2 подряд ok = восстановился (4 мин)
HEALTH_TCP_TIMEOUT = 5


def probe_server_alive(server_cfg):
    """TCP-коннект на tcp/port сервера. True/False. Хватит для Xray-инбаунда;
    Hysteria слушает UDP — он отдельно валидируется чеком systemctl-метрик,
    но для MVP failover достаточно TCP 443, т.к. оба сервиса обычно падают вместе
    (это bare-metal box, если QUIC упал — Xray тоже скорее всего не ответит)."""
    ip = server_cfg.get("ip")
    port = int(server_cfg.get("port") or 443)
    if not ip:
        return False
    try:
        with _socket.create_connection((ip, port), timeout=HEALTH_TCP_TIMEOUT):
            return True
    except Exception:
        return False


def _find_backup_for(primary_key):
    """Ищем сервер, у которого backup_for == primary_key. Возвращаем ключ или None."""
    for k, cfg in SERVERS.items():
        if k == primary_key: continue
        if cfg.get("disabled"): continue
        if cfg.get("backup_for") == primary_key:
            return k
    return None


def _load_server_status():
    return _load_json(SERVER_STATUS_FILE, {})


def _save_server_status(status):
    _save_json(SERVER_STATUS_FILE, status)


def _build_vless_for_server(user_uuid, server_key, username):
    """Обёртка — чтобы можно было построить VLESS URL для произвольного сервера.
    `username` больше не используется в имени ключа (новый формат:
    BRAND-Server-Reality), но оставлен в сигнатуре ради совместимости с call-site'ами."""
    return build_vless_url(user_uuid, server_key)


def _write_subscription_raw(user, target_server_key, hy_only=False):
    """Пишет файл подписки user'а, но с URL'ами, указывающими на target_server_key.
    Если hy_only=True — только hysteria2:// (для failover; VLESS UUID не
    зарегистрирован на backup xray, поэтому VLESS туда слать нельзя)."""
    user_uuid = user["uuid"]
    username = user["username"]
    hy_pw = user.get("hysteria_password")
    urls = []
    if not hy_only:
        urls.append(_build_vless_for_server(user_uuid, target_server_key, username))
    if hy_pw:
        hy = build_hysteria_url(target_server_key, username, hy_pw)
        if hy: urls.append(hy)
    if not urls:
        return False
    encoded = base64.b64encode("\n".join(urls).encode()).decode()
    os.makedirs(SUB_DIR, exist_ok=True)
    filepath = os.path.join(SUB_DIR, sub_slug(username, user_uuid))
    with open(filepath, "w") as f:
        f.write(encoded)
    return True


def _failover_activate(primary_key, backup_key):
    """Для всех юзеров на primary_key переписываем /var/www/sub/<slug> так,
    чтобы subscription указывала на backup_key (только hysteria2://, т.к.
    VLESS UUID не зарегистрирован на backup xray)."""
    users = load_users()
    affected = 0
    for u in users:
        if u.get("server") != primary_key: continue
        try:
            if _write_subscription_raw(u, backup_key, hy_only=True):
                affected += 1
        except Exception as e:
            print(f"[failover] rewrite sub failed for {u.get('username')}: {e}")
    print(f"[failover] {primary_key} → {backup_key}: переписано {affected} подписок")
    return affected


def _failover_deactivate(primary_key):
    """Возвращаем подписки юзеров с primary_key на нормальный вид (VLESS+Hy2 на primary)."""
    users = load_users()
    restored = 0
    for u in users:
        if u.get("server") != primary_key: continue
        try:
            update_subscription(u["uuid"], primary_key, u["username"], u.get("hysteria_password"))
            restored += 1
        except Exception as e:
            print(f"[failover] restore sub failed for {u.get('username')}: {e}")
    print(f"[failover] {primary_key} восстановлен: {restored} подписок вернули на primary")
    return restored


def _health_tick():
    """Один прогон: опрашивает все не-disabled сервера, обновляет счётчики,
    переключает failover при пересечении порогов."""
    status = _load_server_status()
    now = int(time.time())
    current_servers = dict(SERVERS)  # snapshot
    for key, cfg in current_servers.items():
        if cfg.get("disabled"): continue
        st = status.setdefault(key, {
            "ok_count": 0, "fail_count": 0, "failed_over": False,
            "failover_to": None, "last_check_ts": 0, "last_ok_ts": 0,
        })
        alive = probe_server_alive(cfg)
        st["last_check_ts"] = now
        if alive:
            st["ok_count"] += 1
            st["fail_count"] = 0
            st["last_ok_ts"] = now
            # Восстановление
            if st["failed_over"] and st["ok_count"] >= HEALTH_OK_THRESHOLD:
                _failover_deactivate(key)
                st["failed_over"] = False
                st["failover_to"] = None
                _admin_notify_failover(key, recovered=True)
        else:
            st["fail_count"] += 1
            st["ok_count"] = 0
            # Активация failover
            if not st["failed_over"] and st["fail_count"] >= HEALTH_FAIL_THRESHOLD:
                backup_key = _find_backup_for(key)
                if backup_key and probe_server_alive(SERVERS[backup_key]):
                    _failover_activate(key, backup_key)
                    st["failed_over"] = True
                    st["failover_to"] = backup_key
                    _admin_notify_failover(key, backup=backup_key)
                else:
                    # Резерва нет или он тоже лежит — только уведомляем админа
                    _admin_notify_failover(key, backup=None)
    _save_server_status(status)


def _admin_notify_failover(primary_key, backup=None, recovered=False):
    """Шлёт админу email. Дедуп — по маркеру в ALERTS_STATE_FILE, чтобы не спамить."""
    state = _load_json(ALERTS_STATE_FILE, {})
    marker_key = f"failover:{primary_key}:{'recovered' if recovered else (backup or 'no-backup')}"
    last = state.get(marker_key, 0)
    if int(time.time()) - last < ALERTS_COOLDOWN_SEC:
        return
    state[marker_key] = int(time.time())
    _save_json(ALERTS_STATE_FILE, state)

    if recovered:
        subject = f"[WIREX] Сервер {primary_key} восстановлен"
        body = f"<p>Сервер <b>{primary_key}</b> снова отвечает. Подписки юзеров возвращены на primary.</p>"
    elif backup:
        subject = f"[WIREX] Failover: {primary_key} → {backup}"
        body = (f"<p>Сервер <b>{primary_key}</b> не отвечает ≥{HEALTH_FAIL_THRESHOLD * HEALTH_CHECK_INTERVAL_SEC // 60} мин.</p>"
                f"<p>Подписки юзеров переписаны на <b>{backup}</b> (только Hysteria 2, "
                f"VLESS UUID не зарегистрированы на резерве).</p>")
    else:
        subject = f"[WIREX] Сервер {primary_key} не отвечает, резерв не настроен"
        body = (f"<p>Сервер <b>{primary_key}</b> не отвечает, а в servers.json у него нет "
                f"резерва (backup_for). Юзеры без связи.</p>")
    send_admin_email(subject, body)


def _health_worker():
    """Фоновый поток — тикает каждые HEALTH_CHECK_INTERVAL_SEC."""
    time.sleep(30)  # дать Flask'у поднять сокеты
    while True:
        try:
            _health_tick()
        except Exception as e:
            print(f"[health] tick error: {e}")
            traceback.print_exc()
        time.sleep(HEALTH_CHECK_INTERVAL_SEC)


ADMIN_PASSWORD = _secrets.get("admin_password", "")

if not ADMIN_PASSWORD:
    print("WARNING: admin_password не задан — админ-эндпоинты будут отклонять все запросы")
if not SMTP_CONFIG["password"]:
    print("WARNING: smtp_password не задан — отправка email работать не будет")

# CORS: отвечаем заголовками только своему origin'у. Без `*` — иначе любой сторонний
# сайт мог бы делать POST /api/create с угнанным токеном.
ALLOWED_ORIGINS = {
    "https://wirex.online",
    "https://www.wirex.online",
    "https://api.wirex.online",
    # Vercel preview-деплои — закрыть, как только домен проверится
    "http://109.248.162.180:8080",
    "https://109.248.162.180:8080",
}


@app.after_request
def after_request(response):
    origin = request.headers.get("Origin")
    if origin and origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        response.headers["Access-Control-Allow-Headers"] = "Content-Type, Idempotency-Key"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# --- Rate-limiting / IP throttle / Idempotency ---------------------------

# Глобальный IP-лимит: сколько запросов в минуту на API может делать один IP,
# до того как начнём отдавать 429. Защищает от ботов, которые шарят все ручки.
GLOBAL_IP_REQ_PER_MIN = 120
GLOBAL_IP_WINDOW = 60

# Per-endpoint лимитеры. Декораторы @rate_limit.
_rate_buckets: dict = {}  # key -> deque[float timestamps]
_rate_lock = threading.Lock()

# Idempotency cache (Idempotency-Key header на мутирующих ручках). TTL 10 мин.
IDEM_TTL = 600
IDEM_MAX_KEYS = 10000
_idem_cache: dict = {}   # key -> (body_bytes, status_int, expires_at)
_idem_lock = threading.Lock()

# Глобальный lock для read-modify-write на JSON-стейте (users.json,
# subscriptions.json, promo_codes.json, payment_requests.json).
# Применяется точечно в горячих местах гонок (promo redeem) — не на каждой
# ручке, иначе долгие SSH-операции залочат всё. На <100 юзеров одного лока хватает.
_STATE_LOCK = threading.Lock()

# Endpoint'ы, которые не надо троттлить глобально (health для мониторинга,
# hy-auth — его дёргает сама Hysteria, может быть очень часто).
_IP_THROTTLE_EXEMPT_PATHS = {"/api/health", "/api/hy-auth"}


def _get_client_ip() -> str:
    """Клиентский IP — первый из X-Forwarded-For (если сайт за прокси/CF/Vercel),
    иначе X-Real-IP, иначе remote_addr."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    xr = request.headers.get("X-Real-IP", "")
    if xr:
        return xr.strip()
    return request.remote_addr or "unknown"


def _bucket_hit(bucket_key: str, limit: int, window: int):
    """True, 0 — OK; False, retry_after_sec — переполнено."""
    now = time.time()
    with _rate_lock:
        bucket = _rate_buckets.setdefault(bucket_key, deque())
        while bucket and bucket[0] < now - window:
            bucket.popleft()
        if len(bucket) >= limit:
            retry = int(bucket[0] + window - now) + 1
            return False, max(retry, 1)
        bucket.append(now)
        return True, 0


def rate_limit(limit: int, window: int = 60, scope: str = "ip"):
    """Per-IP (scope='ip') или per-IP+endpoint (scope='endpoint') лимит.
    Возвращает 429 с Retry-After заголовком при переполнении."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            ip = _get_client_ip()
            key = f"rl:{scope}:{func.__name__}:{ip}" if scope == "endpoint" \
                  else f"rl:ip:{func.__name__}:{ip}"
            ok, retry = _bucket_hit(key, limit, window)
            if not ok:
                resp = jsonify({"error": "Слишком много запросов, попробуйте позже",
                                "retry_after": retry})
                resp.status_code = 429
                resp.headers["Retry-After"] = str(retry)
                return resp
            return func(*args, **kwargs)
        return wrapper
    return decorator


def idempotent(func):
    """Кэширует ответ по (endpoint + IP + Idempotency-Key header) на IDEM_TTL.
    Если заголовка нет — проходит мимо (обратная совместимость). 5xx не кэшируется."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        idem = (request.headers.get("Idempotency-Key") or "").strip()
        if not idem or len(idem) > 128:
            return func(*args, **kwargs)
        full_key = f"idem:{request.path}:{_get_client_ip()}:{idem}"
        now = time.time()
        with _idem_lock:
            # lazy cleanup: если кэш разросся — выкидываем все протухшие
            if len(_idem_cache) > IDEM_MAX_KEYS:
                for k in list(_idem_cache.keys()):
                    if _idem_cache[k][2] < now:
                        _idem_cache.pop(k, None)
            cached = _idem_cache.get(full_key)
            if cached and cached[2] >= now:
                body, status, _ = cached
                return Response(body, status=status, mimetype="application/json")
        resp = func(*args, **kwargs)
        # нормализуем: может быть Response / tuple (Response, status) / (dict, status)
        if isinstance(resp, tuple):
            r_obj = resp[0]
            status = int(resp[1]) if len(resp) > 1 else 200
        else:
            r_obj = resp
            status = getattr(resp, "status_code", 200)
        if hasattr(r_obj, "get_data"):
            body = r_obj.get_data()
        elif isinstance(r_obj, (dict, list)):
            body = json.dumps(r_obj).encode()
        else:
            body = str(r_obj).encode()
        if 200 <= status < 500:
            with _idem_lock:
                _idem_cache[full_key] = (body, status, now + IDEM_TTL)
        return resp
    return wrapper


@app.before_request
def _global_ip_throttle():
    """Глобальный IP-троттлинг на API. Не трогает health/hy-auth/статику."""
    path = request.path or ""
    if not path.startswith("/api/"):
        return None
    if path in _IP_THROTTLE_EXEMPT_PATHS:
        return None
    ip = _get_client_ip()
    ok, retry = _bucket_hit(f"rl:global:{ip}", GLOBAL_IP_REQ_PER_MIN, GLOBAL_IP_WINDOW)
    if not ok:
        resp = jsonify({"error": "Слишком много запросов, попробуйте позже",
                        "retry_after": retry})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(retry)
        return resp
    return None


# Rate-limit для admin-логина: in-memory, per-IP. Сбрасывается при рестарте Flask,
# но этого достаточно — перезапуск ломает и брутфорсер тоже.
_ADMIN_BRUTE_WINDOW = 900  # 15 мин
_ADMIN_BRUTE_LIMIT = 5
_admin_login_fails: dict = {}
_admin_fails_lock = threading.Lock()


def _admin_brute_check(ip: str):
    """True, 0 — можно пробовать; False, wait_seconds — надо подождать."""
    now = time.time()
    with _admin_fails_lock:
        fails = [t for t in _admin_login_fails.get(ip, []) if now - t < _ADMIN_BRUTE_WINDOW]
        _admin_login_fails[ip] = fails
        if len(fails) >= _ADMIN_BRUTE_LIMIT:
            return False, int(_ADMIN_BRUTE_WINDOW - (now - min(fails)))
        return True, 0


def _admin_brute_register_fail(ip: str):
    with _admin_fails_lock:
        _admin_login_fails.setdefault(ip, []).append(time.time())


def _admin_brute_clear(ip: str):
    with _admin_fails_lock:
        _admin_login_fails.pop(ip, None)

def load_verification_codes():
    if os.path.exists(VERIFICATION_CODES_DB):
        with open(VERIFICATION_CODES_DB, "r") as f:
            return json.load(f)
    return {}

def save_verification_codes(codes):
    os.makedirs(os.path.dirname(VERIFICATION_CODES_DB), exist_ok=True)
    with open(VERIFICATION_CODES_DB, "w") as f:
        json.dump(codes, f, indent=2)


def load_sessions():
    if os.path.exists(SESSIONS_DB):
        with open(SESSIONS_DB, "r") as f:
            return json.load(f)
    return {}


def save_sessions(sessions):
    os.makedirs(os.path.dirname(SESSIONS_DB), exist_ok=True)
    with open(SESSIONS_DB, "w") as f:
        json.dump(sessions, f, indent=2)


def _purge_expired_sessions(sessions):
    now = datetime.now()
    return {
        t: s for t, s in sessions.items()
        if datetime.fromisoformat(s["expires"]) > now
    }


def create_session(email):
    sessions = _purge_expired_sessions(load_sessions())
    token = secrets.token_urlsafe(32)
    now = datetime.now()
    sessions[token] = {
        "email": email,
        "created": now.isoformat(),
        "expires": (now + timedelta(days=SESSION_TTL_DAYS)).isoformat()
    }
    save_sessions(sessions)
    return token


def get_session(token):
    if not token or len(token) < 10:
        return None
    sessions = load_sessions()
    s = sessions.get(token)
    if not s:
        return None
    if datetime.fromisoformat(s["expires"]) < datetime.now():
        del sessions[token]
        save_sessions(sessions)
        return None
    return s


def revoke_session(token):
    sessions = load_sessions()
    if token in sessions:
        del sessions[token]
        save_sessions(sessions)

def send_verification_email(email, code):
    try:
        msg = MIMEMultipart()
        msg['From'] = f"WIREX <{SMTP_CONFIG['username']}>"
        msg['To'] = email
        msg['Subject'] = "Подтверждение email - WIREX"
        
        body = f"""
        <html>
        <head>
            <meta charset="UTF-8">
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #8ff5ff 0%, #00eefc 100%); padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: #F5F5F5; margin: 0;">WIREX</h1>
            </div>
            <div style="background: #161a21; padding: 30px; border-radius: 0 0 10px 10px; color: #ecedf6;">
                <h2 style="margin-top: 0;">Подтверждение email</h2>
                <p>Ваш код подтверждения:</p>
                <div style="font-size: 36px; font-weight: bold; text-align: center; padding: 20px; background: #22262f; border-radius: 10px; letter-spacing: 8px; color: #00eefc;">
                    {code}
                </div>
                <p>Код действителен в течение 10 минут.</p>
                <hr style="border-color: #45484f;">
                <p style="font-size: 12px; color: #a9abb3; margin-top: 20px;">
                    Это автоматическое сообщение, пожалуйста, не отвечайте на него.<br>
                    Если вы не запрашивали этот код, просто проигнорируйте это письмо.
                </p>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(SMTP_CONFIG["server"], SMTP_CONFIG["port"])
        server.starttls()
        server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {e}")
        return False

@app.route("/api/send-code", methods=["POST"])
@rate_limit(5, 60)
def send_code():
    data = request.json
    email = data.get("email", "").strip().lower()

    if not email or not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return jsonify({"error": "Введите корректный email"}), 400

    if is_disposable_email(email):
        return jsonify({"error": "Одноразовые email-адреса не поддерживаются. Используйте постоянный email."}), 400

    codes = load_verification_codes()
    existing = codes.get(email)
    if existing:
        last_sent = existing.get("sent_at")
        if last_sent:
            elapsed = (datetime.now() - datetime.fromisoformat(last_sent)).total_seconds()
            if elapsed < OTP_RESEND_COOLDOWN:
                wait = int(OTP_RESEND_COOLDOWN - elapsed)
                return jsonify({"error": f"Подождите {wait} сек перед повторной отправкой"}), 429

    code = str(secrets.randbelow(900000) + 100000)
    now = datetime.now()
    codes[email] = {
        "code": code,
        "expires": (now + timedelta(minutes=10)).isoformat(),
        "sent_at": now.isoformat()
    }
    save_verification_codes(codes)

    if send_verification_email(email, code):
        return jsonify({"ok": True, "message": "Код отправлен"})
    else:
        return jsonify({"error": "Ошибка отправки email"}), 500

@app.route("/api/verify-code", methods=["POST"])
@rate_limit(15, 60)
def verify_code():
    data = request.json
    email = data.get("email", "").strip()
    code = data.get("code", "").strip()
    
    codes = load_verification_codes()
    
    if email not in codes:
        return jsonify({"error": "Код не найден"}), 400
    
    code_data = codes[email]
    expires = datetime.fromisoformat(code_data["expires"])

    if datetime.now() > expires:
        del codes[email]
        save_verification_codes(codes)
        return jsonify({"error": "Код истек"}), 400

    # Brute-force защита: 5 попыток на один код, потом код инвалидируется.
    # Иначе атакующий перебирает 1М шестизначных кодов за минуты.
    attempts = code_data.get("attempts", 0)
    if attempts >= 5:
        del codes[email]
        save_verification_codes(codes)
        return jsonify({"error": "Слишком много попыток. Запросите код заново."}), 429

    if code_data["code"] != code:
        code_data["attempts"] = attempts + 1
        codes[email] = code_data
        save_verification_codes(codes)
        remaining = 5 - code_data["attempts"]
        if remaining <= 0:
            return jsonify({"error": "Неверный код. Код инвалидирован, запросите новый."}), 400
        return jsonify({"error": f"Неверный код. Осталось попыток: {remaining}"}), 400

    del codes[email]
    save_verification_codes(codes)

    session_token = create_session(email)

    return jsonify({
        "ok": True,
        "token": session_token,
        "email": email
    })

@app.route('/api/verify-session', methods=['POST'])
@rate_limit(60, 60)
def verify_session():
    data = request.json or {}
    token = data.get('token', '')
    session = get_session(token)
    if session:
        return jsonify({"ok": True, "email": session["email"]})
    return jsonify({"ok": False}), 401


@app.route('/api/logout', methods=['POST'])
def logout():
    data = request.json or {}
    token = data.get('token', '')
    revoke_session(token)
    return jsonify({"ok": True})


@app.route('/api/hy-auth', methods=['POST'])
def hy_auth():
    """Колбэк авторизации от Hysteria (auth.type=http в конфиге сервера).
    Hysteria шлёт {"addr": "...", "auth": "<password>", "tx": N}. Мы ищем юзера
    с таким hysteria_password и у которого in_xray=True. Если нашёлся — 200 + id.
    Иначе 401. Никаких сессий/токенов Flask — это отдельный канал."""
    data = request.get_json(silent=True) or {}
    pw = data.get("auth", "")
    if not pw:
        return jsonify({"ok": False}), 401
    try:
        users = load_users()
    except Exception as e:
        print(f"[hy-auth] load_users failed: {e}")
        return jsonify({"ok": False}), 500
    for u in users:
        if u.get("hysteria_password") == pw and u.get("in_xray"):
            return jsonify({"ok": True, "id": u.get("username", "")}), 200
    return jsonify({"ok": False}), 401

def load_users():
    if os.path.exists(USERS_DB):
        with open(USERS_DB, "r") as f:
            return json.load(f)
    return []

def save_users(users):
    os.makedirs(os.path.dirname(USERS_DB), exist_ok=True)
    with open(USERS_DB, "w") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def _load_json(path, default):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return default
    return default


def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def load_subscriptions():
    return _load_json(SUBSCRIPTIONS_DB, {})


def save_subscriptions(subs):
    _save_json(SUBSCRIPTIONS_DB, subs)


def get_subscription(email):
    """Возвращает dict с {plan, expires_at, active} или None."""
    if not email:
        return None
    subs = load_subscriptions()
    s = subs.get(email.lower())
    if not s:
        return None
    active = False
    if s.get("plan") == "unlimited":
        active = True
    else:
        exp = s.get("expires_at")
        if exp:
            try:
                active = datetime.fromisoformat(exp) > datetime.now()
            except Exception:
                active = False
    return {**s, "active": active}


def is_subscribed(email):
    s = get_subscription(email)
    return bool(s and s.get("active"))


def extend_subscription(email, days):
    """Продляет подписку на N дней. Если не было — создаёт. Если активна — прибавляет к её концу."""
    email = email.lower()
    subs = load_subscriptions()
    now = datetime.now()
    existing = subs.get(email)

    if existing and existing.get("plan") == "unlimited":
        # безлимиту дни не нужны — ничего не меняем
        return existing

    start_from = now
    if existing:
        try:
            curr_exp = datetime.fromisoformat(existing.get("expires_at", ""))
            if curr_exp > now:
                start_from = curr_exp
        except Exception:
            pass

    new_exp = start_from + timedelta(days=days)
    subs[email] = {
        "plan": "paid",
        "expires_at": new_exp.isoformat(),
        "created": (existing or {}).get("created", now.isoformat()),
        "updated": now.isoformat(),
    }
    save_subscriptions(subs)
    return subs[email]


def set_unlimited(email, unlimited):
    """Включает/выключает безлимит для email."""
    email = email.lower()
    subs = load_subscriptions()
    now = datetime.now()

    if unlimited:
        subs[email] = {
            "plan": "unlimited",
            "expires_at": None,
            "created": subs.get(email, {}).get("created", now.isoformat()),
            "updated": now.isoformat(),
        }
    else:
        # Если был безлимит — сносим подписку полностью
        if email in subs and subs[email].get("plan") == "unlimited":
            del subs[email]

    save_subscriptions(subs)
    return subs.get(email)


def revoke_subscription(email):
    email = email.lower()
    subs = load_subscriptions()
    if email in subs:
        del subs[email]
        save_subscriptions(subs)


def load_payment_requests():
    return _load_json(PAYMENT_REQUESTS_DB, [])


def save_payment_requests(items):
    _save_json(PAYMENT_REQUESTS_DB, items)


def load_promo_codes():
    return _load_json(PROMO_CODES_DB, {})


def save_promo_codes(codes):
    _save_json(PROMO_CODES_DB, codes)


# ---------- lava.top интеграция ----------

def load_lava_payments():
    return _load_json(LAVA_PAYMENTS_DB, {})


def save_lava_payments(payments):
    _save_json(LAVA_PAYMENTS_DB, payments)


def _lava_request(method, path, body=None, timeout=15):
    """Низкоуровневый вызов API lava.top. Возвращает (status, json_or_text).
    Не кидает исключения на не-2xx — отдаём статус наверх для логики."""
    if not LAVA_API_KEY:
        return 0, {"error": "lava_api_key не сконфигурирован"}
    url = f"{LAVA_API_BASE}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = Request(url, data=data, method=method)
    req.add_header("X-Api-Key", LAVA_API_KEY)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            try:
                return resp.status, json.loads(raw) if raw else {}
            except json.JSONDecodeError:
                return resp.status, raw
    except HTTPError as e:
        raw = e.read().decode("utf-8", errors="replace")
        try:
            return e.code, json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return e.code, raw
    except URLError as e:
        return 0, {"error": f"network: {e.reason}"}
    except Exception as e:
        return 0, {"error": f"{type(e).__name__}: {e}"}


def lava_create_invoice(email, tariff_id):
    """Создаёт invoice в lava.top для оплаты тарифа `tariff_id`. Возвращает
    (contract_id, payment_url, error). На ошибку — (None, None, str)."""
    offer_id = LAVA_OFFERS.get(tariff_id)
    if not offer_id:
        return None, None, f"Нет offer_id для тарифа {tariff_id}"
    payload = {
        "email": email,
        "offerId": offer_id,
        "currency": "RUB",
        "paymentProvider": "SMART_GLOCAL",
        "paymentMethod": "CARD",
        "buyerLanguage": "RU",
        "periodicity": "ONE_TIME",
    }
    status, body = _lava_request("POST", LAVA_INVOICE_CREATE, body=payload)
    if status not in (200, 201):
        err = (body.get("error") or body.get("message") or str(body)) if isinstance(body, dict) else str(body)
        return None, None, f"lava {status}: {err}"
    if not isinstance(body, dict):
        return None, None, f"lava ответил не JSON: {body!r:.200}"
    contract_id = body.get("id")
    payment_url = body.get("paymentUrl")
    if not contract_id or not payment_url:
        return None, None, f"lava не вернул id/paymentUrl: {body!r:.200}"
    return contract_id, payment_url, None


def lava_fetch_invoice(contract_id):
    """GET к lava.top — двойная проверка статуса. Webhook без подписи, поэтому
    перед зачислением идём в lava с нашим API-ключом — фейк webhook'а это не пройдёт."""
    status, body = _lava_request("GET", LAVA_INVOICE_GET.format(id=contract_id))
    if status != 200 or not isinstance(body, dict):
        return None
    return body


def _hy_log(msg):
    print(f"[hysteria] {msg}", file=sys.stderr, flush=True)


def add_to_hysteria_safe(server_key, username):
    """Генерит hysteria-пароль. Конфиг на серверах больше не трогаем:
    auth-state живёт в users.json и проверяется через /api/hy-auth."""
    try:
        return hysteria_config.generate_password()
    except Exception as e:
        _hy_log(f"generate_password({server_key}, {username}) FAILED: {type(e).__name__}: {e}")
        return None


def remove_from_hysteria_safe(server_key, username):
    """No-op: достаточно выставить in_xray=False в users.json — /api/hy-auth
    такого юзера уже не пропустит."""
    return None


def build_hysteria_url(server_key, username, password):
    """Строит hysteria2:// URL или None если не удалось (obfs password недоступен)."""
    if not password:
        return None
    try:
        tag = key_tag(server_key, "Hysteria")
        return hysteria_config.build_uri(
            server_key, SERVERS[server_key], username, password, name_tag=tag
        )
    except Exception as e:
        _hy_log(f"build_uri({server_key}, {username}) FAILED: {type(e).__name__}: {e}")
        return None


def build_vless_url(user_uuid, server_key, name=None):
    s = SERVERS[server_key]
    tag = name if name else key_tag(s, "Reality")
    return (
        f"vless://{user_uuid}@{s['ip']}:{s['port']}"
        f"?encryption=none&type=tcp&security={s['security']}"
        f"&sni={s['sni']}&pbk={s['pbk']}&sid={s['sid']}"
        f"&fp={s['fp']}&flow=#{quote(tag)}"
    )

def generate_qr_base64(text):
    img = qrcode.make(text)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()

def run_on_server(server_key, command):
    s = SERVERS[server_key]
    if s.get("remote"):
        ssh = s["ssh"]
        subprocess.run(
            ["ssh", "-o", "StrictHostKeyChecking=no", ssh, command],
            check=True,
            capture_output=True
        )
    else:
        subprocess.run(command, shell=True, check=True, capture_output=True)


def exec_python_on_server(server_key, script):
    """Отправить python-скрипт на сервер через stdin — без экранирования кавычек."""
    s = SERVERS[server_key]
    if s.get("remote"):
        cmd = ["ssh", "-o", "StrictHostKeyChecking=no", s["ssh"], "python3", "-"]
    else:
        cmd = ["python3", "-"]
    r = subprocess.run(cmd, input=script, capture_output=True, text=True)
    if r.returncode != 0:
        # дефолтный CalledProcessError не печатает stderr — делаем это сами,
        # иначе в админке видно только "returned non-zero exit status 1".
        raise RuntimeError(
            f"python3 on {server_key} exit={r.returncode}: "
            f"{(r.stderr or r.stdout or '<no output>').strip()[:800]}"
        )
    return r.stdout


def add_to_xray(user_uuid, server_key, email):
    config_path = SERVERS[server_key]["xray_config"]
    script = (
        "import json\n"
        f"p = {config_path!r}\n"
        "with open(p) as f: c = json.load(f)\n"
        "ib = next(i for i in c['inbounds'] if i.get('protocol') == 'vless')\n"
        "clients = ib['settings']['clients']\n"
        f"if not any(x['id'] == {user_uuid!r} for x in clients):\n"
        f"    clients.append({{'id': {user_uuid!r}, 'email': {email!r}, 'flow': ''}})\n"
        "with open(p, 'w') as f: json.dump(c, f, indent=2)\n"
    )
    exec_python_on_server(server_key, script)
    run_on_server(server_key, "systemctl restart xray")


def remove_from_xray(user_uuid, server_key):
    config_path = SERVERS[server_key]["xray_config"]
    script = (
        "import json\n"
        f"p = {config_path!r}\n"
        "with open(p) as f: c = json.load(f)\n"
        "ib = next(i for i in c['inbounds'] if i.get('protocol') == 'vless')\n"
        f"ib['settings']['clients'] = [x for x in ib['settings']['clients'] if x['id'] != {user_uuid!r}]\n"
        "with open(p, 'w') as f: json.dump(c, f, indent=2)\n"
    )
    exec_python_on_server(server_key, script)
    run_on_server(server_key, "systemctl restart xray")


def query_xray_stats(server_key):
    """Возвращает {email: {'up': int, 'down': int}} по данным Stats API."""
    s = SERVERS[server_key]
    cmd_str = "xray api statsquery --server=127.0.0.1:10085 -pattern 'user>>>'"
    try:
        if s.get("remote"):
            r = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", s["ssh"], cmd_str],
                capture_output=True, text=True, timeout=10
            )
        else:
            r = subprocess.run(cmd_str, shell=True, capture_output=True, text=True, timeout=10)
    except Exception as e:
        print(f"Stats query failed for {server_key}: {e}")
        return {}

    if r.returncode != 0 or not r.stdout.strip():
        return {}

    try:
        data = json.loads(r.stdout)
    except Exception:
        return {}

    result = {}
    for stat in data.get("stat", []):
        parts = stat.get("name", "").split(">>>")
        if len(parts) != 4 or parts[0] != "user":
            continue
        email = parts[1]
        direction = parts[3]
        value = int(stat.get("value", 0) or 0)
        bucket = result.setdefault(email, {"up": 0, "down": 0})
        if direction == "uplink":
            bucket["up"] = value
        elif direction == "downlink":
            bucket["down"] = value
    return result

_SERVER_METRICS_CACHE = {"ts": 0, "data": None}
_SERVER_METRICS_TTL = 30  # секунд


def collect_server_metrics(server_key):
    """Снимает метрики с одного сервера одним SSH round-trip. Возвращает dict с online/online_reason и полями."""
    s = SERVERS[server_key]
    config_path = s["xray_config"]
    script = (
        "import json, subprocess, re\n"
        "out = {}\n"
        "try:\n"
        "    with open('/proc/uptime') as f: out['uptime_sec'] = float(f.read().split()[0])\n"
        "except Exception: pass\n"
        "try:\n"
        "    with open('/proc/loadavg') as f: p = f.read().split()\n"
        "    out['load_1m'] = float(p[0]); out['load_5m'] = float(p[1]); out['load_15m'] = float(p[2])\n"
        "except Exception: pass\n"
        "try:\n"
        "    import multiprocessing; out['cpu_count'] = multiprocessing.cpu_count()\n"
        "except Exception: pass\n"
        "try:\n"
        "    mem = {}\n"
        "    with open('/proc/meminfo') as f:\n"
        "        for line in f:\n"
        "            k, _, v = line.partition(':')\n"
        "            mem[k.strip()] = int(v.strip().split()[0]) * 1024\n"
        "    out['mem_total'] = mem.get('MemTotal', 0)\n"
        "    out['mem_available'] = mem.get('MemAvailable', 0)\n"
        "    out['mem_used'] = out['mem_total'] - out['mem_available']\n"
        "except Exception: pass\n"
        "try:\n"
        "    rx = 0; tx = 0\n"
        "    with open('/proc/net/dev') as f: lines = f.read().splitlines()\n"
        "    for line in lines[2:]:\n"
        "        parts = line.split()\n"
        "        if not parts: continue\n"
        "        iface = parts[0].rstrip(':')\n"
        "        if iface == 'lo' or iface.startswith(('docker','veth','br-','tun','tap')): continue\n"
        "        rx += int(parts[1]); tx += int(parts[9])\n"
        "    out['net_rx'] = rx; out['net_tx'] = tx\n"
        "except Exception: pass\n"
        "try:\n"
        "    r = subprocess.run(['xray','version'], capture_output=True, text=True, timeout=3)\n"
        "    first = (r.stdout or '').splitlines()[0] if r.stdout else ''\n"
        "    m = re.search(r'(\\d+\\.\\d+\\.\\d+)', first)\n"
        "    out['xray_version'] = m.group(1) if m else (first.strip() or None)\n"
        "except Exception: out['xray_version'] = None\n"
        "try:\n"
        "    r = subprocess.run(['systemctl','is-active','xray'], capture_output=True, text=True, timeout=3)\n"
        "    out['xray_active'] = (r.stdout.strip() == 'active')\n"
        "except Exception: out['xray_active'] = None\n"
        "try:\n"
        "    r = subprocess.run(['systemctl','is-active','hysteria-server'], capture_output=True, text=True, timeout=3)\n"
        "    out['hysteria_active'] = (r.stdout.strip() == 'active')\n"
        "    r2 = subprocess.run(['systemctl','list-unit-files','hysteria-server.service'], capture_output=True, text=True, timeout=3)\n"
        "    out['hysteria_installed'] = 'hysteria-server' in (r2.stdout or '')\n"
        "except Exception:\n"
        "    out['hysteria_active'] = None\n"
        "    out['hysteria_installed'] = None\n"
        "try:\n"
        f"    with open({config_path!r}) as f: c = json.load(f)\n"
        "    ib = next(i for i in c['inbounds'] if i.get('protocol') == 'vless')\n"
        "    out['xray_clients'] = len(ib['settings']['clients'])\n"
        "    out['xray_port'] = ib.get('port')\n"
        "except Exception: out['xray_clients'] = None\n"
        "print(json.dumps(out))\n"
    )
    t_start = time.time()
    try:
        if s.get("remote"):
            cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=5", s["ssh"], "python3", "-"]
        else:
            cmd = ["python3", "-"]
        r = subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=12)
        latency_ms = int((time.time() - t_start) * 1000)
        if r.returncode != 0 or not r.stdout.strip():
            return {"online": False, "online_reason": (r.stderr or "нет ответа").strip()[:200], "latency_ms": latency_ms}
        metrics = json.loads(r.stdout)
        metrics["online"] = True
        metrics["latency_ms"] = latency_ms
        return metrics
    except subprocess.TimeoutExpired:
        return {"online": False, "online_reason": "timeout", "latency_ms": int((time.time() - t_start) * 1000)}
    except Exception as e:
        return {"online": False, "online_reason": str(e)[:200], "latency_ms": int((time.time() - t_start) * 1000)}


def get_servers_stats(force_refresh=False):
    """Возвращает список с метриками по всем серверам. Кешируется на _SERVER_METRICS_TTL секунд."""
    now = time.time()
    if not force_refresh and _SERVER_METRICS_CACHE["data"] and (now - _SERVER_METRICS_CACHE["ts"] < _SERVER_METRICS_TTL):
        return _SERVER_METRICS_CACHE["data"], True

    users = load_users()
    users_by_server = {}
    for u in users:
        srv = u.get("server")
        if not srv: continue
        b = users_by_server.setdefault(srv, {"total": 0, "active": 0})
        b["total"] += 1
        if u.get("in_xray"): b["active"] += 1

    keys = list(SERVERS.keys())
    with ThreadPoolExecutor(max_workers=max(1, len(keys))) as ex:
        raw = list(ex.map(collect_server_metrics, keys))

    result = []
    for srv_key, metrics in zip(keys, raw):
        s = SERVERS[srv_key]
        counts = users_by_server.get(srv_key, {"total": 0, "active": 0})
        result.append({
            "key": srv_key,
            "name": s["name"],
            "flag": s["flag"],
            "ip": s["ip"],
            "port": s["port"],
            "remote": s.get("remote", False),
            "users_total": counts["total"],
            "users_active": counts["active"],
            "max_users": capacity_for_server(s),
            "bandwidth_mbps": s.get("bandwidth_mbps"),
            "country": s.get("country"),
            "backup_for": s.get("backup_for"),
            "disabled": bool(s.get("disabled")),
            "full": counts["total"] >= capacity_for_server(s),
            **metrics,
        })
    _SERVER_METRICS_CACHE["ts"] = now
    _SERVER_METRICS_CACHE["data"] = result
    return result, False


def sub_slug(username, user_uuid):
    """Имя файла подписки — <username>_<uuid8>. Уникально даже при одинаковых username."""
    return f"{username.lower()}_{user_uuid.split('-')[0]}"


def update_subscription(user_uuid, server_key, username, hysteria_password=None):
    """Пишет файл подписки. Если передан hysteria_password — добавляет hysteria2:// URL
    рядом с VLESS (клиент импортирует оба, выберет рабочий)."""
    os.makedirs(SUB_DIR, exist_ok=True)
    urls = [build_vless_url(user_uuid, server_key)]
    hy2 = build_hysteria_url(server_key, username, hysteria_password)
    if hy2:
        urls.append(hy2)
    encoded = base64.b64encode("\n".join(urls).encode()).decode()
    filepath = os.path.join(SUB_DIR, sub_slug(username, user_uuid))
    with open(filepath, "w") as f:
        f.write(encoded)


def suggest_username_for_email(email):
    """Предложить валидный username по email. Использует префикс до @, чистит до [a-zA-Z0-9_-]."""
    local = (email or "").split("@", 1)[0]
    cleaned = re.sub(r"[^a-zA-Z0-9_\-]", "", local)
    if len(cleaned) < 2:
        cleaned = f"user{secrets.token_hex(3)}"
    return cleaned[:32]

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/servers")
def get_servers():
    users = load_users()
    counts = {}
    for u in users:
        srv = u.get("server")
        if srv: counts[srv] = counts.get(srv, 0) + 1
    result = {}
    for key, s in SERVERS.items():
        if s.get("disabled"):
            continue
        max_users = capacity_for_server(s)
        cnt = counts.get(key, 0)
        result[key] = {
            "name": s["name"],
            "flag": s["flag"],
            "ip": s["ip"],
            "port": s["port"],
            "country": s.get("country"),
            "bandwidth_mbps": s.get("bandwidth_mbps"),
            "users_count": cnt,
            "max_users": max_users,
            "full": cnt >= max_users
        }
    return jsonify(result)

def build_key_data(user):
    """Собирает всё, что нужно фронту для показа ключа: URL, подписка, QR, мета.
    Если у юзера есть hysteria_password — добавляет hysteria2:// URL и QR."""
    server_key = user["server"]
    username = user["username"]
    s = SERVERS[server_key]
    vless_url = build_vless_url(user["uuid"], server_key)
    sub_url = f"https://{SUB_HOST}/sub/{sub_slug(username, user['uuid'])}"
    data = {
        "uuid": user["uuid"],
        "username": username,
        "server": server_key,
        "server_name": s["name"],
        "server_flag": s["flag"],
        "created": user.get("created", ""),
        "vless_url": vless_url,
        "sub_url": sub_url,
        "qr": generate_qr_base64(vless_url),
        "hysteria_url": None,
        "hysteria_qr": None,
    }
    hy_pw = user.get("hysteria_password")
    if hy_pw:
        hy_url = build_hysteria_url(server_key, username, hy_pw)
        if hy_url:
            data["hysteria_url"] = hy_url
            data["hysteria_qr"] = generate_qr_base64(hy_url)
    return data


@app.route("/api/create", methods=["POST"])
@rate_limit(10, 60)
@idempotent
def create_key():
    data = request.json
    server_key = data.get("server")
    username = data.get("username", "").strip()
    token = data.get("token", "")

    session = get_session(token)
    if not session:
        return jsonify({"error": "Сессия истекла, войдите заново"}), 401

    if not is_subscribed(session["email"]):
        return jsonify({"error": "Нужна активная подписка. Оформите её, чтобы создать ключ.", "code": "subscription_required"}), 402

    if server_key not in SERVERS:
        return jsonify({"error": "Сервер не найден"}), 400

    if not username:
        username = suggest_username_for_email(session["email"])
    if not re.match(r"^[a-zA-Z0-9_\-]{2,32}$", username):
        return jsonify({"error": "Имя: 2–32 символа, только латиница/цифры/_-"}), 400

    users = load_users()
    email_lc = session["email"].lower()
    if any((u.get("email") or "").lower() == email_lc and u.get("server") == server_key for u in users):
        return jsonify({"error": "У вас уже есть ключ на этом сервере. Замените его, чтобы пересоздать.", "code": "key_exists_on_server"}), 409

    max_users = capacity_for_server(SERVERS[server_key])
    server_user_count = sum(1 for u in users if u.get("server") == server_key)
    if server_user_count >= max_users:
        return jsonify({"error": "Этот сервер заполнен. Выберите другой.", "code": "server_full"}), 409

    user_uuid = str(uuid.uuid4())

    try:
        add_to_xray(user_uuid, server_key, username)
    except Exception as e:
        return jsonify({"error": f"Ошибка Xray: {str(e)}"}), 500

    hysteria_password = add_to_hysteria_safe(server_key, username)

    try:
        update_subscription(user_uuid, server_key, username, hysteria_password)
    except Exception as e:
        return jsonify({"error": f"Ошибка подписки: {str(e)}"}), 500

    user_entry = {
        "username": username,
        "uuid": user_uuid,
        "server": server_key,
        "email": session["email"],
        "created": datetime.now().isoformat(),
        "in_xray": True,
        "hysteria_password": hysteria_password,
    }
    users.append(user_entry)
    save_users(users)

    return jsonify(build_key_data(user_entry))


@app.route("/api/my-keys", methods=["POST"])
def my_keys():
    data = request.json or {}
    token = data.get("token", "")
    session = get_session(token)
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    email = session["email"]
    users = load_users()
    mine = [u for u in users if u.get("email") == email]
    return jsonify([build_key_data(u) for u in mine])


@app.route("/api/my-keys/delete", methods=["POST"])
@rate_limit(10, 60)
@idempotent
def delete_my_key():
    data = request.json or {}
    token = data.get("token", "")
    key_uuid = (data.get("uuid") or "").strip()
    username = data.get("username", "")

    session = get_session(token)
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    users = load_users()
    if key_uuid:
        user = next((u for u in users if u["uuid"] == key_uuid), None)
    else:
        user = next((u for u in users if u["username"].lower() == username.lower()), None)
    if not user:
        return jsonify({"error": "Ключ не найден"}), 404

    if user.get("email") != session["email"]:
        return jsonify({"error": "Это не ваш ключ"}), 403

    try:
        remove_from_xray(user["uuid"], user["server"])
    except Exception as e:
        return jsonify({"error": f"Ошибка Xray: {str(e)}"}), 500

    remove_from_hysteria_safe(user["server"], user["username"])

    sub_path = os.path.join(SUB_DIR, sub_slug(user["username"], user["uuid"]))
    if os.path.exists(sub_path):
        os.remove(sub_path)

    users = [u for u in users if u["uuid"] != user["uuid"]]
    save_users(users)

    return jsonify({"ok": True})


@app.route("/api/my-keys/replace", methods=["POST"])
@rate_limit(10, 60)
@idempotent
def replace_my_key():
    """Заменяет конкретный ключ юзера (по old_uuid) на новый. Сервер можно оставить тем же или сменить, но новый не должен быть занят другим ключом того же юзера."""
    data = request.json or {}
    token = data.get("token", "")
    old_uuid = (data.get("old_uuid") or "").strip()
    server_key = data.get("server")
    new_username = (data.get("username") or "").strip()

    session = get_session(token)
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    if not is_subscribed(session["email"]):
        return jsonify({"error": "Нужна активная подписка", "code": "subscription_required"}), 402

    if server_key not in SERVERS:
        return jsonify({"error": "Сервер не найден"}), 400

    if not new_username:
        new_username = suggest_username_for_email(session["email"])
    if not re.match(r"^[a-zA-Z0-9_\-]{2,32}$", new_username):
        return jsonify({"error": "Имя: 2–32 символа, только латиница/цифры/_-"}), 400

    email_lc = session["email"].lower()
    users = load_users()
    old = None
    if old_uuid:
        old = next((u for u in users if u.get("uuid") == old_uuid and (u.get("email") or "").lower() == email_lc), None)
        if not old:
            return jsonify({"error": "Старый ключ не найден"}), 404

    if any((u.get("email") or "").lower() == email_lc
           and u.get("server") == server_key
           and (not old or u.get("uuid") != old["uuid"])
           for u in users):
        return jsonify({"error": "У вас уже есть ключ на этом сервере.", "code": "key_exists_on_server"}), 409

    # Проверка лимита: только если меняем сервер (иначе число ключей на сервере не растёт)
    if not old or old.get("server") != server_key:
        max_users = capacity_for_server(SERVERS[server_key])
        server_user_count = sum(1 for u in users if u.get("server") == server_key)
        if server_user_count >= max_users:
            return jsonify({"error": "Этот сервер заполнен. Выберите другой.", "code": "server_full"}), 409

    if old:
        try:
            remove_from_xray(old["uuid"], old["server"])
        except Exception as e:
            return jsonify({"error": f"Ошибка Xray (удаление старого): {str(e)}"}), 500
        remove_from_hysteria_safe(old["server"], old["username"])
        old_sub_path = os.path.join(SUB_DIR, sub_slug(old["username"], old["uuid"]))
        if os.path.exists(old_sub_path):
            os.remove(old_sub_path)
        users = [u for u in users if u["uuid"] != old["uuid"]]

    new_uuid = str(uuid.uuid4())
    try:
        add_to_xray(new_uuid, server_key, new_username)
    except Exception as e:
        save_users(users)
        return jsonify({"error": f"Ошибка Xray (создание нового): {str(e)}"}), 500

    hysteria_password = add_to_hysteria_safe(server_key, new_username)

    try:
        update_subscription(new_uuid, server_key, new_username, hysteria_password)
    except Exception as e:
        save_users(users)
        return jsonify({"error": f"Ошибка подписки: {str(e)}"}), 500

    entry = {
        "username": new_username,
        "uuid": new_uuid,
        "server": server_key,
        "email": session["email"],
        "created": datetime.now().isoformat(),
        "in_xray": True,
        "hysteria_password": hysteria_password,
    }
    users.append(entry)
    save_users(users)
    return jsonify(build_key_data(entry))


@app.route("/api/suggest-username", methods=["POST"])
@rate_limit(30, 60)
def api_suggest_username():
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401
    return jsonify({"username": suggest_username_for_email(session["email"])})


@app.route("/api/tariffs", methods=["GET"])
def api_tariffs():
    return jsonify([
        {"id": key, **value, "card_pay_enabled": bool(LAVA_API_KEY and key in LAVA_OFFERS)}
        for key, value in TARIFFS.items()
    ])


@app.route("/api/payment-info", methods=["GET"])
def api_payment_info():
    # Публичная инфа для ручной оплаты — берём из secrets.json, чтобы реквизиты не лежали в репе.
    # `lava_enabled` — фронт включает кнопку «Оплатить картой», если бэк сконфигурирован.
    return jsonify({
        "sbp_phone": _secrets.get("sbp_phone", ""),
        "sbp_bank": _secrets.get("sbp_bank", ""),
        "card_number": _secrets.get("card_number", ""),
        "card_holder": _secrets.get("card_holder", ""),
        "note": _secrets.get("payment_note", "После оплаты нажмите «Я оплатил». Доступ откроется после подтверждения админом (обычно до 1 часа)."),
        "lava_enabled": bool(LAVA_API_KEY and LAVA_OFFERS),
    })


@app.route("/api/subscription/status", methods=["POST"])
def api_subscription_status():
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    email = session["email"]
    sub = get_subscription(email) or {"plan": None, "expires_at": None, "active": False}

    requests_list = load_payment_requests()
    pending = next(
        (r for r in requests_list
         if r.get("email") == email and r.get("status") == "pending"),
        None
    )

    return jsonify({
        "email": email,
        "subscription": sub,
        "pending_request": pending,
    })


@app.route("/api/subscription/request", methods=["POST"])
@rate_limit(5, 60)
@idempotent
def api_subscription_request():
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    tariff_id = data.get("tariff")
    if tariff_id not in TARIFFS:
        return jsonify({"error": "Неизвестный тариф"}), 400

    email = session["email"]
    tariff = TARIFFS[tariff_id]

    # Lock — иначе двойной клик/race создаст 2 pending-заявки.
    with _STATE_LOCK:
        items = load_payment_requests()
        if any(r.get("email") == email and r.get("status") == "pending" for r in items):
            return jsonify({"error": "У вас уже есть заявка в ожидании подтверждения"}), 400
        req = {
            "id": secrets.token_urlsafe(8),
            "email": email,
            "tariff": tariff_id,
            "days": tariff["days"],
            "price": tariff["price"],
            "status": "pending",
            "created": datetime.now().isoformat(),
        }
        items.append(req)
        save_payment_requests(items)
    return jsonify({"ok": True, "request": req})


@app.route("/api/subscription/cancel-request", methods=["POST"])
def api_subscription_cancel_request():
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    email = session["email"]
    items = load_payment_requests()
    new_items = [
        r for r in items
        if not (r.get("email") == email and r.get("status") == "pending")
    ]
    if len(new_items) == len(items):
        return jsonify({"error": "Нет активной заявки"}), 404
    save_payment_requests(new_items)
    return jsonify({"ok": True})


@app.route("/api/promo/redeem", methods=["POST"])
@rate_limit(10, 60)
@idempotent
def api_promo_redeem():
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    code = (data.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "Введите промокод"}), 400

    # Lock на всю операцию: иначе два параллельных запроса с одним промокодом
    # оба пройдут проверку `email in used_by` и оба вызовут extend_subscription —
    # юзер получит двойную подписку, а лимит max_uses обойдётся.
    with _STATE_LOCK:
        codes = load_promo_codes()
        promo = codes.get(code)
        if not promo:
            return jsonify({"error": "Промокод не найден"}), 404

        if promo.get("expires_at"):
            try:
                if datetime.fromisoformat(promo["expires_at"]) < datetime.now():
                    return jsonify({"error": "Срок промокода истёк"}), 400
            except Exception:
                pass

        max_uses = promo.get("max_uses") or 0
        uses = promo.get("uses", 0)
        if max_uses and uses >= max_uses:
            return jsonify({"error": "Промокод уже использован"}), 400

        used_by = promo.setdefault("used_by", [])
        email = session["email"]
        if email in used_by:
            return jsonify({"error": "Вы уже активировали этот промокод"}), 400

        days = int(promo.get("days", 0))
        unlimited = bool(promo.get("unlimited"))
        if not days and not unlimited:
            return jsonify({"error": "Некорректный промокод"}), 400

        if unlimited:
            set_unlimited(email, True)
        else:
            extend_subscription(email, days)

        used_by.append(email)
        promo["uses"] = uses + 1
        codes[code] = promo
        save_promo_codes(codes)

        sub = get_subscription(email)
    return jsonify({"ok": True, "subscription": sub, "days": days, "unlimited": unlimited})


# ---------- lava.top: создание оплаты + webhook ----------

# Маппинг paymentEventType из webhook lava → True если зачислять подписку.
_LAVA_SUCCESS_EVENTS = {
    "payment.success",
    "subscription.recurring.payment.success",
}
_LAVA_SUCCESS_STATUSES = {
    "completed",
    "subscription-active",
}


@app.route("/api/payment/lava/create", methods=["POST"])
@rate_limit(10, 60)
@idempotent
def api_payment_lava_create():
    """Юзер выбирает тариф → мы создаём invoice в lava.top → возвращаем
    payment_url, фронт делает window.location.href = payment_url."""
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    if not LAVA_API_KEY or not LAVA_OFFERS:
        return jsonify({"error": "Платежи через карту временно недоступны"}), 503

    tariff_id = data.get("tariff")
    if tariff_id not in TARIFFS:
        return jsonify({"error": "Неизвестный тариф"}), 400
    if tariff_id not in LAVA_OFFERS:
        return jsonify({"error": "Тариф недоступен для оплаты картой"}), 400

    email = session["email"]
    contract_id, payment_url, err = lava_create_invoice(email, tariff_id)
    if err:
        print(f"[lava] create_invoice failed for {email}/{tariff_id}: {err}", flush=True)
        # На этапе отладки возвращаем причину наружу — потом можно убрать.
        return jsonify({"error": "Не удалось создать платёж. Попробуйте позже.", "debug": err}), 502

    with _STATE_LOCK:
        payments = load_lava_payments()
        payments[contract_id] = {
            "email": email,
            "tariff": tariff_id,
            "days": TARIFFS[tariff_id]["days"],
            "amount": TARIFFS[tariff_id]["price"],
            "status": "pending",
            "created": datetime.now().isoformat(),
            "credited_at": None,
        }
        save_lava_payments(payments)

    return jsonify({
        "ok": True,
        "contract_id": contract_id,
        "payment_url": payment_url,
    })


@app.route("/api/payment/lava/status", methods=["POST"])
@rate_limit(60, 60)
def api_payment_lava_status():
    """Фронт после редиректа с lava.top пуляет сюда — узнать, прошёл ли webhook.
    Если да — обновить UI ('подписка активна'). Чужой contract_id не выдаём."""
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    contract_id = (data.get("contract_id") or "").strip()
    if not contract_id:
        return jsonify({"error": "contract_id обязателен"}), 400

    payments = load_lava_payments()
    p = payments.get(contract_id)
    if not p or p.get("email") != session["email"]:
        return jsonify({"error": "Платёж не найден"}), 404

    return jsonify({
        "status": p.get("status"),  # pending / credited / failed
        "credited_at": p.get("credited_at"),
        "tariff": p.get("tariff"),
        "days": p.get("days"),
        "amount": p.get("amount"),
    })


@app.route("/api/payment/lava/webhook/<secret>", methods=["POST"])
def api_payment_lava_webhook(secret):
    """Webhook от lava.top. Защита на двух уровнях:
    1) Секрет в URL пути — должен совпасть с LAVA_WEBHOOK_SECRET.
    2) После получения вебхука GET'им invoice через наш API-ключ — фейк
       вебхука этого не пройдёт, потому что чужой не знает наш X-Api-Key.
    Идемпотентность: если contract уже credited — просто 200 OK без действий."""
    if not LAVA_WEBHOOK_SECRET or not hmac.compare_digest(secret, LAVA_WEBHOOK_SECRET):
        # Не светим, что секрет не совпал — отвечаем как обычной 404.
        return jsonify({"error": "Not found"}), 404

    payload = request.get_json(silent=True) or {}
    event_type = payload.get("eventType") or ""
    contract_id = payload.get("contractId") or ""
    if not contract_id:
        return jsonify({"error": "contractId обязателен"}), 400

    # Двойная проверка через GET — не доверяем телу webhook'а слепо.
    invoice = lava_fetch_invoice(contract_id)
    if not invoice:
        print(f"[lava-webhook] cannot fetch invoice {contract_id}")
        return jsonify({"error": "cannot verify"}), 502

    invoice_status = (invoice.get("status") or "").lower()
    is_success = (event_type in _LAVA_SUCCESS_EVENTS) or (invoice_status in _LAVA_SUCCESS_STATUSES)

    with _STATE_LOCK:
        payments = load_lava_payments()
        p = payments.get(contract_id)
        if not p:
            # Webhook прилетел до того как мы записали платёж в локальную БД,
            # либо это вообще не наш платёж. Пытаемся восстановить по email из payload.
            buyer_email = (payload.get("buyer") or {}).get("email") or invoice.get("buyer", {}).get("email")
            if not buyer_email:
                print(f"[lava-webhook] unknown contract {contract_id}, no buyer email — ignore")
                return jsonify({"ok": True}), 200
            p = {
                "email": buyer_email.lower(),
                "tariff": None,
                "days": None,
                "amount": None,
                "status": "pending",
                "created": datetime.now().isoformat(),
                "credited_at": None,
                "recovered": True,
            }
            payments[contract_id] = p

        if p.get("status") == "credited":
            return jsonify({"ok": True, "already_credited": True}), 200

        if not is_success:
            # неуспешный или промежуточный статус — фиксируем, но не зачисляем
            p["status"] = "failed" if "fail" in event_type or invoice_status in ("failed", "cancelled") else "pending"
            p["last_event"] = event_type
            payments[contract_id] = p
            save_lava_payments(payments)
            return jsonify({"ok": True, "credited": False, "status": p["status"]}), 200

        # Успех — определяем сколько дней. Сначала из локальной записи, иначе по сумме.
        days = p.get("days")
        if not days:
            # Восстанавливаем по amount: ищем тариф с такой же ценой.
            amt = (invoice.get("amountTotal") or {}).get("amount") or payload.get("amount")
            try: amt = int(amt)
            except Exception: amt = None
            for tid, t in TARIFFS.items():
                # Спека lava не уточняет: amount в рублях или копейках. Проверяем оба варианта.
                if amt and (t["price"] == amt or t["price"] * 100 == amt):
                    p["tariff"] = tid
                    p["days"] = t["days"]
                    p["amount"] = amt
                    days = t["days"]
                    break
            if not days:
                print(f"[lava-webhook] cannot determine days for {contract_id}, amount={amt}")
                return jsonify({"error": "unknown tariff"}), 400

        extend_subscription(p["email"], int(days))
        p["status"] = "credited"
        p["credited_at"] = datetime.now().isoformat()
        p["last_event"] = event_type
        payments[contract_id] = p
        save_lava_payments(payments)

    # Восстанавливаем ключи юзера в xray, если они были отключены.
    _sync_user_xray_state(p["email"])

    print(f"[lava-webhook] credited {p['email']} +{days}d (contract={contract_id})")
    return jsonify({"ok": True, "credited": True}), 200


# ---------- Админские эндпоинты для подписок/платежей/промокодов ----------

def _require_admin():
    """Проверка пароля + IP-брутфорс на ВСЕХ админ-ручках (а не только /login).
    Иначе атакующий мог бы перебирать пароль через любую /api/admin/* без лимита."""
    ip = _get_client_ip()
    allowed, wait = _admin_brute_check(ip)
    if not allowed:
        mins = wait // 60 + 1
        return None, (jsonify({"error": f"Слишком много попыток. Подождите ~{mins} мин."}), 429)
    data = request.json or {}
    if _is_admin(data):
        return data, None
    _admin_brute_register_fail(ip)
    return None, (jsonify({"error": "Неверный пароль"}), 403)


@app.route("/api/admin/payments/list", methods=["POST"])
def admin_payments_list():
    data, err = _require_admin()
    if err: return err
    items = load_payment_requests()
    status_filter = data.get("status")
    if status_filter:
        items = [r for r in items if r.get("status") == status_filter]
    items.sort(key=lambda r: r.get("created", ""), reverse=True)
    return jsonify({"requests": items, "tariffs": TARIFFS})


@app.route("/api/admin/payments/approve", methods=["POST"])
def admin_payments_approve():
    data, err = _require_admin()
    if err: return err
    req_id = data.get("id")
    items = load_payment_requests()
    req = next((r for r in items if r.get("id") == req_id), None)
    if not req:
        return jsonify({"error": "Заявка не найдена"}), 404
    if req.get("status") != "pending":
        return jsonify({"error": "Заявка уже обработана"}), 400

    sub = extend_subscription(req["email"], int(req["days"]))
    req["status"] = "approved"
    req["resolved_at"] = datetime.now().isoformat()
    save_payment_requests(items)

    # Сразу восстанавливаем ключи юзера в xray, если они там отсутствовали
    _sync_user_xray_state(req["email"])

    return jsonify({"ok": True, "subscription": sub})


@app.route("/api/admin/payments/reject", methods=["POST"])
def admin_payments_reject():
    data, err = _require_admin()
    if err: return err
    req_id = data.get("id")
    items = load_payment_requests()
    req = next((r for r in items if r.get("id") == req_id), None)
    if not req:
        return jsonify({"error": "Заявка не найдена"}), 404
    if req.get("status") != "pending":
        return jsonify({"error": "Заявка уже обработана"}), 400
    req["status"] = "rejected"
    req["resolved_at"] = datetime.now().isoformat()
    req["reason"] = data.get("reason", "")
    save_payment_requests(items)
    return jsonify({"ok": True})


@app.route("/api/admin/subscription/extend", methods=["POST"])
def admin_subscription_extend():
    data, err = _require_admin()
    if err: return err
    email = (data.get("email") or "").strip().lower()
    days = int(data.get("days") or 0)
    if not email or days <= 0:
        return jsonify({"error": "Нужен email и дни > 0"}), 400
    sub = extend_subscription(email, days)
    _sync_user_xray_state(email)
    return jsonify({"ok": True, "subscription": sub})


@app.route("/api/admin/subscription/unlimited", methods=["POST"])
def admin_subscription_unlimited():
    data, err = _require_admin()
    if err: return err
    email = (data.get("email") or "").strip().lower()
    enabled = bool(data.get("enabled"))
    if not email:
        return jsonify({"error": "Нужен email"}), 400
    set_unlimited(email, enabled)
    _sync_user_xray_state(email)
    return jsonify({"ok": True, "subscription": get_subscription(email)})


@app.route("/api/admin/subscription/revoke", methods=["POST"])
def admin_subscription_revoke():
    data, err = _require_admin()
    if err: return err
    email = (data.get("email") or "").strip().lower()
    if not email:
        return jsonify({"error": "Нужен email"}), 400
    revoke_subscription(email)
    _sync_user_xray_state(email)
    return jsonify({"ok": True})


@app.route("/api/admin/subscription/list", methods=["POST"])
def admin_subscription_list():
    data, err = _require_admin()
    if err: return err
    subs = load_subscriptions()
    result = []
    for email, s in subs.items():
        entry = dict(s)
        entry["email"] = email
        active = False
        if s.get("plan") == "unlimited":
            active = True
        elif s.get("expires_at"):
            try:
                active = datetime.fromisoformat(s["expires_at"]) > datetime.now()
            except Exception:
                active = False
        entry["active"] = active
        result.append(entry)
    result.sort(key=lambda x: (not x["active"], x["email"]))
    return jsonify(result)


@app.route("/api/admin/promo/list", methods=["POST"])
def admin_promo_list():
    data, err = _require_admin()
    if err: return err
    codes = load_promo_codes()
    result = []
    for code, p in codes.items():
        result.append({"code": code, **p})
    result.sort(key=lambda x: x.get("created", ""), reverse=True)
    return jsonify(result)


@app.route("/api/admin/promo/create", methods=["POST"])
def admin_promo_create():
    data, err = _require_admin()
    if err: return err
    code = (data.get("code") or "").strip().upper()
    if not code or not re.match(r"^[A-Z0-9_-]{3,32}$", code):
        return jsonify({"error": "Код: 3–32 символа, A-Z/0-9/_-"}), 400

    codes = load_promo_codes()
    if code in codes:
        return jsonify({"error": "Такой код уже существует"}), 400

    days = int(data.get("days") or 0)
    unlimited = bool(data.get("unlimited"))
    max_uses = int(data.get("max_uses") or 0)
    expires_in_days = int(data.get("expires_in_days") or 0)

    if not days and not unlimited:
        return jsonify({"error": "Нужно указать дни или unlimited"}), 400

    entry = {
        "days": days,
        "unlimited": unlimited,
        "max_uses": max_uses,
        "uses": 0,
        "used_by": [],
        "created": datetime.now().isoformat(),
    }
    if expires_in_days > 0:
        entry["expires_at"] = (datetime.now() + timedelta(days=expires_in_days)).isoformat()

    codes[code] = entry
    save_promo_codes(codes)
    return jsonify({"ok": True, "code": code, **entry})


@app.route("/api/admin/promo/delete", methods=["POST"])
def admin_promo_delete():
    data, err = _require_admin()
    if err: return err
    code = (data.get("code") or "").strip().upper()
    codes = load_promo_codes()
    if code not in codes:
        return jsonify({"error": "Код не найден"}), 404
    del codes[code]
    save_promo_codes(codes)
    return jsonify({"ok": True})


# ---------- Фоновая синхронизация Xray и истёкших подписок ----------

def _sync_user_xray_state(email):
    """
    Приводит состояние ключей юзера в xray в соответствие с подпиской:
    - подписка активна → все его ключи должны быть в xray + в /var/www/sub
    - подписка неактивна → удаляем из xray и из sub (но запись users.json сохраняем,
      чтобы при продлении можно было восстановить)
    Легаси-пользователей без email пропускаем — ими рулит админ вручную.
    """
    if not email:
        return
    email = email.lower()
    users = load_users()
    mine = [u for u in users if (u.get("email") or "").lower() == email]
    if not mine:
        return

    active = is_subscribed(email)
    changed = False

    for u in mine:
        in_xray = u.get("in_xray", True)  # legacy: считаем что в xray
        username = u["username"]
        server_key = u["server"]

        if active and not in_xray:
            try:
                add_to_xray(u["uuid"], server_key, username)
                # При восстановлении — создаём новый Hy2-пароль, если его не было
                hy_pw = u.get("hysteria_password")
                if not hy_pw:
                    hy_pw = add_to_hysteria_safe(server_key, username)
                    if hy_pw:
                        u["hysteria_password"] = hy_pw
                update_subscription(u["uuid"], server_key, username, hy_pw)
                u["in_xray"] = True
                changed = True
                print(f"[sub-sync] restored {username} ({email})")
            except Exception as e:
                print(f"[sub-sync] restore failed for {username}: {e}")

        elif not active and in_xray:
            try:
                remove_from_xray(u["uuid"], server_key)
                remove_from_hysteria_safe(server_key, username)
                sub_path = os.path.join(SUB_DIR, sub_slug(username, u["uuid"]))
                if os.path.exists(sub_path):
                    os.remove(sub_path)
                u["in_xray"] = False
                changed = True
                print(f"[sub-sync] revoked {username} ({email})")
            except Exception as e:
                print(f"[sub-sync] revoke failed for {username}: {e}")

    if changed:
        save_users(users)


def _subscription_sweeper():
    """Раз в 10 минут сверяет всех юзеров с email и их подписки."""
    while True:
        try:
            users = load_users()
            emails = {(u.get("email") or "").lower() for u in users if u.get("email")}
            for email in emails:
                _sync_user_xray_state(email)
        except Exception as e:
            print(f"[sub-sweeper] error: {e}")
        time.sleep(600)


def _is_admin(data):
    # compare_digest — защита от timing attack. Сетевой шум маскирует разницу,
    # но фикс ничего не стоит, поэтому он есть.
    if not ADMIN_PASSWORD:
        return False
    pw = data.get("password") or ""
    return hmac.compare_digest(pw, ADMIN_PASSWORD)


@app.route("/admin")
def admin_page():
    return send_from_directory("static", "admin.html")


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    # _get_client_ip — за nginx remote_addr=127.0.0.1, без X-Forwarded-For
    # все попытки делили бы один счётчик и брутфорс-защита превратилась бы в DoS-самоблокировку.
    ip = _get_client_ip()
    allowed, wait = _admin_brute_check(ip)
    if not allowed:
        mins = wait // 60 + 1
        return jsonify({"error": f"Слишком много попыток. Подождите ~{mins} мин."}), 429
    data = request.json or {}
    if _is_admin(data):
        _admin_brute_clear(ip)
        return jsonify({"ok": True})
    _admin_brute_register_fail(ip)
    return jsonify({"error": "Неверный пароль"}), 403


@app.route("/api/health", methods=["GET"])
def health():
    """Публичный healthcheck для внешнего мониторинга. Если Flask умер —
    endpoint не ответит вообще; если что-то сломано внутри — вернём 500."""
    try:
        load_users()
    except Exception as e:
        return jsonify({"ok": False, "error": f"users.json: {e}"}), 500
    return jsonify({"ok": True, "ts": int(time.time())}), 200


def load_traffic_snapshot():
    if os.path.exists(TRAFFIC_SNAPSHOT_FILE):
        try:
            with open(TRAFFIC_SNAPSHOT_FILE, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_traffic_snapshot(snap):
    with open(TRAFFIC_SNAPSHOT_FILE, "w") as f:
        json.dump(snap, f)


@app.route("/api/admin/stats", methods=["POST"])
def admin_stats():
    data, err = _require_admin()
    if err: return err

    users = load_users()
    snapshot = load_traffic_snapshot()
    now = datetime.now()
    now_iso = now.isoformat()

    # Один запрос статистики на сервер, затем выбираем per-user
    stats_by_server = {}
    for srv_key in SERVERS:
        stats_by_server[srv_key] = query_xray_stats(srv_key)

    result = []
    new_snapshot = {}

    for u in users:
        username = u["username"]
        srv_key = u["server"]
        srv_stats = stats_by_server.get(srv_key, {})
        traffic = srv_stats.get(username, {"up": 0, "down": 0})

        prev = snapshot.get(username, {})
        prev_total = prev.get("up", 0) + prev.get("down", 0)
        curr_total = traffic["up"] + traffic["down"]

        if curr_total > prev_total:
            last_active = now_iso
        else:
            last_active = prev.get("last_active")

        online = False
        if last_active:
            try:
                delta = (now - datetime.fromisoformat(last_active)).total_seconds()
                online = delta < ONLINE_THRESHOLD_SECONDS
            except Exception:
                online = False

        new_snapshot[username] = {
            "up": traffic["up"],
            "down": traffic["down"],
            "last_active": last_active
        }

        result.append({
            "username": username,
            "email": u.get("email", "—"),
            "server": srv_key,
            "server_name": SERVERS[srv_key]["name"],
            "server_flag": SERVERS[srv_key]["flag"],
            "created": u.get("created", ""),
            "traffic_up": traffic["up"],
            "traffic_down": traffic["down"],
            "online": online,
            "last_active": last_active,
        })

    save_traffic_snapshot(new_snapshot)

    result.sort(key=lambda x: (not x["online"], -(x["traffic_up"] + x["traffic_down"])))

    return jsonify({
        "users": result,
        "total": len(users),
        "online_count": sum(1 for u in result if u["online"]),
    })


@app.route("/api/admin/servers-stats", methods=["POST"])
def admin_servers_stats():
    data, err = _require_admin()
    if err: return err
    force = bool(data.get("refresh"))
    result, cached = get_servers_stats(force_refresh=force)
    return jsonify({
        "servers": result,
        "cached": cached,
        "cache_ttl": _SERVER_METRICS_TTL,
        "ts": int(_SERVER_METRICS_CACHE["ts"]),
    })


BACKUP_SCRIPT = "/opt/vpn-site/backup.sh"
BACKUP_DIR = "/opt/vpn-site/backups"


@app.route("/api/admin/backups", methods=["POST"])
def admin_backups_list():
    """Список локальных бэкапов."""
    data, err = _require_admin()
    if err: return err

    items = []
    if os.path.isdir(BACKUP_DIR):
        for name in os.listdir(BACKUP_DIR):
            if not (name.startswith("bypass-backup-") and name.endswith(".tar.gz")):
                continue
            path = os.path.join(BACKUP_DIR, name)
            try:
                st = os.stat(path)
                items.append({
                    "name": name,
                    "size": st.st_size,
                    "mtime": int(st.st_mtime),
                })
            except OSError:
                continue
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return jsonify({"backups": items, "dir": BACKUP_DIR})


# ---------- Управление серверами (Phase 3b) ----------
# Предполагается, что SSH-ключ root@amsterdam уже добавлен в authorized_keys
# нового сервера при его провиженинге у хостера. Мы не просим пароль у админа.

SITE_DIR = os.path.dirname(os.path.abspath(__file__))
INSTALL_XRAY_SH = os.path.join(SITE_DIR, "install_xray.sh")
INSTALL_HYSTERIA_SH = os.path.join(SITE_DIR, "install_hysteria.sh")


def _gen_server_key(country_code, existing_keys):
    """Генерит уникальный slug по коду страны: nl, nl2, nl3..."""
    cc = (country_code or "xx").lower()[:2]
    if cc and cc not in existing_keys:
        return cc
    for i in range(2, 100):
        k = f"{cc}{i}"
        if k not in existing_keys:
            return k
    return f"srv{secrets.token_hex(3)}"


def _ssh_probe(ip, user="root", timeout=8):
    """Пробует SSH-коннект. Возвращает (ok: bool, error: str)."""
    try:
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
             "-o", f"ConnectTimeout={timeout}", f"{user}@{ip}", "echo ok"],
            capture_output=True, text=True, timeout=timeout + 5,
        )
        if r.returncode == 0 and "ok" in r.stdout:
            return True, ""
        return False, (r.stderr or "нет ответа").strip()[:400]
    except subprocess.TimeoutExpired:
        return False, "timeout"
    except Exception as e:
        return False, str(e)[:400]


def _scp_and_run(ip, user, local_script, remote_path, timeout=180):
    """Копирует скрипт на сервер и запускает его. Возвращает (rc, stdout, stderr)."""
    scp = subprocess.run(
        ["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
         local_script, f"{user}@{ip}:{remote_path}"],
        capture_output=True, text=True, timeout=60,
    )
    if scp.returncode != 0:
        return scp.returncode, "", f"scp failed: {scp.stderr.strip()}"
    run = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
         f"{user}@{ip}", f"bash {remote_path}"],
        capture_output=True, text=True, timeout=timeout,
    )
    return run.returncode, run.stdout, run.stderr


@app.route("/api/admin/servers/list", methods=["POST"])
def admin_servers_list():
    """Возвращает все сервера (seed + overrides) + их статус из server_status.json."""
    data, err = _require_admin()
    if err: return err
    store = load_servers_store()
    status = _load_json(SERVER_STATUS_FILE, {})
    users = load_users()
    counts = {}
    for u in users:
        srv = u.get("server")
        if srv: counts[srv] = counts.get(srv, 0) + 1
    items = []
    for key, cfg in SERVERS.items():
        items.append({
            "key": key,
            "name": cfg.get("name"),
            "flag": cfg.get("flag"),
            "country": cfg.get("country"),
            "ip": cfg.get("ip"),
            "port": cfg.get("port"),
            "remote": cfg.get("remote", True),
            "bandwidth_mbps": cfg.get("bandwidth_mbps"),
            "max_users": capacity_for_server(cfg),
            "backup_for": cfg.get("backup_for"),
            "disabled": bool(cfg.get("disabled")),
            "users_count": counts.get(key, 0),
            "from_seed": key in _SEED_SERVERS,
            "status": status.get(key, {}),
        })
    items.sort(key=lambda x: (x["country"] or "zz", x["key"]))
    return jsonify({
        "servers": items,
        "capacity_rule": {
            "peak_mbps_per_user": CAPACITY_PEAK_MBPS,
            "concurrency": CAPACITY_CONCURRENCY,
        },
    })


@app.route("/api/admin/servers/add", methods=["POST"])
@idempotent
def admin_servers_add():
    """Добавляет сервер: проверяет SSH, ставит xray+hysteria, пишет в servers.json.

    Вход: {password, ip, country, name, flag, bandwidth_mbps, ssh_user?, backup_for?}
    SSH-ключ от Амстердама должен быть заранее прописан в ~/.ssh/authorized_keys на цели."""
    data, err = _require_admin()
    if err: return err

    ip = (data.get("ip") or "").strip()
    country = (data.get("country") or "").strip().upper()
    name = (data.get("name") or "").strip()
    flag = (data.get("flag") or "").strip()
    ssh_user = (data.get("ssh_user") or "root").strip()
    # ssh попадает в argv (не shell=True), но `-oProxyCommand=...` в роли user
    # теоретически может быть интерпретирован OpenSSH'ем — фильтруем.
    if not re.match(r"^[a-z_][a-z0-9_-]{0,31}$", ssh_user):
        return jsonify({"error": "Неверный ssh_user (a-z, 0-9, _-, до 32 симв)"}), 400
    backup_for = (data.get("backup_for") or "").strip() or None
    try:
        bandwidth_mbps = int(data.get("bandwidth_mbps") or 50)
    except Exception:
        return jsonify({"error": "bandwidth_mbps должен быть целым числом"}), 400

    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
        return jsonify({"error": "IP имеет неверный формат"}), 400
    if not country or not re.match(r"^[A-Z]{2}$", country):
        return jsonify({"error": "country должен быть ISO-кодом из 2 букв (RU, NL, US...)"}), 400
    if not name:
        return jsonify({"error": "Укажи название (например, 'Германия')"}), 400
    if bandwidth_mbps < 10:
        return jsonify({"error": "bandwidth_mbps слишком мал (минимум 10)"}), 400

    # Уникальность IP
    for k, cfg in SERVERS.items():
        if cfg.get("ip") == ip:
            return jsonify({"error": f"Сервер с IP {ip} уже добавлен (key={k})"}), 409

    if backup_for and backup_for not in SERVERS:
        return jsonify({"error": f"backup_for={backup_for} — нет такого сервера"}), 400

    # 1. SSH probe
    ok, err_msg = _ssh_probe(ip, ssh_user, timeout=8)
    if not ok:
        return jsonify({
            "error": f"SSH до {ssh_user}@{ip} не работает. Добавь публичный ключ Амстердама в authorized_keys.",
            "ssh_error": err_msg,
        }), 400

    # 2. Установка Xray
    if not os.path.isfile(INSTALL_XRAY_SH):
        return jsonify({"error": f"Скрипт не найден: {INSTALL_XRAY_SH}"}), 500
    rc, stdout, stderr = _scp_and_run(ip, ssh_user, INSTALL_XRAY_SH, "/root/install_xray.sh", timeout=240)
    if rc != 0:
        return jsonify({"error": "Установка xray не удалась", "stderr": stderr[-1500:], "stdout": stdout[-1500:]}), 500
    m = re.search(r'\{"pbk":\s*"([^"]+)",\s*"sid":\s*"([^"]+)",\s*"sni":\s*"([^"]+)",\s*"port":\s*(\d+)\}', stdout)
    if not m:
        return jsonify({"error": "install_xray.sh не вернул JSON с ключами", "stdout": stdout[-2000:]}), 500
    pbk, sid, sni, port = m.group(1), m.group(2), m.group(3), int(m.group(4))

    # 3. Установка Hysteria
    if not os.path.isfile(INSTALL_HYSTERIA_SH):
        return jsonify({"error": f"Скрипт не найден: {INSTALL_HYSTERIA_SH}"}), 500
    rc, stdout2, stderr2 = _scp_and_run(ip, ssh_user, INSTALL_HYSTERIA_SH, "/root/install_hysteria.sh", timeout=240)
    if rc != 0:
        return jsonify({"error": "Установка hysteria не удалась", "stderr": stderr2[-1500:], "stdout": stdout2[-1500:]}), 500

    # 4. Пишем в servers.json
    store = load_servers_store()
    existing_keys = set(SERVERS.keys()) | set(store.get("servers", {}).keys())
    new_key = _gen_server_key(country, existing_keys)

    entry = {
        "name": name,
        "country": country,
        "flag": flag or "🏳️",
        "ip": ip,
        "port": port,
        "security": "reality",
        "sni": sni,
        "pbk": pbk,
        "sid": sid,
        "fp": "chrome",
        "xray_config": "/usr/local/etc/xray/config.json",
        "remote": True,
        "ssh": f"{ssh_user}@{ip}",
        "bandwidth_mbps": bandwidth_mbps,
    }
    if backup_for:
        entry["backup_for"] = backup_for

    store.setdefault("servers", {})[new_key] = entry
    # на случай если этот key был в deleted — убираем
    if new_key in (store.get("deleted") or []):
        store["deleted"] = [k for k in store["deleted"] if k != new_key]
    save_servers_store(store)
    reload_servers()

    return jsonify({
        "ok": True,
        "key": new_key,
        "server": {**entry, "max_users": capacity_for_server(entry)},
    })


@app.route("/api/admin/servers/update", methods=["POST"])
def admin_servers_update():
    """Правит поля сервера. Вход: {password, key, bandwidth_mbps?, name?, flag?,
    max_users?, backup_for?, disabled?}."""
    data, err = _require_admin()
    if err: return err

    key = (data.get("key") or "").strip()
    if key not in SERVERS:
        return jsonify({"error": "Сервер не найден"}), 404

    store = load_servers_store()
    overrides = store.setdefault("servers", {})
    patch = overrides.get(key, {})

    for field in ("name", "flag", "country"):
        if field in data and isinstance(data[field], str):
            patch[field] = data[field].strip() or None
    for field in ("bandwidth_mbps", "max_users"):
        if field in data and data[field] is not None:
            try:
                v = int(data[field])
                if v <= 0: raise ValueError
                patch[field] = v
            except Exception:
                return jsonify({"error": f"{field}: нужен положительный int"}), 400
    if "backup_for" in data:
        bf = (data["backup_for"] or "").strip() or None
        if bf and bf not in SERVERS:
            return jsonify({"error": f"backup_for={bf} — нет такого сервера"}), 400
        patch["backup_for"] = bf
    if "disabled" in data:
        patch["disabled"] = bool(data["disabled"])

    overrides[key] = patch
    save_servers_store(store)
    reload_servers()
    return jsonify({"ok": True, "server": {**SERVERS[key], "max_users": capacity_for_server(SERVERS[key])}})


@app.route("/api/admin/servers/status", methods=["POST"])
def admin_servers_status():
    """Возвращает состояние health-checker'а: failover state, последний чек."""
    _, err = _require_admin()
    if err: return err
    status = _load_server_status()
    return jsonify({
        "status": status,
        "interval_sec": HEALTH_CHECK_INTERVAL_SEC,
        "fail_threshold": HEALTH_FAIL_THRESHOLD,
        "ok_threshold": HEALTH_OK_THRESHOLD,
        "now": int(time.time()),
    })


@app.route("/api/admin/servers/failover-run", methods=["POST"])
def admin_failover_run():
    """Принудительный прогон health-check. Для отладки."""
    _, err = _require_admin()
    if err: return err
    _health_tick()
    return jsonify({"ok": True, "status": _load_server_status()})


@app.route("/api/admin/servers/remove", methods=["POST"])
def admin_servers_remove():
    """Удаляет сервер. С force=true удалит даже при наличии юзеров (они останутся в users.json
    со сломанным server — их надо будет потом подвигать руками через админку)."""
    data, err = _require_admin()
    if err: return err

    key = (data.get("key") or "").strip()
    force = bool(data.get("force"))
    if key not in SERVERS:
        return jsonify({"error": "Сервер не найден"}), 404

    users = load_users()
    active = [u for u in users if u.get("server") == key]
    if active and not force:
        return jsonify({
            "error": f"На сервере {key} ещё {len(active)} юзер(ов). Передай force=true чтобы удалить всё равно.",
            "users": len(active),
        }), 409

    store = load_servers_store()
    store.setdefault("deleted", [])
    if key not in store["deleted"]:
        store["deleted"].append(key)
    # если был в overrides — чистим чтобы не воскрес при следующем build_servers
    store.setdefault("servers", {}).pop(key, None)
    save_servers_store(store)
    reload_servers()
    return jsonify({"ok": True, "removed_key": key, "orphaned_users": len(active)})


@app.route("/api/admin/backup-now", methods=["POST"])
def admin_backup_now():
    """Запуск бэкапа вручную. Ничего не перезапускает — читает JSON и копирует."""
    data, err = _require_admin()
    if err: return err

    if not os.path.isfile(BACKUP_SCRIPT):
        return jsonify({"error": f"Скрипт не найден: {BACKUP_SCRIPT}"}), 500

    try:
        proc = subprocess.run(
            ["bash", BACKUP_SCRIPT],
            capture_output=True, text=True, timeout=300
        )
        return jsonify({
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout[-4000:],
            "stderr": proc.stderr[-2000:],
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Бэкап не уложился в 5 минут"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/delete", methods=["POST"])
def delete_user():
    data, err = _require_admin()
    if err: return err

    username = data.get("username", "")
    users = load_users()
    user = next((u for u in users if u["username"].lower() == username.lower()), None)

    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    server_key = user["server"]

    try:
        remove_from_xray(user["uuid"], server_key)
    except Exception as e:
        return jsonify({"error": f"Ошибка удаления из Xray: {str(e)}"}), 500

    sub_path = os.path.join(SUB_DIR, sub_slug(user["username"], user["uuid"]))
    if os.path.exists(sub_path):
        os.remove(sub_path)

    users = [u for u in users if u["uuid"] != user["uuid"]]
    save_users(users)

    return jsonify({"ok": True})

@app.route("/sub/<filename>")
def serve_subscription(filename):
    # send_from_directory нормализует путь и режет .. / абсолютные пути -> 404.
    # Имя файла без слешей уже ограничено <filename> (не <path:>).
    return send_from_directory(SUB_DIR, filename, mimetype="text/plain")

ISSUE_LABELS = {
    "offline": "Сервер не отвечает",
    "xray_stopped": "Xray остановлен",
    "hysteria_stopped": "Hysteria 2 остановлен",
    "overload": f"Перегрузка CPU (load > {ALERT_LOAD_RATIO}× ядер)",
    "mem_high": f"Память занята > {ALERT_MEM_PCT}%",
}


def _load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return default


def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.replace(tmp, path)


def compute_server_issues(s):
    """Возвращает отсортированный список кодов проблем для метрик сервера.
    hysteria_stopped проверяется только если протокол установлен — иначе его отсутствие не алерт."""
    issues = []
    if not s.get("online"):
        issues.append("offline")
    else:
        if s.get("xray_active") is False:
            issues.append("xray_stopped")
        if s.get("hysteria_installed") and s.get("hysteria_active") is False:
            issues.append("hysteria_stopped")
        load = s.get("load_1m")
        cpu = s.get("cpu_count") or 1
        if load is not None and cpu and (load / cpu) > ALERT_LOAD_RATIO:
            issues.append("overload")
        mem_t, mem_u = s.get("mem_total"), s.get("mem_used")
        if mem_t and mem_u and (mem_u / mem_t * 100) > ALERT_MEM_PCT:
            issues.append("mem_high")
    return sorted(issues)


def send_admin_email(subject, body_html):
    """Отправляет письмо на ADMIN_EMAIL. Возвращает True при успехе."""
    if not (ADMIN_EMAIL and SMTP_CONFIG["password"] and SMTP_CONFIG["username"]):
        return False
    try:
        msg = MIMEMultipart()
        msg['From'] = f"WIREX Alerts <{SMTP_CONFIG['username']}>"
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = subject
        msg.attach(MIMEText(body_html, 'html'))
        server = smtplib.SMTP(SMTP_CONFIG["server"], SMTP_CONFIG["port"])
        server.starttls()
        server.login(SMTP_CONFIG["username"], SMTP_CONFIG["password"])
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"[alerts] email error: {e}")
        return False


def _append_alert_log(entry):
    log = _load_json(ALERTS_LOG_FILE, [])
    log.append(entry)
    if len(log) > ALERTS_LOG_MAX:
        log = log[-ALERTS_LOG_MAX:]
    _save_json(ALERTS_LOG_FILE, log)


def _build_alert_email(srv_key, srv, new_issues, resolved_issues):
    s = SERVERS.get(srv_key, {})
    title = f"{s.get('flag','')} {s.get('name', srv_key)}"
    rows = []
    if new_issues:
        rows.append("<b style='color:#c7183d'>Новые проблемы:</b><ul>" +
                    "".join(f"<li>{ISSUE_LABELS.get(i,i)}</li>" for i in new_issues) + "</ul>")
    if resolved_issues:
        rows.append("<b style='color:#1a7f37'>Восстановилось:</b><ul>" +
                    "".join(f"<li>{ISSUE_LABELS.get(i,i)}</li>" for i in resolved_issues) + "</ul>")
    load = srv.get("load_1m")
    cpu = srv.get("cpu_count")
    mem_t = srv.get("mem_total"); mem_u = srv.get("mem_used")
    mem_pct = round(mem_u / mem_t * 100) if (mem_t and mem_u) else None
    body = f"""
    <html><body style='font-family:Arial,sans-serif;max-width:600px'>
    <h2 style='margin:0 0 8px'>⚠️ WIREX alerts — {title}</h2>
    <div style='color:#666;font-size:12px;margin-bottom:16px'>{s.get('ip','')}:{s.get('port','')}</div>
    {''.join(rows)}
    <hr style='border:none;border-top:1px solid #ddd;margin:16px 0'>
    <div style='font-size:12px;color:#444'>
      online: <b>{srv.get('online')}</b> · xray: <b>{srv.get('xray_active')}</b>
      · load 1m/5m/15m: <b>{load}</b> / {srv.get('load_5m')} / {srv.get('load_15m')} на {cpu or '?'} CPU
      · mem: <b>{mem_pct if mem_pct is not None else '?'}%</b>
      · latency: {srv.get('latency_ms','?')} мс
    </div>
    </body></html>
    """
    subj_parts = [f"[WIREX] {s.get('name', srv_key)}"]
    if new_issues: subj_parts.append("PROBLEM: " + ", ".join(new_issues))
    if resolved_issues and not new_issues: subj_parts.append("RECOVERED: " + ", ".join(resolved_issues))
    return " · ".join(subj_parts), body


def check_and_alert():
    """Разовая проверка: сравнивает состояние с прошлым, отправляет алерты на переходы.
    Можно звать из фона или вручную через админский эндпоинт."""
    metrics, _ = get_servers_stats(force_refresh=True)
    state = _load_json(ALERTS_STATE_FILE, {"servers": {}})
    by_key = state.setdefault("servers", {})
    now = int(time.time())
    events = []

    for srv in metrics:
        k = srv["key"]
        curr_issues = compute_server_issues(srv)
        prev = by_key.get(k, {"issues": [], "last_alert_ts": 0, "alerted_issues": []})
        prev_issues = prev.get("issues", [])
        prev_alerted = prev.get("alerted_issues", [])
        last_ts = prev.get("last_alert_ts", 0)

        new = [i for i in curr_issues if i not in prev_issues]
        resolved = [i for i in prev_issues if i not in curr_issues]

        should_alert = False
        if new or resolved:
            should_alert = True
        elif curr_issues and curr_issues != prev_alerted and (now - last_ts) > ALERTS_COOLDOWN_SEC:
            # cooldown истёк и проблемы всё ещё есть — напоминание
            new = curr_issues
            should_alert = True

        if should_alert and (new or resolved):
            subj, body = _build_alert_email(k, srv, new, resolved)
            ok = send_admin_email(subj, body)
            events.append({
                "ts": now, "server": k, "server_name": srv.get("name", k),
                "new": new, "resolved": resolved,
                "email_sent": ok, "email_target": ADMIN_EMAIL or None,
            })
            _append_alert_log(events[-1])
            by_key[k] = {"issues": curr_issues, "last_alert_ts": now, "alerted_issues": curr_issues}
        else:
            by_key[k] = {"issues": curr_issues, "last_alert_ts": last_ts, "alerted_issues": prev_alerted}

    _save_json(ALERTS_STATE_FILE, state)
    return events


def _alerts_watcher():
    """Фон: раз в ALERTS_CHECK_INTERVAL_SEC проверяем серверы и шлём письма."""
    # Небольшая пауза при старте, чтобы не спамить если сервер только что перезагрузили
    time.sleep(30)
    while True:
        try:
            check_and_alert()
        except Exception as e:
            print(f"[alerts] watcher error: {e}")
        time.sleep(ALERTS_CHECK_INTERVAL_SEC)


@app.route("/api/admin/alerts", methods=["POST"])
def admin_alerts():
    """Текущее состояние + лог последних событий."""
    _, err = _require_admin()
    if err: return err
    state = _load_json(ALERTS_STATE_FILE, {"servers": {}})
    log = _load_json(ALERTS_LOG_FILE, [])
    current = []
    for srv_key, info in (state.get("servers") or {}).items():
        current.append({
            "server": srv_key,
            "name": SERVERS.get(srv_key, {}).get("name", srv_key),
            "flag": SERVERS.get(srv_key, {}).get("flag", ""),
            "issues": info.get("issues", []),
            "last_alert_ts": info.get("last_alert_ts", 0),
        })
    current.sort(key=lambda x: (not x["issues"], x["server"]))
    return jsonify({
        "current": current,
        "log": list(reversed(log[-50:])),
        "admin_email": ADMIN_EMAIL or None,
        "labels": ISSUE_LABELS,
        "interval_sec": ALERTS_CHECK_INTERVAL_SEC,
        "cooldown_sec": ALERTS_COOLDOWN_SEC,
    })


@app.route("/api/admin/alerts-run", methods=["POST"])
def admin_alerts_run():
    """Принудительная проверка (не ждать 5 минут)."""
    _, err = _require_admin()
    if err: return err
    events = check_and_alert()
    return jsonify({"ok": True, "events": events})


@app.route("/api/admin/alerts-test", methods=["POST"])
def admin_alerts_test():
    """Тестовое письмо — проверить, что SMTP и admin_email настроены."""
    _, err = _require_admin()
    if err: return err
    if not ADMIN_EMAIL:
        return jsonify({"error": "admin_email не задан в secrets.json"}), 400
    ok = send_admin_email(
        "[WIREX] Тестовое письмо алертов",
        "<p>Это тестовое сообщение из админ-панели WIREX. Если вы его получили — алерты настроены корректно.</p>"
    )
    return jsonify({"ok": ok, "admin_email": ADMIN_EMAIL})


if __name__ == "__main__":
    t = threading.Thread(target=_subscription_sweeper, daemon=True)
    t.start()
    if ADMIN_EMAIL:
        ta = threading.Thread(target=_alerts_watcher, daemon=True)
        ta.start()
    else:
        print("WARNING: admin_email не задан — алерты выключены")
    th = threading.Thread(target=_health_worker, daemon=True)
    th.start()
    app.run(host="0.0.0.0", port=8080)