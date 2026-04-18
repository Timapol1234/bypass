from flask import Flask, jsonify, request, send_from_directory
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
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

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

# Тарифы: дни → цена в рублях
TARIFFS = {
    "1mo":  {"days": 30,  "price": 99,  "label": "1 месяц"},
    "3mo":  {"days": 90,  "price": 269, "label": "3 месяца"},
    "6mo":  {"days": 180, "price": 499, "label": "6 месяцев"},
    "12mo": {"days": 365, "price": 899, "label": "12 месяцев"},
}

# Хост, с которого раздаются файлы подписок (файлы лежат только на NL-сервере)
SUB_HOST = "109.248.162.180:8080"

# Время жизни сессии
SESSION_TTL_DAYS = 30
# Минимальный интервал между запросами кода на один email (секунды)
OTP_RESEND_COOLDOWN = 60
# Юзер считается online, если трафик рос в последние N секунд
ONLINE_THRESHOLD_SECONDS = 120


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

# 4 сервера с правильными параметрами
SERVERS = {
    "amsterdam": {
        "name": "Амстердам",
        "flag": "🇳🇱",
        "ip": "109.248.162.180",
        "port": 443,
        "security": "reality",
        "sni": "www.microsoft.com",
        "pbk": "YfQM06_AHria4kt_wURFu1CfWtoytNDUgakGp5NelhY",
        "sid": "abcd1234",
        "fp": "chrome",
        "xray_config": "/usr/local/etc/xray/config.json",
        "remote": False
    },
    "usa": {
        "name": "США",
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
        "ssh": "root@31.56.229.94"
    },
    "finland": {
        "name": "Финляндия",
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
        "ssh": "root@109.248.161.20"
    },
    "france": {
        "name": "Франция",
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
        "ssh": "root@45.38.23.141"
    }
}

ADMIN_PASSWORD = _secrets.get("admin_password", "")

if not ADMIN_PASSWORD:
    print("WARNING: admin_password не задан — админ-эндпоинты будут отклонять все запросы")
if not SMTP_CONFIG["password"]:
    print("WARNING: smtp_password не задан — отправка email работать не будет")

# CORS поддержка
@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    return response

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
        msg['From'] = f"BYPASS <{SMTP_CONFIG['username']}>"
        msg['To'] = email
        msg['Subject'] = "Подтверждение email - BYPASS VPN"
        
        body = f"""
        <html>
        <head>
            <meta charset="UTF-8">
        </head>
        <body style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
            <div style="background: linear-gradient(135deg, #8ff5ff 0%, #00eefc 100%); padding: 20px; text-align: center; border-radius: 10px 10px 0 0;">
                <h1 style="color: #005d63; margin: 0;">BYPASS VPN</h1>
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
def send_code():
    data = request.json
    email = data.get("email", "").strip().lower()

    if not email or not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
        return jsonify({"error": "Введите корректный email"}), 400

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
    
    if code_data["code"] != code:
        return jsonify({"error": "Неверный код"}), 400
    
    del codes[email]
    save_verification_codes(codes)

    session_token = create_session(email)

    return jsonify({
        "ok": True,
        "token": session_token,
        "email": email
    })

@app.route('/api/verify-session', methods=['POST'])
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


def build_vless_url(user_uuid, server_key, name):
    s = SERVERS[server_key]
    return (
        f"vless://{user_uuid}@{s['ip']}:{s['port']}"
        f"?encryption=none&type=tcp&security={s['security']}"
        f"&sni={s['sni']}&pbk={s['pbk']}&sid={s['sid']}"
        f"&fp={s['fp']}&flow=#{name}"
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
    r = subprocess.run(cmd, input=script, capture_output=True, text=True, check=True)
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

def update_subscription(user_uuid, server_key, username):
    os.makedirs(SUB_DIR, exist_ok=True)
    url = build_vless_url(user_uuid, server_key, f"VPN-{username}")
    encoded = base64.b64encode(url.encode()).decode()
    filepath = os.path.join(SUB_DIR, username.lower())
    with open(filepath, "w") as f:
        f.write(encoded)

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/servers")
def get_servers():
    result = {}
    for key, s in SERVERS.items():
        result[key] = {
            "name": s["name"],
            "flag": s["flag"],
            "ip": s["ip"],
            "port": s["port"]
        }
    return jsonify(result)

def build_key_data(user):
    """Собирает всё, что нужно фронту для показа ключа: URL, подписка, QR, мета."""
    server_key = user["server"]
    username = user["username"]
    s = SERVERS[server_key]
    vless_url = build_vless_url(user["uuid"], server_key, f"VPN-{username}")
    sub_url = f"http://{SUB_HOST}/sub/{username.lower()}"
    return {
        "username": username,
        "server": server_key,
        "server_name": s["name"],
        "server_flag": s["flag"],
        "created": user.get("created", ""),
        "vless_url": vless_url,
        "sub_url": sub_url,
        "qr": generate_qr_base64(vless_url),
    }


@app.route("/api/create", methods=["POST"])
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

    if not username or not re.match(r"^[a-zA-Z0-9_\-]{2,32}$", username):
        return jsonify({"error": "Имя: 2–32 символа, только латиница/цифры/_-"}), 400

    users = load_users()
    if any(u["username"].lower() == username.lower() for u in users):
        return jsonify({"error": "Имя уже занято, выберите другое"}), 400

    user_uuid = str(uuid.uuid4())

    try:
        add_to_xray(user_uuid, server_key, username)
    except Exception as e:
        return jsonify({"error": f"Ошибка Xray: {str(e)}"}), 500

    try:
        update_subscription(user_uuid, server_key, username)
    except Exception as e:
        return jsonify({"error": f"Ошибка подписки: {str(e)}"}), 500

    user_entry = {
        "username": username,
        "uuid": user_uuid,
        "server": server_key,
        "email": session["email"],
        "created": datetime.now().isoformat(),
        "in_xray": True,
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
def delete_my_key():
    data = request.json or {}
    token = data.get("token", "")
    username = data.get("username", "")

    session = get_session(token)
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    users = load_users()
    user = next((u for u in users if u["username"].lower() == username.lower()), None)
    if not user:
        return jsonify({"error": "Ключ не найден"}), 404

    if user.get("email") != session["email"]:
        return jsonify({"error": "Это не ваш ключ"}), 403

    try:
        remove_from_xray(user["uuid"], user["server"])
    except Exception as e:
        return jsonify({"error": f"Ошибка Xray: {str(e)}"}), 500

    sub_path = os.path.join(SUB_DIR, username.lower())
    if os.path.exists(sub_path):
        os.remove(sub_path)

    users = [u for u in users if u["username"].lower() != username.lower()]
    save_users(users)

    return jsonify({"ok": True})

@app.route("/api/tariffs", methods=["GET"])
def api_tariffs():
    return jsonify([
        {"id": key, **value}
        for key, value in TARIFFS.items()
    ])


@app.route("/api/payment-info", methods=["GET"])
def api_payment_info():
    # Публичная инфа для ручной оплаты — берём из secrets.json, чтобы реквизиты не лежали в репе.
    return jsonify({
        "sbp_phone": _secrets.get("sbp_phone", ""),
        "sbp_bank": _secrets.get("sbp_bank", ""),
        "card_number": _secrets.get("card_number", ""),
        "card_holder": _secrets.get("card_holder", ""),
        "note": _secrets.get("payment_note", "После оплаты нажмите «Я оплатил». Доступ откроется после подтверждения админом (обычно до 1 часа)."),
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
def api_subscription_request():
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    tariff_id = data.get("tariff")
    if tariff_id not in TARIFFS:
        return jsonify({"error": "Неизвестный тариф"}), 400

    email = session["email"]
    items = load_payment_requests()

    if any(r.get("email") == email and r.get("status") == "pending" for r in items):
        return jsonify({"error": "У вас уже есть заявка в ожидании подтверждения"}), 400

    tariff = TARIFFS[tariff_id]
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
def api_promo_redeem():
    data = request.json or {}
    session = get_session(data.get("token", ""))
    if not session:
        return jsonify({"error": "Сессия истекла"}), 401

    code = (data.get("code") or "").strip().upper()
    if not code:
        return jsonify({"error": "Введите промокод"}), 400

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


# ---------- Админские эндпоинты для подписок/платежей/промокодов ----------

def _require_admin():
    data = request.json or {}
    if not (bool(ADMIN_PASSWORD) and data.get("password") == ADMIN_PASSWORD):
        return None, (jsonify({"error": "Неверный пароль"}), 403)
    return data, None


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
                update_subscription(u["uuid"], server_key, username)
                u["in_xray"] = True
                changed = True
                print(f"[sub-sync] restored {username} ({email})")
            except Exception as e:
                print(f"[sub-sync] restore failed for {username}: {e}")

        elif not active and in_xray:
            try:
                remove_from_xray(u["uuid"], server_key)
                sub_path = os.path.join(SUB_DIR, username.lower())
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
    return bool(ADMIN_PASSWORD) and data.get("password") == ADMIN_PASSWORD


@app.route("/admin")
def admin_page():
    return send_from_directory("static", "admin.html")


@app.route("/api/admin/login", methods=["POST"])
def admin_login():
    data = request.json or {}
    if _is_admin(data):
        return jsonify({"ok": True})
    return jsonify({"error": "Неверный пароль"}), 403


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
    data = request.json or {}
    if not _is_admin(data):
        return jsonify({"error": "Неверный пароль"}), 403

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


@app.route("/api/delete", methods=["POST"])
def delete_user():
    data = request.json
    if not _is_admin(data):
        return jsonify({"error": "Неверный пароль"}), 403

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

    sub_path = os.path.join(SUB_DIR, username.lower())
    if os.path.exists(sub_path):
        os.remove(sub_path)

    users = [u for u in users if u["username"].lower() != username.lower()]
    save_users(users)

    return jsonify({"ok": True})

@app.route("/sub/<path:filename>")
def serve_subscription(filename):
    filepath = os.path.join(SUB_DIR, filename)
    if not os.path.exists(filepath):
        return "Not found", 404
    with open(filepath, "r") as f:
        content = f.read()
    return content, 200, {"Content-Type": "text/plain"}

if __name__ == "__main__":
    t = threading.Thread(target=_subscription_sweeper, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=8080)