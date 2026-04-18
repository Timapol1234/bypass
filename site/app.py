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

# Максимальное количество пользователей на сервер
MAX_USERS_PER_SERVER = 10

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

# Функции для статистики серверов
def get_xray_stats(server_key):
    """Получает количество активных подключений с сервера"""
    s = SERVERS[server_key]
    
    try:
        if s.get("remote"):
            cmd = f'ssh {s["ssh"]} "ss -tn | grep :{s["port"]} | wc -l"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
            connections = int(result.stdout.strip() or 0)
        else:
            result = subprocess.run(f'ss -tn | grep ":{s["port"]}" | wc -l', shell=True, capture_output=True, text=True)
            connections = int(result.stdout.strip() or 0)
        
        # Получаем количество клиентов в конфиге
        count_script = (
            "import json\n"
            f"c = json.load(open({s['xray_config']!r}))\n"
            "ib = next((i for i in c['inbounds'] if i.get('protocol') == 'vless'), None)\n"
            "print(len(ib['settings']['clients']) if ib else 0)\n"
        )
        if s.get("remote"):
            r = subprocess.run(
                ["ssh", "-o", "StrictHostKeyChecking=no", s["ssh"], "python3", "-"],
                input=count_script, capture_output=True, text=True, timeout=5
            )
        else:
            r = subprocess.run(
                ["python3", "-"],
                input=count_script, capture_output=True, text=True, timeout=5
            )
        clients_count = int(r.stdout.strip() or 0)
        
        return {
            "active_connections": connections,
            "total_clients": clients_count,
            "is_overloaded": connections > MAX_USERS_PER_SERVER
        }
    except Exception as e:
        print(f"Error getting stats for {server_key}: {e}")
        return {
            "active_connections": 0,
            "total_clients": 0,
            "is_overloaded": False
        }

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

@app.route('/api/status', methods=['GET'])
def get_servers_status():
    import time
    
    statuses = {}
    for key, server in SERVERS.items():
        ip = server['ip']
        port = server['port']
        
        try:
            start = time.time()
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", ip],
                capture_output=True,
                timeout=3
            )
            latency = round((time.time() - start) * 1000)
            
            if result.returncode == 0:
                statuses[key] = {
                    "status": "online",
                    "latency": latency,
                    "port": port,
                    "ip": ip
                }
            else:
                statuses[key] = {"status": "offline", "latency": None}
        except:
            statuses[key] = {"status": "offline", "latency": None}
    
    return jsonify(statuses)

@app.route('/api/server-stats', methods=['GET'])
def get_server_stats():
    stats = {}
    for key in SERVERS.keys():
        stats[key] = get_xray_stats(key)
    return jsonify(stats)

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

@app.route("/api/create", methods=["POST"])
def create_key():
    data = request.json
    server_key = data.get("server")
    username = data.get("username", "").strip()
    token = data.get("token", "")

    session = get_session(token)
    if not session:
        return jsonify({"error": "Сессия истекла, войдите заново"}), 401

    if server_key not in SERVERS:
        return jsonify({"error": "Сервер не найден"}), 400

    if not username or not re.match(r"^[a-zA-Z0-9_\-]{2,32}$", username):
        return jsonify({"error": "Имя: 2–32 символа, только латиница/цифры/_-"}), 400

    users = load_users()
    if any(u["username"].lower() == username.lower() for u in users):
        return jsonify({"error": "Пользователь уже существует"}), 400

    user_uuid = str(uuid.uuid4())

    try:
        add_to_xray(user_uuid, server_key, username)
    except Exception as e:
        return jsonify({"error": f"Ошибка Xray: {str(e)}"}), 500

    try:
        update_subscription(user_uuid, server_key, username)
    except Exception as e:
        return jsonify({"error": f"Ошибка подписки: {str(e)}"}), 500

    vless_url = build_vless_url(user_uuid, server_key, f"VPN-{username}")
    sub_url = f"http://{SUB_HOST}/sub/{username.lower()}"
    qr_b64 = generate_qr_base64(vless_url)

    user_entry = {
        "username": username,
        "uuid": user_uuid,
        "server": server_key,
        "email": session["email"],
        "created": datetime.now().isoformat()
    }
    users.append(user_entry)
    save_users(users)

    return jsonify({
        "vless_url": vless_url,
        "sub_url": sub_url,
        "qr": qr_b64,
        "username": username,
        "server": SERVERS[server_key]["name"]
    })

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


@app.route("/api/users", methods=["POST"])
def list_users():
    data = request.json
    if not _is_admin(data):
        return jsonify({"error": "Неверный пароль"}), 403
    users = load_users()
    return jsonify(users)

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

CHATS_DB = "/opt/vpn-site/chats.json"

def load_chats():
    if os.path.exists(CHATS_DB):
        with open(CHATS_DB, "r") as f:
            return json.load(f)
    return {}

def save_chats(chats):
    os.makedirs(os.path.dirname(CHATS_DB), exist_ok=True)
    with open(CHATS_DB, "w") as f:
        json.dump(chats, f, indent=2, ensure_ascii=False)

@app.route("/api/chat/send", methods=["POST"])
def chat_send():
    data = request.json
    chat_id = data.get("chat_id", "")
    name = data.get("name", "").strip()
    message = data.get("message", "").strip()

    if not chat_id or not message:
        return jsonify({"error": "Пустое сообщение"}), 400

    chats = load_chats()
    if chat_id not in chats:
        chats[chat_id] = {"name": name or "Гость", "messages": []}

    from datetime import datetime
    chats[chat_id]["messages"].append({
        "from": "user",
        "text": message,
        "time": datetime.now().strftime("%H:%M")
    })
    save_chats(chats)
    return jsonify({"ok": True})

@app.route("/api/chat/get", methods=["POST"])
def chat_get():
    data = request.json
    chat_id = data.get("chat_id", "")
    chats = load_chats()
    chat = chats.get(chat_id, {"messages": []})
    return jsonify(chat["messages"])

@app.route("/api/chat/list", methods=["POST"])
def chat_list():
    data = request.json
    if not _is_admin(data):
        return jsonify({"error": "Неверный пароль"}), 403
    chats = load_chats()
    result = []
    for cid, chat in chats.items():
        last_msg = chat["messages"][-1] if chat["messages"] else None
        unread = sum(1 for m in chat["messages"] if m["from"] == "user" and not m.get("read"))
        result.append({
            "chat_id": cid,
            "name": chat.get("name", "Гость"),
            "last_message": last_msg["text"][:50] if last_msg else "",
            "last_time": last_msg["time"] if last_msg else "",
            "unread": unread
        })
    return jsonify(result)

@app.route("/api/chat/reply", methods=["POST"])
def chat_reply():
    data = request.json
    if not _is_admin(data):
        return jsonify({"error": "Неверный пароль"}), 403

    chat_id = data.get("chat_id", "")
    message = data.get("message", "").strip()

    if not chat_id or not message:
        return jsonify({"error": "Пустое сообщение"}), 400

    chats = load_chats()
    if chat_id not in chats:
        return jsonify({"error": "Чат не найден"}), 404

    from datetime import datetime
    for m in chats[chat_id]["messages"]:
        if m["from"] == "user":
            m["read"] = True

    chats[chat_id]["messages"].append({
        "from": "admin",
        "text": message,
        "time": datetime.now().strftime("%H:%M")
    })
    save_chats(chats)
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
    app.run(host="0.0.0.0", port=8080)