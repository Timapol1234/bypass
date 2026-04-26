"""
Интеграция Hysteria 2 на серверах WIREX.

Авторизация теперь через HTTP-колбэк: Hysteria дёргает /api/hy-auth на Flask
(Амстердам, порт 8080), тот сверяет пароль с users.json. Значит per-server
YAML-список юзеров больше не нужен — auth-state хранится только в users.json
на Flask-боксе.

Этот модуль превратился в тонкую прослойку:
  * get_obfs_password(server_key)   — читает /etc/hysteria/.obfs_password (SSH)
  * build_uri(...)                  — строит hysteria2://PASSWORD@host:port/?...
  * generate_password()             — генерит новый hysteria-пароль для юзера
  * get_status(server)              — systemctl is-active для админки

Функции add_user/remove_user/list_users оставлены как no-op shim'ы ради
обратной совместимости со старым кодом app.py (он может их вызывать на путях,
где мы их ещё не удалили). Они ничего не делают и не трогают конфиг на сервере.
"""

import subprocess
from urllib.parse import quote
from typing import Dict, Optional

HYSTERIA_CONFIG = "/etc/hysteria/config.yaml"
OBFS_FILE = "/etc/hysteria/.obfs_password"
HYSTERIA_PORT = 443
HYSTERIA_SNI = "www.microsoft.com"

_obfs_cache: Dict[str, str] = {}


def _ssh_run(server: dict, cmd: str, stdin_data: Optional[str] = None, timeout: int = 15):
    """Выполняет команду на сервере. Если server.remote=False — локально."""
    if server.get("remote"):
        args = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                "-o", "StrictHostKeyChecking=accept-new", server["ssh"], cmd]
    else:
        args = ["bash", "-c", cmd]
    return subprocess.run(
        args, capture_output=True, text=True,
        timeout=timeout, input=stdin_data,
    )


def get_obfs_password(server_key: str, server: dict) -> str:
    """Читает obfs password с сервера (кэшируется)."""
    if server_key in _obfs_cache:
        return _obfs_cache[server_key]
    r = _ssh_run(server, f"cat {OBFS_FILE}")
    if r.returncode != 0:
        raise RuntimeError(f"hysteria obfs password not found on {server_key}: {r.stderr.strip()}")
    pw = r.stdout.strip()
    _obfs_cache[server_key] = pw
    return pw


# --- No-op shims (auth-state теперь живёт в users.json, не в конфиге Hy2) ---

def list_users(server: dict) -> Dict[str, str]:
    return {}


def add_user(server: dict, username: str, password: str) -> None:
    return None


def remove_user(server: dict, username: str) -> bool:
    return True


# --- URI и метаданные ---

def build_uri(server_key: str, server: dict, username: str, password: str,
              name_tag: Optional[str] = None) -> str:
    """Строит hysteria2:// URI для клиента.

    Формат: hysteria2://<password>@<host>:<port>/?...  (без username перед ':').
    Так его парсит V2Box — он не поддерживает userpass-форму user:pass@host.
    `username` в сигнатуре оставлен ради совместимости со старыми вызовами.
    `name_tag` — готовый Remarks для клиента (см. app.key_tag). Если None,
    подставляется legacy-формат `WIREX-<server name>`."""
    obfs_pw = get_obfs_password(server_key, server)
    host = server["ip"]
    if not name_tag:
        name_tag = f"WIREX-{server.get('name', 'server')}"
    params = [
        "obfs=salamander",
        f"obfs-password={quote(obfs_pw, safe='')}",
        f"sni={HYSTERIA_SNI}",
        "insecure=1",
    ]
    return (
        f"hysteria2://{quote(password, safe='')}@{host}:{HYSTERIA_PORT}"
        f"/?{'&'.join(params)}#{quote(name_tag)}"
    )


def get_status(server: dict) -> dict:
    """Возвращает {active: bool, users_count: int, error: str|None}.
    users_count всегда 0 — per-server списка больше нет, реальный счётчик юзеров
    даёт load_users() в app.py."""
    r = _ssh_run(server, "systemctl is-active hysteria-server", timeout=8)
    active = r.stdout.strip() == "active"
    return {"active": active, "users_count": 0, "error": None}


def generate_password(length: int = 24) -> str:
    """Генерирует случайный пароль для нового юзера (base64url, без '=')."""
    import secrets
    import base64
    return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode().rstrip("=")[:length]
