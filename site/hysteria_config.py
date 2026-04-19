"""
Управление пользователями Hysteria 2 на VPN-серверах BYPASS.

Конфиг Hysteria: /etc/hysteria/config.yaml (создаётся install_hysteria.sh).
Список юзеров хранится внутри YAML между маркерами:

    # BYPASS-USERS-BEGIN
    username1: password1
    username2: password2
    # BYPASS-USERS-END

Это позволяет парсить/править список без YAML-зависимости (format контролируем мы).
Перезагрузка: systemctl reload hysteria-server → SIGHUP, без обрыва активных соединений.

Obfs-пароль читается из /etc/hysteria/.obfs_password (тоже создаёт installer).
Кэшируется в модуле — после рестарта Flask подтянется заново.
"""

import os
import re
import subprocess
from urllib.parse import quote
from typing import Dict, List, Optional

HYSTERIA_CONFIG = "/etc/hysteria/config.yaml"
OBFS_FILE = "/etc/hysteria/.obfs_password"
HYSTERIA_PORT = 8443
HYSTERIA_SNI = "www.microsoft.com"
USERS_BEGIN = "    # BYPASS-USERS-BEGIN"
USERS_END = "    # BYPASS-USERS-END"

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


def _read_config(server: dict) -> str:
    r = _ssh_run(server, f"cat {HYSTERIA_CONFIG}")
    if r.returncode != 0:
        raise RuntimeError(f"cannot read hysteria config: {r.stderr.strip()}")
    return r.stdout


def _extract_users_block(config_text: str) -> List[str]:
    """Возвращает строки между BEGIN/END (без маркеров)."""
    lines = config_text.splitlines()
    out = []
    in_block = False
    for ln in lines:
        if "BYPASS-USERS-BEGIN" in ln:
            in_block = True
            continue
        if "BYPASS-USERS-END" in ln:
            in_block = False
            continue
        if in_block:
            out.append(ln)
    return out


def _parse_users(user_lines: List[str]) -> Dict[str, str]:
    """Парсит строки вида '    username: password' в dict."""
    users = {}
    for ln in user_lines:
        m = re.match(r'\s{4,}([^:#\s]+)\s*:\s*(.+?)\s*$', ln)
        if m:
            users[m.group(1)] = m.group(2).strip().strip('"').strip("'")
    return users


def _format_users(users: Dict[str, str]) -> str:
    """Dict юзеров → YAML-блок (4-пробельный indent)."""
    if not users:
        return ""
    lines = []
    for u, p in sorted(users.items()):
        safe_u = re.sub(r'[^a-zA-Z0-9_\-]', '_', u)
        lines.append(f"    {safe_u}: {p}")
    return "\n".join(lines)


def _replace_users_block(config_text: str, new_block: str) -> str:
    """Заменяет содержимое между маркерами."""
    pattern = re.compile(
        r'(\s*#\s*BYPASS-USERS-BEGIN\s*\n).*?(\n\s*#\s*BYPASS-USERS-END)',
        re.DOTALL,
    )
    if not pattern.search(config_text):
        raise RuntimeError(
            "в конфиге Hysteria нет маркеров BYPASS-USERS-BEGIN/END — "
            "перезапусти install_hysteria.sh на этом сервере"
        )
    replacement = r'\1' + (new_block + "\n" if new_block else "") + r'\2'
    return pattern.sub(replacement, config_text, count=1)


def _write_config_and_reload(server: dict, new_text: str):
    """Пишет новый конфиг на сервер и перезагружает Hysteria (SIGHUP)."""
    if server.get("remote"):
        # Передаём контент через stdin
        r = subprocess.run(
            ["ssh", "-o", "BatchMode=yes", server["ssh"],
             f"cat > {HYSTERIA_CONFIG}.new && "
             f"mv {HYSTERIA_CONFIG}.new {HYSTERIA_CONFIG} && "
             f"chmod 600 {HYSTERIA_CONFIG} && "
             f"systemctl reload hysteria-server"],
            input=new_text, capture_output=True, text=True, timeout=20,
        )
    else:
        tmp = HYSTERIA_CONFIG + ".new"
        with open(tmp, "w") as f:
            f.write(new_text)
        os.chmod(tmp, 0o600)
        os.replace(tmp, HYSTERIA_CONFIG)
        r = subprocess.run(
            ["systemctl", "reload", "hysteria-server"],
            capture_output=True, text=True, timeout=10,
        )
    if r.returncode != 0:
        raise RuntimeError(f"hysteria reload failed: {r.stderr.strip() or r.stdout.strip()}")


def list_users(server: dict) -> Dict[str, str]:
    """Возвращает текущих юзеров {username: password} с сервера."""
    cfg = _read_config(server)
    return _parse_users(_extract_users_block(cfg))


def add_user(server: dict, username: str, password: str) -> None:
    """Добавляет юзера (или перезаписывает пароль, если юзер уже есть)."""
    cfg = _read_config(server)
    users = _parse_users(_extract_users_block(cfg))
    users[username] = password
    new_cfg = _replace_users_block(cfg, _format_users(users))
    _write_config_and_reload(server, new_cfg)


def remove_user(server: dict, username: str) -> bool:
    """Удаляет юзера. Возвращает True если был удалён, False если не найден."""
    cfg = _read_config(server)
    users = _parse_users(_extract_users_block(cfg))
    if username not in users:
        return False
    del users[username]
    new_cfg = _replace_users_block(cfg, _format_users(users))
    _write_config_and_reload(server, new_cfg)
    return True


def build_uri(server_key: str, server: dict, username: str, password: str) -> str:
    """Строит hysteria2:// URI для клиента."""
    obfs_pw = get_obfs_password(server_key, server)
    host = server["ip"]
    name_tag = server.get("name", "BYPASS")
    auth = f"{quote(username, safe='')}:{quote(password, safe='')}"
    params = [
        f"obfs=salamander",
        f"obfs-password={quote(obfs_pw, safe='')}",
        f"sni={HYSTERIA_SNI}",
        "insecure=1",
    ]
    return f"hysteria2://{auth}@{host}:{HYSTERIA_PORT}/?{'&'.join(params)}#BYPASS-{quote(name_tag)}"


def get_status(server: dict) -> dict:
    """Возвращает {active: bool, users_count: int, error: str|None}."""
    r = _ssh_run(server, "systemctl is-active hysteria-server", timeout=8)
    active = r.stdout.strip() == "active"
    try:
        users = list_users(server) if active else {}
        return {"active": active, "users_count": len(users), "error": None}
    except Exception as e:
        return {"active": active, "users_count": 0, "error": str(e)}


def generate_password(length: int = 24) -> str:
    """Генерирует случайный пароль для нового юзера (base64, без спецсимволов)."""
    import secrets
    import base64
    return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode().rstrip("=")[:length]
