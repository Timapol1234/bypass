#!/usr/bin/env python3
"""
Одноразовая миграция: включает Xray Stats API на всех 4 серверах WIREX.

Запускать на NL-сервере: python3 scripts/migrate_xray_stats.py

Действия на каждом сервере:
  1. Бэкап /usr/local/etc/xray/config.json в .bak.<timestamp>
  2. Добавляет stats/api/policy/routing блоки (идемпотентно)
  3. Добавляет tag "vless-in" к vless-inbound
  4. Добавляет email к каждому client (username из users.json или legacy-<uuid8>)
  5. Добавляет api-inbound на 127.0.0.1:10085
  6. systemctl restart xray

Идемпотентно: повторный запуск не ломает уже мигрированный конфиг.
"""

import base64
import json
import os
import shlex
import subprocess
import sys
from datetime import datetime

SERVERS = [
    {"name": "amsterdam", "ssh": None},  # локальный
    {"name": "usa", "ssh": "root@31.56.229.94"},
    {"name": "finland", "ssh": "root@109.248.161.20"},
    {"name": "france", "ssh": "root@45.38.23.141"},
]

XRAY_CONFIG = "/usr/local/etc/xray/config.json"
USERS_JSON = "/opt/vpn-site/users.json"


def run(cmd, check=True):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and r.returncode != 0:
        print(f"  FAIL ({r.returncode}): {cmd}")
        print(f"  stderr: {r.stderr}")
        sys.exit(1)
    return r.stdout


def load_user_map():
    if not os.path.exists(USERS_JSON):
        return {}
    with open(USERS_JSON) as f:
        return {u["uuid"]: u["username"] for u in json.load(f)}


def migrate_config(config_json, user_map):
    cfg = json.loads(config_json)

    vless_inbound = next(
        (ib for ib in cfg.get("inbounds", []) if ib.get("protocol") == "vless"),
        None
    )
    if not vless_inbound:
        raise RuntimeError("vless-inbound не найден")

    vless_inbound["tag"] = "vless-in"

    for client in vless_inbound["settings"]["clients"]:
        if "email" not in client or not client["email"]:
            uid = client["id"]
            client["email"] = user_map.get(uid, f"legacy-{uid[:8]}")
        if "flow" not in client:
            client["flow"] = ""

    if not any(ib.get("tag") == "api" for ib in cfg["inbounds"]):
        cfg["inbounds"].insert(0, {
            "tag": "api",
            "listen": "127.0.0.1",
            "port": 10085,
            "protocol": "dokodemo-door",
            "settings": {"address": "127.0.0.1"}
        })

    cfg["stats"] = {}
    cfg["api"] = {
        "tag": "api",
        "services": ["HandlerService", "LoggerService", "StatsService"]
    }
    cfg["policy"] = {
        "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
        "system": {
            "statsInboundUplink": True,
            "statsInboundDownlink": True,
            "statsOutboundUplink": True,
            "statsOutboundDownlink": True
        }
    }

    routing = cfg.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    has_api_rule = any(
        r.get("outboundTag") == "api" and "api" in r.get("inboundTag", [])
        for r in rules
    )
    if not has_api_rule:
        rules.insert(0, {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api"
        })

    for ob in cfg.get("outbounds", []):
        if ob.get("protocol") == "freedom" and "tag" not in ob:
            ob["tag"] = "direct"

    return json.dumps(cfg, indent=2)


def ssh_read(ssh, path):
    return run(f"ssh -o StrictHostKeyChecking=no {ssh} 'cat {shlex.quote(path)}'")


def ssh_write(ssh, path, content):
    # base64 чтобы не возиться с экранированием
    encoded = base64.b64encode(content.encode()).decode()
    run(
        f"ssh -o StrictHostKeyChecking=no {ssh} "
        f"'echo {encoded} | base64 -d > {shlex.quote(path)}'"
    )


def ssh_run(ssh, cmd):
    return run(f"ssh -o StrictHostKeyChecking=no {ssh} {shlex.quote(cmd)}")


def migrate_server(server, user_map):
    print(f"\n=== {server['name']} ===")
    ssh = server.get("ssh")

    try:
        if ssh:
            config_json = ssh_read(ssh, XRAY_CONFIG)
        else:
            with open(XRAY_CONFIG) as f:
                config_json = f.read()
    except Exception as e:
        print(f"  ERROR reading config: {e}")
        return False

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = f"{XRAY_CONFIG}.bak.{ts}"
    if ssh:
        ssh_run(ssh, f"cp {XRAY_CONFIG} {backup_path}")
    else:
        run(f"cp {XRAY_CONFIG} {backup_path}")
    print(f"  backup: {backup_path}")

    try:
        new_config = migrate_config(config_json, user_map)
    except Exception as e:
        print(f"  ERROR migrating: {e}")
        return False

    try:
        parsed = json.loads(new_config)
        assert any(ib.get("tag") == "api" for ib in parsed["inbounds"])
        assert any(ib.get("tag") == "vless-in" for ib in parsed["inbounds"])
    except Exception as e:
        print(f"  ERROR validating: {e}")
        return False

    if ssh:
        ssh_write(ssh, XRAY_CONFIG, new_config)
        ssh_run(ssh, "systemctl restart xray")
    else:
        with open(XRAY_CONFIG, "w") as f:
            f.write(new_config)
        run("systemctl restart xray")

    print(f"  config updated, xray restarted")
    return True


if __name__ == "__main__":
    user_map = load_user_map()
    print(f"Users из users.json: {len(user_map)}")

    failed = []
    for server in SERVERS:
        try:
            ok = migrate_server(server, user_map)
            if not ok:
                failed.append(server["name"])
        except Exception as e:
            print(f"  UNEXPECTED: {e}")
            failed.append(server["name"])

    print()
    if failed:
        print(f"Ошибки на серверах: {', '.join(failed)}")
        sys.exit(1)
    print("Готово. Проверь: xray api statsquery --server=127.0.0.1:10085 -pattern 'user>>>'")
