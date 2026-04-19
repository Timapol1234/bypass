#!/usr/bin/env bash
# Чинит корраптнутые конфиги Hysteria на всех серверах + деплоит фикс
# хелперной библиотеки hysteria_config.py на Амстердам.
#
# Причина: старая версия _extract_users_block делала подстрочное сравнение
# маркеров, из-за чего шапка-комментарий со словами BYPASS-USERS-BEGIN/END
# давала ложный триггер. В итоге __seed__ и salamander.password оказывались
# ВНУТРИ маркеров, а Hysteria падал на дубликате __seed__.
#
# Запускать на Амстердаме.

set -e

REPO=https://github.com/Timapol1234/bypass.git
DEPLOY_DIR=/tmp/bypass-deploy

declare -A SERVERS=(
    [amsterdam]="109.248.162.180"
    [usa]="31.56.229.94"
    [finland]="109.248.161.20"
    [france]="45.38.23.141"
)

echo ">>> 1. Обновляю клон репозитория"
rm -rf "$DEPLOY_DIR"
git clone "$REPO" "$DEPLOY_DIR"
cd "$DEPLOY_DIR"
echo "  последний коммит: $(git log --oneline -1)"

echo ""
echo ">>> 2. Копирую hysteria_config.py в /opt/vpn-site/"
cp "$DEPLOY_DIR/site/hysteria_config.py" /opt/vpn-site/hysteria_config.py
md5sum "$DEPLOY_DIR/site/hysteria_config.py" /opt/vpn-site/hysteria_config.py

echo ""
echo ">>> 3. Рестарт vpn-site"
systemctl restart vpn-site
sleep 2
systemctl is-active vpn-site && echo "  vpn-site активен"

echo ""
echo ">>> 4. Запускаю install_hysteria.sh локально на Амстердаме"
bash "$DEPLOY_DIR/site/install_hysteria.sh" 2>&1 | tail -20
echo "  статус hysteria-server на amsterdam: $(systemctl is-active hysteria-server)"

echo ""
echo ">>> 5. Перезаливаю install_hysteria.sh + запускаю на удалённых серверах"
for key in usa finland france; do
    ip="${SERVERS[$key]}"
    echo ""
    echo "--- $key ($ip) ---"

    # Копируем свежий installer
    scp -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
        "$DEPLOY_DIR/site/install_hysteria.sh" "root@$ip:/root/install_hysteria.sh"

    # Запускаем installer (идемпотентный — подчистит корраптнутый блок,
    # перезапишет конфиг в каноническом виде, перезапустит сервис)
    ssh -n -o BatchMode=yes "root@$ip" 'bash /root/install_hysteria.sh 2>&1 | tail -20'

    # Финальная проверка
    echo "  статус hysteria-server на $key:"
    ssh -n "root@$ip" 'systemctl is-active hysteria-server'
done

echo ""
echo ">>> 6. Проверка: есть ли дубликаты __seed__ в любом конфиге"
FOUND_DUPES=0

# amsterdam — локально
count=$(grep -c '__seed__' /etc/hysteria/config.yaml || echo "?")
echo "  amsterdam: __seed__ встречается $count раз (должен быть 1)"
if [ "$count" != "1" ]; then FOUND_DUPES=1; fi

# остальные — по ssh
for key in usa finland france; do
    ip="${SERVERS[$key]}"
    count=$(ssh -n "root@$ip" "grep -c '__seed__' /etc/hysteria/config.yaml" || echo "?")
    echo "  $key: __seed__ встречается $count раз (должен быть 1)"
    if [ "$count" != "1" ]; then
        FOUND_DUPES=1
    fi
done

echo ""
if [ "$FOUND_DUPES" -eq 0 ]; then
    echo "=== ВСЁ ОК: конфиги чистые, hysteria-server работает на всех серверах ==="
else
    echo "=== ВНИМАНИЕ: где-то остались дубликаты __seed__, проверь вручную ==="
    exit 1
fi
