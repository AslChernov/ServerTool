#!/bin/bash
# ======================================================
# Server Setup & Management Tool
# Создано на основе:
# - Balbuto/Setup-and-Test-Server-Ubuntu-24
# - SawGoD/bbr-control
# - Balbuto/ufw-manager
# - DonMatteoVPN/TrafficGuard-auto
# ======================================================

set -uo pipefail

# --- Константы ---
GITHUB_RAW_URL="https://raw.githubusercontent.com/AslChernov/ServerTool/main/server_tool.sh"
TIMEZONE="Europe/Moscow"
export DEBIAN_FRONTEND=noninteractive

# --- Цвета ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ======================================================
# Вспомогательные функции
# ======================================================
msg_info() { echo -e "${CYAN}$1${NC}"; }
msg_ok()   { echo -e "${GREEN}✅ $1${NC}"; }
msg_err()  { echo -e "${RED}❌ $1${NC}"; }
msg_warn() { echo -e "${YELLOW}⚠️ $1${NC}"; }
msg_step() { echo -e "${YELLOW}$1${NC}"; }

press_enter() {
    echo ""
    read -p "Нажмите Enter для продолжения..."
}

confirm_action() {
    local prompt="$1"
    local default="${2:-y}"
    read -p "$prompt (y/n) [$default]: " confirm
    confirm=${confirm:-$default}
    if [[ "${confirm,,}" == "y" ]]; then
        return 0
    else
        return 1
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        msg_err "Этот скрипт должен быть запущен с правами root!"
        msg_warn "Используйте: sudo $0"
        exit 1
    fi
}

check_internet() {
    if ! ping -c 1 8.8.8.8 &> /dev/null; then
        msg_err "Нет подключения к интернету! Проверьте сеть."
        press_enter
        return 1
    fi
    return 0
}

# ======================================================
# 1. Подготовка Ubuntu 24
# ======================================================
ubuntu_prep() {
    msg_info "=== Подготовка Ubuntu 24 ==="
    
    msg_step "[1/3] Обновление системы..."
    apt-get update -qq && apt-get upgrade -y -qq
    apt-get dist-upgrade -y -qq
    apt-get autoremove -y -qq && apt-get autoclean -qq
    
    msg_step "[2/3] Установка базового ПО и настройка времени..."
    apt-get install -y -qq mc net-tools curl wget git ufw fail2ban iproute2 iptables systemd-timesyncd
    
    timedatectl set-timezone "$TIMEZONE"
    systemctl enable --now systemd-timesyncd
    msg_ok "Часовой пояс установлен ($TIMEZONE), время синхронизировано."
    
    msg_step "[3/3] Установка Docker..."
    if ! command -v docker &> /dev/null; then
        curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
        sh /tmp/get-docker.sh >/dev/null 2>&1
        rm -f /tmp/get-docker.sh
        msg_ok "Docker установлен."
    else
        msg_ok "Docker уже установлен."
    fi
    
    msg_ok "Подготовка системы завершена."
    
    if [[ -f /var/run/reboot-required ]]; then
        msg_err "Требуется перезагрузка системы (установлено новое ядро и т.д.)!"
    fi
    press_enter
}

# ======================================================
# 2. Настройка сети и BBR
# ======================================================
setup_network_bbr() {
    local conf iface ts bdir bbr_choice b_name
    while true; do
        clear
        msg_info "=== Настройка сети и BBR ==="
        msg_err "ВНИМАНИЕ: Если потребуется перезагрузка (например, после BBR3), делайте её ТОЛЬКО через админ-панель хостинга!"
        echo -e "  1) Стандартная оптимизация (BBR1 + fq)"
        echo -e "  2) Low-Latency профиль (BBR2 + fq_codel) [из bbr-control]"
        echo -e "  3) High-Throughput профиль (BBR3 + fq) [из bbr-control]"
        echo -e "  4) Включить/Отключить IPv6 [из bbr-control]"
        echo -e "  5) Бэкап сетевых настроек"
        echo -e "  6) Восстановить сетевые настройки"
        echo -e "  0) Назад"
        read -p "Выберите режим (0-6): " bbr_choice || true
        bbr_choice=${bbr_choice:-}
        
        case $bbr_choice in
            1)
                msg_step "Применение стандартной оптимизации..."
                conf="/etc/sysctl.d/99-network-optimizations.conf"
                cat > "$conf" <<EOF
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096
net.core.rmem_max = 33554432
net.core.wmem_max = 33554432
net.ipv4.tcp_rmem = 4096 87380 33554432
net.ipv4.tcp_wmem = 4096 65536 33554432
net.core.default_qdisc = fq
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 262144
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5
fs.file-max = 2097152
vm.swappiness = 10
EOF
                sysctl --load "$conf" >/dev/null 2>&1
                if sysctl -a 2>/dev/null | grep -q '^net\.ipv4\.tcp_low_latency'; then
                    sysctl -w net.ipv4.tcp_low_latency=1 >/dev/null || true
                fi
                iface=$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
                if [[ -n "${iface:-}" ]]; then
                    tc qdisc replace dev "$iface" root fq >/dev/null 2>&1 || msg_warn "Не удалось применить fq к $iface"
                fi
                modprobe tcp_bbr 2>/dev/null || true
                sysctl -w "net.ipv4.tcp_congestion_control=bbr" >/dev/null 2>&1
                msg_ok "Алгоритм контроля перегрузки: $(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null)"
                press_enter
                ;;
            2)
                check_internet || continue
                msg_step "Запуск профиля BBR2..."
                bash <(curl -fsSL https://raw.githubusercontent.com/SawGoD/bbr-control/main/bbr2.sh)
                press_enter
                ;;
            3)
                check_internet || continue
                msg_step "Запуск профиля BBR3..."
                bash <(curl -fsSL https://raw.githubusercontent.com/SawGoD/bbr-control/main/bbr3.sh)
                press_enter
                ;;
            4)
                check_internet || continue
                msg_step "Запуск скрипта управления IPv6..."
                bash <(curl -fsSL https://raw.githubusercontent.com/SawGoD/bbr-control/main/toggle_ipv6.sh)
                press_enter
                ;;
            5)
                msg_step "Создание бэкапа сетевых конфигураций..."
                mkdir -p /root/network_backups
                ts=$(date +%Y%m%d_%H%M%S)
                bdir="/root/network_backups/$ts"
                mkdir -p "$bdir"
                cp -a /etc/sysctl.d/99-* "$bdir/" 2>/dev/null || true
                cp -a /etc/default/ufw "$bdir/" 2>/dev/null || true
                cp -a /etc/default/grub "$bdir/" 2>/dev/null || true
                msg_ok "Бэкап сохранен в $bdir"
                press_enter
                ;;
            6)
                msg_step "Доступные бэкапы (/root/network_backups/):"
                if [ -d "/root/network_backups" ]; then
                    ls -1 /root/network_backups/
                    echo ""
                    read -p "Введите имя папки (или оставьте пустым для отмены): " b_name
                    if [ -n "$b_name" ] && [ -d "/root/network_backups/$b_name" ]; then
                        msg_step "Восстановление из $b_name..."
                        cp -a /root/network_backups/"$b_name"/99-* /etc/sysctl.d/ 2>/dev/null || true
                        cp -a /root/network_backups/"$b_name"/ufw /etc/default/ 2>/dev/null || true
                        cp -a /root/network_backups/"$b_name"/grub /etc/default/ 2>/dev/null || true
                        sysctl --system >/dev/null 2>&1
                        if command -v update-grub >/dev/null 2>&1; then update-grub >/dev/null 2>&1 || true; fi
                        msg_ok "Настройки восстановлены!"
                    else
                        msg_warn "Отмена восстановления."
                    fi
                else
                    msg_err "Папка с бэкапами не найдена."
                fi
                press_enter
                ;;
            0) return ;;
            *) msg_err "Неверный выбор!"; sleep 1 ;;
        esac
    done
}

# ======================================================
# 3. Настройка UFW (через UFW Manager)
# ======================================================
setup_ufw() {
    msg_info "=== Установка и запуск UFW Manager ==="
    local ufw_dir="/opt/ufw-manager"
    
    if [[ ! -d "$ufw_dir" ]]; then
        msg_step "Клонирование UFW Manager..."
        mkdir -p /opt
        git clone -q https://github.com/Balbuto/ufw-manager.git "$ufw_dir"
    else
        msg_step "Обновление UFW Manager..."
        ( cd "$ufw_dir" && git pull -q )
    fi
    
    if [[ -f "$ufw_dir/ufw-manager.sh" ]]; then
        chmod +x "$ufw_dir/ufw-manager.sh"
        msg_ok "Запуск UFW Manager..."
        ( cd "$ufw_dir" && ./ufw-manager.sh )
    else
        msg_err "ОШИБКА: ufw-manager.sh не найден!"
    fi
    press_enter
}

# ======================================================
# 4. Установка TrafficGuard
# ======================================================
setup_trafficguard() {
    msg_info "=== Установка TrafficGuard PRO ==="
    
    msg_step "Скачивание и установка TrafficGuard-auto (от DonMatteoVPN)..."
    curl -fsSL "https://raw.githubusercontent.com/DonMatteoVPN/TrafficGuard-auto/refs/heads/main/install-trafficguard.sh" | bash
    
    press_enter
}

# ======================================================
# 5. Установка AdGuard Home
# ======================================================
setup_adguard() {
    clear
    msg_info "=== Установка AdGuard Home ==="
    msg_step "Шаг 1: Освобождение порта 53..."
    
    # Останавливаем и отключаем системный DNS
    systemctl disable systemd-resolved >/dev/null 2>&1
    systemctl stop systemd-resolved >/dev/null 2>&1
    
    # Удаляем символическую ссылку и задаем временный DNS
    rm -f /etc/resolv.conf
    echo "nameserver 1.1.1.1" > /etc/resolv.conf
    msg_ok "systemd-resolved отключен, временный DNS установлен (1.1.1.1)."
    
    if command -v ufw >/dev/null && ufw status | grep -q "active"; then
        msg_step "Открытие портов (3000, 53) в UFW..."
        ufw allow 3000/tcp >/dev/null
        ufw allow 53/tcp >/dev/null
        ufw allow 53/udp >/dev/null
        msg_ok "Порты открыты."
    fi
    
    msg_step "Шаг 2: Скачивание и установка AdGuard Home..."
    curl -s -S -L https://raw.githubusercontent.com/AdguardTeam/AdGuardHome/master/scripts/install.sh | sh -s -- -v
    
    if systemctl is-active --quiet AdGuardHome; then
        msg_ok "AdGuard Home успешно установлен!"
        msg_step "Шаг 3: Настройка локального DNS на AdGuard Home..."
        echo "nameserver 127.0.0.1" > /etc/resolv.conf
        msg_ok "Локальный DNS перенаправлен на 127.0.0.1."
        msg_info "Теперь откройте браузер: http://$(curl -s --max-time 3 ifconfig.me || echo 'IP_СЕРВЕРА'):3000"
        msg_info "Пройдите настройку, указав нужные порты для веб-интерфейса и 53 для DNS."
    else
        msg_err "ОШИБКА: AdGuardHome не запущен. Проверьте логи."
    fi
    
    press_enter
}

# ======================================================
# 6. Базовая защита SSH
# ======================================================
setup_ssh() {
    local old_port key_choice pub_key new_port
    msg_info "=== Настройка SSH ==="
    old_port=$(awk '/^Port / {print $2; exit}' /etc/ssh/sshd_config 2>/dev/null)
    if [[ -z "${old_port:-}" ]]; then old_port=22; fi
    msg_step "Текущий порт: ${old_port}"
    
    msg_info "--- Настройка SSH Ключей ---"
    echo "1) Вставить свой публичный ключ (рекомендуется)"
    echo "2) Сгенерировать новую пару ключей (ed25519) на сервере"
    echo "0) Пропустить настройку ключей"
    read -p "Выберите действие (0-2): " key_choice
    
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    case $key_choice in
        1)
            read -p "Вставьте ваш публичный SSH ключ (ssh-rsa ... или ssh-ed25519 ...): " pub_key
            if [[ -n "$pub_key" ]]; then
                echo "$pub_key" >> /root/.ssh/authorized_keys
                chmod 600 /root/.ssh/authorized_keys
                msg_ok "Ключ добавлен в authorized_keys."
            else
                msg_warn "Ключ пуст, пропускаем."
            fi
            ;;
        2)
            if [ -f /root/.ssh/id_ed25519 ]; then
                if confirm_action "Ключ /root/.ssh/id_ed25519 уже существует! Перезаписать?"; then
                    rm -f /root/.ssh/id_ed25519*
                fi
            fi
            if [ ! -f /root/.ssh/id_ed25519 ]; then
                ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N "" -q
                cat /root/.ssh/id_ed25519.pub >> /root/.ssh/authorized_keys
                chmod 600 /root/.ssh/authorized_keys
                msg_ok "Новая пара ключей сгенерирована и добавлена в authorized_keys."
                msg_step "Файлы сохранены на сервере:"
                echo -e " - Приватный ключ: ${CYAN}/root/.ssh/id_ed25519${NC}"
                echo -e " - Публичный ключ: ${CYAN}/root/.ssh/id_ed25519.pub${NC}"
                msg_err "ВНИМАНИЕ! Вы можете скачать файл id_ed25519 через SFTP (например, WinSCP/FileZilla)"
                msg_err "или просто скопировать его текст прямо отсюда:"
                echo -e "${CYAN}=================================================================${NC}"
                cat /root/.ssh/id_ed25519
                echo -e "${CYAN}=================================================================${NC}"
                press_enter
            fi
            ;;
    esac

    msg_info "--- Настройка порта и паролей ---"
    read -p "Введите новый порт SSH (10000-60000), 0 для отмены, или Enter для случайного порта: " new_port
    
    if [[ -z "$new_port" ]]; then
        new_port=$(shuf -i 10000-60000 -n 1)
        msg_ok "Сгенерирован случайный порт: $new_port"
    fi

    if [[ "$new_port" != "0" && "$new_port" =~ ^[0-9]+$ ]]; then
        if (( new_port >= 10000 && new_port <= 60000 )); then
            # Разрешаем новый порт в UFW если он включен
            if command -v ufw >/dev/null && ufw status | grep -q "active"; then
                if [[ "$old_port" != "$new_port" ]]; then
                    # Удаляем старый порт во всех возможных форматах
                    ufw delete allow "$old_port/tcp" > /dev/null 2>&1
                    ufw delete allow "$old_port" > /dev/null 2>&1
                    # Удаляем SSH-профили приложений
                    ufw delete allow OpenSSH > /dev/null 2>&1
                    ufw delete allow SSH > /dev/null 2>&1
                    ufw delete allow "SSH-Custom" > /dev/null 2>&1
                fi
                # Создаём/обновляем UFW-профиль SSH-Custom с новым портом
                cat > /etc/ufw/applications.d/ssh-custom <<EOAPP
[SSH-Custom]
title=SSH on port $new_port
description=OpenSSH Server on custom port
ports=$new_port/tcp
EOAPP
                ufw app update SSH-Custom > /dev/null 2>&1
                ufw allow SSH-Custom > /dev/null 2>&1
                msg_ok "Порт $new_port добавлен в UFW как SSH-Custom."
            fi
            
            sed -i '/^#\?Port /d' /etc/ssh/sshd_config
            echo "Port $new_port" >> /etc/ssh/sshd_config
            
            # В Ubuntu 24.04 SSH может работать через systemd socket, что конфликтует с кастомными портами
            if systemctl is-active --quiet ssh.socket; then
                systemctl disable --now ssh.socket >/dev/null 2>&1
                systemctl enable ssh.service >/dev/null 2>&1
            fi
            
            # Проверяем наличие ключей перед отключением пароля
            if [[ -s /root/.ssh/authorized_keys ]]; then
                if confirm_action "Отключаем вход по паролю (разрешаем только ключи)?"; then
                    # Основной конфиг
                    sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
                    sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
                    # Ubuntu 24.04: переопределяем настройки из sshd_config.d (cloud-init и др.)
                    for f in /etc/ssh/sshd_config.d/*.conf; do
                        [[ -f "$f" ]] && sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' "$f"
                    done
                    msg_ok "Вход по паролю отключен."
                fi
            else
                msg_warn "SSH-ключи не найдены в authorized_keys! Отключение пароля пропущено (иначе потеряете доступ)."
            fi
            
            systemctl restart ssh 2>/dev/null || systemctl restart sshd
            msg_ok "SSH перенастроен! УБЕДИТЕСЬ, что вы можете подключиться по новому порту $new_port!"
        else
            msg_err "Порт должен быть от 10000 до 60000."
        fi
    else
        msg_warn "Изменение порта отменено."
    fi
    press_enter
}

# ======================================================
# 7. Управление Swap-файлом
# ======================================================
setup_swap() {
    local current_swap swap_choice size
    msg_info "=== Управление Swap-файлом ==="
    current_swap=$(free -m | awk '/^Swap:/ {print $2}')
    
    if [[ "${current_swap:-0}" -gt 0 ]]; then
        msg_ok "У вас уже есть $current_swap MB Swap."
        if confirm_action "Хотите удалить текущий Swap?"; then
            swapoff -a
            rm -f /swapfile
            sed -i '/\/swapfile/d' /etc/fstab
            msg_ok "Swap удален."
        fi
    else
        msg_warn "Swap не найден. Рекомендуется создать его для избежания OOM ошибок."
        echo "  1) Создать Swap 2GB"
        echo "  2) Создать Swap 4GB"
        echo "  0) Отмена"
        read -p "Выберите опцию: " swap_choice
        
        case $swap_choice in
            1|2)
                size=$((swap_choice * 2))
                msg_step "Создание файла подкачки на ${size}GB..."
                if ! fallocate -l ${size}G /swapfile 2>/dev/null; then
                    msg_warn "fallocate не поддерживается файловой системой, используем dd (это займет время)..."
                    dd if=/dev/zero of=/swapfile bs=1M count=$((size * 1024)) status=progress
                fi
                chmod 600 /swapfile
                mkswap /swapfile >/dev/null
                swapon /swapfile
                if ! grep -q '/swapfile none swap sw 0 0' /etc/fstab; then
                    echo '/swapfile none swap sw 0 0' >> /etc/fstab
                fi
                msg_ok "Swap-файл на ${size}GB успешно создан и активирован!"
                ;;
            0) echo "Отмена." ;;
            *) msg_err "Неверный выбор." ;;
        esac
    fi
    press_enter
}

# ======================================================
# 8. Бенчмарк (YABS)
# ======================================================
run_bench() {
    clear
    msg_info "=== Серверный Бенчмарк (YABS) ==="
    msg_step "Скрипт выполнит проверку диска, CPU и сети (IPv4/IPv6). Это займет несколько минут..."
    if confirm_action "Продолжить?"; then
        curl -sL yabs.sh | bash
    fi
    press_enter
}

# ======================================================
# 10. Установка скрипта в систему
# ======================================================
install_to_system() {
    clear
    msg_info "=== Установка в систему ==="
    local bin_path="/usr/local/bin/server-tool"
    
    if [[ -f "$0" ]]; then
        cp "$0" "$bin_path"
    else
        # Скрипт запущен через pipe/подстановку — скачиваем с GitHub
        msg_step "Скачивание скрипта с GitHub..."
        if ! curl -fsSL "$GITHUB_RAW_URL" -o "$bin_path"; then
            msg_err "Не удалось скачать скрипт!"
            press_enter
            return
        fi
    fi
    
    chmod +x "$bin_path"
    
    msg_ok "Скрипт успешно установлен!"
    msg_step "Теперь вы можете запускать его из любого места командой: ${CYAN}sudo server-tool${NC}"
    press_enter
}

# ======================================================
# 11. Обновление скрипта (Self-update)
# ======================================================
self_update() {
    msg_info "=== Обновление server_tool.sh ==="
    if [[ -z "${GITHUB_RAW_URL:-}" || "$GITHUB_RAW_URL" == *"YourUsername"* ]]; then
        msg_err "Ссылка на обновление (GITHUB_RAW_URL) не настроена!"
        echo -e "Отредактируйте скрипт и вставьте вашу прямую ссылку на RAW файл GitHub."
        press_enter
        return
    fi
    
    msg_step "Скачивание последней версии..."
    local tmp_file="/tmp/server_tool_update.sh"
    local bin_path="/usr/local/bin/server-tool"
    if curl -fsSL "$GITHUB_RAW_URL" -o "$tmp_file"; then
        # Обновляем установленную в систему копию
        if [[ -f "$bin_path" ]]; then
            cp "$tmp_file" "$bin_path"
            chmod +x "$bin_path"
        fi
        # Обновляем исходный файл, если запущен из файла
        if [[ -f "$0" && "$(readlink -f "$0")" != "$(readlink -f "$bin_path")" ]]; then
            cp "$tmp_file" "$0"
            chmod +x "$0"
        fi
        rm -f "$tmp_file"
        msg_ok "Скрипт обновлен! Перезапуск..."
        if [[ -f "$bin_path" ]]; then
            exec "$bin_path"
        elif [[ -f "$0" ]]; then
            exec "$0"
        fi
    else
        msg_err "Не удалось скачать обновление!"
    fi
    press_enter
}

# ======================================================
# 9. Очистка системы
# ======================================================
system_cleanup() {
    clear
    msg_info "=== Очистка системы ==="
    msg_step "Будут выполнены следующие действия:"
    echo " - Удаление ненужных пакетов (apt autoremove/clean)"
    echo " - Очистка старых логов systemd (старше 3 дней)"
    echo " - Удаление старых архивов логов (/var/log/*.gz)"
    echo " - Очистка кэша пользователя (~/.cache)"
    if command -v docker >/dev/null; then
        echo " - Удаление неиспользуемых данных Docker (dangling images/containers)"
    fi
    echo ""
    if confirm_action "Продолжить очистку?"; then
        msg_step "Очистка кэша APT..."
        apt-get autoremove -y -qq
        apt-get autoclean -qq
        apt-get clean -qq
        
        msg_step "Очистка системных логов..."
        journalctl --vacuum-time=3d >/dev/null 2>&1
        rm -f /var/log/*.gz 2>/dev/null
        
        msg_step "Очистка кэша..."
        rm -rf /root/.cache/* 2>/dev/null
        
        if command -v docker >/dev/null; then
            msg_step "Очистка неиспользуемых ресурсов Docker..."
            docker system prune -f >/dev/null 2>&1
        fi
        
        msg_ok "Система успешно очищена от мусора!"
    else
        msg_warn "Очистка отменена."
    fi
    press_enter
}

# ======================================================
# Главное меню
# ======================================================
show_menu() {
    local choice
    local server_ip
    server_ip=$(curl -s --max-time 3 ifconfig.me 2>/dev/null || echo 'Неизвестно')
    while true; do
        clear
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${GREEN}                🚀 SERVER SETUP TOOL 🚀                        ${NC}"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        if [[ -f /etc/os-release ]]; then . /etc/os-release; echo -e "${YELLOW}  ОС:${NC} $PRETTY_NAME"; fi
        echo -e "${YELLOW}  Ядро:${NC} $(uname -r)"
        echo -e "${YELLOW}  IP:${NC} $server_ip"
        echo -e "${YELLOW}  Uptime:${NC} $(uptime -p 2>/dev/null || uptime | awk -F'( |,|:)+' '{print $6"h "$7"m"}')"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "  1) Подготовка Ubuntu 24 (Обновление + Базовое ПО + Docker)"
        echo -e "  2) Настройка сети и включение BBR"
        echo -e "  3) Настройка UFW (запуск UFW Manager)"
        echo -e "  4) Установка TrafficGuard"
        echo -e "  5) Установка AdGuard Home"
        echo -e "  6) Настройка базовой защиты SSH"
        echo -e "  7) Управление файлом подкачки (Swap)"
        echo -e "  8) Бенчмарк сервера (YABS)"
        echo -e "  9) Очистка системы от мусора и кэша"
        echo -e "  10) Установить скрипт в систему (запуск через server-tool)"
        echo -e "  11) Обновить этот скрипт (Self-Update)"
        echo -e "  0) Выход"
        echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
        read -p "Выберите опцию: " choice
        
        case $choice in
            1) ubuntu_prep ;;
            2) setup_network_bbr ;;
            3) setup_ufw ;;
            4) setup_trafficguard ;;
            5) setup_adguard ;;
            6) setup_ssh ;;
            7) setup_swap ;;
            8) run_bench ;;
            9) system_cleanup ;;
            10) install_to_system ;;
            11) self_update ;;
            0) msg_ok "Выход..."; exit 0 ;;
            *) msg_err "Неверный выбор!"; sleep 1 ;;
        esac
    done
}

# ======================================================
# Точка входа
# ======================================================
check_root
show_menu
