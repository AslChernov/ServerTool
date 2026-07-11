#!/usr/bin/env bash
# ServerTool — interactive post-install hardening for a Remnawave node.

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly VERSION="2.0.0"
readonly APP_NAME="ServerTool"
readonly CONFIG_DIR="/etc/server-tool"
readonly BACKUP_ROOT="/var/backups/server-tool"
readonly LOG_FILE="/var/log/server-tool.log"
readonly SSH_DROPIN="/etc/ssh/sshd_config.d/00-server-tool.conf"
readonly GUARD_CONFIG="${CONFIG_DIR}/guard.conf"
readonly GUARD_UPDATER="/usr/local/sbin/server-tool-guard-update"
readonly GUARD_SERVICE="/etc/systemd/system/server-tool-guard.service"
readonly GUARD_TIMER="/etc/systemd/system/server-tool-guard.timer"
readonly DEFAULT_PANEL_IP="45.148.62.18"
readonly DEFAULT_NODE_PORT="2222"

if [[ -t 1 ]]; then
    readonly RED='\033[0;31m' GREEN='\033[0;32m' YELLOW='\033[1;33m'
    readonly BLUE='\033[0;34m' CYAN='\033[0;36m' BOLD='\033[1m' NC='\033[0m'
else
    readonly RED='' GREEN='' YELLOW='' BLUE='' CYAN='' BOLD='' NC=''
fi

info()    { printf '%bℹ️  %s%b\n' "$CYAN" "$*" "$NC"; }
success() { printf '%b✅ %s%b\n' "$GREEN" "$*" "$NC"; }
warn()    { printf '%b⚠️  %s%b\n' "$YELLOW" "$*" "$NC"; }
error()   { printf '%b❌ %s%b\n' "$RED" "$*" "$NC" >&2; }
step()    { printf '\n%b▶ %s%b\n' "$BLUE" "$*" "$NC"; }

log() {
    local level="$1"; shift
    if [[ $EUID -eq 0 ]]; then
        printf '%s [%s] %s\n' "$(date '+%F %T')" "$level" "$*" >> "$LOG_FILE" 2>/dev/null || true
    fi
}

die() { error "$*"; log ERROR "$*"; exit 1; }

on_error() {
    local code=$? line=${BASH_LINENO[0]:-?}
    error "Ошибка в строке ${line} (код ${code}). Подробности: ${LOG_FILE}"
    log ERROR "line=${line} exit=${code} command=${BASH_COMMAND}"
    exit "$code"
}
trap on_error ERR

pause() {
    printf '\n'
    read -r -p "Нажмите Enter, чтобы продолжить..." _ || true
}

confirm() {
    local prompt="$1" default="${2:-N}" answer hint="y/N"
    [[ $default == Y ]] && hint="Y/n"
    read -r -p "${prompt} [${hint}]: " answer || true
    answer=${answer:-$default}
    [[ $answer =~ ^[YyДд]$ ]]
}

require_root() {
    [[ $EUID -eq 0 ]] || die "Запустите скрипт от root: sudo bash server_tool.sh"
}

require_supported_os() {
    [[ -r /etc/os-release ]] || die "Не удалось определить операционную систему."
    # shellcheck disable=SC1091
    source /etc/os-release
    case "${ID:-}" in
        ubuntu|debian) ;;
        *) die "Поддерживаются только Ubuntu и Debian (обнаружено: ${ID:-unknown})." ;;
    esac
    [[ $(dpkg --print-architecture 2>/dev/null) == amd64 ]] || \
        warn "XanMod доступен только для amd64; остальные разделы продолжат работать."
}

valid_port() { [[ ${1:-} =~ ^[0-9]+$ ]] && ((1 <= 10#$1 && 10#$1 <= 65535)); }

valid_ipv4_cidr() {
    python3 - "$1" <<'PY' >/dev/null 2>&1
import ipaddress, sys
try:
    value = ipaddress.ip_network(sys.argv[1], strict=False)
    raise SystemExit(0 if value.version == 4 else 1)
except ValueError:
    raise SystemExit(1)
PY
}

ensure_packages() {
    local missing=() package
    for package in "$@"; do
        dpkg-query -W -f='${Status}' "$package" 2>/dev/null | grep -q 'ok installed' || missing+=("$package")
    done
    if ((${#missing[@]})); then
        step "Установка пакетов: ${missing[*]}"
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}"
    fi
}

make_backup() {
    local label="$1" dir
    dir="${BACKUP_ROOT}/$(date +%Y%m%d-%H%M%S)-${label}"
    mkdir -p "$dir"
    chmod 700 "$dir"
    printf '%s\n' "$dir"
}

detect_ssh_port() {
    local port
    port=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2; exit}') || true
    if ! valid_port "${port:-}"; then
        port=$(ss -ltnp 2>/dev/null | awk '/sshd/ {sub(/^.*:/, "", $4); print $4; exit}') || true
    fi
    valid_port "${port:-}" && printf '%s\n' "$port" || printf '22\n'
}

ufw_active() { ufw status 2>/dev/null | grep -q '^Status: active'; }

system_update() {
    require_root
    step "Обновление системы"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y
    DEBIAN_FRONTEND=noninteractive apt-get autoremove -y
    apt-get autoclean
    success "Система обновлена."
    [[ ! -f /var/run/reboot-required ]] || warn "Для завершения обновления нужна перезагрузка."
    log INFO "system update completed"
}

choose_https_mode() {
    local choice
    printf '\n443 для VPN:\n  1) TCP + UDP (рекомендуется)\n  2) Только TCP\n  3) Только UDP\n  0) Не открывать\n' >&2
    while true; do
        read -r -p "Выбор [1]: " choice || true
        choice=${choice:-1}
        case $choice in 1) printf 'both\n'; return;; 2) printf 'tcp\n'; return;; 3) printf 'udp\n'; return;; 0) printf 'none\n'; return;; esac
        warn "Введите 0, 1, 2 или 3."
    done
}

configure_firewall() {
    require_root
    ensure_packages ufw nftables python3 curl ca-certificates
    local ssh_port https_mode node_port panel_ip backup
    ssh_port=$(detect_ssh_port)
    info "Обнаружен SSH-порт: ${ssh_port}/tcp"
    https_mode=$(choose_https_mode)
    read -r -p "Порт Remnawave-ноды [${DEFAULT_NODE_PORT}]: " node_port || true
    node_port=${node_port:-$DEFAULT_NODE_PORT}
    valid_port "$node_port" || { error "Некорректный порт."; return 1; }
    read -r -p "IPv4/CIDR панели, которой разрешён порт ${node_port} [${DEFAULT_PANEL_IP}]: " panel_ip || true
    panel_ip=${panel_ip:-$DEFAULT_PANEL_IP}
    valid_ipv4_cidr "$panel_ip" || { error "Некорректный IPv4 или CIDR."; return 1; }

    printf '\nБудут применены правила:\n'
    printf '  🔐 SSH:             %s/tcp — для всех\n' "$ssh_port"
    printf '  🌐 VPN 443:         %s\n' "$https_mode"
    printf '  🧩 Remnawave API:   %s/tcp — только %s\n' "$node_port" "$panel_ip"
    warn "UFW будет сброшен. Остальные входящие правила будут удалены."
    confirm "Продолжить?" || { warn "Отменено."; return 0; }

    backup=$(make_backup firewall)
    cp -a /etc/default/ufw "$backup/" 2>/dev/null || true
    cp -a /etc/ufw "$backup/" 2>/dev/null || true
    ufw status numbered > "$backup/ufw-status.txt" 2>&1 || true
    sed -Ei 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw limit "$ssh_port/tcp" comment "SSH"
    ufw allow proto tcp from "$panel_ip" to any port "$node_port" comment "Remnawave API"
    case $https_mode in
        both) ufw allow 443/tcp comment "VPN HTTPS"; ufw allow 443/udp comment "VPN QUIC/UDP" ;;
        tcp)  ufw allow 443/tcp comment "VPN HTTPS" ;;
        udp)  ufw allow 443/udp comment "VPN UDP" ;;
    esac
    ufw logging low
    ufw --force enable
    write_guard_config "$node_port" "$panel_ip"
    install_guard_runtime
    success "Firewall настроен. Резервная копия: ${backup}"
    printf '\n'; ufw status numbered
    log INFO "firewall configured ssh=${ssh_port} https=${https_mode} node=${node_port} panel=${panel_ip}"
}

write_guard_config() {
    local node_port="$1" panel_ip="$2"
    mkdir -p "$CONFIG_DIR"
    cat > "$GUARD_CONFIG" <<EOF
# Managed by ServerTool. Shell syntax; root-writable only.
NODE_PORT="${node_port}"
PANEL_IPV4="${panel_ip}"
BLOCKLIST_URLS=(
  "https://cdn.jsdelivr.net/gh/shadow-netlab/traffic-guard-lists@main/public/antiscanner.list"
  "https://cdn.jsdelivr.net/gh/shadow-netlab/traffic-guard-lists@main/public/government_networks.list"
)
# Optional ISO 3166-1 alpha-2 country codes, separated by spaces.
GEO_COUNTRIES=""
EOF
    chmod 600 "$GUARD_CONFIG"
}

install_guard_runtime() {
    mkdir -p "$CONFIG_DIR"
    [[ -f $GUARD_CONFIG ]] || write_guard_config "$DEFAULT_NODE_PORT" "$DEFAULT_PANEL_IP"
    cat > "$GUARD_UPDATER" <<'GUARD_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
CONFIG=/etc/server-tool/guard.conf
TABLE=server_tool_guard
[[ -r $CONFIG ]] || { echo "Missing $CONFIG" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONFIG"
[[ ${NODE_PORT:-} =~ ^[0-9]+$ ]] && ((NODE_PORT >= 1 && NODE_PORT <= 65535)) || exit 1
python3 - "$PANEL_IPV4" <<'PY' >/dev/null
import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1], strict=False)
assert n.version == 4
PY
work=$(mktemp -d /run/server-tool-guard.XXXXXX)
trap 'rm -rf "$work"' EXIT
: > "$work/raw"
downloaded=0
for url in "${BLOCKLIST_URLS[@]:-}"; do
    if curl --fail --silent --show-error --location --max-time 45 "$url" >> "$work/raw"; then
        downloaded=$((downloaded + 1)); printf '\n' >> "$work/raw"
    else
        echo "Warning: could not download $url" >&2
    fi
done
geo_codes=()
IFS=' ' read -r -a geo_codes <<< "${GEO_COUNTRIES:-}"
for cc in "${geo_codes[@]}"; do
    [[ -n $cc ]] || continue
    [[ $cc =~ ^[a-zA-Z]{2}$ ]] || continue
    url="https://www.ipdeny.com/ipblocks/data/countries/${cc,,}.zone"
    if curl --fail --silent --show-error --location --max-time 45 "$url" >> "$work/raw"; then
        downloaded=$((downloaded + 1)); printf '\n' >> "$work/raw"
    fi
done
if ((downloaded == 0)); then
    echo "No blocklist source was downloaded; keeping current nftables table." >&2
    exit 1
fi
python3 - "$work/raw" "$work/collapsed" <<'PY'
import ipaddress, sys
nets = []
with open(sys.argv[1], encoding="utf-8", errors="ignore") as source:
    for raw in source:
        value = raw.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            net = ipaddress.ip_network(value, strict=False)
            # Never let a bad feed block default/private/local ranges or consume unbounded RAM.
            if net.version == 4 and net.prefixlen >= 8 and net.is_global:
                nets.append(net)
        except ValueError:
            pass
if len(nets) > 500_000:
    raise SystemExit("Too many blocklist entries; refusing update")
with open(sys.argv[2], "w", encoding="ascii") as target:
    for net in ipaddress.collapse_addresses(nets):
        target.write(f"{net}\n")
PY
count=$(wc -l < "$work/collapsed")
((count >= 10)) || { echo "Only $count valid networks received; keeping current rules." >&2; exit 1; }
{
    nft list table inet "$TABLE" >/dev/null 2>&1 && echo "delete table inet $TABLE"
    cat <<EOF
table inet $TABLE {
  set blocked_v4 {
    type ipv4_addr
    flags interval
    auto-merge
    elements = {
EOF
    sed 's/$/,/' "$work/collapsed"
    cat <<EOF
    }
  }
  set panel_v4 {
    type ipv4_addr
    flags interval
    elements = { $PANEL_IPV4 }
  }
  chain input_guard {
    type filter hook input priority -20; policy accept;
    ip saddr @panel_v4 counter accept
    ip saddr @blocked_v4 counter drop
    tcp dport $NODE_PORT counter drop
  }
  chain forward_guard {
    type filter hook forward priority -20; policy accept;
    ip saddr @panel_v4 counter accept
    ip saddr @blocked_v4 counter drop
    meta l4proto tcp ct original proto-dst $NODE_PORT counter drop
    tcp dport $NODE_PORT counter drop
  }
}
EOF
} > "$work/rules.nft"
nft --check --file "$work/rules.nft"
nft --file "$work/rules.nft"
echo "Loaded $count IPv4 networks into inet/$TABLE"
GUARD_SCRIPT
    chmod 750 "$GUARD_UPDATER"
    cat > "$GUARD_SERVICE" <<EOF
[Unit]
Description=ServerTool nftables guard for Remnawave
Wants=network-online.target
After=network-online.target ufw.service docker.service

[Service]
Type=oneshot
ExecStart=${GUARD_UPDATER}
TimeoutStartSec=3min

[Install]
WantedBy=multi-user.target
EOF
    cat > "$GUARD_TIMER" <<EOF
[Unit]
Description=Update ServerTool nftables blocklists daily

[Timer]
OnBootSec=10min
OnUnitActiveSec=1d
RandomizedDelaySec=30min
Persistent=true
Unit=server-tool-guard.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable server-tool-guard.service server-tool-guard.timer >/dev/null
    if systemctl start server-tool-guard.service; then
        systemctl enable --now server-tool-guard.timer >/dev/null
        success "nftables-защита активна; списки обновляются ежедневно."
    else
        warn "Не удалось загрузить списки. UFW уже настроен; повторите обновление позже."
    fi
}

guard_menu() {
    require_root
    ensure_packages nftables python3 curl ca-certificates
    local choice node_port panel_ip countries
    while true; do
        clear
        printf '%b🛡️  NFTABLES-ЗАЩИТА%b\n\n' "$BOLD" "$NC"
        printf '  1) Установить/переустановить защиту\n'
        printf '  2) Обновить списки сейчас\n'
        printf '  3) Настроить Geo-block по кодам стран\n'
        printf '  4) Показать статус и счётчики\n'
        printf '  5) Удалить только nftables-защиту\n'
        printf '  0) Назад\n\n'
        read -r -p "Выбор: " choice || true
        case $choice in
            1)
                read -r -p "Порт ноды [${DEFAULT_NODE_PORT}]: " node_port || true
                node_port=${node_port:-$DEFAULT_NODE_PORT}
                read -r -p "IPv4/CIDR панели [${DEFAULT_PANEL_IP}]: " panel_ip || true
                panel_ip=${panel_ip:-$DEFAULT_PANEL_IP}
                valid_port "$node_port" && valid_ipv4_cidr "$panel_ip" || { error "Некорректные данные."; pause; continue; }
                write_guard_config "$node_port" "$panel_ip"
                install_guard_runtime
                pause
                ;;
            2)
                [[ -x $GUARD_UPDATER ]] || install_guard_runtime
                "$GUARD_UPDATER" && success "Списки обновлены."
                pause
                ;;
            3)
                [[ -f $GUARD_CONFIG ]] || write_guard_config "$DEFAULT_NODE_PORT" "$DEFAULT_PANEL_IP"
                read -r -p "Коды стран через пробел (например: cn ir); пусто = отключить: " countries || true
                if [[ -n $countries ]] && ! [[ $countries =~ ^([a-zA-Z]{2})([[:space:]]+[a-zA-Z]{2})*$ ]]; then
                    error "Используйте двухбуквенные коды стран через пробел."
                else
                    sed -Ei "s/^GEO_COUNTRIES=.*/GEO_COUNTRIES=\"${countries,,}\"/" "$GUARD_CONFIG"
                    install_guard_runtime
                fi
                pause
                ;;
            4)
                systemctl --no-pager --full status server-tool-guard.service 2>/dev/null || true
                nft list table inet server_tool_guard 2>/dev/null || warn "Таблица не загружена."
                pause
                ;;
            5)
                if confirm "Удалить таблицу ServerTool, сервис и таймер?"; then
                    systemctl disable --now server-tool-guard.timer server-tool-guard.service 2>/dev/null || true
                    nft delete table inet server_tool_guard 2>/dev/null || true
                    rm -f "$GUARD_UPDATER" "$GUARD_SERVICE" "$GUARD_TIMER"
                    systemctl daemon-reload
                    success "nftables-защита удалена. UFW не изменён."
                fi
                pause
                ;;
            0) return ;;
            *) warn "Неизвестный пункт."; sleep 1 ;;
        esac
    done
}

target_user_prompt() {
    local default_user user
    default_user=${SUDO_USER:-root}
    [[ $default_user == root ]] || id "$default_user" >/dev/null 2>&1 || default_user=root
    read -r -p "Пользователь SSH [${default_user}]: " user || true
    user=${user:-$default_user}
    id "$user" >/dev/null 2>&1 || return 1
    printf '%s\n' "$user"
}

user_home() { getent passwd "$1" | cut -d: -f6; }

install_public_key() {
    local user home pubkey keyfile owner_group tmp
    user=$(target_user_prompt) || { error "Пользователь не найден."; return 1; }
    home=$(user_home "$user")
    read -r -p "Вставьте публичный ключ одной строкой: " pubkey || true
    [[ $pubkey =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh.com)[[:space:]] ]] || {
        error "Формат публичного ключа не распознан."; return 1;
    }
    tmp=$(mktemp)
    printf '%s\n' "$pubkey" > "$tmp"
    ssh-keygen -l -f "$tmp" >/dev/null 2>&1 || { rm -f "$tmp"; error "Ключ повреждён."; return 1; }
    rm -f "$tmp"
    install -d -m 700 "${home}/.ssh"
    keyfile="${home}/.ssh/authorized_keys"
    touch "$keyfile"; chmod 600 "$keyfile"
    if grep -Fqx "$pubkey" "$keyfile"; then
        warn "Такой ключ уже добавлен."
    else
        printf '%s\n' "$pubkey" >> "$keyfile"
        success "Публичный ключ добавлен для ${user}."
    fi
    owner_group=$(id -gn "$user")
    chown -R "$user:$owner_group" "${home}/.ssh"
    log INFO "public key added for user=${user}"
}

generate_ssh_key() {
    local user home out_dir key_name key_path passphrase owner_group
    user=$(target_user_prompt) || { error "Пользователь не найден."; return 1; }
    home=$(user_home "$user")
    out_dir="/root/server-tool-keys"
    mkdir -p "$out_dir"; chmod 700 "$out_dir"
    key_name="$(hostname -s)-${user}-$(date +%Y%m%d-%H%M%S)"
    key_path="${out_dir}/${key_name}"
    read -r -s -p "Пароль для приватного ключа (Enter = без пароля): " passphrase || true
    printf '\n'
    ssh-keygen -q -t ed25519 -a 100 -N "$passphrase" -C "${user}@$(hostname)-ServerTool" -f "$key_path"
    install -d -m 700 "${home}/.ssh"
    cat "${key_path}.pub" >> "${home}/.ssh/authorized_keys"
    chmod 600 "${home}/.ssh/authorized_keys"
    owner_group=$(id -gn "$user")
    chown -R "$user:$owner_group" "${home}/.ssh"
    success "Ключ создан и разрешён для входа:"
    printf '  Приватный: %s\n  Публичный: %s.pub\n' "$key_path" "$key_path"
    warn "Скачайте приватный ключ по защищённому каналу, проверьте вход и удалите его с сервера."
    log INFO "ed25519 key generated for user=${user} path=${key_path}"
}

random_free_port() {
    local port
    for _ in {1..100}; do
        port=$(shuf -i 20000-60999 -n 1)
        ss -H -ltn "sport = :$port" 2>/dev/null | grep -q . || { printf '%s\n' "$port"; return; }
    done
    return 1
}

authorized_key_exists() {
    local user="$1" home
    home=$(user_home "$user")
    [[ -s "${home}/.ssh/authorized_keys" ]] && grep -Eq '^(ssh-|ecdsa-|sk-)' "${home}/.ssh/authorized_keys"
}

restore_ssh_backup() {
    local backup="$1"
    rm -f "$SSH_DROPIN"
    cp -a "$backup/sshd_config" /etc/ssh/sshd_config
    [[ ! -d "$backup/sshd_config.d" ]] || cp -a "$backup/sshd_config.d/." /etc/ssh/sshd_config.d/
}

configure_ssh() {
    require_root
    ensure_packages openssh-server openssh-client iproute2
    local old_port new_port user backup disable_password has_key choice file restart_ok
    old_port=$(detect_ssh_port)
    user=$(target_user_prompt) || { error "Пользователь не найден."; return 1; }
    new_port=$(random_free_port) || { error "Не удалось подобрать свободный порт."; return 1; }
    printf '\nТекущий порт: %s\nСлучайный порт: %s\n' "$old_port" "$new_port"
    read -r -p "Новый порт SSH [${new_port}]: " choice || true
    new_port=${choice:-$new_port}
    valid_port "$new_port" || { error "Некорректный порт."; return 1; }
    ss -H -ltn "sport = :$new_port" 2>/dev/null | grep -q . && { error "Порт ${new_port} уже занят."; return 1; }
    disable_password=no
    has_key=no
    if authorized_key_exists "$user"; then
        has_key=yes
        confirm "Отключить вход по паролю (рекомендуется после проверки ключа)?" && disable_password=yes
    else
        warn "У ${user} нет authorized_keys — вход по паролю отключён не будет."
    fi
    warn "Не закрывайте текущую SSH-сессию, пока не проверите новый вход в отдельном окне."
    confirm "Применить SSH-порт ${new_port}?" || return 0
    backup=$(make_backup ssh)
    cp -a /etc/ssh/sshd_config "$backup/"
    [[ -d /etc/ssh/sshd_config.d ]] && cp -a /etc/ssh/sshd_config.d "$backup/"
    mkdir -p /etc/ssh/sshd_config.d
    while IFS= read -r -d '' file; do
        [[ $file == "$SSH_DROPIN" ]] && continue
        sed -Ei 's/^([[:space:]]*)Port[[:space:]]+([0-9]+)/\1# ServerTool disabled previous Port \2/' "$file"
    done < <(find /etc/ssh -maxdepth 2 -type f \( -name sshd_config -o -path '/etc/ssh/sshd_config.d/*.conf' \) -print0)
    cat > "$SSH_DROPIN" <<EOF
# Managed by ServerTool. Keep this file before other drop-ins.
Port ${new_port}
PubkeyAuthentication yes
MaxAuthTries 3
LoginGraceTime 30
X11Forwarding no
AllowTcpForwarding yes
EOF
    if [[ $user == root && $has_key == yes ]]; then
        printf 'PermitRootLogin prohibit-password\n' >> "$SSH_DROPIN"
    fi
    [[ $disable_password != yes ]] || printf 'PasswordAuthentication no\nKbdInteractiveAuthentication no\n' >> "$SSH_DROPIN"
    if ! sshd -t; then
        restore_ssh_backup "$backup"
        error "Проверка sshd не прошла; конфигурация восстановлена."
        return 1
    fi
    if command -v ufw >/dev/null && ufw_active; then
        ufw allow "$new_port/tcp" comment "SSH"
    fi
    systemctl daemon-reload
    restart_ok=yes
    if systemctl is-active --quiet ssh.socket; then
        systemctl restart ssh.socket || restart_ok=no
    fi
    systemctl restart ssh.service || restart_ok=no
    if [[ $restart_ok != yes ]]; then
        restore_ssh_backup "$backup"
        systemctl daemon-reload
        if systemctl is-active --quiet ssh.socket; then
            systemctl restart ssh.socket || true
        fi
        systemctl restart ssh.service || true
        error "SSH не перезапустился с новой конфигурацией; файлы восстановлены."
        return 1
    fi
    sleep 1
    if ss -H -ltn "sport = :$new_port" | grep -q .; then
        success "SSH слушает порт ${new_port}. Резервная копия: ${backup}"
        printf 'Проверка из нового окна: ssh -p %s %s@IP_СЕРВЕРА\n' "$new_port" "$user"
    else
        error "Новый порт не обнаружен. Текущую сессию не закрывайте; восстановите файлы из ${backup}."
        return 1
    fi
    log INFO "ssh configured old_port=${old_port} new_port=${new_port} user=${user} password_disabled=${disable_password}"
}

ssh_menu() {
    local choice
    while true; do
        clear
        printf '%b🔑 НАСТРОЙКА SSH%b\n\n' "$BOLD" "$NC"
        printf '  1) Вставить публичный ключ\n'
        printf '  2) Сгенерировать пару Ed25519\n'
        printf '  3) Сменить SSH на случайный/свой порт\n'
        printf '  4) Показать эффективные настройки\n'
        printf '  0) Назад\n\n'
        read -r -p "Выбор: " choice || true
        case $choice in
            1) install_public_key; pause ;;
            2) generate_ssh_key; pause ;;
            3) configure_ssh; pause ;;
            4) sshd -T 2>/dev/null | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|maxauthtries) '; pause ;;
            0) return ;;
            *) warn "Неизвестный пункт."; sleep 1 ;;
        esac
    done
}

detect_psabi() {
    local loader
    for loader in /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do
        [[ -x $loader ]] || continue
        "$loader" --help 2>/dev/null | grep -Eq 'x86-64-v3.*(supported|поддерж)' && { printf 'v3\n'; return; }
    done
    printf 'v2\n'
}

install_xanmod() {
    require_root
    [[ $(dpkg --print-architecture) == amd64 ]] || { error "XanMod поддерживается этим скриптом только на amd64."; return 1; }
    ensure_packages wget gpg ca-certificates lsb-release
    local codename level branch package key_tmp
    codename=$(lsb_release -sc)
    level=$(detect_psabi)
    info "Кодовое имя системы: ${codename}; рекомендуемый psABI: x86-64-${level}."
    printf '\nВетка XanMod:\n  1) LTS (рекомендуется для VPN-ноды)\n  2) Main\n  0) Отмена\n'
    read -r -p "Выбор [1]: " branch || true
    branch=${branch:-1}
    case $branch in
        1) package="linux-xanmod-lts-x64${level}" ;;
        2) package="linux-xanmod-x64${level}" ;;
        0) return 0 ;;
        *) error "Неизвестный вариант."; return 1 ;;
    esac
    if ! wget -qO /dev/null "http://deb.xanmod.org/dists/${codename}/Release"; then
        error "XanMod не публикует репозиторий для ${codename}. Настройки APT не изменены."
        return 1
    fi
    warn "Сторонние DKMS-модули могут быть несовместимы с новым ядром."
    confirm "Добавить официальный репозиторий и установить ${package}?" || return 0
    key_tmp=$(mktemp)
    wget -qO "$key_tmp" https://dl.xanmod.org/archive.key
    mkdir -p /etc/apt/keyrings
    gpg --batch --yes --dearmor -o /etc/apt/keyrings/xanmod-archive-keyring.gpg "$key_tmp"
    rm -f "$key_tmp"
    printf 'deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org %s main\n' "$codename" \
        > /etc/apt/sources.list.d/xanmod-release.list
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$package"
    success "${package} установлен. Перезагрузитесь, когда будет удобно."
    printf 'Текущее ядро: %s\n' "$(uname -r)"
    log INFO "xanmod installed package=${package}"
}

show_status() {
    clear
    printf '%b📊 СОСТОЯНИЕ НОДЫ%b\n\n' "$BOLD" "$NC"
    printf 'ОС:          %s\n' "$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")"
    printf 'Ядро:        %s\n' "$(uname -r)"
    printf 'SSH-порт:    %s/tcp\n' "$(detect_ssh_port)"
    if command -v ufw >/dev/null; then ufw status verbose || true; else printf 'UFW:         не установлен\n'; fi
    printf '\n'
    if nft list table inet server_tool_guard >/dev/null 2>&1; then
        printf 'nft guard:   активен\n'
        systemctl list-timers server-tool-guard.timer --no-pager 2>/dev/null || true
    else
        printf 'nft guard:   не активен\n'
    fi
    [[ ! -f /var/run/reboot-required ]] || warn "Требуется перезагрузка."
}

full_setup() {
    warn "Мастер последовательно предложит обновление, SSH, firewall/nftables и XanMod."
    confirm "Запустить полный мастер?" || return 0
    confirm "Обновить систему сейчас?" Y && system_update
    info "Сначала добавьте/создайте ключ, затем настройте порт SSH."
    ssh_menu
    configure_firewall
    confirm "Установить XanMod?" && install_xanmod
    success "Мастер завершён. Проверьте статус и новый SSH-вход до выхода из текущей сессии."
}

show_help() {
    cat <<EOF
${APP_NAME} ${VERSION} — настройка и защита Remnawave-ноды

Использование:
  sudo bash server_tool.sh          интерактивное меню
  sudo bash server_tool.sh --status состояние сервера
  bash server_tool.sh --version     версия
  bash server_tool.sh --help        справка
EOF
}

show_menu() {
    local choice
    while true; do
        clear
        printf '%b╔══════════════════════════════════════════╗%b\n' "$CYAN" "$NC"
        printf '%b║  🚀 ServerTool %-6s • Remnawave Node   ║%b\n' "$CYAN" "v${VERSION}" "$NC"
        printf '%b╚══════════════════════════════════════════╝%b\n\n' "$CYAN" "$NC"
        printf '  1) 🧰 Полная рекомендуемая настройка\n'
        printf '  2) 🔄 Обновить систему\n'
        printf '  3) 🔥 Настроить UFW и порты ноды\n'
        printf '  4) 🔑 Настроить SSH\n'
        printf '  5) 🛡️  nftables: Anti-Scanner и Geo-block\n'
        printf '  6) ⚡ Установить XanMod\n'
        printf '  7) 📊 Показать состояние\n'
        printf '  0) 👋 Выход\n\n'
        read -r -p "Выберите пункт: " choice || true
        case $choice in
            1) full_setup; pause ;;
            2) system_update; pause ;;
            3) configure_firewall; pause ;;
            4) ssh_menu ;;
            5) guard_menu ;;
            6) install_xanmod; pause ;;
            7) show_status; pause ;;
            0) success "Готово. Не забудьте проверить новый SSH-вход."; return ;;
            *) warn "Неизвестный пункт."; sleep 1 ;;
        esac
    done
}

main() {
    case "${1:-}" in
        -h|--help) show_help; return ;;
        -v|--version) printf '%s %s\n' "$APP_NAME" "$VERSION"; return ;;
        --status) require_root; require_supported_os; show_status; return ;;
        "") ;;
        *) show_help; return 2 ;;
    esac
    require_root
    require_supported_os
    mkdir -p "$BACKUP_ROOT"
    touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
    log INFO "ServerTool ${VERSION} started"
    show_menu
}

main "$@"
