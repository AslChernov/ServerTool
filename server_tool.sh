#!/usr/bin/env bash
# ServerTool — interactive post-install hardening for a Remnawave node.

set -Eeuo pipefail
IFS=$'\n\t'
umask 027

readonly APP_VERSION="3.0.12"
readonly APP_NAME="ServerTool"
readonly APT_LOCK_TIMEOUT=300
readonly APT_LOCK_RETRY_DELAY=5
readonly CONFIG_DIR="/etc/server-tool"
readonly BACKUP_ROOT="/var/backups/server-tool"
readonly LOG_FILE="/var/log/server-tool.log"
readonly SSH_DROPIN="/etc/ssh/sshd_config.d/00-server-tool.conf"
readonly GUARD_CONFIG="${CONFIG_DIR}/guard.conf"
readonly GUARD_UPDATER="/usr/local/sbin/server-tool-guard-update"
readonly GUARD_SERVICE="/etc/systemd/system/server-tool-guard.service"
readonly GUARD_UPDATE_SERVICE="/etc/systemd/system/server-tool-guard-update.service"
readonly GUARD_TIMER="/etc/systemd/system/server-tool-guard.timer"
readonly CROWDSEC_ACQUIS="/etc/crowdsec/acquis.d/server-tool.yaml"
readonly CROWDSEC_FORWARD="/usr/local/sbin/server-tool-crowdsec-forward"
readonly CROWDSEC_BOUNCER_CONFIG="/etc/crowdsec/bouncers/crowdsec-firewall-bouncer.yaml"
readonly CROWDSEC_BOUNCER_LOCAL="${CROWDSEC_BOUNCER_CONFIG}.local"
readonly CROWDSEC_BOUNCER_NAME="server-tool-firewall-bouncer"
readonly CROWDSEC_CONFIG_LOCAL="/etc/crowdsec/config.yaml.local"
readonly CROWDSEC_LAPI_CREDENTIALS_LOCAL="/etc/crowdsec/local_api_credentials.yaml.local"
readonly CROWDSEC_LAPI_PORT_FILE="${CONFIG_DIR}/crowdsec-lapi-port"
readonly CROWDSEC_MANAGED_MARKER="# Managed by ServerTool"
readonly DEFAULT_PANEL_IP="45.148.62.18"
readonly DEFAULT_NODE_PORT="2222"
readonly REMNAWAVE_NGINX_CONTAINER="remnawave-nginx"
readonly REMNANODE_CONTAINER="remnanode"

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
    local os_id
    [[ -r /etc/os-release ]] || die "Не удалось определить операционную систему."
    os_id=$(
        # Load OS metadata in a subshell so names such as VERSION cannot
        # collide with ServerTool's own constants or leak into application state.
        # shellcheck disable=SC1091
        source /etc/os-release
        printf '%s' "${ID:-}"
    )
    case "$os_id" in
        ubuntu|debian) ;;
        *) die "Поддерживаются только Ubuntu и Debian (обнаружено: ${os_id:-unknown})." ;;
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

log_package_failure() {
    local command="$1" output_file="$2"
    [[ $EUID -eq 0 ]] || return 0
    {
        printf '%s [ERROR] package command failed: %s\n' "$(date '+%F %T')" "$command"
        sed 's/^/[PACKAGE] /' "$output_file"
    } >> "$LOG_FILE" 2>/dev/null || true
}

report_dpkg_state() {
    local packages
    packages=$(dpkg-query -W -f='${binary:Package}\t${db:Status-Abbrev}\n' 2>/dev/null | \
        awk '$2 ~ /^i/ && ($2 !~ /^ii/ || substr($2, 3, 1) == "R") {print $1 " [" $2 "]"}' || true)
    if [[ -n $packages ]]; then
        error "Незавершённые пакеты dpkg:"
        while IFS= read -r package; do
            printf '  - %s\n' "$package" >&2
        done <<< "$packages"
    fi
}

prepare_dpkg_recovery_context() {
    local failed_output="$1" lapi_port crowdsec_failed=no

    if grep -Eqi \
        'dpkg: error processing package (crowdsec|crowdsec-firewall-bouncer)|installed (crowdsec|crowdsec-firewall-bouncer).*script.*error' \
        "$failed_output"; then
        crowdsec_failed=yes
    elif sed -n '/^Errors were encountered while processing:/,$p' "$failed_output" | \
        grep -Eqi '(^|[[:space:]/])(crowdsec|crowdsec-firewall-bouncer)([[:space:]:/]|$)'; then
        crowdsec_failed=yes
    fi

    if [[ $crowdsec_failed == yes ]]; then
        warn "Ошибка затрагивает CrowdSec. Останавливается restart-loop и проверяется порт LAPI."
        systemctl stop crowdsec-firewall-bouncer crowdsec >/dev/null 2>&1 || true
        if lapi_port=$(prepare_crowdsec_lapi); then
            info "CrowdSec подготовлен к повторной настройке (LAPI 127.0.0.1:${lapi_port})."
        else
            warn "Не удалось автоматически подготовить CrowdSec; dpkg всё равно попробует завершить настройку."
        fi
    fi
}

recover_dpkg_state() {
    local failed_output="$1" output_file status fix_status
    local -a pipe_status
    warn "dpkg не завершил настройку пакетов. Выполняется одна попытка штатного восстановления."
    prepare_dpkg_recovery_context "$failed_output"

    output_file=$(mktemp /tmp/server-tool-dpkg.XXXXXX)
    if LC_ALL=C DEBIAN_FRONTEND=noninteractive dpkg --configure --pending 2>&1 | tee "$output_file"; then
        status=0
    else
        pipe_status=("${PIPESTATUS[@]}")
        status=${pipe_status[0]}
        ((status != 0)) || status=${pipe_status[1]:-1}
        log_package_failure "dpkg --configure --pending" "$output_file"
        warn "dpkg --configure --pending не завершился успешно; APT попробует исправить зависимости."
    fi
    rm -f "$output_file"

    if APT_DPKG_RECOVERY_ACTIVE=1 run_apt --fix-broken install -y; then
        success "Состояние APT/dpkg восстановлено."
        return 0
    else
        fix_status=$?
    fi

    error "Автоматическое восстановление APT/dpkg не удалось."
    report_dpkg_state
    return "$fix_status"
}

run_apt() {
    local output_file status deadline remaining delay command
    local recovery_attempted=0
    local -a pipe_status
    output_file=$(mktemp /tmp/server-tool-apt.XXXXXX)
    deadline=$((SECONDS + APT_LOCK_TIMEOUT))
    printf -v command '%q ' apt-get "$@"
    command=${command% }

    while true; do
        : > "$output_file"
        if LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get "$@" 2>&1 | tee "$output_file"; then
            rm -f "$output_file"
            return 0
        else
            pipe_status=("${PIPESTATUS[@]}")
            status=${pipe_status[0]}
            ((status != 0)) || status=${pipe_status[1]:-1}
        fi

        if ((status == 100)) && grep -Eqi \
            'could not get lock|unable to acquire.*lock|unable to lock directory' "$output_file"; then
            remaining=$((deadline - SECONDS))
            if ((remaining <= 0)); then
                log_package_failure "$command" "$output_file"
                rm -f "$output_file"
                error "APT остаётся занят другим процессом более ${APT_LOCK_TIMEOUT} секунд. Повторите операцию позже."
                return "$status"
            fi

            delay=$APT_LOCK_RETRY_DELAY
            ((delay <= remaining)) || delay=$remaining
            warn "APT занят другим процессом. Повтор через ${delay} с (ожидание до ${remaining} с)..."
            sleep "$delay"
            continue
        fi

        log_package_failure "$command" "$output_file"
        if ((status == 100 && recovery_attempted == 0)) && \
            [[ ${APT_DPKG_RECOVERY_ACTIVE:-0} != 1 ]] && \
            grep -Eqi 'sub-process .*dpkg.*returned an error code|dpkg: error processing package' "$output_file"; then
            recovery_attempted=1
            if recover_dpkg_state "$output_file"; then
                warn "Повтор команды после восстановления: ${command}"
                continue
            fi
            rm -f "$output_file"
            error "Команда ${command} завершилась с кодом ${status}. Полный вывод сохранён в ${LOG_FILE}."
            return "$status"
        fi

        rm -f "$output_file"
        error "Команда ${command} завершилась с кодом ${status}. Полный вывод сохранён в ${LOG_FILE}."
        [[ $status != 100 ]] || report_dpkg_state
        return "$status"
    done
}

ensure_packages() {
    local missing=() package status
    for package in "$@"; do
        status=$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)
        [[ $status == *"ok installed"* ]] || missing+=("$package")
    done
    if ((${#missing[@]})); then
        step "Установка пакетов: ${missing[*]}"
        run_apt update
        run_apt install -y --no-install-recommends "${missing[@]}"
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
    local port output
    output=$(sshd -T 2>/dev/null || true)
    port=$(awk '$1 == "port" {print $2; exit}' <<< "$output")
    if ! valid_port "${port:-}"; then
        output=$(ss -ltnp 2>/dev/null || true)
        port=$(awk '/sshd/ {sub(/^.*:/, "", $4); print $4; exit}' <<< "$output")
    fi
    valid_port "${port:-}" && printf '%s\n' "$port" || printf '22\n'
}

system_update() {
    require_root
    step "Обновление системы"
    run_apt update
    run_apt full-upgrade -y
    run_apt autoremove -y
    run_apt autoclean
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
    ensure_packages nftables python3 curl ca-certificates
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
    warn "Будет включён единый nftables-firewall. Все неразрешённые входящие и Docker-порты будут закрыты."
    confirm "Продолжить?" || { warn "Отменено."; return 0; }

    backup=$(make_backup firewall)
    nft list ruleset > "$backup/nft-ruleset.txt" 2>&1 || true
    cp -a /etc/default/ufw "$backup/" 2>/dev/null || true
    cp -a /etc/ufw "$backup/" 2>/dev/null || true
    ufw status numbered > "$backup/ufw-status.txt" 2>&1 || true

    write_guard_config "$ssh_port" "$node_port" "$panel_ip" "$https_mode"
    install_guard_runtime

    # The new firewall is already active. Now remove UFW without flushing unrelated nftables tables.
    if command -v ufw >/dev/null 2>&1; then
        ufw --force disable >/dev/null 2>&1 || true
        systemctl disable --now ufw.service >/dev/null 2>&1 || true
        run_apt purge -y ufw >/dev/null || warn "UFW отключён, но пакет не удалось удалить."
        "$GUARD_UPDATER" --apply
    fi

    success "Firewall настроен. Резервная копия: ${backup}"
    printf '\n'; nft list table inet server_tool_guard
    log INFO "firewall configured ssh=${ssh_port} https=${https_mode} node=${node_port} panel=${panel_ip}"
}

write_guard_config() {
    local ssh_port="$1" node_port="$2" panel_ip="$3" https_mode="$4" geo_countries=""
    if [[ -r $GUARD_CONFIG ]]; then
        geo_countries=$(awk -F= '$1 == "GEO_COUNTRIES" {gsub(/\"/, "", $2); print $2; exit}' "$GUARD_CONFIG")
    fi
    mkdir -p "$CONFIG_DIR"
    cat > "$GUARD_CONFIG" <<EOF
# Managed by ServerTool. Shell syntax; root-writable only.
SSH_PORT="${ssh_port}"
NODE_PORT="${node_port}"
PANEL_IPV4="${panel_ip}"
HTTPS_MODE="${https_mode}"
BLOCKLIST_URLS=(
  "https://cdn.jsdelivr.net/gh/shadow-netlab/traffic-guard-lists@main/public/antiscanner.list"
  "https://cdn.jsdelivr.net/gh/shadow-netlab/traffic-guard-lists@main/public/government_networks.list"
)
# Optional ISO 3166-1 alpha-2 country codes, separated by spaces.
GEO_COUNTRIES="${geo_countries}"
EOF
    chmod 600 "$GUARD_CONFIG"
}

install_guard_runtime() {
    mkdir -p "$CONFIG_DIR"
    [[ -f $GUARD_CONFIG ]] || write_guard_config "$(detect_ssh_port)" "$DEFAULT_NODE_PORT" "$DEFAULT_PANEL_IP" both
    cat > "$GUARD_UPDATER" <<'GUARD_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
CONFIG=/etc/server-tool/guard.conf
TABLE=server_tool_guard
CACHE=/var/lib/server-tool/blocklist-v4.txt
[[ -r $CONFIG ]] || { echo "Missing $CONFIG" >&2; exit 1; }
# shellcheck disable=SC1090
source "$CONFIG"
[[ ${SSH_PORT:-} =~ ^[0-9]+$ ]] && ((SSH_PORT >= 1 && SSH_PORT <= 65535)) || exit 1
[[ ${NODE_PORT:-} =~ ^[0-9]+$ ]] && ((NODE_PORT >= 1 && NODE_PORT <= 65535)) || exit 1
[[ ${HTTPS_MODE:-} =~ ^(both|tcp|udp|none)$ ]] || exit 1
python3 - "$PANEL_IPV4" <<'PY' >/dev/null
import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1], strict=False)
assert n.version == 4
PY
mkdir -p /var/lib/server-tool
work=$(mktemp -d /run/server-tool-guard.XXXXXX)
trap 'rm -rf "$work"' EXIT
if [[ ${1:---apply} == --refresh ]]; then
    : > "$work/raw"
    downloaded=0
    expected=${#BLOCKLIST_URLS[@]}
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
        expected=$((expected + 1))
        url="https://www.ipdeny.com/ipblocks/data/countries/${cc,,}.zone"
        if curl --fail --silent --show-error --location --max-time 45 "$url" >> "$work/raw"; then
            downloaded=$((downloaded + 1)); printf '\n' >> "$work/raw"
        fi
    done
    if ((downloaded == 0)); then
        [[ -s $CACHE ]] || { echo "No list source and no cache; core firewall will use an empty blocklist." >&2; : > "$CACHE"; }
    elif ((downloaded < expected)) && [[ -s $CACHE ]]; then
        echo "Only $downloaded of $expected sources downloaded; keeping cached blocklist." >&2
    else
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
        if ((count >= 10)); then
            install -m 600 "$work/collapsed" "$CACHE"
        elif [[ ! -s $CACHE ]]; then
            echo "Only $count valid networks and no cache; refusing update." >&2
            exit 1
        else
            echo "Only $count valid networks; keeping cached blocklist." >&2
        fi
    fi
fi
touch "$CACHE"
count=$(wc -l < "$CACHE")
{
    nft list table inet "$TABLE" >/dev/null 2>&1 && echo "delete table inet $TABLE"
    cat <<EOF
table inet $TABLE {
  set blocked_v4 {
    type ipv4_addr
    flags interval
    auto-merge
EOF
    if ((count > 0)); then
        echo '    elements = {'
        sed 's/^/      /; s/$/,/' "$CACHE"
        echo '    }'
    fi
    cat <<EOF
  }
  set panel_v4 {
    type ipv4_addr
    flags interval
    elements = { $PANEL_IPV4 }
  }
  chain input {
    type filter hook input priority -20; policy drop;
    iifname "lo" counter accept
    iifname "docker0" counter accept
    iifname "br-*" counter accept
    ct state invalid counter drop
    ct state established,related counter accept
    meta l4proto ipv6-icmp counter accept
    meta nfproto ipv4 ip protocol icmp limit rate 10/second counter accept
    meta nfproto ipv4 udp sport 67 udp dport 68 counter accept
    meta nfproto ipv4 ip saddr @panel_v4 tcp dport $NODE_PORT counter accept
    meta nfproto ipv4 ip saddr @blocked_v4 counter drop
    meta nfproto ipv4 tcp dport $SSH_PORT counter accept
EOF
    case "$HTTPS_MODE" in
        both) echo '    meta nfproto ipv4 tcp dport 443 counter accept'; echo '    meta nfproto ipv4 udp dport 443 counter accept' ;;
        tcp)  echo '    meta nfproto ipv4 tcp dport 443 counter accept' ;;
        udp)  echo '    meta nfproto ipv4 udp dport 443 counter accept' ;;
    esac
    cat <<EOF
    counter drop
  }
  chain forward {
    type filter hook forward priority -20; policy accept;
    ct state invalid counter drop
    meta nfproto ipv4 ip saddr @panel_v4 meta l4proto tcp ct original proto-dst $NODE_PORT counter accept
    ip saddr @blocked_v4 counter drop
    ct state established,related counter accept
    iifname "docker0" counter accept
    iifname "br-*" counter accept
    meta l4proto tcp ct original proto-dst $NODE_PORT counter drop
    tcp dport $NODE_PORT counter drop
EOF
    case "$HTTPS_MODE" in
        both) echo '    meta l4proto tcp ct original proto-dst 443 counter accept'; echo '    meta l4proto udp ct original proto-dst 443 counter accept' ;;
        tcp)  echo '    meta l4proto tcp ct original proto-dst 443 counter accept' ;;
        udp)  echo '    meta l4proto udp ct original proto-dst 443 counter accept' ;;
    esac
    cat <<EOF
    ct status dnat counter drop
  }
}
EOF
} > "$work/rules.nft"
nft --check --file "$work/rules.nft"
if [[ ${1:-} == --check ]]; then
    echo "nftables syntax is valid"
    exit 0
fi
nft --file "$work/rules.nft"
echo "Applied nftables firewall with $count blocked IPv4 networks"
GUARD_SCRIPT
    chmod 750 "$GUARD_UPDATER"
    cat > "$GUARD_SERVICE" <<EOF
[Unit]
Description=ServerTool nftables firewall for Remnawave
After=local-fs.target
Before=docker.service

[Service]
Type=oneshot
ExecStart=${GUARD_UPDATER} --apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
    cat > "$GUARD_UPDATE_SERVICE" <<EOF
[Unit]
Description=Refresh ServerTool nftables blocklists
Wants=network-online.target
After=network-online.target server-tool-guard.service

[Service]
Type=oneshot
ExecStart=${GUARD_UPDATER} --refresh
TimeoutStartSec=3min
EOF
    cat > "$GUARD_TIMER" <<EOF
[Unit]
Description=Update ServerTool nftables blocklists daily

[Timer]
OnBootSec=10min
OnUnitActiveSec=1d
RandomizedDelaySec=30min
Persistent=true
Unit=server-tool-guard-update.service

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable server-tool-guard.service server-tool-guard.timer >/dev/null
    if "$GUARD_UPDATER" --refresh; then
        systemctl restart server-tool-guard.service >/dev/null
        systemctl enable --now server-tool-guard.timer >/dev/null
        success "Единый nftables-firewall активен; списки обновляются ежедневно."
    else
        "$GUARD_UPDATER" --apply
        systemctl restart server-tool-guard.service >/dev/null
        systemctl enable --now server-tool-guard.timer >/dev/null
        warn "Firewall активен с кэшированным/пустым списком; сетевые списки обновятся позже."
    fi
}

guard_menu() {
    require_root
    ensure_packages nftables python3 curl ca-certificates
    local choice countries
    while true; do
        clear 2>/dev/null || true
        printf '%b🛡️  NFTABLES-ЗАЩИТА%b\n\n' "$BOLD" "$NC"
        printf '  1) Настроить/переустановить firewall\n'
        printf '  2) Обновить списки сейчас\n'
        printf '  3) Настроить Geo-block по кодам стран\n'
        printf '  4) Показать статус и счётчики\n'
        printf '  5) Удалить только nftables-защиту\n'
        printf '  0) Назад\n\n'
        read -r -p "Выбор: " choice || true
        case $choice in
            1)
                configure_firewall
                pause
                ;;
            2)
                if [[ ! -r $GUARD_CONFIG || ! -x $GUARD_UPDATER ]]; then
                    error "Сначала настройте firewall через пункт 1."
                    pause
                    continue
                fi
                "$GUARD_UPDATER" --refresh && success "Списки обновлены, firewall применён."
                pause
                ;;
            3)
                if [[ ! -f $GUARD_CONFIG ]]; then
                    error "Сначала настройте firewall через пункт 1."
                    pause
                    continue
                fi
                read -r -p "Коды стран через пробел (например: cn ir); пусто = отключить: " countries || true
                if [[ -n $countries ]] && ! [[ $countries =~ ^([a-zA-Z]{2})([[:space:]]+[a-zA-Z]{2})*$ ]]; then
                    error "Используйте двухбуквенные коды стран через пробел."
                else
                    sed -Ei "s/^GEO_COUNTRIES=.*/GEO_COUNTRIES=\"${countries,,}\"/" "$GUARD_CONFIG"
                    "$GUARD_UPDATER" --refresh
                fi
                pause
                ;;
            4)
                systemctl --no-pager --full status server-tool-guard.service 2>/dev/null || true
                nft list table inet server_tool_guard 2>/dev/null || warn "Таблица не загружена."
                pause
                ;;
            5)
                warn "После удаления сервер останется без основного входящего firewall."
                if confirm "Удалить таблицу ServerTool, сервисы и таймер?"; then
                    systemctl disable --now server-tool-guard.timer server-tool-guard-update.service server-tool-guard.service 2>/dev/null || true
                    nft delete table inet server_tool_guard 2>/dev/null || true
                    rm -f "$GUARD_UPDATER" "$GUARD_SERVICE" "$GUARD_UPDATE_SERVICE" "$GUARD_TIMER"
                    systemctl daemon-reload
                    success "Основной nftables-firewall удалён."
                fi
                pause
                ;;
            0) return ;;
            *) warn "Неизвестный пункт."; sleep 1 ;;
        esac
    done
}

crowdsec_installed() {
    local status
    command -v cscli >/dev/null 2>&1 || return 1
    status=$(dpkg-query -W -f='${Status}' crowdsec 2>/dev/null || true)
    [[ $status == *"ok installed"* ]]
}

crowdsec_port_available() {
    local port="$1"
    python3 - "$port" <<'PY'
import socket
import sys

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    raise SystemExit(1)
finally:
    sock.close()
PY
}

select_crowdsec_lapi_port() {
    local preferred="${1:-}" port

    if valid_port "$preferred" && crowdsec_port_available "$preferred"; then
        printf '%s\n' "$preferred"
        return 0
    fi

    for port in 8080 {18080..18089}; do
        [[ $port == "$preferred" ]] && continue
        if crowdsec_port_available "$port"; then
            printf '%s\n' "$port"
            return 0
        fi
    done

    error "Не найден свободный loopback-порт для CrowdSec LAPI (проверены 8080 и 18080-18089)."
    return 1
}

write_crowdsec_lapi_overrides() {
    local port="$1"
    local config_local="${2:-$CROWDSEC_CONFIG_LOCAL}"
    local credentials_local="${3:-$CROWDSEC_LAPI_CREDENTIALS_LOCAL}"
    local file

    for file in "$config_local" "$credentials_local"; do
        if [[ -s $file ]] && ! grep -Fqx "$CROWDSEC_MANAGED_MARKER" "$file"; then
            error "Файл ${file} уже содержит пользовательские настройки. ServerTool не будет его перезаписывать."
            return 1
        fi
    done

    cat > "$config_local" <<EOF
${CROWDSEC_MANAGED_MARKER}
api:
  server:
    listen_uri: 127.0.0.1:${port}
EOF
    cat > "$credentials_local" <<EOF
${CROWDSEC_MANAGED_MARKER}
url: http://127.0.0.1:${port}/
EOF
    chmod 0640 "$config_local" "$credentials_local"
}

prepare_crowdsec_lapi() {
    local preferred="" port owner

    if [[ -r $CROWDSEC_LAPI_PORT_FILE ]]; then
        read -r preferred < "$CROWDSEC_LAPI_PORT_FILE" || true
        valid_port "$preferred" || preferred=""
    fi

    port=$(select_crowdsec_lapi_port "$preferred") || return 1
    if [[ $port != 8080 ]]; then
        if crowdsec_port_available 8080; then
            info "CrowdSec LAPI продолжит использовать сохранённый порт 127.0.0.1:${port}." >&2
        else
            warn "127.0.0.1:8080 занят другим процессом; CrowdSec LAPI будет использовать 127.0.0.1:${port}." >&2
            owner=$(ss -H -ltnp "sport = :8080" 2>/dev/null || true)
            [[ -z $owner ]] || printf 'Владелец занятого порта: %s\n' "$owner" >&2
        fi
    fi

    write_crowdsec_lapi_overrides "$port" || return 1
    mkdir -p "$CONFIG_DIR"
    printf '%s\n' "$port" > "$CROWDSEC_LAPI_PORT_FILE"
    chmod 0600 "$CROWDSEC_LAPI_PORT_FILE"
    printf '%s\n' "$port"
}

write_crowdsec_limits() {
    local ram_mb high_mb max_mb go_limit
    ram_mb=$(awk '/MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
    if ((ram_mb < 1800)); then
        high_mb=160; max_mb=256
    elif ((ram_mb < 3800)); then
        high_mb=256; max_mb=384
    else
        high_mb=384; max_mb=512
    fi
    go_limit=$((max_mb * 3 / 4))
    mkdir -p /etc/systemd/system/crowdsec.service.d /etc/systemd/system/crowdsec-firewall-bouncer.service.d
    cat > /etc/systemd/system/crowdsec.service.d/server-tool.conf <<EOF
[Service]
Environment=GOGC=50
Environment=GOMEMLIMIT=${go_limit}MiB
MemoryHigh=${high_mb}M
MemoryMax=${max_mb}M
OOMScoreAdjust=-500
EOF
    cat > /etc/systemd/system/crowdsec-firewall-bouncer.service.d/server-tool.conf <<EOF
[Service]
MemoryHigh=96M
MemoryMax=160M
OOMScoreAdjust=-400
ExecStartPost=-${CROWDSEC_FORWARD}
EOF
}

write_crowdsec_forward_helper() {
    cat > "$CROWDSEC_FORWARD" <<'CROWDSEC_FORWARD_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
for _ in {1..20}; do
    nft list table ip crowdsec >/dev/null 2>&1 && break
    sleep 1
done
nft list table ip crowdsec >/dev/null 2>&1 || exit 0
set_name=$(nft list table ip crowdsec | awk '$1 == "set" {print $2; exit}')
[[ -n $set_name ]] || exit 0
if ! nft list chain ip crowdsec crowdsec-forward >/dev/null 2>&1; then
    nft add chain ip crowdsec crowdsec-forward '{ type filter hook forward priority -10; policy accept; }'
fi
if ! nft list chain ip crowdsec crowdsec-forward | grep -Fq "@$set_name"; then
    nft add rule ip crowdsec crowdsec-forward ip saddr "@$set_name" counter drop
fi
CROWDSEC_FORWARD_SCRIPT
    chmod 0750 "$CROWDSEC_FORWARD"
}

configure_crowdsec_acquisition() {
    mkdir -p /etc/crowdsec/acquis.d

    if ! command -v docker >/dev/null 2>&1; then
        rm -f "$CROWDSEC_ACQUIS"
        warn "Docker не найден. SSH будет защищён; Nginx можно подключить позже."
        return 0
    fi

    # На всех Remnawave-нодах используются фиксированные имена:
    #   remnawave-nginx — Nginx
    #   remnanode       — контейнер ноды
    # Никакого поиска по шаблонам: проверяем точное имя контейнера через inspect.
    if ! docker container inspect "$REMNAWAVE_NGINX_CONTAINER" >/dev/null 2>&1; then
        rm -f "$CROWDSEC_ACQUIS"
        warn "Контейнер ${REMNAWAVE_NGINX_CONTAINER} не найден. SSH будет защищён; Nginx можно подключить позже."
        return 0
    fi

    cat > "$CROWDSEC_ACQUIS" <<EOF
source: docker
container_name:
  - ${REMNAWAVE_NGINX_CONTAINER}
labels:
  type: nginx
EOF

    success "Подключены Docker-логи Nginx: ${REMNAWAVE_NGINX_CONTAINER}"

    if docker container inspect "$REMNANODE_CONTAINER" >/dev/null 2>&1; then
        info "Контейнер ноды найден: ${REMNANODE_CONTAINER}"
    else
        warn "Контейнер ноды ${REMNANODE_CONTAINER} не найден. Это не мешает подключению логов Nginx."
    fi
}

wait_for_crowdsec_lapi() {
    local attempt
    for attempt in {1..20}; do
        if cscli lapi status >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    error "CrowdSec LAPI не отвечает после ${attempt} попыток."
    journalctl -u crowdsec -n 80 --no-pager || true
    return 1
}

configure_crowdsec_bouncer() {
    local lapi_port="$1" api_key

    # The package-generated key may become stale after reinstalling or resetting
    # CrowdSec's local database. Recreate a deterministic local bouncer identity
    # on every ServerTool run and place the matching key in the merged .local file.
    cscli bouncers delete "$CROWDSEC_BOUNCER_NAME" --ignore-missing >/dev/null 2>&1 || true
    api_key=$(cscli bouncers add "$CROWDSEC_BOUNCER_NAME" --output raw)
    if [[ -z $api_key ]]; then
        error "Не удалось создать API-ключ CrowdSec bouncer."
        return 1
    fi

    install -d -o root -g root -m 0750 /etc/crowdsec/bouncers
    cat > "$CROWDSEC_BOUNCER_LOCAL" <<EOF
${CROWDSEC_MANAGED_MARKER}
api_url: http://127.0.0.1:${lapi_port}/
api_key: "${api_key}"
mode: nftables
disable_ipv6: true
nftables:
  ipv4:
    enabled: true
    set-only: false
    table: crowdsec
    chain: crowdsec-chain
  ipv6:
    enabled: false
EOF
    chmod 0640 "$CROWDSEC_BOUNCER_LOCAL"

    if ! crowdsec-firewall-bouncer -c "$CROWDSEC_BOUNCER_CONFIG" -t >/dev/null; then
        error "Конфигурация CrowdSec firewall bouncer не прошла проверку."
        return 1
    fi
}

install_crowdsec() {
    require_root
    ensure_packages curl gpg ca-certificates apt-transport-https python3 iproute2
    local key_tmp collection candidate policy lapi_port
    crowdsec_installed && warn "CrowdSec уже установлен; пакет и конфигурация будут обновлены."
    step "Подключение официального репозитория CrowdSec"
    key_tmp=$(mktemp)
    curl -fsSL https://packagecloud.io/crowdsec/crowdsec/gpgkey -o "$key_tmp"
    # APT verifies repository metadata as the unprivileged _apt user.
    # The global umask is intentionally restrictive (027), so explicitly
    # make the keyring directory traversable and the public key readable.
    install -d -o root -g root -m 0755 /etc/apt/keyrings /etc/apt/preferences.d
    gpg --batch --yes --dearmor -o /etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg "$key_tmp"
    chmod 0644 /etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg
    rm -f "$key_tmp"
    cat > /etc/apt/sources.list.d/crowdsec_crowdsec.list <<'EOF'
deb [signed-by=/etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg] https://packagecloud.io/crowdsec/crowdsec/any any main
EOF
    cat > /etc/apt/preferences.d/crowdsec <<'EOF'
Package: *
Pin: release o=packagecloud.io/crowdsec/crowdsec,a=any,n=any,c=main
Pin-Priority: 1001
EOF
    run_apt update
    policy=$(apt-cache policy crowdsec)
    candidate=$(awk '$1 == "Candidate:" {print $2; exit}' <<< "$policy")
    [[ -n $candidate && $candidate != '(none)' ]] || { error "CrowdSec недоступен из официального репозитория."; return 1; }
    run_apt install -y crowdsec crowdsec-firewall-bouncer-nftables

    # Package installation can start CrowdSec immediately. Stop both units
    # before probing the LAPI port so the service does not race our checks or
    # remain in an auto-restart loop after a bind failure.
    systemctl stop crowdsec-firewall-bouncer crowdsec >/dev/null 2>&1 || true
    lapi_port=$(prepare_crowdsec_lapi) || return 1

    cscli hub update
    for collection in crowdsecurity/linux crowdsecurity/sshd crowdsecurity/nginx; do
        cscli collections install "$collection" >/dev/null 2>&1 || true
    done
    configure_crowdsec_acquisition
    # The official nftables bouncer creates an input hook. Add a separate,
    # idempotent forward hook so the same decisions also cover Docker DNAT.
    write_crowdsec_forward_helper
    nft delete chain ip crowdsec crowdsec-forward 2>/dev/null || true
    write_crowdsec_limits
    systemctl daemon-reload
    systemctl enable crowdsec crowdsec-firewall-bouncer >/dev/null
    if ! crowdsec -c /etc/crowdsec/config.yaml -t -error; then
        error "Конфигурация CrowdSec не прошла проверку."
        return 1
    fi

    systemctl reset-failed crowdsec >/dev/null 2>&1 || true
    if ! systemctl restart crowdsec; then
        error "Не удалось запустить CrowdSec."
        systemctl --no-pager --full status crowdsec || true
        journalctl -u crowdsec -n 80 --no-pager || true
        return 1
    fi
    wait_for_crowdsec_lapi || return 1
    configure_crowdsec_bouncer "$lapi_port" || return 1

    systemctl reset-failed crowdsec-firewall-bouncer >/dev/null 2>&1 || true
    if ! systemctl restart crowdsec-firewall-bouncer; then
        error "Не удалось запустить CrowdSec firewall bouncer."
        systemctl --no-pager --full status crowdsec-firewall-bouncer || true
        journalctl -u crowdsec-firewall-bouncer -n 80 --no-pager || true
        [[ -r /var/log/crowdsec-firewall-bouncer.log ]] && tail -n 80 /var/log/crowdsec-firewall-bouncer.log || true
        return 1
    fi
    if ! "$CROWDSEC_FORWARD"; then
        error "CrowdSec запущен, но не удалось подключить блокировки к Docker forward."
        return 1
    fi

    sleep 1
    if systemctl is-active --quiet crowdsec && systemctl is-active --quiet crowdsec-firewall-bouncer; then
        success "CrowdSec и nftables-bouncer активны (LAPI 127.0.0.1:${lapi_port})."
        cscli bouncers list || true
    else
        error "CrowdSec установлен, но один из сервисов не запустился."
        systemctl --no-pager --full status crowdsec crowdsec-firewall-bouncer || true
        return 1
    fi
    log INFO "CrowdSec installed with nftables bouncer lapi=127.0.0.1:${lapi_port}"
}

remove_crowdsec() {
    warn "Будут удалены CrowdSec, bouncer и их nftables-таблицы. Основной ServerTool firewall сохранится."
    confirm "Удалить CrowdSec?" || return 0
    systemctl disable --now crowdsec-firewall-bouncer crowdsec >/dev/null 2>&1 || true
    run_apt purge -y crowdsec-firewall-bouncer-nftables crowdsec
    rm -f /etc/apt/sources.list.d/crowdsec_crowdsec.list \
        /etc/apt/preferences.d/crowdsec \
        /etc/apt/keyrings/crowdsec_crowdsec-archive-keyring.gpg \
        "$CROWDSEC_FORWARD" "$CROWDSEC_ACQUIS" \
        "$CROWDSEC_BOUNCER_CONFIG" "$CROWDSEC_BOUNCER_LOCAL"
    for file in "$CROWDSEC_CONFIG_LOCAL" "$CROWDSEC_LAPI_CREDENTIALS_LOCAL"; do
        if [[ -f $file ]] && grep -Fqx "$CROWDSEC_MANAGED_MARKER" "$file"; then
            rm -f "$file"
        fi
    done
    rm -f "$CROWDSEC_LAPI_PORT_FILE"
    rm -rf /etc/systemd/system/crowdsec.service.d /etc/systemd/system/crowdsec-firewall-bouncer.service.d
    nft delete table ip crowdsec 2>/dev/null || true
    nft delete table ip6 crowdsec6 2>/dev/null || true
    systemctl daemon-reload
    success "CrowdSec удалён; основной nftables-firewall не изменён."
}

crowdsec_menu() {
    local choice
    while true; do
        clear 2>/dev/null || true
        printf '%b🕵️  CROWDSEC%b\n\n' "$BOLD" "$NC"
        if crowdsec_installed && systemctl is-active --quiet crowdsec; then
            success "CrowdSec активен"
        else
            warn "CrowdSec не активен"
        fi
        printf '\n  1) Установить/обновить CrowdSec\n'
        printf '  2) Подключить заново Nginx-контейнер\n'
        printf '  3) Показать метрики и решения\n'
        printf '  4) Удалить CrowdSec\n'
        printf '  0) Назад\n\n'
        read -r -p "Выбор: " choice || true
        case $choice in
            1) install_crowdsec; pause ;;
            2)
                crowdsec_installed || { error "Сначала установите CrowdSec."; pause; continue; }
                configure_crowdsec_acquisition
                systemctl restart crowdsec
                pause
                ;;
            3)
                crowdsec_installed || { error "CrowdSec не установлен."; pause; continue; }
                cscli metrics || true
                cscli decisions list || true
                nft list table ip crowdsec 2>/dev/null || true
                pause
                ;;
            4) remove_crowdsec; pause ;;
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
        [[ -n $(ss -H -ltn "sport = :$port" 2>/dev/null) ]] || { printf '%s\n' "$port"; return; }
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

ensure_sshd_runtime_dir() {
    local runtime_dir=$1
    if [[ -L $runtime_dir || ( -e $runtime_dir && ! -d $runtime_dir ) ]]; then
        error "${runtime_dir} существует, но не является безопасным каталогом."
        return 1
    fi
    install -d -o root -g root -m 0755 "$runtime_dir"
}

show_effective_ssh_settings() {
    ensure_sshd_runtime_dir /run/sshd || return 1
    sshd -T 2>/dev/null \
        | grep -E '^(port|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|maxauthtries) '
}

configure_ssh() {
    require_root
    ensure_packages openssh-server openssh-client iproute2
    ensure_sshd_runtime_dir /run/sshd || return 1
    local old_port new_port user backup disable_password has_key choice file restart_ok firewall_config_changed
    old_port=$(detect_ssh_port)
    user=$(target_user_prompt) || { error "Пользователь не найден."; return 1; }
    new_port=$(random_free_port) || { error "Не удалось подобрать свободный порт."; return 1; }
    printf '\nТекущий порт: %s\nСлучайный порт: %s\n' "$old_port" "$new_port"
    read -r -p "Новый порт SSH [${new_port}]: " choice || true
    new_port=${choice:-$new_port}
    valid_port "$new_port" || { error "Некорректный порт."; return 1; }
    [[ -z $(ss -H -ltn "sport = :$new_port" 2>/dev/null) ]] || { error "Порт ${new_port} уже занят."; return 1; }
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
    firewall_config_changed=no
    if [[ -r $GUARD_CONFIG && -x $GUARD_UPDATER ]]; then
        cp -a "$GUARD_CONFIG" "$backup/firewall.conf"
        sed -Ei "s/^SSH_PORT=.*/SSH_PORT=\"${new_port}\"/" "$GUARD_CONFIG"
        if ! "$GUARD_UPDATER" --apply; then
            cp -a "$backup/firewall.conf" "$GUARD_CONFIG"
            restore_ssh_backup "$backup"
            error "Не удалось открыть новый SSH-порт в nftables; изменения отменены."
            return 1
        fi
        firewall_config_changed=yes
    fi
    systemctl daemon-reload
    restart_ok=yes
    if systemctl is-active --quiet ssh.socket; then
        systemctl restart ssh.socket || restart_ok=no
    fi
    systemctl restart ssh.service || restart_ok=no
    if [[ $restart_ok != yes ]]; then
        restore_ssh_backup "$backup"
        if [[ $firewall_config_changed == yes ]]; then
            cp -a "$backup/firewall.conf" "$GUARD_CONFIG"
            "$GUARD_UPDATER" --apply || true
        fi
        systemctl daemon-reload
        if systemctl is-active --quiet ssh.socket; then
            systemctl restart ssh.socket || true
        fi
        systemctl restart ssh.service || true
        error "SSH не перезапустился с новой конфигурацией; файлы восстановлены."
        return 1
    fi
    sleep 1
    if [[ -n $(ss -H -ltn "sport = :$new_port" 2>/dev/null) ]]; then
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
        clear 2>/dev/null || true
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
            4) show_effective_ssh_settings; pause ;;
            0) return ;;
            *) warn "Неизвестный пункт."; sleep 1 ;;
        esac
    done
}

detect_psabi() {
    local loader help_text
    for loader in /lib64/ld-linux-x86-64.so.2 /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2; do
        [[ -x $loader ]] || continue
        help_text=$("$loader" --help 2>/dev/null || true)
        grep -Eq 'x86-64-v3.*(supported|поддерж)' <<< "$help_text" && { printf 'v3\n'; return; }
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
    install -d -m 0755 /etc/apt/keyrings
    gpg --batch --yes --dearmor -o /etc/apt/keyrings/xanmod-archive-keyring.gpg "$key_tmp"
    rm -f "$key_tmp"

    # ServerTool uses umask 027. APT downloads repository metadata as the
    # unprivileged _apt user, so keyrings referenced by signed-by must remain
    # world-readable. Otherwise APT reports NO_PUBKEY even when the right key
    # was imported successfully.
    chmod 0644 /etc/apt/keyrings/xanmod-archive-keyring.gpg

    local xanmod_fingerprint
    xanmod_fingerprint=$(gpg --batch --show-keys --with-colons \
        /etc/apt/keyrings/xanmod-archive-keyring.gpg 2>/dev/null \
        | awk -F: '$1 == "fpr" {print $10; exit}')
    if [[ $xanmod_fingerprint != D38D7D1DA1349567ADED882D86F7D09EE734E623 ]]; then
        rm -f /etc/apt/keyrings/xanmod-archive-keyring.gpg
        error "Отпечаток ключа XanMod не совпал с официальным. Репозиторий не добавлен."
        return 1
    fi

    printf 'deb [signed-by=/etc/apt/keyrings/xanmod-archive-keyring.gpg] http://deb.xanmod.org %s main\n' "$codename" \
        > /etc/apt/sources.list.d/xanmod-release.list
    chmod 0644 /etc/apt/sources.list.d/xanmod-release.list
    run_apt update
    run_apt install -y "$package"
    success "${package} установлен. Перезагрузитесь, когда будет удобно."
    printf 'Текущее ядро: %s\n' "$(uname -r)"
    log INFO "xanmod installed package=${package}"
}

configure_bbr() {
    require_root
    ensure_packages iproute2 kmod
    step "Настройка BBR и сетевой очереди fq"
    modprobe tcp_bbr 2>/dev/null || { error "Текущее ядро не содержит модуль tcp_bbr. Сначала установите XanMod или другое совместимое ядро."; return 1; }
    printf 'tcp_bbr\n' > /etc/modules-load.d/server-tool-bbr.conf
    cat > /etc/sysctl.d/99-server-tool-network.conf <<'EOF'
# Managed by ServerTool
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_mtu_probing = 1
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
EOF
    sysctl --load /etc/sysctl.d/99-server-tool-network.conf >/dev/null
    if [[ $(sysctl -n net.ipv4.tcp_congestion_control) == bbr ]]; then
        success "BBR активирован. XanMod использует собственную актуальную реализацию BBR."
    else
        error "Ядро не приняло BBR; проверьте доступные алгоритмы: sysctl net.ipv4.tcp_available_congestion_control"
        return 1
    fi
    log INFO "BBR network profile applied"
}

show_status() {
    clear 2>/dev/null || true
    printf '%b📊 СОСТОЯНИЕ НОДЫ%b\n\n' "$BOLD" "$NC"
    printf 'ОС:          %s\n' "$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")"
    printf 'Ядро:        %s\n' "$(uname -r)"
    printf 'SSH-порт:    %s/tcp\n' "$(detect_ssh_port)"
    printf 'BBR:         %s\n' "$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || printf 'unknown')"
    if nft list table inet server_tool_guard >/dev/null 2>&1; then
        printf 'nft firewall: активен\n'
        systemctl list-timers server-tool-guard.timer --no-pager 2>/dev/null || true
    else
        printf 'nft firewall: не активен\n'
    fi
    if crowdsec_installed && systemctl is-active --quiet crowdsec; then
        printf 'CrowdSec:    активен\n'
    else
        printf 'CrowdSec:    не активен\n'
    fi
    [[ ! -f /var/run/reboot-required ]] || warn "Требуется перезагрузка."
}

full_setup() {
    warn "Мастер последовательно предложит обновление, SSH, nftables, CrowdSec, XanMod и BBR."
    confirm "Запустить полный мастер?" || return 0
    confirm "Обновить систему сейчас?" Y && system_update
    info "Сначала добавьте/создайте ключ, затем настройте порт SSH."
    ssh_menu
    configure_firewall
    confirm "Установить CrowdSec?" && install_crowdsec
    confirm "Установить XanMod?" && install_xanmod
    confirm "Включить BBR?" Y && configure_bbr
    success "Мастер завершён. Проверьте статус и новый SSH-вход до выхода из текущей сессии."
}

show_help() {
    cat <<EOF
${APP_NAME} ${APP_VERSION} — настройка и защита Remnawave-ноды

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
        clear 2>/dev/null || true
        printf '%b╔══════════════════════════════════════════╗%b\n' "$CYAN" "$NC"
        printf '%b║  🚀 ServerTool %-7s • Remnawave Node  ║%b\n' "$CYAN" "v${APP_VERSION}" "$NC"
        printf '%b╚══════════════════════════════════════════╝%b\n\n' "$CYAN" "$NC"
        printf '  1) 🧰 Полная рекомендуемая настройка\n'
        printf '  2) 🔄 Обновить систему\n'
        printf '  3) 🔥 Настроить nftables и порты ноды\n'
        printf '  4) 🔑 Настроить SSH\n'
        printf '  5) 🛡️  Firewall, Anti-Scanner и Geo-block\n'
        printf '  6) 🕵️  CrowdSec\n'
        printf '  7) ⚡ Установить XanMod\n'
        printf '  8) 🚄 Включить BBR\n'
        printf '  9) 📊 Показать состояние\n'
        printf '  0) 👋 Выход\n\n'
        read -r -p "Выберите пункт: " choice || true
        case $choice in
            1) full_setup; pause ;;
            2) system_update; pause ;;
            3) configure_firewall; pause ;;
            4) ssh_menu ;;
            5) guard_menu ;;
            6) crowdsec_menu ;;
            7) install_xanmod; pause ;;
            8) configure_bbr; pause ;;
            9) show_status; pause ;;
            0) success "Готово. Не забудьте проверить новый SSH-вход."; return ;;
            *) warn "Неизвестный пункт."; sleep 1 ;;
        esac
    done
}

main() {
    case "${1:-}" in
        -h|--help) show_help; return ;;
        -v|--version) printf '%s %s\n' "$APP_NAME" "$APP_VERSION"; return ;;
        --status) require_root; require_supported_os; show_status; return ;;
        "") ;;
        *) show_help; return 2 ;;
    esac
    require_root
    require_supported_os
    mkdir -p "$BACKUP_ROOT"
    touch "$LOG_FILE"; chmod 600 "$LOG_FILE"
    log INFO "ServerTool ${APP_VERSION} started"
    show_menu
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    main "$@"
fi
