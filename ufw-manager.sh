#!/bin/bash
#
# UFW Manager с интеграцией Fail2ban
# Версия 2.1.0 - Полностью исправленная и улучшенная
#
# ОСОБЕННОСТИ:
# - Полная интеграция UFW и Fail2ban
# - Автоматическая синхронизация правил
# - Защита от удаления SSH правил
# - Поддержка systemd, OpenRC, SysVinit
# - Цветной вывод с эмодзи
# - Кэширование для оптимизации
# - Транзакционное создание jails
# - Автоматическое резервное копирование
#
# ЗАВИСИМОСТИ:
# - ufw
# - fail2ban (опционально)
# - bash 4.0+
# - coreutils (grep, sed, awk)
#
# ИСПОЛЬЗОВАНИЕ:
#   sudo ./ufw-manager.sh
#   DEBUG=1 sudo ./ufw-manager.sh  # Режим отладки
#
# ФАЙЛЫ КОНФИГУРАЦИИ:
# - rules.config - список правил UFW
# - /etc/fail2ban/jail.d/*.local - jails fail2ban
# - /var/log/ufw-manager.log - лог-файл
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# ============================================================================
# РЕЖИМ ОТЛАДКИ
# ============================================================================
DEBUG_MODE=${DEBUG:-0}

debug_log() {
    if [[ $DEBUG_MODE -eq 1 ]]; then
        echo "[DEBUG] $*" >&2
    fi
    log_action "DEBUG" "$*"
}

# ============================================================================
# КОНФИГУРАЦИЯ И КОНСТАНТЫ
# ============================================================================

readonly SCRIPT_VERSION="2.1.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOCK_FILE="/var/run/ufw-manager.lock"
readonly LOG_FILE="/var/log/ufw-manager.log"
readonly BACKUP_DIR="/var/backups/ufw-manager"
readonly TEMP_DIR="$(mktemp -d -t ufw-manager.XXXXXX)"

# Файлы конфигурации
readonly RULES_FILE="${SCRIPT_DIR}/rules.config"
readonly FAIL2BAN_LOCAL_CONFIG="/etc/fail2ban/jail.local"
readonly FAIL2BAN_JAIL_DIR="/etc/fail2ban/jail.d/"
readonly FAIL2BAN_FILTER_DIR="/etc/fail2ban/filter.d/"
readonly FAIL2BAN_ACTION_DIR="/etc/fail2ban/action.d/"

# Цвета для вывода
readonly COLOR_RED='\033[0;31m'
readonly COLOR_GREEN='\033[0;32m'
readonly COLOR_YELLOW='\033[1;33m'
readonly COLOR_BLUE='\033[0;34m'
readonly COLOR_CYAN='\033[0;36m'
readonly COLOR_NC='\033[0m'

# Эмодзи
readonly EMOJI_OK='✅'
readonly EMOJI_ERROR='❌'
readonly EMOJI_WARN='⚠️'
readonly EMOJI_INFO='ℹ️'
readonly EMOJI_LOCK='🔒'
readonly EMOJI_UNLOCK='🔓'
readonly EMOJI_FIRE='🔥'
readonly EMOJI_SHIELD='🛡️'
readonly EMOJI_GEAR='⚙️'
readonly EMOJI_FILE='📄'
readonly EMOJI_FOLDER='📁'
readonly EMOJI_SEARCH='🔍'
readonly EMOJI_ADD='➕'
readonly EMOJI_REMOVE='➖'
readonly EMOJI_EDIT='✏️'
readonly EMOJI_LIST='📋'
readonly EMOJI_BACK='🔙'
readonly EMOJI_EXIT='🚪'

# ============================================================================
# УТИЛИТЫ И ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

# Логирование действий
log_action() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local user="${SUDO_USER:-$USER}"
    local ip="${SSH_CLIENT%% *:-localhost}"
    
    echo "[$timestamp] [$level] [UID:$EUID] [USER:$user] [IP:$ip] $message" >> "$LOG_FILE" 2>/dev/null || true
    
    # Ротация логов если файл больше 10MB
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(stat -c%s "$LOG_FILE" 2>/dev/null || stat -f%z "$LOG_FILE" 2>/dev/null || echo 0)
        if [[ $size -gt 10485760 ]]; then
            mv "$LOG_FILE" "${LOG_FILE}.old" 2>/dev/null || true
            touch "$LOG_FILE" 2>/dev/null || true
        fi
    fi
}

# Цветной вывод
color_echo() {
    local color="$1"
    shift
    case "$color" in
        RED)    echo -e "${COLOR_RED}$*${COLOR_NC}" ;;
        GREEN)  echo -e "${COLOR_GREEN}$*${COLOR_NC}" ;;
        YELLOW) echo -e "${COLOR_YELLOW}$*${COLOR_NC}" ;;
        BLUE)   echo -e "${COLOR_BLUE}$*${COLOR_NC}" ;;
        CYAN)   echo -e "${COLOR_CYAN}$*${COLOR_NC}" ;;
        *)      echo -e "$*" ;;
    esac
}

# Транзакционное выполнение (с защитой от прерываний)
critical_operation() {
    local op="$1"
    shift
    
    debug_log "Начало критической операции: $op"
    
    # Блокируем прерывания
    trap '' INT
    
    $op "$@"
    local result=$?
    
    debug_log "Критическая операция завершена с кодом: $result"
    
    # Восстанавливаем обработку прерываний
    trap 'cleanup' INT
    
    return $result
}

# Успешное завершение с очисткой
cleanup() {
    local exit_code=$?
    
    debug_log "Запуск cleanup с кодом: $exit_code"
    
    # Восстановление курсора
    tput cnorm 2>/dev/null || true
    
    # Удаление временных файлов
    if [[ -n "${TEMP_DIR:-}" && -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR" 2>/dev/null || true
        debug_log "Временная директория удалена: $TEMP_DIR"
    fi
    
    # Освобождение lock-файла
    if [[ -f "$LOCK_FILE" ]]; then
        rm -f "$LOCK_FILE" 2>/dev/null || true
        debug_log "Lock-файл удален: $LOCK_FILE"
    fi
    
    # Логирование завершения
    if [[ $exit_code -eq 0 ]]; then
        log_action "INFO" "Скрипт завершен успешно"
    else
        log_action "ERROR" "Скрипт завершен с ошибкой (код: $exit_code)"
    fi
    
    exit $exit_code
}

# Обработка ошибок
error_handler() {
    local line_no=$1
    local error_code=$?
    log_action "ERROR" "Ошибка в строке $line_no (код: $error_code)"
    color_echo RED "${EMOJI_ERROR} Произошла внутренняя ошибка (строка: $line_no, код: $error_code)"
    exit $error_code
}

# Установка обработчиков
trap 'cleanup' EXIT INT TERM HUP
trap 'error_handler $LINENO' ERR

# Проверка root-прав
check_root() {
    if [[ $EUID -ne 0 ]]; then
        color_echo RED "${EMOJI_ERROR} Этот скрипт должен запускаться от root"
        log_action "ERROR" "Попытка запуска без root-прав"
        exit 1
    fi
    debug_log "Проверка root-прав: OK"
}

# Блокировка повторного запуска
acquire_lock() {
    if [[ -f "$LOCK_FILE" ]]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "0")
        if [[ "$pid" != "0" ]] && kill -0 "$pid" 2>/dev/null; then
            color_echo YELLOW "${EMOJI_WARN} Скрипт уже запущен (PID: $pid)"
            return 1
        else
            rm -f "$LOCK_FILE" 2>/dev/null || true
        fi
    fi
    echo $$ > "$LOCK_FILE"
    debug_log "Lock-файл создан с PID: $$"
    return 0
}

# Проверка зависимостей
check_dependencies() {
    local deps=("ufw" "grep" "sed" "awk" "mktemp")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    if [[ ${#missing[@]} -gt 0 ]]; then
        color_echo RED "${EMOJI_ERROR} Отсутствуют обязательные зависимости: ${missing[*]}"
        log_action "ERROR" "Отсутствуют зависимости: ${missing[*]}"
        exit 1
    fi
    debug_log "Проверка зависимостей: OK"
}

# Создание backup
backup_file() {
    local file="$1"
    if [[ -f "$file" ]]; then
        mkdir -p "$BACKUP_DIR" 2>/dev/null || true
        local backup_name="${BACKUP_DIR}/$(basename "$file").$(date +%Y%m%d_%H%M%S).bak"
        cp -a "$file" "$backup_name" 2>/dev/null || true
        log_action "INFO" "Создан backup: $backup_name"
        debug_log "Backup создан: $backup_name"
        echo "$backup_name"
    fi
}

# Пауза
pause() {
    echo ""
    read -rp "Нажмите Enter для продолжения..." </dev/tty
}

# Валидация ввода
validate_port() {
    local port="$1"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 ))
}

validate_protocol() {
    local proto="$1"
    [[ "$proto" == "tcp" || "$proto" == "udp" || "$proto" == "both" ]]
}

validate_direction() {
    local dir="$1"
    [[ "$dir" == "IN" || "$dir" == "OUT" || "$dir" == "BOTH" ]]
}

validate_ip() {
    local ip="$1"
    # IPv4
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -ra octets <<< "$ip"
        for octet in "${octets[@]}"; do
            (( octet >= 0 && octet <= 255 )) || return 1
        done
        return 0
    fi
    # IPv6
    [[ "$ip" =~ ^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$ ]] && return 0
    [[ "$ip" =~ ^::1$ ]] && return 0
    [[ "$ip" =~ ^::$ ]] && return 0
    return 1
}

validate_jail_name() {
    local name="$1"
    [[ "$name" =~ ^[a-zA-Z0-9_-]+$ ]] && [[ ${#name} -le 50 ]]
}

# Определение диспетчера служб
get_service_manager() {
    if command -v systemctl >/dev/null 2>&1; then
        echo "systemd"
    elif command -v rc-service >/dev/null 2>&1; then
        echo "openrc"
    elif command -v service >/dev/null 2>&1; then
        echo "sysvinit"
    else
        echo "unknown"
    fi
}

# Управление службами
service_action() {
    local action="$1"
    local service_name="$2"
    local manager
    manager=$(get_service_manager)
    
    log_action "INFO" "Действие '$action' для службы '$service_name'"
    debug_log "Service manager: $manager, action: $action, service: $service_name"
    
    case "$manager" in
        systemd)
            systemctl "$action" "$service_name" 2>/dev/null || return 1
            ;;
        openrc)
            rc-service "$service_name" "$action" 2>/dev/null || return 1
            ;;
        sysvinit)
            service "$service_name" "$action" 2>/dev/null || return 1
            ;;
        *)
            color_echo RED "${EMOJI_ERROR} Неизвестный диспетчер служб"
            return 1
            ;;
    esac
    return 0
}

is_service_active() {
    local service_name="$1"
    local manager
    manager=$(get_service_manager)
    
    case "$manager" in
        systemd)
            systemctl is-active --quiet "$service_name" 2>/dev/null
            ;;
        *)
            service "$service_name" status 2>/dev/null | grep -q "running"
            ;;
    esac
}

# ============================================================================
# UFW ФУНКЦИИ
# ============================================================================

# Кэш статуса UFW (с учетом направления)
declare -A UFW_CACHE
declare UFW_CACHE_TIME=0

refresh_ufw_cache() {
    debug_log "Обновление кэша UFW"
    UFW_CACHE=()
    local status_output
    status_output=$(ufw status verbose 2>/dev/null || true)
    UFW_CACHE_TIME=$(date +%s)
    
    while IFS= read -r line; do
        # Парсим вывод ufw status verbose для определения направления
        if [[ "$line" =~ ^([0-9]+/(tcp|udp)).*ALLOW ]]; then
            local port_proto="${BASH_REMATCH[1]}"
            local direction="IN"
            
            # Проверяем, не исходящее ли это правило
            if [[ "$line" =~ .*\(out\) ]]; then
                direction="OUT"
            fi
            
            UFW_CACHE["${direction}:${port_proto}"]=1
            debug_log "Кэшировано правило: ${direction}:${port_proto}"
        fi
    done <<< "$status_output"
}

get_ufw_rules() {
    local numbered=${1:-0}
    local rules=()
    
    if [[ $numbered -eq 1 ]]; then
        while IFS= read -r line; do
            if [[ "$line" =~ ^\[[0-9]+\] ]]; then
                rules+=("$line")
            fi
        done < <(ufw status numbered 2>/dev/null)
    else
        while IFS= read -r line; do
            if [[ "$line" =~ ^[0-9]+/.*(ALLOW|DENY) ]]; then
                rules+=("$line")
            fi
        done < <(ufw status verbose 2>/dev/null)
    fi
    
    printf '%s\n' "${rules[@]}"
}

is_ufw_enabled() {
    ufw status numbered 2>/dev/null | head -1 | grep -q "Status: active"
}

ufw_rule_exists() {
    local dir="$1"
    local port="$2"
    local proto="$3"
    local cache_key="${dir}:${port}/${proto}"
    
    debug_log "Проверка существования правила: $cache_key"
    
    local current_time
    current_time=$(date +%s)
    if [[ $((current_time - UFW_CACHE_TIME)) -gt 5 ]]; then
        refresh_ufw_cache
    fi
    
    [[ -n "${UFW_CACHE[$cache_key]:-}" ]]
}

apply_ufw_rule() {
    local dir="$1"
    local port="$2"
    local proto="$3"
    
    debug_log "Применение правила: $dir $port/$proto"
    
    if [[ "$proto" == "both" ]]; then
        apply_ufw_rule "$dir" "$port" "tcp" || return 1
        apply_ufw_rule "$dir" "$port" "udp" || return 1
        return 0
    fi
    
    if ufw_rule_exists "$dir" "$port" "$proto"; then
        color_echo YELLOW "${EMOJI_WARN} Правило $dir $port/$proto уже существует"
        return 0
    fi
    
    local cmd
    case "$dir" in
        IN)  cmd="ufw allow $port/$proto" ;;
        OUT) cmd="ufw allow out $port/$proto" ;;
        BOTH)
            ufw allow "$port/$proto" >/dev/null 2>&1 || {
                log_action "ERROR" "Не удалось добавить правило IN $port/$proto"
                return 1
            }
            ufw allow out "$port/$proto" >/dev/null 2>&1 || {
                log_action "ERROR" "Не удалось добавить правило OUT $port/$proto"
                return 1
            }
            color_echo GREEN "${EMOJI_OK} Правило BOTH $port/$proto добавлено"
            log_action "INFO" "Добавлено правило BOTH $port/$proto"
            UFW_CACHE["IN:${port}/${proto}"]=1
            UFW_CACHE["OUT:${port}/${proto}"]=1
            return 0
            ;;
        *)
            color_echo RED "${EMOJI_ERROR} Неверное направление: $dir"
            return 1
            ;;
    esac
    
    if critical_operation eval "$cmd >/dev/null 2>&1"; then
        color_echo GREEN "${EMOJI_OK} Правило $dir $port/$proto добавлено"
        log_action "INFO" "Добавлено правило $dir $port/$proto"
        UFW_CACHE["${dir}:${port}/${proto}"]=1
        return 0
    else
        color_echo RED "${EMOJI_ERROR} Не удалось добавить правило $dir $port/$proto"
        log_action "ERROR" "Не удалось добавить правило $dir $port/$proto"
        return 1
    fi
}

delete_ufw_rule() {
    local dir="$1"
    local port="$2"
    local proto="$3"
    
    debug_log "Удаление правила: $dir $port/$proto"
    
    local ssh_port
    ssh_port=$(detect_ssh_port)
    if [[ "$port" == "$ssh_port" && "$proto" == "tcp" && "$dir" == "IN" ]]; then
        color_echo RED "${EMOJI_ERROR} Удаление SSH правила запрещено (порт: $ssh_port)"
        log_action "WARN" "Попытка удаления SSH правила"
        return 1
    fi
    
    if [[ "$proto" == "both" ]]; then
        delete_ufw_rule "$dir" "$port" "tcp" || true
        delete_ufw_rule "$dir" "$port" "udp" || true
        return 0
    fi
    
    case "$dir" in
        IN)
            ufw delete allow "$port/$proto" >/dev/null 2>&1 || {
                color_echo YELLOW "${EMOJI_WARN} Правило IN $port/$proto не найдено"
                return 1
            }
            ;;
        OUT)
            ufw delete allow out "$port/$proto" >/dev/null 2>&1 || {
                color_echo YELLOW "${EMOJI_WARN} Правило OUT $port/$proto не найдено"
                return 1
            }
            ;;
        BOTH)
            ufw delete allow "$port/$proto" >/dev/null 2>&1 || true
            ufw delete allow out "$port/$proto" >/dev/null 2>&1 || true
            color_echo GREEN "${EMOJI_OK} Правило BOTH $port/$proto удалено"
            log_action "INFO" "Удалено правило BOTH $port/$proto"
            unset "UFW_CACHE[IN:${port}/${proto}]"
            unset "UFW_CACHE[OUT:${port}/${proto}]"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
    
    color_echo GREEN "${EMOJI_OK} Правило $dir $port/$proto удалено"
    log_action "INFO" "Удалено правило $dir $port/$proto"
    unset "UFW_CACHE[${dir}:${port}/${proto}]"
    return 0
}

detect_ssh_port() {
    local port
    port=$(grep -E "^Port\s+" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' | head -1)
    echo "${port:-22}"
}

# ============================================================================
# FAIL2BAN ФУНКЦИИ
# ============================================================================

fail2ban_installed() {
    command -v fail2ban-client >/dev/null 2>&1
}

# Проверка/создание действия ufw для fail2ban
ensure_fail2ban_ufw_action() {
    local ufw_action_file="${FAIL2BAN_ACTION_DIR}/ufw.conf"
    
    if [[ ! -f "$ufw_action_file" ]]; then
        color_echo YELLOW "${EMOJI_WARN} Действие ufw для fail2ban не найдено, создаю..."
        debug_log "Создание действия ufw: $ufw_action_file"
        
        mkdir -p "$FAIL2BAN_ACTION_DIR"
        cat > "$ufw_action_file" << 'EOF'
# Fail2Ban action configuration for UFW
#
# Author: Yannick Charton
# Modified for ufw-manager

[Definition]
description = UFW firewall

[Init]
name = default
port = ssh
protocol = tcp

[ActionStart]
# Не требуется

[ActionStop]
# Не требуется

[ActionCheck]
# Не требуется

[ActionBan]
ufw insert 1 deny from <ip> to any port <port> proto <protocol>

[ActionUnban]
ufw delete deny from <ip> to any port <port> proto <protocol>
EOF
        color_echo GREEN "${EMOJI_OK} Действие ufw создано"
        log_action "INFO" "Создано действие ufw для fail2ban"
    fi
}

get_fail2ban_jails() {
    if ! fail2ban_installed; then
        return 0
    fi
    
    local jails_output
    jails_output=$(fail2ban-client status 2>/dev/null | grep "Jail list" || true)
    
    if [[ -n "$jails_output" ]]; then
        echo "$jails_output" | sed 's/.*Jail list:\s*//' | tr ',' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'
    fi
}

jail_exists() {
    local jail_name="$1"
    fail2ban_installed || return 1
    fail2ban-client status "$jail_name" >/dev/null 2>&1
}

get_jail_port_proto() {
    local jail="$1"
    
    if ! fail2ban_installed; then
        return 0
    fi
    
    local port proto
    port=$(fail2ban-client get "$jail" port 2>/dev/null || true)
    proto=$(fail2ban-client get "$jail" protocol 2>/dev/null || true)
    
    [[ -z "$proto" ]] && proto="tcp"
    [[ -z "$port" ]] && return 0
    
    echo "${port}:${proto}"
}

validate_fail2ban_config() {
    if fail2ban_installed; then
        fail2ban-client -t >/dev/null 2>&1
    else
        return 0
    fi
}

# Транзакционное создание jail
create_fail2ban_jail() {
    if ! fail2ban_installed; then
        color_echo RED "${EMOJI_ERROR} Fail2ban не установлен"
        return 1
    fi
    
    # Проверяем наличие действия ufw
    ensure_fail2ban_ufw_action
    
    color_echo CYAN "${EMOJI_ADD} Создание нового Fail2ban Jail"
    echo ""
    
    local jail_name=""
    while true; do
        read -rp "Имя jail (латинские буквы, цифры, дефисы): " jail_name
        jail_name=$(echo "$jail_name" | tr -d '[:space:]')
        
        if [[ -z "$jail_name" ]]; then
            color_echo YELLOW "${EMOJI_WARN} Имя не может быть пустым"
            continue
        fi
        
        if ! validate_jail_name "$jail_name"; then
            color_echo YELLOW "${EMOJI_WARN} Некорректное имя. Используйте: a-z, A-Z, 0-9, _, - (макс. 50 символов)"
            continue
        fi
        
        if jail_exists "$jail_name"; then
            color_echo YELLOW "${EMOJI_WARN} Jail '$jail_name' уже существует"
            continue
        fi
        
        break
    done
    
    read -rp "Порт для мониторинга [all]: " jail_port
    jail_port=${jail_port:-all}
    
    read -rp "Протокол [tcp]: " jail_protocol
    jail_protocol=${jail_protocol:-tcp}
    
    read -rp "Время блокировки в секундах [600]: " bantime
    bantime=${bantime:-600}
    [[ "$bantime" =~ ^[0-9]+$ ]] || bantime=600
    
    read -rp "Максимальное количество попыток [3]: " maxretry
    maxretry=${maxretry:-3}
    [[ "$maxretry" =~ ^[0-9]+$ ]] || maxretry=3
    
    read -rp "Время поиска в секундах [600]: " findtime
    findtime=${findtime:-600}
    [[ "$findtime" =~ ^[0-9]+$ ]] || findtime=600
    
    read -rp "Путь к лог-файлу [/var/log/auth.log]: " logpath
    logpath=${logpath:-/var/log/auth.log}
    
    # Валидация лог-файла
    if [[ ! -f "$logpath" ]]; then
        color_echo YELLOW "${EMOJI_WARN} Лог-файл $logpath не существует"
        read -rp "Продолжить создание jail? (y/N): " confirm
        [[ "$confirm" =~ ^[Yy]$ ]] || return 1
    fi
    
    local temp_jail_file="${TEMP_DIR}/${jail_name}.local"
    local temp_filter_file="${TEMP_DIR}/${jail_name}.conf"
    
    # Определяем правильное действие в зависимости от версии fail2ban
    local banaction="ufw"
    if fail2ban-client -V 2>/dev/null | grep -q "0\.\(8\|9\|10\)"; then
        banaction="ufw"
    fi
    
    cat > "$temp_jail_file" << EOF
[$jail_name]
enabled = true
port = $jail_port
protocol = $jail_protocol
filter = $jail_name
logpath = $logpath
maxretry = $maxretry
bantime = $bantime
findtime = $findtime
banaction = $banaction
action = $banaction[name=$jail_name, port="$jail_port", protocol="$jail_protocol"]
backend = auto
EOF
    
    cat > "$temp_filter_file" << EOF
[Definition]
failregex = ^.*Failed password for .* from <HOST> port .*$
            ^.*Invalid user .* from <HOST> port .*$
            ^.*authentication failure.*rhost=<HOST>.*$
            ^.*Connection closed by authenticating user .* <HOST> port .*$
ignoreregex = ^.*Failed password for .* from 127.0.0.1.*$
EOF
    
    debug_log "Временные файлы созданы: $temp_jail_file, $temp_filter_file"
    
    backup_file "${FAIL2BAN_JAIL_DIR}/${jail_name}.local" >/dev/null 2>&1 || true
    backup_file "${FAIL2BAN_FILTER_DIR}/${jail_name}.conf" >/dev/null 2>&1 || true
    
    mkdir -p "$FAIL2BAN_JAIL_DIR" "$FAIL2BAN_FILTER_DIR"
    cp "$temp_jail_file" "${FAIL2BAN_JAIL_DIR}/${jail_name}.local"
    cp "$temp_filter_file" "${FAIL2BAN_FILTER_DIR}/${jail_name}.conf"
    
    if ! validate_fail2ban_config; then
        color_echo RED "${EMOJI_ERROR} Ошибка в конфигурации fail2ban! Откатываем изменения..."
        rm -f "${FAIL2BAN_JAIL_DIR}/${jail_name}.local"
        rm -f "${FAIL2BAN_FILTER_DIR}/${jail_name}.conf"
        log_action "ERROR" "Ошибка конфигурации fail2ban при создании jail $jail_name"
        return 1
    fi
    
    if critical_operation service_action "restart" "fail2ban" || service_action "reload" "fail2ban"; then
        sleep 2
        if jail_exists "$jail_name"; then
            color_echo GREEN "${EMOJI_OK} Jail '$jail_name' успешно создан и активирован"
            log_action "INFO" "Создан jail $jail_name (порт: $jail_port, протокол: $jail_protocol)"
            echo ""
            color_echo CYAN "${EMOJI_INFO} Параметры:"
            echo "  Конфигурация: ${FAIL2BAN_JAIL_DIR}${jail_name}.local"
            echo "  Фильтр: ${FAIL2BAN_FILTER_DIR}${jail_name}.conf"
            echo "  Порт: $jail_port"
            echo "  Протокол: $jail_protocol"
            echo "  Bantime: ${bantime}сек"
            echo "  Maxretry: $maxretry"
            return 0
        else
            color_echo YELLOW "${EMOJI_WARN} Jail создан, но не активировался автоматически"
            return 1
        fi
    else
        color_echo RED "${EMOJI_ERROR} Не удалось перезапустить fail2ban"
        return 1
    fi
}

delete_fail2ban_jail() {
    if ! fail2ban_installed; then
        color_echo RED "${EMOJI_ERROR} Fail2ban не установлен"
        return 1
    fi
    
    local jails=()
    while IFS= read -r jail; do
        [[ -n "$jail" ]] && jails+=("$jail")
    done < <(get_fail2ban_jails)
    
    if [[ ${#jails[@]} -eq 0 ]]; then
        color_echo YELLOW "${EMOJI_WARN} Нет доступных jails для удаления"
        return 1
    fi
    
    color_echo CYAN "${EMOJI_REMOVE} Удаление Fail2ban Jail"
    echo ""
    echo "Доступные jails:"
    local i=1
    for jail in "${jails[@]}"; do
        echo "  $i. $jail"
        ((i++))
    done
    echo ""
    
    read -rp "Введите номер jail для удаления: " choice
    [[ "$choice" =~ ^[0-9]+$ ]] || { color_echo RED "${EMOJI_ERROR} Неверный номер"; return 1; }
    (( choice >= 1 && choice <= ${#jails[@]} )) || { color_echo RED "${EMOJI_ERROR} Неверный номер"; return 1; }
    
    local jail_name="${jails[$((choice-1))]}"
    
    if [[ "$jail_name" == "sshd" || "$jail_name" == "dropbear" ]]; then
        color_echo RED "${EMOJI_ERROR} Нельзя удалить системный jail '$jail_name'"
        return 1
    fi
    
    read -rp "Удалить jail '$jail_name'? (y/N): " confirm
    [[ "$confirm" =~ ^[Yy]$ ]] || { color_echo YELLOW "${EMOJI_INFO} Отменено"; return 0; }
    
    backup_file "${FAIL2BAN_JAIL_DIR}/${jail_name}.local" >/dev/null 2>&1 || true
    
    critical_operation fail2ban-client stop "$jail_name" >/dev/null 2>&1 || true
    rm -f "${FAIL2BAN_JAIL_DIR}/${jail_name}.local"
    rm -f "${FAIL2BAN_FILTER_DIR}/${jail_name}.conf"
    
    service_action "reload" "fail2ban" || service_action "restart" "fail2ban"
    
    color_echo GREEN "${EMOJI_OK} Jail '$jail_name' удален"
    log_action "INFO" "Удален jail $jail_name"
}

edit_fail2ban_jail() {
    if ! fail2ban_installed; then
        color_echo RED "${EMOJI_ERROR} Fail2ban не установлен"
        return 1
    fi
    
    local jails=()
    while IFS= read -r jail; do
        [[ -n "$jail" ]] && jails+=("$jail")
    done < <(get_fail2ban_jails)
    
    [[ ${#jails[@]} -eq 0 ]] && { color_echo YELLOW "${EMOJI_WARN} Нет доступных jails"; return 1; }
    
    color_echo CYAN "${EMOJI_EDIT} Редактирование Fail2ban Jail"
    echo ""
    echo "Доступные jails:"
    local i=1
    for jail in "${jails[@]}"; do
        echo "  $i. $jail"
        ((i++))
    done
    echo ""
    
    read -rp "Введите номер jail: " choice
    [[ "$choice" =~ ^[0-9]+$ ]] || { color_echo RED "${EMOJI_ERROR} Неверный номер"; return 1; }
    (( choice >= 1 && choice <= ${#jails[@]} )) || { color_echo RED "${EMOJI_ERROR} Неверный номер"; return 1; }
    
    local jail_name="${jails[$((choice-1))]}"
    local config_file="${FAIL2BAN_JAIL_DIR}/${jail_name}.local"
    
    [[ -f "$config_file" ]] || config_file="$FAIL2BAN_LOCAL_CONFIG"
    
    backup_file "$config_file" >/dev/null 2>&1 || true
    
    echo ""
    color_echo CYAN "Текущие параметры jail '$jail_name':"
    grep -E "^(port|protocol|maxretry|bantime|findtime|enabled)" "$config_file" 2>/dev/null | head -10 || echo "  (не удалось прочитать параметры)"
    
    echo ""
    echo "Выберите параметр:"
    echo "  1. Порт"
    echo "  2. Протокол"
    echo "  3. Maxretry (макс. попыток)"
    echo "  4. Bantime (время блокировки)"
    echo "  5. Findtime (время поиска)"
    echo "  6. Enabled (вкл/выкл)"
    echo "  0. Отмена"
    echo ""
    
    read -rp "Выбор: " param_choice
    
    case $param_choice in
        1)
            read -rp "Новый порт (например: 22,80,443,all): " new_val
            [[ -n "$new_val" ]] && sed -i "s/^port = .*/port = $new_val/" "$config_file"
            ;;
        2)
            read -rp "Новый протокол (tcp/udp): " new_val
            [[ -n "$new_val" ]] && sed -i "s/^protocol = .*/protocol = $new_val/" "$config_file"
            ;;
        3)
            read -rp "Новое значение maxretry: " new_val
            [[ "$new_val" =~ ^[0-9]+$ ]] && sed -i "s/^maxretry = .*/maxretry = $new_val/" "$config_file"
            ;;
        4)
            read -rp "Новое значение bantime (сек): " new_val
            [[ "$new_val" =~ ^[0-9]+$ ]] && sed -i "s/^bantime = .*/bantime = $new_val/" "$config_file"
            ;;
        5)
            read -rp "Новое значение findtime (сек): " new_val
            [[ "$new_val" =~ ^[0-9]+$ ]] && sed -i "s/^findtime = .*/findtime = $new_val/" "$config_file"
            ;;
        6)
            read -rp "Включить jail? (y/n): " new_val
            [[ "$new_val" =~ ^[Yy]$ ]] && sed -i "s/^enabled = .*/enabled = true/" "$config_file"
            [[ "$new_val" =~ ^[Nn]$ ]] && sed -i "s/^enabled = .*/enabled = false/" "$config_file"
            ;;
        0) return 0 ;;
        *) color_echo YELLOW "${EMOJI_WARN} Неверный выбор"; return 1 ;;
    esac
    
    if validate_fail2ban_config; then
        service_action "reload" "fail2ban"
        color_echo GREEN "${EMOJI_OK} Параметры обновлены"
        log_action "INFO" "Обновлены параметры jail $jail_name"
    else
        color_echo RED "${EMOJI_ERROR} Ошибка в конфигурации! Восстановите из backup."
        return 1
    fi
}

manage_jail_rules() {
    if ! fail2ban_installed; then
        color_echo RED "${EMOJI_ERROR} Fail2ban не установлен"
        return 1
    fi
    
    local jails=()
    while IFS= read -r jail; do
        [[ -n "$jail" ]] && jails+=("$jail")
    done < <(get_fail2ban_jails)
    
    [[ ${#jails[@]} -eq 0 ]] && { color_echo YELLOW "${EMOJI_WARN} Нет доступных jails"; return 1; }
    
    echo "Доступные jails:"
    local i=1
    for jail in "${jails[@]}"; do
        echo "  $i. $jail"
        ((i++))
    done
    echo ""
    
    read -rp "Введите номер jail: " choice
    [[ "$choice" =~ ^[0-9]+$ ]] || { color_echo RED "${EMOJI_ERROR} Неверный номер"; return 1; }
    (( choice >= 1 && choice <= ${#jails[@]} )) || { color_echo RED "${EMOJI_ERROR} Неверный номер"; return 1; }
    
    local jail_name="${jails[$((choice-1))]}"
    
    while true; do
        clear
        color_echo CYAN "${EMOJI_SHIELD} Управление jail: $jail_name"
        echo "  1. Показать заблокированные IP"
        echo "  2. Разблокировать конкретный IP"
        echo "  3. Разблокировать все IP"
        echo "  4. Включить jail"
        echo "  5. Выключить jail"
        echo "  6. Проверить статус"
        echo "  0. Назад"
        echo ""
        
        read -rp "Выбор: " action
        
        case $action in
            1)
                echo ""
                color_echo CYAN "Заблокированные IP:"
                fail2ban-client status "$jail_name" 2>/dev/null | grep -A 100 "Banned IP list:" | head -20 || echo "  (нет заблокированных IP)"
                pause
                ;;
            2)
                read -rp "IP для разблокировки: " ip
                if validate_ip "$ip"; then
                    if fail2ban-client set "$jail_name" unbanip "$ip" 2>/dev/null; then
                        color_echo GREEN "${EMOJI_OK} IP $ip разблокирован"
                        log_action "INFO" "Разблокирован IP $ip в jail $jail_name"
                    else
                        color_echo YELLOW "${EMOJI_WARN} IP $ip не найден или ошибка разблокировки"
                    fi
                else
                    color_echo RED "${EMOJI_ERROR} Некорректный IP адрес"
                fi
                pause
                ;;
            3)
                read -rp "Разблокировать ВСЕ IP? (y/N): " confirm
                if [[ "$confirm" =~ ^[Yy]$ ]]; then
                    if fail2ban-client set "$jail_name" unban --all 2>/dev/null; then
                        color_echo GREEN "${EMOJI_OK} Все IP разблокированы"
                        log_action "INFO" "Разблокированы все IP в jail $jail_name"
                    else
                        color_echo RED "${EMOJI_ERROR} Ошибка при разблокировке"
                    fi
                fi
                pause
                ;;
            4)
                fail2ban-client start "$jail_name" 2>/dev/null && color_echo GREEN "${EMOJI_OK} Jail включен" || color_echo RED "${EMOJI_ERROR} Ошибка"
                pause
                ;;
            5)
                fail2ban-client stop "$jail_name" 2>/dev/null && color_echo GREEN "${EMOJI_OK} Jail выключен" || color_echo RED "${EMOJI_ERROR} Ошибка"
                pause
                ;;
            6)
                echo ""
                fail2ban-client status "$jail_name" 2>/dev/null | head -15 || color_echo RED "${EMOJI_ERROR} Не удалось получить статус"
                pause
                ;;
            0) break ;;
            *) color_echo YELLOW "${EMOJI_WARN} Неверный выбор"; sleep 1 ;;
        esac
    done
}

fail2ban_unban_ip() {
    if ! fail2ban_installed; then
        color_echo RED "${EMOJI_ERROR} Fail2ban не установлен"
        return 1
    fi
    
    read -rp "Введите IP для разблокировки: " ip
    [[ -z "$ip" ]] && { color_echo YELLOW "${EMOJI_WARN} IP не указан"; return 1; }
    
    if ! validate_ip "$ip"; then
        color_echo RED "${EMOJI_ERROR} Некорректный IP адрес: $ip"
        return 1
    fi
    
    local jails=()
    while IFS= read -r jail; do
        [[ -n "$jail" ]] && jails+=("$jail")
    done < <(get_fail2ban_jails)
    
    [[ ${#jails[@]} -eq 0 ]] && { color_echo YELLOW "${EMOJI_WARN} Нет активных jails"; return 1; }
    
    local unbanned=0
    for jail in "${jails[@]}"; do
        if fail2ban-client set "$jail" unbanip "$ip" 2>/dev/null; then
            color_echo GREEN "${EMOJI_OK} $ip разблокирован в $jail"
            ((unbanned++))
        fi
    done
    
    if [[ $unbanned -gt 0 ]]; then
        log_action "INFO" "IP $ip разблокирован в $unbanned jails"
    else
        color_echo YELLOW "${EMOJI_WARN} IP $ip не найден ни в одном jail"
    fi
}

create_ufw_rule_from_jail() {
    local jail="$1"
    
    if ! fail2ban_installed; then
        color_echo YELLOW "${EMOJI_WARN} Fail2ban не установлен"
        return 1
    fi
    
    local port_proto
    port_proto=$(get_jail_port_proto "$jail")
    [[ -z "$port_proto" ]] && { color_echo YELLOW "${EMOJI_WARN} Не удалось определить порт для $jail"; return 1; }
    
    IFS=":" read -r port proto <<< "$port_proto"
    
    # Обработка специальных значений
    if [[ "$port" == "all" || "$port" == "0:65535" ]]; then
        color_echo YELLOW "${EMOJI_WARN} Jail $jail отслеживает все порты, пропускаем автоматическое создание правила"
        return 0
    fi
    
    # Проверка на диапазон портов
    if [[ "$port" =~ ^[0-9]+:[0-9]+$ ]]; then
        color_echo YELLOW "${EMOJI_WARN} Jail $jail использует диапазон портов ($port), требуется ручная настройка"
        return 0
    fi
    
    # Проверка на несколько портов через запятую
    if [[ "$port" == *,* ]]; then
        local IFS=','
        read -ra ports <<< "$port"
        local success=0
        for p in "${ports[@]}"; do
            p=$(echo "$p" | tr -d ' ')
            if [[ "$p" =~ ^[0-9]+$ ]] && apply_ufw_rule "IN" "$p" "$proto"; then
                ((success++))
            fi
        done
        if [[ $success -gt 0 ]]; then
            echo "fail2ban-$jail:IN:${port}:${proto}" >> "$RULES_FILE"
            return 0
        fi
        return 1
    fi
    
    # Обычный порт
    if [[ "$port" =~ ^[0-9]+$ ]]; then
        if ufw_rule_exists "IN" "$port" "$proto"; then
            color_echo YELLOW "${EMOJI_WARN} Правило для $jail ($port/$proto) уже существует"
            return 0
        fi
        
        color_echo CYAN "${EMOJI_ADD} Добавление UFW правила для $jail ($port/$proto)"
        
        if apply_ufw_rule "IN" "$port" "$proto"; then
            if ! grep -q ":IN:$port:$proto$" "$RULES_FILE" 2>/dev/null; then
                echo "fail2ban-$jail:IN:$port:$proto" >> "$RULES_FILE"
            fi
            return 0
        fi
    fi
    
    return 1
}

fail2ban_autosync() {
    if ! fail2ban_installed; then
        color_echo YELLOW "${EMOJI_WARN} Fail2ban не установлен"
        return 1
    fi
    
    local jails=()
    while IFS= read -r jail; do
        [[ -n "$jail" ]] && jails+=("$jail")
    done < <(get_fail2ban_jails)
    
    [[ ${#jails[@]} -eq 0 ]] && { color_echo YELLOW "${EMOJI_WARN} Нет активных jails"; return 1; }
    
    color_echo CYAN "${EMOJI_GEAR} Автосинхронизация с UFW..."
    local synced=0
    for jail in "${jails[@]}"; do
        if create_ufw_rule_from_jail "$jail"; then
            ((synced++))
        fi
    done
    
    color_echo GREEN "${EMOJI_OK} Синхронизировано $synced jails"
    log_action "INFO" "Автосинхронизация: $synced jails"
}

fail2ban_manage() {
    while true; do
        clear
        color_echo CYAN "${EMOJI_GEAR} Установка/Удаление Fail2ban"
        echo "  1. Установить Fail2ban"
        echo "  2. Удалить Fail2ban"
        echo "  0. Назад"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1)
                if fail2ban_installed; then
                    color_echo YELLOW "${EMOJI_WARN} Fail2ban уже установлен"
                    pause
                    continue
                fi
                
                color_echo CYAN "${EMOJI_INFO} Установка Fail2ban..."
                
                if command -v apt >/dev/null 2>&1; then
                    echo "Обновление пакетов..."
                    apt update -qq
                    
                    echo "Установка fail2ban..."
                    if DEBIAN_FRONTEND=noninteractive apt install -y -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" fail2ban; then
                        
                        if [[ ! -f "$FAIL2BAN_LOCAL_CONFIG" ]]; then
                            cat > "$FAIL2BAN_LOCAL_CONFIG" << 'EOF'
[DEFAULT]
bantime = 600
findtime = 600
maxretry = 3
backend = auto
usedns = warn
logencoding = auto
enabled = false
mode = normal
filter = %(__name__)s
destemail = root@localhost
sender = root@localhost
mta = sendmail
protocol = tcp
chain = <known/chain>
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
banaction = ufw
banaction_allports = ufw
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = %(sshd_log)s
maxretry = 3
bantime = 600
EOF
                        fi
                        
                        mkdir -p "$FAIL2BAN_JAIL_DIR" "$FAIL2BAN_ACTION_DIR"
                        
                        # Создаем действие ufw
                        ensure_fail2ban_ufw_action
                        
                        service_action "enable" "fail2ban"
                        service_action "start" "fail2ban"
                        
                        sleep 2
                        
                        if is_service_active "fail2ban"; then
                            color_echo GREEN "${EMOJI_OK} Fail2ban установлен и запущен"
                            log_action "INFO" "Fail2ban установлен"
                        else
                            color_echo YELLOW "${EMOJI_WARN} Установлен, но не запущен автоматически"
                        fi
                    else
                        color_echo RED "${EMOJI_ERROR} Ошибка при установке"
                    fi
                else
                    color_echo RED "${EMOJI_ERROR} Не найден пакетный менеджер apt"
                fi
                pause
                ;;
            2)
                if ! fail2ban_installed; then
                    color_echo YELLOW "${EMOJI_WARN} Fail2ban не установлен"
                    pause
                    continue
                fi
                
                read -rp "Удалить fail2ban? (y/N): " confirm
                [[ "$confirm" =~ ^[Yy]$ ]] || continue
                
                backup_file "$FAIL2BAN_LOCAL_CONFIG" >/dev/null 2>&1 || true
                
                service_action "stop" "fail2ban"
                service_action "disable" "fail2ban"
                
                if apt remove -y fail2ban; then
                    apt autoremove -y 2>/dev/null || true
                    color_echo GREEN "${EMOJI_OK} Fail2ban удален"
                    log_action "INFO" "Fail2ban удален"
                else
                    color_echo RED "${EMOJI_ERROR} Ошибка при удалении"
                fi
                pause
                ;;
            0) break ;;
            *) color_echo YELLOW "${EMOJI_WARN} Неверный выбор"; sleep 1 ;;
        esac
    done
}

# ============================================================================
# УПРАВЛЕНИЕ ПРАВИЛАМИ
# ============================================================================

init_rules_file() {
    color_echo CYAN "${EMOJI_INFO} Инициализация файла правил..."
    
    if [[ ! -f "$RULES_FILE" ]]; then
        color_echo YELLOW "${EMOJI_WARN} Файл $RULES_FILE не существует. Создаю..."
    elif [[ ! -s "$RULES_FILE" ]]; then
        color_echo YELLOW "${EMOJI_WARN} Файл $RULES_FILE пуст. Заполняю..."
    else
        color_echo GREEN "${EMOJI_OK} Файл правил существует"
        
        local ssh_port
        ssh_port=$(detect_ssh_port)
        if ! grep -q "^SSH:IN:${ssh_port}:tcp$" "$RULES_FILE" 2>/dev/null; then
            color_echo YELLOW "${EMOJI_WARN} Добавляю базовые правила..."
            echo "SSH:IN:${ssh_port}:tcp" >> "$RULES_FILE"
            echo "HTTP:IN:80:tcp" >> "$RULES_FILE"
            echo "HTTPS:IN:443:tcp" >> "$RULES_FILE"
        fi
        return 0
    fi
    
    local ssh_port
    ssh_port=$(detect_ssh_port)
    
    cat > "$RULES_FILE" << EOF
# Конфигурация правил UFW
# Формат: Имя:Направление:Порт:Протокол
# Направление: IN, OUT, BOTH
# Протокол: tcp, udp, both

# Базовые службы
SSH:IN:${ssh_port}:tcp
HTTP:IN:80:tcp
HTTPS:IN:443:tcp

# Дополнительные службы (раскомментируйте при необходимости)
#DNS:OUT:53:both
#NTP:OUT:123:udp
#SMTP:OUT:25:tcp
#MySQL:IN:3306:tcp
#PostgreSQL:IN:5432:tcp
EOF
    
    color_echo GREEN "${EMOJI_OK} Файл $RULES_FILE создан"
    log_action "INFO" "Создан файл правил $RULES_FILE"
}

# ============================================================================
# ФУНКЦИЯ ПРОВЕРКИ ЦЕЛОСТНОСТИ
# ============================================================================

verify_integrity() {
    color_echo CYAN "${EMOJI_SEARCH} Проверка целостности системы..."
    echo ""
    
    # Проверка UFW
    if is_ufw_enabled; then
        color_echo GREEN "${EMOJI_OK} UFW: активен"
    else
        color_echo YELLOW "${EMOJI_WARN} UFW: не активен"
    fi
    
    # Проверка Fail2ban
    if fail2ban_installed; then
        if is_service_active "fail2ban"; then
            color_echo GREEN "${EMOJI_OK} Fail2ban: активен"
        else
            color_echo YELLOW "${EMOJI_WARN} Fail2ban: установлен, но не активен"
        fi
    else
        color_echo YELLOW "${EMOJI_WARN} Fail2ban: не установлен"
    fi
    
    echo ""
    
    # Проверка соответствия правил UFW и Fail2ban
    if fail2ban_installed && is_service_active "fail2ban"; then
        color_echo CYAN "Проверка синхронизации UFW и Fail2ban..."
        
        local jails=()
        while IFS= read -r jail; do
            [[ -n "$jail" ]] && jails+=("$jail")
        done < <(get_fail2ban_jails)
        
        local issues=0
        for jail in "${jails[@]}"; do
            local port_proto
            port_proto=$(get_jail_port_proto "$jail")
            if [[ -n "$port_proto" ]]; then
                IFS=":" read -r port proto <<< "$port_proto"
                
                # Пропускаем специальные значения
                if [[ "$port" == "all" || "$port" == "0:65535" ]]; then
                    continue
                fi
                
                # Проверка диапазона
                if [[ "$port" =~ ^[0-9]+:[0-9]+$ ]]; then
                    continue
                fi
                
                # Проверка списка портов
                if [[ "$port" == *,* ]]; then
                    local IFS=','
                    read -ra ports <<< "$port"
                    for p in "${ports[@]}"; do
                        p=$(echo "$p" | tr -d ' ')
                        if [[ "$p" =~ ^[0-9]+$ ]] && ! ufw_rule_exists "IN" "$p" "$proto"; then
                            color_echo YELLOW "${EMOJI_WARN} Jail $jail (порт $p/$proto) не имеет правила UFW"
                            ((issues++))
                        fi
                    done
                elif [[ "$port" =~ ^[0-9]+$ ]]; then
                    if ! ufw_rule_exists "IN" "$port" "$proto"; then
                        color_echo YELLOW "${EMOJI_WARN} Jail $jail ($port/$proto) не имеет правила UFW"
                        ((issues++))
                    fi
                fi
            fi
        done
        
        if [[ $issues -eq 0 ]]; then
            color_echo GREEN "${EMOJI_OK} Все jails имеют соответствующие правила UFW"
        else
            color_echo YELLOW "${EMOJI_WARN} Найдено $issues проблем. Запустите автосинхронизацию (меню Fail2ban -> 8)"
        fi
    fi
    
    # Проверка правил в rules.config
    if [[ -f "$RULES_FILE" ]]; then
        echo ""
        color_echo CYAN "Проверка файла правил $RULES_FILE..."
        
        local line_num=0
        local invalid=0
        while IFS= read -r line; do
            ((line_num++))
            [[ -z "$line" || "$line" =~ ^# ]] && continue
            
            IFS=":" read -r name dir port proto <<< "$line"
            
            if ! validate_direction "$dir" 2>/dev/null; then
                color_echo YELLOW "${EMOJI_WARN} Строка $line_num: неверное направление '$dir'"
                ((invalid++))
            fi
            
            if ! validate_port "$port" 2>/dev/null && [[ "$port" != "all" ]] && ! [[ "$port" =~ ^[0-9]+:[0-9]+$ ]] && ! [[ "$port" == *,* ]]; then
                color_echo YELLOW "${EMOJI_WARN} Строка $line_num: неверный порт '$port'"
                ((invalid++))
            fi
            
            if ! validate_protocol "$proto" 2>/dev/null; then
                color_echo YELLOW "${EMOJI_WARN} Строка $line_num: неверный протокол '$proto'"
                ((invalid++))
            fi
        done < "$RULES_FILE"
        
        if [[ $invalid -eq 0 ]]; then
            color_echo GREEN "${EMOJI_OK} Файл правил корректен"
        else
            color_echo YELLOW "${EMOJI_WARN} Найдено $invalid проблем в файле правил"
        fi
    fi
    
    pause
}

# ============================================================================
# МЕНЮ
# ============================================================================

check_rules_menu() {
    while true; do
        clear
        color_echo CYAN "${EMOJI_LIST} Проверка текущих правил UFW"
        echo "================================"
        echo ""
        ufw status verbose 2>/dev/null || color_echo YELLOW "${EMOJI_WARN} Не удалось получить статус UFW"
        echo ""
        echo "  1. Добавить правила"
        echo "  2. Удалить правила"
        echo "  3. Проверить целостность"
        echo "  0. Назад"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1) add_rules_menu ;;
            2) delete_rules_menu ;;
            3) verify_integrity ;;
            0) break ;;
            *) color_echo YELLOW "${EMOJI_WARN} Неверный выбор"; sleep 1 ;;
        esac
    done
}

add_rules_menu() {
    while true; do
        clear
        color_echo CYAN "${EMOJI_ADD} Добавление правил UFW"
        echo "========================"
        echo ""
        echo "  1. Типовые (SSH, HTTP, HTTPS)"
        echo "  2. Из rules.config"
        echo "  3. Вручную"
        echo "  0. Назад"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1)
                echo ""
                color_echo CYAN "Добавление типовых правил..."
                local ssh_port
                ssh_port=$(detect_ssh_port)
                apply_ufw_rule "IN" "$ssh_port" "tcp"
                apply_ufw_rule "IN" "80" "tcp"
                apply_ufw_rule "IN" "443" "tcp"
                pause
                ;;
            2)
                echo ""
                if [[ ! -f "$RULES_FILE" ]]; then
                    color_echo YELLOW "${EMOJI_WARN} Файл $RULES_FILE не найден"
                    init_rules_file
                else
                    color_echo CYAN "Добавление правил из $RULES_FILE..."
                    local applied=0
                    while IFS=":" read -r name dir port proto; do
                        [[ -z "$name" || "$name" =~ ^# ]] && continue
                        if apply_ufw_rule "$dir" "$port" "$proto"; then
                            ((applied++))
                        fi
                    done < "$RULES_FILE"
                    color_echo GREEN "${EMOJI_OK} Применено $applied правил"
                fi
                pause
                ;;
            3)
                echo ""
                color_echo CYAN "Ручное добавление правила:"
                echo "--------------------------"
                
                read -rp "Имя правила [custom]: " name
                name=${name:-custom}
                
                read -rp "Направление (IN/OUT/BOTH): " dir
                if ! validate_direction "$dir"; then
                    color_echo RED "${EMOJI_ERROR} Неверное направление"
                    pause
                    continue
                fi
                
                read -rp "Порт (1-65535): " port
                if ! validate_port "$port"; then
                    color_echo RED "${EMOJI_ERROR} Неверный порт"
                    pause
                    continue
                fi
                
                read -rp "Протокол (tcp/udp/both): " proto
                if ! validate_protocol "$proto"; then
                    color_echo RED "${EMOJI_ERROR} Неверный протокол"
                    pause
                    continue
                fi
                
                if apply_ufw_rule "$dir" "$port" "$proto"; then
                    if ! grep -q ":$dir:$port:$proto$" "$RULES_FILE" 2>/dev/null; then
                        echo "$name:$dir:$port:$proto" >> "$RULES_FILE"
                        color_echo GREEN "${EMOJI_OK} Правило добавлено в $RULES_FILE"
                    fi
                fi
                pause
                ;;
            0) break ;;
            *) color_echo YELLOW "${EMOJI_WARN} Неверный выбор"; sleep 1 ;;
        esac
    done
}

delete_rules_menu() {
    while true; do
        clear
        color_echo CYAN "${EMOJI_REMOVE} Удаление правил UFW"
        echo "======================"
        echo ""
        echo "  1. Типовые (HTTP, HTTPS)"
        echo "  2. Из rules.config"
        echo "  3. По номеру (SSH защищен)"
        echo "  0. Назад"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1)
                echo ""
                color_echo CYAN "Удаление типовых правил..."
                delete_ufw_rule "IN" "80" "tcp"
                delete_ufw_rule "IN" "443" "tcp"
                pause
                ;;
            2)
                echo ""
                if [[ ! -f "$RULES_FILE" ]]; then
                    color_echo YELLOW "${EMOJI_WARN} Файл $RULES_FILE не найден"
                else
                    color_echo CYAN "Удаление правил из $RULES_FILE..."
                    local deleted=0
                    while IFS=":" read -r name dir port proto; do
                        [[ -z "$name" || "$name" =~ ^# ]] && continue
                        
                        # Защита SSH правила
                        local ssh_port
                        ssh_port=$(detect_ssh_port)
                        if [[ "$name" == "SSH" && "$port" == "$ssh_port" && "$proto" == "tcp" ]]; then
                            color_echo YELLOW "${EMOJI_WARN} Пропускаем SSH правило"
                            continue
                        fi
                        
                        if delete_ufw_rule "$dir" "$port" "$proto"; then
                            ((deleted++))
                        fi
                    done < "$RULES_FILE"
                    color_echo GREEN "${EMOJI_OK} Удалено $deleted правил"
                fi
                pause
                ;;
            3)
                echo ""
                color_echo CYAN "Текущие правила UFW:"
                ufw status numbered 2>/dev/null || { color_echo RED "${EMOJI_ERROR} Не удалось получить список"; pause; continue; }
                echo ""
                
                read -rp "Номер правила для удаления: " num
                if [[ "$num" =~ ^[0-9]+$ ]]; then
                    local rule
                    rule=$(ufw status numbered 2>/dev/null | grep "^\[$num\]")
                    if [[ -n "$rule" ]]; then
                        local ssh_port
                        ssh_port=$(detect_ssh_port)
                        if echo "$rule" | grep -q "${ssh_port}/tcp.*ALLOW IN"; then
                            color_echo RED "${EMOJI_ERROR} Удаление SSH правила запрещено"
                        else
                            if critical_operation ufw delete "$num" <<< "y" 2>/dev/null; then
                                color_echo GREEN "${EMOJI_OK} Правило №$num удалено"
                                log_action "INFO" "Удалено правило UFW №$num"
                                refresh_ufw_cache
                            else
                                color_echo RED "${EMOJI_ERROR} Ошибка удаления"
                            fi
                        fi
                    else
                        color_echo YELLOW "${EMOJI_WARN} Правило №$num не найдено"
                    fi
                else
                    color_echo RED "${EMOJI_ERROR} Неверный номер"
                fi
                pause
                ;;
            0) break ;;
            *) color_echo YELLOW "${EMOJI_WARN} Неверный выбор"; sleep 1 ;;
        esac
    done
}

edit_rules_file_menu() {
    while true; do
        clear
        color_echo CYAN "${EMOJI_EDIT} Редактирование rules.config"
        echo "============================="
        echo ""
        echo "  1. Показать правила"
        echo "  2. Добавить правило"
        echo "  3. Удалить правило"
        echo "  0. Назад"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1)
                echo ""
                if [[ -f "$RULES_FILE" && -s "$RULES_FILE" ]]; then
                    color_echo CYAN "Содержимое $RULES_FILE:"
                    nl -w2 -s'. ' "$RULES_FILE"
                else
                    color_echo YELLOW "${EMOJI_WARN} Файл пуст или не существует"
                    read -rp "Создать файл с правилами по умолчанию? (y/N): " create_choice
                    [[ "$create_choice" =~ ^[Yy]$ ]] && init_rules_file
                fi
                pause
                ;;
            2)
                echo ""
                color_echo CYAN "Добавление нового правила:"
                
                read -rp "Имя правила: " name
                [[ -z "$name" ]] && { color_echo YELLOW "${EMOJI_WARN} Имя не может быть пустым"; pause; continue; }
                
                read -rp "Направление (IN/OUT/BOTH): " dir
                validate_direction "$dir" || { color_echo RED "${EMOJI_ERROR} Неверное направление"; pause; continue; }
                
                read -rp "Порт (1-65535): " port
                validate_port "$port" || { color_echo RED "${EMOJI_ERROR} Неверный порт"; pause; continue; }
                
                read -rp "Протокол (tcp/udp/both): " proto
                validate_protocol "$proto" || { color_echo RED "${EMOJI_ERROR} Неверный протокол"; pause; continue; }
                
                if grep -q ":$dir:$port:$proto$" "$RULES_FILE" 2>/dev/null; then
                    color_echo YELLOW "${EMOJI_WARN} Такое правило уже существует"
                else
                    echo "$name:$dir:$port:$proto" >> "$RULES_FILE"
                    color_echo GREEN "${EMOJI_OK} Правило добавлено"
                    log_action "INFO" "Добавлено правило в конфиг: $name:$dir:$port:$proto"
                fi
                pause
                ;;
            3)
                echo ""
                if [[ ! -f "$RULES_FILE" || ! -s "$RULES_FILE" ]]; then
                    color_echo YELLOW "${EMOJI_WARN} Файл пуст или не существует"
                else
                    color_echo CYAN "Текущие правила:"
                    nl -w2 -s'. ' "$RULES_FILE"
                    echo ""
                    
                    read -rp "Номер строки для удаления: " line
                    if [[ "$line" =~ ^[0-9]+$ ]]; then
                        local total_lines
                        total_lines=$(wc -l < "$RULES_FILE")
                        if [[ $line -ge 1 && $line -le $total_lines ]]; then
                            local rule
                            rule=$(sed -n "${line}p" "$RULES_FILE")
                            local ssh_port
                            ssh_port=$(detect_ssh_port)
                            if echo "$rule" | grep -q ":${ssh_port}:tcp$"; then
                                color_echo RED "${EMOJI_ERROR} Удаление SSH правила запрещено"
                            else
                                sed -i "${line}d" "$RULES_FILE"
                                color_echo GREEN "${EMOJI_OK} Строка $line удалена"
                                log_action "INFO" "Удалена строка $line из правил: $rule"
                            fi
                        else
                            color_echo RED "${EMOJI_ERROR} Неверный номер строки"
                        fi
                    else
                        color_echo RED "${EMOJI_ERROR} Неверный номер"
                    fi
                fi
                pause
                ;;
            0) break ;;
            *) color_echo YELLOW "${EMOJI_WARN} Неверный выбор"; sleep 1 ;;
        esac
    done
}

fail2ban_menu() {
    while true; do
        clear
        color_echo CYAN "${EMOJI_SHIELD} Управление Fail2ban"
        echo "====================="
        echo ""
        
        if fail2ban_installed && is_service_active "fail2ban"; then
            color_echo GREEN "${EMOJI_OK} Fail2ban: активен"
            local jail_count
            jail_count=$(get_fail2ban_jails | wc -l)
            echo "  Активных jails: $jail_count"
        elif fail2ban_installed; then
            color_echo YELLOW "${EMOJI_WARN} Fail2ban: установлен, но не активен"
        else
            color_echo YELLOW "${EMOJI_WARN} Fail2ban: не установлен"
        fi
        echo ""
        
        echo "  1. Проверить статус"
        echo "  2. Показать активные jails"
        echo "  3. Создать новый jail"
        echo "  4. Удалить jail"
        echo "  5. Редактировать параметры jail"
        echo "  6. Управление правилами jail"
        echo "  7. Создать UFW-правила для всех jails"
        echo "  8. Автосинхронизация с UFW"
        echo "  9. Разблокировать IP во всех jails"
        echo " 10. Установить/Удалить Fail2ban"
        echo "  0. Назад"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1)
                clear
                if fail2ban_installed; then
                    if command -v systemctl >/dev/null 2>&1; then
                        systemctl status fail2ban --no-pager 2>/dev/null | head -20
                    else
                        service fail2ban status 2>/dev/null | head -20
                    fi
                else
                    color_echo YELLOW "${EMOJI_WARN} Fail2ban не установлен"
                fi
                pause
                ;;
            2)
                clear
                color_echo CYAN "${EMOJI_LIST} Активные jails:"
                local jails=()
                while IFS= read -r jail; do
                    [[ -n "$jail" ]] && jails+=("$jail")
                done < <(get_fail2ban_jails)
                
                if [[ ${#jails[@]} -gt 0 ]]; then
                    local idx=1
                    for jail in "${jails[@]}"; do
                        echo "  $idx. $jail"
                        ((idx++))
                    done
                else
                    echo "  Нет активных jails"
                fi
                pause
                ;;
            3) clear; create_fail2ban_jail; pause ;;
            4) clear; delete_fail2ban_jail; pause ;;
            5) clear; edit_fail2ban_jail; pause ;;
            6) clear; manage_jail_rules ;;
            7)
                clear
                color_echo CYAN "${EMOJI_GEAR} Создание UFW правил для всех jails..."
                local jails=()
                while IFS= read -r jail; do
                    [[ -n "$jail" ]] && jails+=("$jail")
                done < <(get_fail2ban_jails)
                
                if [[ ${#jails[@]} -gt 0 ]]; then
                    for jail in "${jails[@]}"; do
                        create_ufw_rule_from_jail "$jail"
                    done
                else
                    color_echo YELLOW "${EMOJI_WARN} Нет активных jails"
                fi
                pause
                ;;
            8) clear; fail2ban_autosync; pause ;;
            9) clear; fail2ban_unban_ip; pause ;;
            10) fail2ban_manage ;;
            0) break ;;
            *) color_echo YELLOW "${EMOJI_WARN} Неверный выбор"; sleep 1 ;;
        esac
    done
}

main_menu() {
    while true; do
        clear
        color_echo CYAN "${EMOJI_FIRE} UFW Manager v${SCRIPT_VERSION}"
        echo "===================================="
        echo ""
        
        if is_ufw_enabled; then
            color_echo GREEN "${EMOJI_SHIELD} UFW: активен"
        else
            color_echo YELLOW "${EMOJI_WARN} UFW: не активен"
        fi
        
        if fail2ban_installed && is_service_active "fail2ban"; then
            color_echo GREEN "${EMOJI_LOCK} Fail2ban: активен"
        else
            color_echo YELLOW "${EMOJI_UNLOCK} Fail2ban: не активен"
        fi
        echo ""
        
        echo "  1. Проверка текущих правил UFW"
        echo "  2. Добавление правил UFW"
        echo "  3. Удаление правил UFW"
        echo "  4. Редактирование списка правил"
        echo "  5. Управление Fail2ban"
        echo "  0. Выход"
        echo ""
        
        read -rp "Выбор: " c
        
        case $c in
            1) check_rules_menu ;;
            2) add_rules_menu ;;
            3) delete_rules_menu ;;
            4) edit_rules_file_menu ;;
            5) fail2ban_menu ;;
            0)
                clear
                color_echo GREEN "${EMOJI_OK} До свидания!"
                exit 0
                ;;
            *)
                color_echo YELLOW "${EMOJI_WARN} Неверный выбор"
                sleep 1
                ;;
        esac
    done
}

# ============================================================================
# ИНИЦИАЛИЗАЦИЯ И ЗАПУСК
# ============================================================================

init_environment() {
    debug_log "Инициализация окружения"
    
    mkdir -p "$BACKUP_DIR" "$(dirname "$LOG_FILE")" "$FAIL2BAN_ACTION_DIR" 2>/dev/null || true
    
    if ! is_ufw_enabled; then
        color_echo YELLOW "${EMOJI_WARN} UFW не активен. Включаю..."
        if ufw --force enable >/dev/null 2>&1; then
            color_echo GREEN "${EMOJI_OK} UFW включен"
            log_action "INFO" "UFW включен при старте"
        else
            color_echo RED "${EMOJI_ERROR} Не удалось включить UFW"
            log_action "ERROR" "Не удалось включить UFW"
        fi
        sleep 1
    fi
    
    init_rules_file
    refresh_ufw_cache
    
    # Проверяем наличие действия ufw для fail2ban
    if fail2ban_installed; then
        ensure_fail2ban_ufw_action
    fi
    
    debug_log "Инициализация завершена"
}

main() {
    check_root
    acquire_lock || exit 1
    check_dependencies
    
    init_environment
    
    log_action "INFO" "UFW Manager запущен (версия: $SCRIPT_VERSION)"
    debug_log "Режим отладки: $([ $DEBUG_MODE -eq 1 ] && echo "включен" || echo "выключен")"
    
    main_menu
}

# Запуск
main "$@"
