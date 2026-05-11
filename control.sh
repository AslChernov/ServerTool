#!/bin/bash

# ============================================================ #
# 🎮 BBR Control Script
#      v1.2.0 (2025) © @SawGoD
# ------------------------------------------------------------ #
# ✓ Управление профилями BBR2/BBR3 (через отдельные скрипты)
# ✓ Переключение IPv6 (через toggle_ipv6.sh)
# ✓ Статус
# ✓ Бэкап того, что меняется, в ./backup/
# ✓ Откат (restore)
# ============================================================ #

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BBR2_SCRIPT="$SCRIPT_DIR/bbr2.sh"
BBR3_SCRIPT="$SCRIPT_DIR/bbr3.sh"
TOGGLE_IPV6_SCRIPT="$SCRIPT_DIR/toggle_ipv6.sh"
SERVER_TEST_SCRIPT="$SCRIPT_DIR/server_test.sh"

# backup root in the same folder as scripts
BACKUP_ROOT="$SCRIPT_DIR/backup"

# Files that profiles/toggles typically touch
declare -a TRACK_FILES=(
  "/etc/sysctl.d/99-lowlatency.conf"
  "/etc/sysctl.d/99-network-optimizations.conf"
  "/etc/sysctl.d/99-ipv6-disable.conf"
  "/etc/sysctl.d/99-ipv6-security.conf"
  "/etc/default/ufw"
  "/etc/default/grub"
)

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'
BOLD='\033[1m'

die() { echo -e "${RED}❌ $*${NC}" >&2; exit 1; }
info() { echo -e "${BLUE}$*${NC}"; }
ok() { echo -e "${GREEN}$*${NC}"; }
warn() { echo -e "${YELLOW}⚠️ $*${NC}"; }

# --- Root check --- #
check_root() {
  [[ ${EUID:-999} -eq 0 ]] || die "Please run this script as root."
}

# --- Ensure backup dir exists --- #
ensure_backup_dir() {
  mkdir -p "$BACKUP_ROOT"
}

# --- Timestamped backup set dir --- #
new_backup_set_dir() {
  ensure_backup_dir
  local ts
  ts="$(date +%Y%m%d_%H%M%S)"
  local dir="$BACKUP_ROOT/$ts"
  mkdir -p "$dir"
  echo "$dir"
}

# --- Save meta about backup set --- #
write_backup_meta() {
  local dir="$1"
  local label="${2:-manual}"
  {
    echo "created_at=$(date -Iseconds)"
    echo "label=$label"
    echo "hostname=$(hostname 2>/dev/null || echo unknown)"
    echo "kernel=$(uname -r 2>/dev/null || echo unknown)"
  } >"$dir/backup.meta"
}

# --- Backup single file (preserve path) --- #
backup_file_to_set() {
  local setdir="$1"
  local f="$2"
  # store under setdir with absolute-path mirroring
  local rel="${f#/}"               # drop leading slash
  local dest="$setdir/files/$rel"
  local destdir
  destdir="$(dirname "$dest")"
  mkdir -p "$destdir"

  if [[ -f "$f" ]]; then
    cp -a "$f" "$dest"
    echo "$f" >>"$setdir/files.list"
  else
    # record missing so restore can optionally delete if it was created later
    echo "$f (missing)" >>"$setdir/missing.list"
  fi
}

# --- Create backup set for tracked files --- #
create_backup_set() {
  local label="${1:-manual}"
  local setdir
  setdir="$(new_backup_set_dir)"
  write_backup_meta "$setdir" "$label"

  : >"$setdir/files.list"
  : >"$setdir/missing.list"

  for f in "${TRACK_FILES[@]}"; do
    backup_file_to_set "$setdir" "$f"
  done

  ok "🗄️ Backup created: ${BLUE}$setdir${NC}"
  echo "$setdir"
}

# --- List backups --- #
list_backups() {
  ensure_backup_dir
  echo -e "${BOLD}${BLUE}============================================${NC}"
  echo -e "${BOLD}${BLUE}   🗄️ Available Backups${NC}"
  echo -e "${BOLD}${BLUE}============================================${NC}"
  if ! ls -1 "$BACKUP_ROOT" >/dev/null 2>&1; then
    echo -e "${YELLOW}No backups found in $BACKUP_ROOT${NC}"
    return 0
  fi

  # newest first
  ls -1 "$BACKUP_ROOT" | sort -r | while read -r d; do
    [[ -d "$BACKUP_ROOT/$d" ]] || continue
    local meta="$BACKUP_ROOT/$d/backup.meta"
    if [[ -f "$meta" ]]; then
      local label created
      label="$(grep '^label=' "$meta" | cut -d= -f2- || true)"
      created="$(grep '^created_at=' "$meta" | cut -d= -f2- || true)"
      echo -e "• ${GREEN}$d${NC}  [${BLUE}$label${NC}]  ${YELLOW}$created${NC}"
    else
      echo -e "• ${GREEN}$d${NC}"
    fi
  done
}

# --- Restore backup set --- #
restore_backup_set() {
  local setid="$1"
  [[ -n "${setid:-}" ]] || die "restore requires backup id (folder name). Example: restore 20251213_120501"

  local setdir="$BACKUP_ROOT/$setid"
  [[ -d "$setdir" ]] || die "Backup not found: $setdir"

  local filesdir="$setdir/files"
  [[ -d "$filesdir" ]] || die "Invalid backup set (missing files dir): $setdir"

  info "Restoring from: $setdir"
  warn "Это перезапишет системные файлы из бэкапа."

  # Restore backed up existing files
  if [[ -f "$setdir/files.list" ]]; then
    while read -r f; do
      [[ -n "$f" ]] || continue
      local rel="${f#/}"
      local src="$filesdir/$rel"
      if [[ -f "$src" ]]; then
        mkdir -p "$(dirname "$f")"
        cp -a "$src" "$f"
        echo -e "${GREEN}Restored: $f${NC}"
      fi
    done <"$setdir/files.list"
  fi

  # Remove files that were missing at backup time (optional but sensible)
  if [[ -f "$setdir/missing.list" ]]; then
    while read -r line; do
      [[ -n "$line" ]] || continue
      local f="${line% (missing)}"
      if [[ -f "$f" ]]; then
        rm -f "$f"
        echo -e "${YELLOW}Removed (was missing at backup time): $f${NC}"
      fi
    done <"$setdir/missing.list"
  fi

  ok "Restore done."

  # Try to apply sysctl only for the files we track (best-effort)
  if command -v sysctl >/dev/null 2>&1; then
    for f in /etc/sysctl.d/99-lowlatency.conf /etc/sysctl.d/99-network-optimizations.conf /etc/sysctl.d/99-ipv6-disable.conf /etc/sysctl.d/99-ipv6-security.conf; do
      [[ -f "$f" ]] && sysctl --load "$f" >/dev/null 2>&1 || true
    done
  fi

  # GRUB update hint
  if [[ -f /etc/default/grub ]]; then
    warn "Если менялся /etc/default/grub: нужен update-grub и ребут для эффекта."
  fi
}

# --- Show current status --- #
show_status() {
  echo -e "${BOLD}${BLUE}============================================${NC}"
  echo -e "${BOLD}${BLUE}   📊 Current System Status${NC}"
  echo -e "${BOLD}${BLUE}============================================${NC}"
  echo

  command -v sysctl >/dev/null 2>&1 || die "sysctl not found"
  command -v ip >/dev/null 2>&1 || die "ip not found"
  command -v tc >/dev/null 2>&1 || warn "tc not found (qdisc info may be limited)"

  echo -e "${BLUE}🔹 BBR Configuration:${NC}"
  cc_value="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")"
  qdisc_value="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")"

  if [[ "$cc_value" == "bbr" ]]; then
    echo -e "├─ Congestion Control: ${GREEN}BBR (often BBR1)${NC} (${BLUE}bbr${NC})"
  elif [[ "$cc_value" == "bbr2" ]]; then
    echo -e "├─ Congestion Control: ${GREEN}BBR2${NC} (${BLUE}bbr2${NC})"
  elif [[ "$cc_value" == "bbr3" ]]; then
    echo -e "├─ Congestion Control: ${GREEN}BBR3${NC} (${BLUE}bbr3${NC})"
  else
    echo -e "├─ Congestion Control: ${YELLOW}$cc_value${NC}"
  fi

  echo -e "├─ Default qdisc:      ${BLUE}$qdisc_value${NC}"

  iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' || true)"
  if [[ -n "${iface:-}" ]] && command -v tc >/dev/null 2>&1; then
    interface_qdisc="$(tc qdisc show dev "$iface" 2>/dev/null | head -n 1 || echo "unknown")"
    echo -e "└─ Iface (${GREEN}$iface${NC}):      ${BLUE}$interface_qdisc${NC}"
  fi
  echo

  echo -e "${BLUE}🔹 Network Settings:${NC}"
  tfo_value="$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo "unknown")"
  ecn_value="$(sysctl -n net.ipv4.tcp_ecn 2>/dev/null || echo "unknown")"
  low_lat="$(sysctl -n net.ipv4.tcp_low_latency 2>/dev/null || echo "n/a")"
  echo -e "├─ TCP Fast Open:      ${BLUE}$tfo_value${NC}"
  echo -e "├─ ECN:                ${BLUE}$ecn_value${NC}"
  echo -e "└─ TCP Low Latency:    ${BLUE}$low_lat${NC}"
  echo

  echo -e "${BLUE}🔹 Buffer Settings:${NC}"
  rmem_max="$(sysctl -n net.core.rmem_max 2>/dev/null || echo "unknown")"
  wmem_max="$(sysctl -n net.core.wmem_max 2>/dev/null || echo "unknown")"
  tcp_rmem="$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null || echo "unknown")"
  tcp_wmem="$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null || echo "unknown")"
  echo -e "├─ rmem_max:    ${BLUE}$rmem_max${NC}"
  echo -e "├─ wmem_max:    ${BLUE}$wmem_max${NC}"
  echo -e "├─ tcp_rmem:    ${BLUE}$tcp_rmem${NC}"
  echo -e "└─ tcp_wmem:    ${BLUE}$tcp_wmem${NC}"
  echo

  echo -e "${BLUE}🔹 IPv6 Status:${NC}"
  ipv6_all="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown")"
  ipv6_default="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo "unknown")"
  if [[ "$ipv6_all" == "1" ]] && [[ "$ipv6_default" == "1" ]]; then
    echo -e "├─ IPv6 (all):        ${RED}DISABLED${NC}"
    echo -e "└─ IPv6 (default):    ${RED}DISABLED${NC}"
  elif [[ "$ipv6_all" == "0" ]] && [[ "$ipv6_default" == "0" ]]; then
    echo -e "├─ IPv6 (all):        ${GREEN}ENABLED${NC}"
    echo -e "└─ IPv6 (default):    ${GREEN}ENABLED${NC}"
  else
    echo -e "├─ IPv6 (all):        ${YELLOW}$ipv6_all${NC}"
    echo -e "└─ IPv6 (default):    ${YELLOW}$ipv6_default${NC}"
  fi
  echo

  echo -e "${BLUE}🔹 Active Profile (best-effort guess):${NC}"
  if [[ -f /etc/sysctl.d/99-lowlatency.conf ]]; then
    echo -e "├─ Detected: ${GREEN}BBR2 profile file${NC} (${BLUE}/etc/sysctl.d/99-lowlatency.conf${NC})"
  fi
  if [[ -f /etc/sysctl.d/99-network-optimizations.conf ]]; then
    echo -e "├─ Detected: ${GREEN}BBR3 profile file${NC} (${BLUE}/etc/sysctl.d/99-network-optimizations.conf${NC})"
  fi
  if [[ ! -f /etc/sysctl.d/99-lowlatency.conf ]] && [[ ! -f /etc/sysctl.d/99-network-optimizations.conf ]]; then
    echo -e "└─ ${YELLOW}None detected${NC}"
  fi

  echo
  echo -e "${BOLD}${BLUE}============================================${NC}"
}

# --- Run profile script with auto-backup --- #
run_with_backup() {
  local label="$1"
  local script="$2"

  [[ -f "$script" ]] || die "Script not found: $script"
  chmod +x "$script"

  local setdir
  setdir="$(create_backup_set "$label")"

  info "▶ Running: ${GREEN}$script${NC}"
  bash "$script" || {
    warn "Script failed. You can restore: $0 restore $(basename "$setdir")"
    exit 1
  }

  ok "Done. Backup id: ${BLUE}$(basename "$setdir")${NC}"
}

activate_bbr2() { run_with_backup "activate-bbr2" "$BBR2_SCRIPT"; }
activate_bbr3() { run_with_backup "activate-bbr3" "$BBR3_SCRIPT"; }
toggle_ipv6()   { run_with_backup "toggle-ipv6" "$TOGGLE_IPV6_SCRIPT"; }

# --- Run server tests (NO BACKUPS) --- #
run_server_tests() {
  [[ -f "$SERVER_TEST_SCRIPT" ]] || die "Script not found: $SERVER_TEST_SCRIPT"
  chmod +x "$SERVER_TEST_SCRIPT"
  info "▶ Running: ${GREEN}$SERVER_TEST_SCRIPT${NC} (no backups)"
  bash "$SERVER_TEST_SCRIPT"
}

# --- Menu --- #
show_menu() {
  ipv6_all="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")"
  ipv6_enabled=true
  [[ "$ipv6_all" == "1" ]] && ipv6_enabled=false

  echo
  echo -e "${BOLD}${BLUE}============================================${NC}"
  echo -e "${BOLD}${BLUE}   🎮 BBR Control Menu${NC}"
  echo -e "${BOLD}${BLUE}============================================${NC}"
  echo
  echo -e "${BOLD}1)${NC} Activate ${GREEN}BBR2${NC} profile (${YELLOW}Low-Latency${NC})"
  echo -e "${BOLD}2)${NC} Activate ${GREEN}BBR3${NC} profile (${YELLOW}High Throughput${NC})"
  if [[ "$ipv6_enabled" == true ]]; then
    echo -e "${BOLD}3)${NC} ${RED}Disable IPv6${NC}"
  else
    echo -e "${BOLD}3)${NC} ${GREEN}Enable IPv6${NC}"
  fi
  echo -e "${BOLD}4)${NC} ${BLUE}Server tests${NC} (bench)"
  echo -e "${BOLD}5)${NC} Show ${BLUE}status${NC}"
  echo -e "${BOLD}6)${NC} List ${YELLOW}backups${NC}"
  echo -e "${BOLD}7)${NC} ${RED}Restore backup${NC}"
  echo -e "${BOLD}8)${NC} Exit"
  echo
  echo -en "${BOLD}Select option [1-8]: ${NC}"
}

# --- Main --- #
main() {
  check_root

  if [[ $# -eq 0 ]]; then
    show_status
    while true; do
      show_menu
      read -r choice
      echo
      case "$choice" in
        1) activate_bbr2; echo; echo -e "${YELLOW}Press Enter...${NC}"; read -r ;;
        2) activate_bbr3; echo; echo -e "${YELLOW}Press Enter...${NC}"; read -r ;;
        3) toggle_ipv6;   echo; echo -e "${YELLOW}Press Enter...${NC}"; read -r ;;
        4) run_server_tests; echo; echo -e "${YELLOW}Press Enter...${NC}"; read -r ;;
        5) show_status;   echo; echo -e "${YELLOW}Press Enter...${NC}"; read -r ;;
        6) list_backups;  echo; echo -e "${YELLOW}Press Enter...${NC}"; read -r ;;
        7)
          list_backups
          echo
          echo -en "${YELLOW}Enter backup id (folder name, e.g. 20251213_201530): ${NC}"
          read -r bid
          restore_backup_set "$bid"
          echo; echo -e "${YELLOW}Press Enter...${NC}"; read -r
          ;;
        8) echo -e "${GREEN}Exiting...${NC}"; exit 0 ;;
        *) echo -e "${RED}Invalid option. Please select 1-8.${NC}"; sleep 1 ;;
      esac
    done
  else
    case "$1" in
      status|show) show_status ;;
      bbr2|activate-bbr2) activate_bbr2 ;;
      bbr3|activate-bbr3) activate_bbr3 ;;
      toggle-ipv6|ipv6-toggle|disable-ipv6|ipv6-disable|enable-ipv6|ipv6-enable) toggle_ipv6 ;;
      test|tests|bench|server-test|server-tests) run_server_tests ;;
      backup|create-backup)
        create_backup_set "manual"
        ;;
      backups|list-backups)
        list_backups
        ;;
      restore)
        [[ $# -ge 2 ]] || die "Usage: $0 restore <backup_id>"
        restore_backup_set "$2"
        ;;
      *)
        echo -e "${RED}Usage: $0 [status|bbr2|bbr3|toggle-ipv6|test|backup|list-backups|restore <id>]${NC}"
        echo -e "  ${BLUE}status${NC}            - Show current status"
        echo -e "  ${GREEN}bbr2${NC}              - Activate BBR2 profile (auto-backup)"
        echo -e "  ${GREEN}bbr3${NC}              - Activate BBR3 profile (auto-backup)"
        echo -e "  ${YELLOW}toggle-ipv6${NC}       - Toggle IPv6 (auto-backup)"
        echo -e "  ${BLUE}test${NC}              - Server tests / bench menu (NO backups)"
        echo -e "  ${YELLOW}backup${NC}            - Create backup set (tracked files)"
        echo -e "  ${BLUE}list-backups${NC}      - List backups"
        echo -e "  ${RED}restore <id>${NC}      - Restore backup set"
        exit 1
        ;;
    esac
  fi
}

main "$@"
