#!/bin/bash

# ============================================================ #
# 🔄 IPv6 Toggle Script
#      v1.2.0 (2025) © @SawGoD
# ------------------------------------------------------------ #
# ✓ Переключает IPv6 (включает/отключает)
# ✓ sysctl: runtime + persistent (только наши файлы)
# ✓ UFW: IPv6 yes/no (если есть)
# ✓ GRUB: ipv6.disable=1 (если есть / можно убрать)
# ✓ Не делает вид, что "security" = "сломать сеть"
# ============================================================ #

set -euo pipefail

log() { echo -e "$*"; }
die() { echo -e "❌ $*" >&2; exit 1; }

[[ ${EUID:-999} -eq 0 ]] || die "Please run this script as root."

SYSCTL_DISABLE="/etc/sysctl.d/99-ipv6-disable.conf"
SYSCTL_SECURITY="/etc/sysctl.d/99-ipv6-security.conf"
UFW_DEFAULT="/etc/default/ufw"
GRUB_FILE="/etc/default/grub"

backup_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  cp -a "$f" "${f}.bak.$(date +%Y%m%d_%H%M%S)"
}

apply_sysctl_file() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  sysctl --load "$f" >/dev/null 2>&1 || true
}

ipv6_status() {
  sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown"
}

has_sysctl_key() {
  # fast check without dumping whole sysctl -a
  sysctl -n "$1" >/dev/null 2>&1
}

set_ufw_ipv6() {
  local val="$1" # yes/no
  command -v ufw >/dev/null 2>&1 || return 0
  [[ -f "$UFW_DEFAULT" ]] || return 0

  backup_file "$UFW_DEFAULT"
  if grep -q '^IPV6=' "$UFW_DEFAULT"; then
    sed -i "s/^IPV6=.*/IPV6=$val/" "$UFW_DEFAULT"
  else
    echo "IPV6=$val" >>"$UFW_DEFAULT"
  fi
}

grub_add_ipv6_disable() {
  [[ -f "$GRUB_FILE" ]] || return 0
  grep -q 'ipv6\.disable=1' "$GRUB_FILE" && return 0

  backup_file "$GRUB_FILE"

  # add to GRUB_CMDLINE_LINUX_DEFAULT if exists, else GRUB_CMDLINE_LINUX
  local var="GRUB_CMDLINE_LINUX_DEFAULT"
  grep -q "^${var}=" "$GRUB_FILE" || var="GRUB_CMDLINE_LINUX"

  local current
  current="$(grep "^${var}=" "$GRUB_FILE" | sed -E 's/^[^"]*"([^"]*)".*$/\1/' || true)"
  local new="ipv6.disable=1"
  [[ -n "$current" ]] && new="ipv6.disable=1 $current"

  # replace whole line (keeps quotes)
  sed -i "s|^${var}=\".*\"|${var}=\"$new\"|" "$GRUB_FILE"
}

grub_remove_ipv6_disable() {
  [[ -f "$GRUB_FILE" ]] || return 0
  grep -q 'ipv6\.disable=1' "$GRUB_FILE" || return 0

  backup_file "$GRUB_FILE"

  for var in GRUB_CMDLINE_LINUX_DEFAULT GRUB_CMDLINE_LINUX; do
    grep -q "^${var}=" "$GRUB_FILE" || continue
    local current new
    current="$(grep "^${var}=" "$GRUB_FILE" | sed -E 's/^[^"]*"([^"]*)".*$/\1/' || true)"
    new="$(echo "$current" | sed -E 's/(^| )ipv6\.disable=1( |$)/ /g; s/  +/ /g; s/^ //; s/ $//')"
    sed -i "s|^${var}=\".*\"|${var}=\"$new\"|" "$GRUB_FILE"
  done
}

update_grub() {
  if command -v update-grub >/dev/null 2>&1; then
    update-grub >/dev/null 2>&1 || true
  elif command -v grub-mkconfig >/dev/null 2>&1; then
    grub-mkconfig -o /boot/grub/grub.cfg >/dev/null 2>&1 || true
  else
    return 1
  fi
  return 0
}

write_disable_conf() {
  mkdir -p /etc/sysctl.d
  backup_file "$SYSCTL_DISABLE"

  cat >"$SYSCTL_DISABLE" <<'EOF'
# --- Disable IPv6 completely --- #
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF
  # если отключаем - security файл не нужен
  [[ -f "$SYSCTL_SECURITY" ]] && backup_file "$SYSCTL_SECURITY" && rm -f "$SYSCTL_SECURITY"
}

write_security_conf() {
  mkdir -p /etc/sysctl.d
  backup_file "$SYSCTL_SECURITY"

  cat >"$SYSCTL_SECURITY" <<'EOF'
# --- IPv6 Security / sane defaults (only when IPv6 is enabled) --- #
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.all.use_tempaddr = 2
net.ipv6.conf.default.use_tempaddr = 2
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF
}

runtime_disable_ipv6() {
  has_sysctl_key net.ipv6.conf.all.disable_ipv6 || die "IPv6 sysctl keys not available on this kernel."
  sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.lo.disable_ipv6=1 >/dev/null 2>&1 || true
}

runtime_enable_ipv6() {
  has_sysctl_key net.ipv6.conf.all.disable_ipv6 || die "IPv6 sysctl keys not available on this kernel."
  sysctl -w net.ipv6.conf.all.disable_ipv6=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.default.disable_ipv6=0 >/dev/null 2>&1 || true
  sysctl -w net.ipv6.conf.lo.disable_ipv6=0 >/dev/null 2>&1 || true
}

echo "============================================"
echo "   🔄 IPv6 Toggle Script"
echo "============================================"
echo

# --- Decide action by sysctl state --- #
ipv6_all="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "0")"
ipv6_def="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo "0")"

if [[ "$ipv6_all" == "1" ]] || [[ "$ipv6_def" == "1" ]]; then
  ACTION="enable"
  ACTION_EMOJI="✅"
  ACTION_TEXT="Enabling"
else
  ACTION="disable"
  ACTION_EMOJI="🚫"
  ACTION_TEXT="Disabling"
fi

echo "$ACTION_EMOJI Current status: IPv6 is $([[ "$ACTION" == "enable" ]] && echo "DISABLED" || echo "ENABLED")"
echo "$ACTION_EMOJI Action: $ACTION_TEXT IPv6"
echo

if [[ "$ACTION" == "disable" ]]; then
  echo "🔧 Disabling IPv6 via sysctl (runtime)..."
  runtime_disable_ipv6
  echo "└─ Runtime IPv6 disabled"
  echo

  echo "📦 Writing persistent IPv6 disable config..."
  write_disable_conf
  apply_sysctl_file "$SYSCTL_DISABLE"
  echo "└─ Config file: $SYSCTL_DISABLE"
  echo

  echo "🧱 UFW: set IPV6=no (if present)..."
  set_ufw_ipv6 "no"
  echo "└─ Done"
  echo

  echo "📝 GRUB: adding ipv6.disable=1 (kernel-level)..."
  if [[ -f "$GRUB_FILE" ]]; then
    grub_add_ipv6_disable
    if update_grub; then
      echo "└─ GRUB updated (reboot required)"
    else
      echo "└─ GRUB updated in file, but update-grub not found (run manually). Reboot required anyway."
    fi
  else
    echo "└─ GRUB file not found, skipping."
  fi
  echo

else
  echo "🔧 Enabling IPv6 via sysctl (runtime)..."
  runtime_enable_ipv6
  echo "└─ Runtime IPv6 enabled"
  echo

  echo "📦 Removing persistent IPv6 disable config (if exists)..."
  if [[ -f "$SYSCTL_DISABLE" ]]; then
    backup_file "$SYSCTL_DISABLE"
    rm -f "$SYSCTL_DISABLE"
    echo "└─ Removed: $SYSCTL_DISABLE"
  else
    echo "└─ Nothing to remove"
  fi
  echo

  echo "🔒 Writing IPv6 security config..."
  write_security_conf
  apply_sysctl_file "$SYSCTL_SECURITY"
  echo "└─ Config file: $SYSCTL_SECURITY"
  echo

  echo "🧱 UFW: set IPV6=yes (if present)..."
  set_ufw_ipv6 "yes"
  echo "└─ Done"
  echo

  echo "📝 GRUB: removing ipv6.disable=1 (kernel-level)..."
  if [[ -f "$GRUB_FILE" ]]; then
    grub_remove_ipv6_disable
    if update_grub; then
      echo "└─ GRUB updated (reboot may be required)"
    else
      echo "└─ GRUB updated in file, but update-grub not found (run manually)."
    fi
  else
    echo "└─ GRUB file not found, skipping."
  fi
  echo
fi

echo "🔍 Final verification:"
echo "--------------------------------------------"
ipv6_all="$(sysctl -n net.ipv6.conf.all.disable_ipv6 2>/dev/null || echo "unknown")"
ipv6_def="$(sysctl -n net.ipv6.conf.default.disable_ipv6 2>/dev/null || echo "unknown")"
ipv6_lo="$(sysctl -n net.ipv6.conf.lo.disable_ipv6 2>/dev/null || echo "unknown")"

echo "✅ IPv6 Status:"
echo "├─ all.disable_ipv6:     $ipv6_all"
echo "├─ default.disable_ipv6: $ipv6_def"
echo "└─ lo.disable_ipv6:      $ipv6_lo"
echo

if [[ -f "$GRUB_FILE" ]] && grep -q 'ipv6\.disable=1' "$GRUB_FILE"; then
  echo "✅ GRUB Configuration:"
  echo "└─ ipv6.disable=1 present (takes effect after reboot)"
else
  echo "✅ GRUB Configuration:"
  echo "└─ ipv6.disable=1 not present"
fi
echo

if [[ -f "$UFW_DEFAULT" ]] && grep -q '^IPV6=' "$UFW_DEFAULT"; then
  echo "✅ UFW Configuration:"
  echo "└─ IPV6=$(grep '^IPV6=' "$UFW_DEFAULT" | cut -d= -f2)"
  echo
fi

echo "============================================"
echo "            ✨ Done."
echo "============================================"
echo

if [[ "$ACTION" == "disable" ]]; then
  echo "⚠️ Reboot required only for GRUB/kernel-level disable."
else
  echo "⚠️ If IPv6 was previously disabled via GRUB, reboot may be required to fully restore it."
fi
