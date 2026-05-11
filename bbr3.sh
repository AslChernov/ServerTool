#!/bin/bash

# ============================================================ #
# 🚀 Network Optimization Script for VLESS/Xray
#      v2.2.0 (2025) © @ivan-nginx / hardened by @SawGoD
# ------------------------------------------------------------ #
# ✓ Высокая пропускная способность (буферы/очереди)
# ✓ fq (быстрый qdisc без шейпинга) + авто-интерфейс
# ✓ TCP Fast Open = 3
# ✓ ECN on
# ✓ BBR3 через внешний инсталлер (с контролем, что реально включилось)
# ✓ Не трогает ip_forward / redirects (это не "оптимизация", это "потом ты материшься")
# ✓ Совместим Debian 12+ / Ubuntu 22.04+
# ============================================================ #

set -euo pipefail

log() { echo -e "$*"; }
die() { echo -e "❌ $*" >&2; exit 1; }

# sysctl key presence differs across kernels / virtualization (e.g. some OpenVZ/LXC).
sysctl_key_exists() {
  local key="$1"
  # Fast path: procfs entry existence
  [[ -e "/proc/sys/${key//./\/}" ]] && return 0
  # Fallback: sysctl query (handles cases where procfs is restricted)
  sysctl -n "$key" >/dev/null 2>&1
}

append_sysctl_kv() {
  local file="$1" key="$2" value="$3"
  if sysctl_key_exists "$key"; then
    printf '%s = %s\n' "$key" "$value" >>"$file"
  else
    log "⚠️ sysctl key not present, skipping: $key"
  fi
}

log "============================================"
log "   🚀 Network optimization started..."
log "============================================"
log

log "\e[1;33m⚠️ ВАЖНО:\e[0m"
log "\e[1;37m   Если потребуется перезагрузка (ядро/модуль после BBR3),\e[0m"
log "\e[1;37m   выполняй её через \e[1;36mадмин-панель хостинга\e[0m,\e[0m"
log "\e[1;37m   а не \e[1;31mreboot по SSH\e[0m. Иначе можно остаться без доступа.\e[0m"
log "\e[1;37m   Если доступ по SSH уже потерян — обратись в \e[1;36mтехническую поддержку хостинга\e[0m\e[1;37m,\e[0m"
log "\e[1;37m   с просьбой выполнить \e[1;33mперезагрузку VPS\e[0m через их панель управления.\e[0m"
log

[[ ${EUID:-999} -eq 0 ]] || die "Please run this script as root."

command -v ip >/dev/null 2>&1 || die "ip command not found (package: iproute2)."
command -v tc >/dev/null 2>&1 || die "tc command not found (package: iproute2)."
command -v sysctl >/dev/null 2>&1 || die "sysctl command not found."
command -v wget >/dev/null 2>&1 || die "wget command not found (package: wget)."
command -v modprobe >/dev/null 2>&1 || log "⚠️ modprobe not found; modules auto-load may not work."

krn_version="$(uname -r 2>/dev/null || echo "unknown")"

# --- Detect primary network interface --- #
log "🔍 Detecting network interface..."
iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[[ -n "${iface:-}" ]] || die "Failed to detect network interface."
log "├─ Using interface: $iface"
log

# --- Write sysctl config (only safe + throughput/latency knobs) --- #
log "🔧 Writing sysctl config..."
mkdir -p /etc/sysctl.d
conf="/etc/sysctl.d/99-network-optimizations.conf"
bak=""
if [[ -f "$conf" ]]; then
  bak="${conf}.bak.$(date +%Y%m%d_%H%M%S)"
  cp -a "$conf" "$bak"
fi
cat >"$conf" <<'EOF'
# This file is managed by bbr3.sh
# Some sysctl keys may not exist on certain kernels/virtualization; bbr3.sh will (re)write
# this file with only supported keys.
EOF

{
  echo
  echo "# --- Buffer tuning for high throughput --- #"
} >>"$conf"
append_sysctl_kv "$conf" "net.core.netdev_max_backlog" "5000"
append_sysctl_kv "$conf" "net.core.somaxconn" "4096"
append_sysctl_kv "$conf" "net.core.rmem_max" "33554432"
append_sysctl_kv "$conf" "net.core.wmem_max" "33554432"

{
  echo
  echo "# TCP autotuning buffers (min default max)"
} >>"$conf"
append_sysctl_kv "$conf" "net.ipv4.tcp_rmem" "4096 87380 33554432"
append_sysctl_kv "$conf" "net.ipv4.tcp_wmem" "4096 65536 33554432"

{
  echo
  echo "# --- Queue discipline (fast, low overhead) --- #"
} >>"$conf"
# Prefer fq; tc qdisc is applied below anyway. Some kernels don't expose this sysctl.
append_sysctl_kv "$conf" "net.core.default_qdisc" "fq"

{
  echo
  echo "# --- TCP performance --- #"
} >>"$conf"
append_sysctl_kv "$conf" "net.ipv4.tcp_fastopen" "3"
append_sysctl_kv "$conf" "net.ipv4.tcp_ecn" "1"
append_sysctl_kv "$conf" "net.ipv4.tcp_syncookies" "1"
append_sysctl_kv "$conf" "net.ipv4.tcp_timestamps" "1"
append_sysctl_kv "$conf" "net.ipv4.tcp_fin_timeout" "20"
append_sysctl_kv "$conf" "net.ipv4.tcp_tw_reuse" "1"
append_sysctl_kv "$conf" "net.ipv4.tcp_max_syn_backlog" "8192"
append_sysctl_kv "$conf" "net.ipv4.tcp_max_tw_buckets" "262144"
append_sysctl_kv "$conf" "net.ipv4.tcp_sack" "1"
append_sysctl_kv "$conf" "net.ipv4.tcp_keepalive_time" "600"
append_sysctl_kv "$conf" "net.ipv4.tcp_keepalive_intvl" "60"
append_sysctl_kv "$conf" "net.ipv4.tcp_keepalive_probes" "5"

{
  echo
  echo "# --- Kernel hardening (умеренно) --- #"
} >>"$conf"
append_sysctl_kv "$conf" "kernel.yama.ptrace_scope" "1"
append_sysctl_kv "$conf" "kernel.randomize_va_space" "2"
append_sysctl_kv "$conf" "fs.suid_dumpable" "0"

{
  echo
  echo "# --- Filesystem & Memory --- #"
} >>"$conf"
append_sysctl_kv "$conf" "fs.file-max" "2097152"
append_sysctl_kv "$conf" "vm.swappiness" "10"

# apply only our file (not whole sysctl --system)
sysctl --load "$conf" >/dev/null 2>&1 || log "⚠️ sysctl --load had warnings; continuing (unsupported keys were skipped)."

# tcp_low_latency: на многих ядрах либо отсутствует, либо бесполезен.
# Включаем только если параметр реально существует.
if sysctl -a 2>/dev/null | grep -q '^net\.ipv4\.tcp_low_latency'; then
  sysctl -w net.ipv4.tcp_low_latency=1 >/dev/null || true
fi

# --- Apply qdisc to interface (best-effort) --- #
log "⚙️ Applying qdisc to $iface..."
tc qdisc replace dev "$iface" root fq >/dev/null 2>&1 || log "⚠️ Failed to set 'fq' on $iface (maybe unsupported)."
log

# --- Install BBR3 (external installer) --- #
# Можно отключить: SKIP_BBR3=1 ./script.sh
if [[ "${SKIP_BBR3:-0}" == "1" ]]; then
  log "⏭️ SKIP_BBR3=1 set, skipping BBR3 installer."
else
  log "⚙️ Installing BBR3 (external script)..."
  TMP_BBR_SCRIPT="/tmp/install_bbr3.sh"
  BBR3_URL="${BBR3_URL:-https://raw.githubusercontent.com/XDflight/bbr3-debs/refs/heads/build/install_latest.sh}"

  wget -q -O "$TMP_BBR_SCRIPT" "$BBR3_URL" || die "Failed to download BBR3 installer. Check URL/network."
  chmod +x "$TMP_BBR_SCRIPT"
  bash "$TMP_BBR_SCRIPT"
  log
fi

# --- Pick congestion control: prefer bbr3 if available --- #
# try module load quietly
modprobe tcp_bbr3 >/dev/null 2>&1 || true
available_cc="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "")"

cc_target=""
if echo " $available_cc " | grep -q " bbr3 "; then
  cc_target="bbr3"
elif echo " $available_cc " | grep -q " bbr2 "; then
  cc_target="bbr2"
elif echo " $available_cc " | grep -q " bbr "; then
  cc_target="bbr"
fi

if [[ -n "$cc_target" ]]; then
  sysctl -w "net.ipv4.tcp_congestion_control=$cc_target" >/dev/null || true
fi

# --- Final verification --- #
log "🔍 Final verification:"
log "--------------------------------------------"

cc_value="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")"
avail_cc_now="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "unknown")"
qdisc_default="$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")"
qdisc_iface="$(tc qdisc show dev "$iface" 2>/dev/null | head -n 1 || echo "unknown")"
tfo_value="$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo "unknown")"
ecn_value="$(sysctl -n net.ipv4.tcp_ecn 2>/dev/null || echo "unknown")"

rmem_max="$(sysctl -n net.core.rmem_max 2>/dev/null || echo "unknown")"
wmem_max="$(sysctl -n net.core.wmem_max 2>/dev/null || echo "unknown")"
tcp_rmem="$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null || echo "unknown")"
tcp_wmem="$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null || echo "unknown")"
low_lat="$(sysctl -n net.ipv4.tcp_low_latency 2>/dev/null || echo "n/a")"

log "✅ Network settings:"
log "├─ Congestion control: $cc_value"
log "├─ Available CC:       $avail_cc_now"
log "├─ Default qdisc:      $qdisc_default"
log "├─ Iface qdisc:        $qdisc_iface"
log "├─ TCP Fast Open:      $tfo_value"
log "├─ ECN:                $ecn_value"
log "└─ Kernel version:     $krn_version"
log
log "📦 Buffers:"
log "├─ rmem_max:    $rmem_max"
log "├─ wmem_max:    $wmem_max"
log "├─ tcp_rmem:    $tcp_rmem"
log "├─ tcp_wmem:    $tcp_wmem"
log "└─ low_latency: $low_lat"

if [[ -n "${bak:-}" ]]; then
  log
  log "🧾 Backup: $bak"
fi

log
log "============================================"
log "            ✨ Done."
log "============================================"
