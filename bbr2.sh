#!/bin/bash

# ============================================================ #
# 🎯 Low-Latency Network Optimizer
#      v1.3.0 (2025) © @SawGoD
# ------------------------------------------------------------ #
# ✓ BBR2 если доступен (иначе BBR1)
# ✓ fq_codel (автоопределение интерфейса)
# ✓ UDP/TCP буферы + backlog
# ✓ TCP Fast Open = 3 (клиент+сервер)
# ✓ Аккуратно: не ломает ip_forward / redirect-сеттинги
# ✓ Совместимо при наличии ядра ≥ 5.4
# ============================================================ #

set -euo pipefail

log() { echo -e "$*"; }
die() { echo -e "❌ $*" >&2; exit 1; }

log "============================================"
log "  🚀 Low-latency optimization started..."
log "============================================"
log

# --- Root check --- #
[[ ${EUID:-999} -eq 0 ]] || die "Please run this script as root."

# --- Prereqs --- #
command -v ip >/dev/null 2>&1 || die "ip command not found (package: iproute2)."
command -v tc >/dev/null 2>&1 || die "tc command not found (package: iproute2)."
command -v sysctl >/dev/null 2>&1 || die "sysctl command not found."

# --- Kernel check (best-effort) --- #
krn_version="$(uname -r 2>/dev/null || echo "unknown")"
krn_major="$(echo "$krn_version" | awk -F. '{print $1}' 2>/dev/null || echo 0)"
krn_minor="$(echo "$krn_version" | awk -F. '{print $2}' 2>/dev/null || echo 0)"
if [[ "$krn_major" -lt 5 ]] || { [[ "$krn_major" -eq 5 ]] && [[ "$krn_minor" -lt 4 ]]; }; then
  log "⚠️ Kernel seems older than 5.4 ($krn_version). Скрипт применит базовые параметры, но BBR2 может быть недоступен."
fi

# --- Detect primary network interface --- #
log "🔍 Detecting network interface..."
iface="$(ip route get 8.8.8.8 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
[[ -n "${iface:-}" ]] || die "Failed to detect network interface."
log "├─ Using interface: $iface"
log

# --- Pick congestion control (BBR2 if possible) --- #
# BBR1 = "bbr" (tcp_bbr), BBR2 = "bbr2" (tcp_bbr2) if kernel has it.
available_cc="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || true)"

# try load modules quietly (works even if built-in / not present)
modprobe tcp_bbr2 >/dev/null 2>&1 || true
modprobe tcp_bbr  >/dev/null 2>&1 || true
available_cc="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "$available_cc")"

cc_target="bbr"
if echo " $available_cc " | grep -q " bbr2 "; then
  cc_target="bbr2"
elif echo " $available_cc " | grep -q " bbr "; then
  cc_target="bbr"
else
  cc_target="" # don't force unknown cc
fi

# --- Sysctl tuning (write file) --- #
log "🔧 Writing system parameters..."
conf="/etc/sysctl.d/99-lowlatency.conf"
bak=""
if [[ -f "$conf" ]]; then
  bak="${conf}.bak.$(date +%Y%m%d_%H%M%S)"
  cp -a "$conf" "$bak"
fi

cat >"$conf" <<EOF
# --- Low latency network tuning --- #

# backlog / listen queue
net.core.netdev_max_backlog = 5000
net.core.somaxconn = 4096

# socket buffers (bytes)
net.core.rmem_max = 2621440
net.core.wmem_max = 2621440
net.ipv4.tcp_rmem = 4096 131072 2621440
net.ipv4.tcp_wmem = 4096 131072 2621440
net.ipv4.udp_rmem_min = 8192
net.ipv4.udp_wmem_min = 8192

# qdisc
net.core.default_qdisc = fq_codel

# congestion control (set by script if available)
EOF

if [[ -n "$cc_target" ]]; then
  echo "net.ipv4.tcp_congestion_control = $cc_target" >>"$conf"
fi

cat >>"$conf" <<'EOF'

# reduce latency under load
net.ipv4.tcp_notsent_lowat = 16384

# TCP Fast Open (client+server). Note: requires app support and kernel support.
net.ipv4.tcp_fastopen = 3

# TCP behavior
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_fin_timeout = 20
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 262144
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_sack = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 5

# Kernel hardening (safe-ish defaults)
kernel.yama.ptrace_scope = 1
kernel.randomize_va_space = 2
fs.suid_dumpable = 0

# Files / VM
fs.file-max = 2097152
vm.swappiness = 10
EOF

# apply only our file (not whole sysctl --system)
sysctl --load "$conf" >/dev/null

# --- Apply fq_codel --- #
log "⚙️ Configuring fq_codel for interface $iface..."
tc qdisc replace dev "$iface" root fq_codel >/dev/null 2>&1 || die "Failed to install fq_codel on $iface."
log

# --- Verification --- #
log "🔍 Final verification:"
log "--------------------------------------------"

cc_value="$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")"
tfo_value="$(sysctl -n net.ipv4.tcp_fastopen 2>/dev/null || echo "unknown")"
qdisc_value="$(tc qdisc show dev "$iface" 2>/dev/null | head -n 1 || echo "unknown")"
avail_cc_now="$(sysctl -n net.ipv4.tcp_available_congestion_control 2>/dev/null || echo "unknown")"

rmem_max="$(sysctl -n net.core.rmem_max 2>/dev/null || echo "unknown")"
wmem_max="$(sysctl -n net.core.wmem_max 2>/dev/null || echo "unknown")"
tcp_rmem="$(sysctl -n net.ipv4.tcp_rmem 2>/dev/null || echo "unknown")"
tcp_wmem="$(sysctl -n net.ipv4.tcp_wmem 2>/dev/null || echo "unknown")"
udp_rmem_min="$(sysctl -n net.ipv4.udp_rmem_min 2>/dev/null || echo "unknown")"
udp_wmem_min="$(sysctl -n net.ipv4.udp_wmem_min 2>/dev/null || echo "unknown")"

log "✅ Network settings:"
log "├─ Congestion control: $cc_value"
log "├─ Available CC:       $avail_cc_now"
log "├─ TCP Fast Open:      $tfo_value"
log "├─ Interface qdisc:    $qdisc_value"
log "└─ Kernel version:     $krn_version"
log
log "📦 Buffers:"
log "├─ rmem_max:     $rmem_max"
log "├─ wmem_max:     $wmem_max"
log "├─ tcp_rmem:     $tcp_rmem"
log "├─ tcp_wmem:     $tcp_wmem"
log "├─ udp_rmem_min: $udp_rmem_min"
log "└─ udp_wmem_min: $udp_wmem_min"

if [[ -n "${bak:-}" ]]; then
  log
  log "🧾 Backup: $bak"
fi

log
log "============================================"
log "            ✨ Done."
log "============================================"
