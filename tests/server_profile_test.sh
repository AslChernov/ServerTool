#!/usr/bin/env bash
set -Eeuo pipefail

TEST_ROOT=$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/server-tool-profile.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/etc" "$work/backups" "$work/units"
sed -e "s|readonly CONFIG_DIR=\"/etc/server-tool\"|readonly CONFIG_DIR=\"$work/etc\"|" \
    -e "s|readonly BACKUP_ROOT=\"/var/backups/server-tool\"|readonly BACKUP_ROOT=\"$work/backups\"|" \
    -e "s|readonly GUARD_UPDATER=\"/usr/local/sbin/server-tool-guard-update\"|readonly GUARD_UPDATER=\"$work/updater\"|" \
    -e "s|/etc/systemd/system/server-tool-guard|$work/units/server-tool-guard|g" \
    -e "s|/etc/crowdsec/acquis.d|$work/acquis.d|g" \
    "$TEST_ROOT/server_tool.sh" > "$work/source.sh"
# shellcheck disable=SC1091
source "$work/source.sh"
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
require_root() { :; }
log() { :; }
show_disk_usage() { :; }
package_disk_ready() { :; }
original_confirm=$(declare -f confirm)
if ! command -v chmod >/dev/null; then chmod() { :; }; fi
if ! command -v bash >/dev/null; then bash() { "$BASH" "$@"; }; export -f bash; fi

SERVER_ROLE=server
load_server_profile
[[ $SERVER_ROLE == node ]] || fail 'legacy installs must default to node'
[[ $(choose_server_profile <<< 2) == server ]] || fail 'universal profile choice failed'
if choose_server_profile <<< 0 >/dev/null; then fail 'cancelled profile choice succeeded'; fi
confirm() { [[ $1 == 'Запустить полный мастер?' ]]; }
install_xanmod() { fail 'universal wizard offered a kernel replacement'; }
full_setup <<< 2 >/dev/null
[[ $SERVER_ROLE == server && $(< "$PROFILE_FILE") == server ]] || fail 'wizard did not save profile'
SERVER_ROLE=node
load_server_profile
[[ $SERVER_ROLE == server ]] || fail 'saved profile did not load'
printf 'invalid\n' > "$PROFILE_FILE"
if load_server_profile >/dev/null 2>&1; then fail 'invalid profile accepted'; fi
[[ ! -e $GUARD_CONFIG ]] || fail 'profile selection unexpectedly installed firewall'

SERVER_ROLE=server
configure_crowdsec_acquisition <<< 1 >/dev/null
[[ ! -e $CROWDSEC_ACQUIS ]] || fail 'SSH-only mode configured Nginx'
write_crowdsec_bouncer_override 18080 test-key "$work/bouncer.yaml"
grep -Fqx 'disable_ipv6: false' "$work/bouncer.yaml" || fail 'universal bouncer does not protect IPv6'

export PROFILE_TEST_DIR="$work"
systemctl() {
    local IFS=' '
    case "$1" in
        is-active|is-enabled) return 1 ;;
        *) printf '%s\n' "$*" >> "$PROFILE_TEST_DIR/systemctl-calls" ;;
    esac
}
systemd-run() { local IFS=' '; printf '%s\n' "$*" >> "$PROFILE_TEST_DIR/rollback-timers"; }
flock() { :; }
nft() {
    case "$1" in
        list) printf 'table inet server_tool_guard { chain input { } }\n' ;;
        --check) grep -q 'table inet server_tool_guard' "$3" ;;
        --file) cp "$2" "$PROFILE_TEST_DIR/restored.nft" ;;
        *) return 1 ;;
    esac
}
export -f systemctl systemd-run flock nft
printf 'old config\n' > "$GUARD_CONFIG"
printf 'old updater\n' > "$GUARD_UPDATER"
mkdir -p "$work/rollback"
prepare_firewall_rollback "$work/rollback" no
bash -n "$work/rollback/rollback.sh"
printf 'new config\n' > "$GUARD_CONFIG"
printf 'new updater\n' > "$GUARD_UPDATER"
printf 'new unit\n' > "$GUARD_SERVICE"
bash "$work/rollback/rollback.sh"
[[ $(< "$GUARD_CONFIG") == 'old config' ]] || fail 'rollback did not restore config'
[[ $(< "$GUARD_UPDATER") == 'old updater' ]] || fail 'rollback did not restore updater'
[[ ! -e $GUARD_SERVICE ]] || fail 'rollback retained a newly created unit'
[[ -e $work/rollback/rollback-completed ]] || fail 'rollback completion missing'
if grep -Eq 'flush ruleset|table ip crowdsec|table ip6 crowdsec' "$work/restored.nft"; then fail 'rollback touched unrelated firewall tables'; fi
bash "$work/rollback/rollback.sh"

eval "$original_confirm"
ensure_packages() { :; }
detect_ssh_port() { printf '34464\n'; }
ss() { :; }
ufw() { return 1; }
install_guard_runtime() {
    [[ ${FAIL_INSTALL:-no} != yes ]] || return 1
    printf 'new updater\n' > "$GUARD_UPDATER"
}
unset SSH_CONNECTION
printf 'SERVER_ROLE="server"\nSSH_PORT="34464"\nEXTRA_TCP_PORTS=""\nEXTRA_UDP_PORTS=""\n' > "$GUARD_CONFIG"
before=$(< "$GUARD_CONFIG")
if configure_firewall <<< $'80 443\n\n-\nn\n\nn\ny\nno' >/dev/null 2>&1; then
    fail 'unconfirmed firewall was accepted'
fi
[[ $(< "$GUARD_CONFIG") == "$before" ]] || fail 'unconfirmed firewall was not rolled back'
configure_firewall <<< $'80 443\n\n-\nn\n\nn\ny\nyes' >/dev/null
grep -Fqx 'SERVER_ROLE="server"' "$GUARD_CONFIG" || fail 'confirmed server profile missing'
grep -Fqx 'EXTRA_TCP_PORTS="80 443"' "$GUARD_CONFIG" || fail 'confirmed ports missing'
grep -Fq -- '--on-active=5min' "$work/rollback-timers" || fail 'rollback timer not scheduled'
before=$(< "$GUARD_CONFIG")
FAIL_INSTALL=yes
if configure_firewall <<< $'80 443\n\n-\nn\n\nn\ny' >/dev/null 2>&1; then fail 'failed firewall installation accepted'; fi
[[ $(< "$GUARD_CONFIG") == "$before" ]] || fail 'failed installation did not restore previous config'
printf 'PASS: wizard profiles, persistence, SSH-only CrowdSec and idempotent firewall rollback\n'
