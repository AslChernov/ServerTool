#!/usr/bin/env bash
set -Eeuo pipefail

TEST_ROOT=$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/server-tool-ports.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/etc" "$work/backups" "$work/cache"

# Redirect all writable system paths before sourcing the real functions.
sed -e "s|readonly CONFIG_DIR=\"/etc/server-tool\"|readonly CONFIG_DIR=\"$work/etc\"|" \
    -e "s|readonly BACKUP_ROOT=\"/var/backups/server-tool\"|readonly BACKUP_ROOT=\"$work/backups\"|" \
    -e "s|readonly GUARD_UPDATER=\"/usr/local/sbin/server-tool-guard-update\"|readonly GUARD_UPDATER=\"$work/updater\"|" \
    "$TEST_ROOT/server_tool.sh" > "$work/source.sh"
# shellcheck disable=SC1091
source "$work/source.sh"
require_root() { :; }
log() { :; }
if ! command -v chmod >/dev/null; then chmod() { :; }; fi
if ! command -v install >/dev/null; then install() { cp "$3" "$4"; }; fi
if ! command -v python3 >/dev/null; then python3() { return 0; }; export -f python3; fi
if ! command -v bash >/dev/null; then
    TEST_BASH=$BASH
    export TEST_BASH
    bash() { "$TEST_BASH" "$@"; }
    export -f bash
fi

# Retain the actual generator; only filesystem paths are changed for tests.
eval "$(declare -f write_guard_updater | sed '1s/write_guard_updater/test_original_writer/')"
# The sourced change_guard_port function also calls this with explicit paths.
# shellcheck disable=SC2120
write_guard_updater() {
    local target="${1:-$GUARD_UPDATER}"
    test_original_writer "$@"
    sed -i -e "s|CACHE=/var/lib/server-tool/blocklist-v4.txt|CACHE=$work/cache/list|" \
        -e "s|mkdir -p /var/lib/server-tool|mkdir -p '$work/cache'|" \
        -e "s|/run/server-tool-guard.XXXXXX|$work/rules.XXXXXX|" "$target"
}

export NFT_TEST_DIR="$work"
export NFT_FAIL_CHECK=0 NFT_FAIL_APPLY_ONCE=0
nft() {
    case "$1" in
        list) return 0 ;;
        --check)
            [[ $NFT_FAIL_CHECK == 0 ]] || return 1
            cp "$3" "$NFT_TEST_DIR/checked.nft"
            ;;
        --file)
            if [[ $NFT_FAIL_APPLY_ONCE == 1 && ! -f $NFT_TEST_DIR/failed-once ]]; then
                touch "$NFT_TEST_DIR/failed-once"
                return 1
            fi
            cp "$2" "$NFT_TEST_DIR/applied.nft"
            ;;
        *) return 1 ;;
    esac
}
curl() { return 22; } # Refresh tests must never access the network.
export -f nft curl

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
equal() { [[ $1 == "$2" ]] || fail "$3: expected [$1], got [$2]"; }
base_config() {
    cat > "$GUARD_CONFIG" <<'EOF'
SSH_PORT="34464"
NODE_PORT="2222"
PANEL_IPV4="192.0.2.1"
HTTPS_MODE="tcp"
BLOCKLIST_URLS=()
GEO_COUNTRIES=""
# Preserve this operator comment.
EOF
    write_guard_updater
}

equal '' "$(normalize_guard_ports '')" 'empty list'
equal '80 8443 65535' "$(normalize_guard_ports $'00080,8443\t8443\n65535')" 'normalization'
for bad in 0 65536 -1 abc '80;443' '80-90' '99999999999999999999999'; do
    if normalize_guard_ports "$bad" >/dev/null 2>&1; then fail "accepted invalid port $bad"; fi
done
base_config
bash "$GUARD_UPDATER" --check
equal '' "$(read_guard_extra_ports tcp)" 'legacy config without extra fields'

change_guard_port add tcp 8443
equal 8443 "$(read_guard_extra_ports tcp)" 'TCP add'
equal '' "$(read_guard_extra_ports udp)" 'TCP add must not open UDP'
grep -Fq '# Preserve this operator comment.' "$GUARD_CONFIG" || fail 'operator config lost'
grep -Fq 'tcp dport 34464 counter accept' "$work/applied.nft" || fail 'SSH changed'
grep -Fq 'ip saddr @panel_v4 tcp dport 2222 counter accept' "$work/applied.nft" || fail 'API restriction lost'
grep -Fq 'ct original proto-dst @extra_tcp_ports' "$work/applied.nft" || fail 'Docker original-port rule missing'
grep -Fq 'meta nfproto ipv4 udp dport @extra_udp_ports' "$work/applied.nft" || fail 'IPv4-only UDP rule missing'
input_block=$(awk '/ip saddr @blocked_v4 counter drop/ {print NR; exit}' "$work/applied.nft")
input_extra=$(awk '/tcp dport @extra_tcp_ports/ {print NR; exit}' "$work/applied.nft")
forward_api_block=$(awk '/tcp dport 2222 counter drop/ {print NR; exit}' "$work/applied.nft")
forward_extra=$(awk '/ct original proto-dst @extra_tcp_ports/ {print NR; exit}' "$work/applied.nft")
((input_block < input_extra && forward_api_block < forward_extra)) || fail 'extra ports bypass an earlier block'
if grep -Eq 'flush ruleset|table ip crowdsec|table ip6 crowdsec' "$work/applied.nft"; then fail 'unrelated table changed'; fi

change_guard_port add tcp 08443
equal 8443 "$(read_guard_extra_ports tcp)" 'duplicate add'
change_guard_port add udp 5353
change_guard_port add both 9443
equal '8443 9443' "$(read_guard_extra_ports tcp)" 'both adds TCP'
equal '5353 9443' "$(read_guard_extra_ports udp)" 'both adds UDP'
change_guard_port remove tcp 8443
change_guard_port remove both 9443
equal '' "$(read_guard_extra_ports tcp)" 'TCP remove'
equal 5353 "$(read_guard_extra_ports udp)" 'UDP unaffected by TCP remove'

for reserved in 2222 34464 443; do
    before=$(< "$GUARD_CONFIG")
    if change_guard_port add both "$reserved" >/dev/null 2>&1; then fail "reserved port $reserved exposed"; fi
    equal "$before" "$(< "$GUARD_CONFIG")" 'reserved-port rejection is non-mutating'
done
change_guard_port add tcp 8443
write_guard_config 34464 2222 192.0.2.1 tcp
equal 8443 "$(read_guard_extra_ports tcp)" 'reconfigure preserves TCP'
equal 5353 "$(read_guard_extra_ports udp)" 'reconfigure preserves UDP'
bash "$GUARD_UPDATER" --apply
bash "$GUARD_UPDATER" --refresh
grep -Fq 'elements = { 8443 }' "$work/applied.nft" || fail 'refresh lost the extra port'

for failure in CHECK APPLY_ONCE; do
    before_config=$(< "$GUARD_CONFIG")
    before_updater=$(< "$GUARD_UPDATER")
    export "NFT_FAIL_${failure}=1"
    if change_guard_port add tcp 10443 >/dev/null 2>&1; then fail "$failure should reject the change"; fi
    export "NFT_FAIL_${failure}=0"
    equal "$before_config" "$(< "$GUARD_CONFIG")" "$failure restores config"
    equal "$before_updater" "$(< "$GUARD_UPDATER")" "$failure restores updater"
done

base_config
guard_ports_menu <<< $'1\n8443\n1\ny\n\n0' >/dev/null
equal 8443 "$(read_guard_extra_ports tcp)" 'menu opens TCP 8443'
printf 'PASS: custom ports, legacy configs, menu, persistence, rule ordering and rollback\n'
