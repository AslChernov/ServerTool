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
curl() { printf 'called\n' >> "$NFT_TEST_DIR/curl-calls"; return 22; }
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

export SERVER_ROLE=server
write_guard_config 34464 '' '' none '80 443' '443' '192.0.2.10 2001:db8::10' yes no \
    'tcp|9090|192.0.2.0/24' 'tcp|9090|2001:db8:1::/48'
write_guard_updater
: > "$work/curl-calls"
bash "$GUARD_UPDATER" --refresh
[[ ! -s $work/curl-calls ]] || fail 'disabled server blocklists were downloaded'
if grep -Eq 'panel_v4|dport 2222' "$work/applied.nft"; then fail 'server profile contains node API rules'; fi
grep -Fq 'ip saddr 192.0.2.10/32 tcp dport 34464 counter accept' "$work/applied.nft" || fail 'restricted IPv4 SSH missing'
grep -Fq 'ip6 saddr 2001:db8::10/128 tcp dport 34464 counter accept' "$work/applied.nft" || fail 'restricted IPv6 SSH missing'
if grep -Fq 'meta nfproto ipv4 tcp dport 34464 counter accept' "$work/applied.nft"; then fail 'SSH restriction bypassed'; fi
grep -Eq '^ +tcp dport @extra_tcp_ports counter accept$' "$work/applied.nft" || fail 'dual-stack public TCP rule missing'
grep -Fq 'ip6 saddr 2001:db8:1::/48 meta l4proto tcp ct original proto-dst 9090 counter accept' "$work/applied.nft" || fail 'restricted IPv6 Docker rule missing'
before=$(< "$GUARD_CONFIG")
if change_guard_port add tcp 9090 >/dev/null 2>&1; then fail 'restricted port became public'; fi
equal "$before" "$(< "$GUARD_CONFIG")" 'access-conflict rejection restores config'
change_guard_port add tcp 2222
equal '80 443 2222' "$(read_guard_extra_ports tcp)" 'universal profile does not reserve node API port'

for bad_rule in 'tcp|34464|192.0.2.1' 'tcp|80|192.0.2.1' 'icmp|9000|192.0.2.1' 'tcp|9000|192.0.2.1; flush ruleset'; do
    write_guard_config 34464 '' '' none '80 443' '' '' yes no "$bad_rule"
    if bash "$GUARD_UPDATER" --check >/dev/null 2>&1; then fail "accepted unsafe access rule: $bad_rule"; fi
done
write_guard_config 34464 '' '' none '' '' '2001:db8::10' no no
if bash "$GUARD_UPDATER" --check >/dev/null 2>&1; then fail 'IPv6 SSH allowed with IPv6 disabled'; fi

base_config
bash "$GUARD_UPDATER" --check
grep -Fq 'ip saddr @panel_v4 tcp dport 2222 counter accept' "$work/checked.nft" || fail 'legacy config inherited caller server role'
printf 'PASS: custom ports, legacy configs, menu, persistence, rule ordering and rollback\n'
printf 'PASS: universal profile, IPv6, restricted access, disabled feeds and invalid rules\n'

SERVER_ROLE=node
CLIENT_SOURCES_TO_WRITE='192.0.2.8/29 198.51.100.1' GOVIPS_MODE_TO_WRITE=monitor \
    write_guard_config 34464 2222 192.0.2.1 both '9443' '' '192.0.2.4' no yes \
        'tcp|8443|203.0.113.0/24'
write_guard_updater
bash "$GUARD_UPDATER" --apply
active="$work/applied.nft"
grep -Fq 'elements = { 192.0.2.8/29, 198.51.100.1/32 }' "$active" || fail 'trusted 443 sources missing'
grep -Fq 'ip saddr @node_clients_v4 tcp dport 443 counter accept' "$active" || fail 'trusted host TCP 443 rule missing'
grep -Fq 'ct status dnat ip saddr @node_clients_v4 meta l4proto udp ct original proto-dst 443 counter accept' "$active" || fail 'trusted Docker UDP 443 rule missing'
grep -Fq 'ct status dnat ip saddr 203.0.113.0/24 meta l4proto tcp ct original proto-dst 8443 counter accept' "$active" || fail 'restricted node port missing'
grep -Fq 'ip saddr 192.0.2.4/32 tcp dport 34464 counter accept' "$active" || fail 'restricted node SSH missing'
if grep -Eq 'tcp dport 443 jump|proto-dst 443 jump|meta nfproto ipv4 tcp dport 34464 counter accept' "$active"; then fail 'trusted-only service has a public rule'; fi
grep -Fq 'ct state new ip saddr @govips_v4 counter comment "GOVIPS monitor"' "$active" || fail 'GOVIPS monitor blocks or counts unrelated traffic'
grep -Fq 'ct status dnat meta nfproto ipv4 meta l4proto tcp ct original proto-dst @extra_tcp_ports jump public_node' "$active" || fail 'Docker policy is not scoped to published ports'
if change_guard_port add tcp 8443 >/dev/null 2>&1; then fail 'restricted node port became public'; fi

cat >> "$GUARD_CONFIG" <<'EOF'
BLOCKLIST_URLS=("https://test.invalid/anti" "https://test.invalid/government")
GOVIPS_MODE=block
EOF
curl() {
    local output='' url=${*: -1:1}
    while (($#)); do
        if [[ $1 == -o ]]; then output=$2; break; fi
        shift
    done
    case "$url" in
        */anti)
            if [[ ${MOCK_ROUND:-1} == 1 ]]; then printf '8.8.8.8\n' > "$output";
            else printf '8.8.8.9\n' > "$output"; fi ;;
        */government)
            [[ ${MOCK_ROUND:-1} == 1 ]] || return 22
            printf '9.9.9.9\n' > "$output" ;;
        */blacklist-v4.txt)
            if [[ ${MOCK_ROUND:-1} == 1 ]]; then printf '1.1.1.1\n' > "$output";
            else printf '1.0.0.0/8\n' > "$output"; fi ;;
        *) return 22 ;;
    esac
}
export -f curl
bash "$GUARD_UPDATER" --refresh
grep -Fq 'ct state new ip saddr @govips_v4 counter drop comment "GOVIPS block"' "$active" || fail 'GOVIPS blocking rule missing'
equal '1.1.1.1/32' "$(< "$work/cache/list.govips")" 'first GOVIPS refresh'
export MOCK_ROUND=2 NFT_FAIL_CHECK=1
before=$(< "$work/cache/list.sources.json")
if bash "$GUARD_UPDATER" --refresh >/dev/null 2>&1; then fail 'invalid nft rules applied'; fi
equal "$before" "$(< "$work/cache/list.sources.json")" 'failed nft check preserves the source snapshots'
grep -Fq '8.8.8.8/32' "$work/cache/list" || fail 'failed nft check changed the persisted ruleset input'
export NFT_FAIL_CHECK=0
bash "$GUARD_UPDATER" --refresh
grep -Fq '8.8.8.9/32' "$work/cache/list" || fail 'healthy source did not update independently'
grep -Fq '9.9.9.9/32' "$work/cache/list" || fail 'failed source was dropped'
equal '1.1.1.1/32' "$(< "$work/cache/list.govips")" 'coverage limit rejected a one-line /8 expansion'
printf 'PASS: node allowlists, scoped GOVIPS, independent source refresh and rollback of invalid candidate\n'
