#!/usr/bin/env bash

set -Eeuo pipefail

readonly TEST_DIR=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)
readonly REPO_ROOT=$(cd -- "${TEST_DIR}/.." && pwd)

# Sourcing the script is safe because its main entry point is guarded.
# shellcheck disable=SC1091
source "${REPO_ROOT}/server_tool.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

OCCUPIED_PORTS=""

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_equal() {
    local expected="$1" actual="$2" label="$3"
    [[ $actual == "$expected" ]] || fail "${label}: expected ${expected}, got ${actual}"
}

crowdsec_port_available() {
    [[ " $OCCUPIED_PORTS " != *" $1 "* ]]
}

# The bundled minimal Windows Bash used by local tests has no chmod binary.
chmod() { :; }

OCCUPIED_PORTS=""
selected=$(select_crowdsec_lapi_port "")
assert_equal 8080 "$selected" 'default port selection'

OCCUPIED_PORTS="8080"
selected=$(select_crowdsec_lapi_port "")
assert_equal 18080 "$selected" 'first fallback selection'

OCCUPIED_PORTS="8080 18080"
selected=$(select_crowdsec_lapi_port "")
assert_equal 18081 "$selected" 'second fallback selection'

OCCUPIED_PORTS=""
selected=$(select_crowdsec_lapi_port 18082)
assert_equal 18082 "$selected" 'persisted port selection'

OCCUPIED_PORTS="8080 18080 18081 18082 18083 18084 18085 18086 18087 18088 18089"
if select_crowdsec_lapi_port "" >/dev/null 2>&1; then
    fail 'selection succeeded when every candidate was occupied'
fi

config_local="${work}/config.yaml.local"
credentials_local="${work}/local_api_credentials.yaml.local"
write_crowdsec_lapi_overrides 18080 "$config_local" "$credentials_local"
grep -Fqx "$CROWDSEC_MANAGED_MARKER" "$config_local" || fail 'config marker is missing'
grep -Fqx '    listen_uri: 127.0.0.1:18080' "$config_local" || fail 'LAPI listen URI is wrong'
grep -Fqx 'url: http://127.0.0.1:18080/' "$credentials_local" || fail 'LAPI client URL is wrong'

write_crowdsec_lapi_overrides 18081 "$config_local" "$credentials_local"
grep -Fqx '    listen_uri: 127.0.0.1:18081' "$config_local" || fail 'managed config was not updated'
grep -Fqx 'url: http://127.0.0.1:18081/' "$credentials_local" || fail 'managed credentials were not updated'

custom_config="${work}/custom-config.yaml.local"
custom_credentials="${work}/custom-credentials.yaml.local"
printf 'api:\n  server:\n    listen_uri: 127.0.0.1:19000\n' > "$custom_config"
if write_crowdsec_lapi_overrides 18080 "$custom_config" "$custom_credentials" >/dev/null 2>&1; then
    fail 'unmanaged local override was overwritten'
fi
grep -Fqx '    listen_uri: 127.0.0.1:19000' "$custom_config" || fail 'custom config changed'
[[ ! -e $custom_credentials ]] || fail 'credentials were written after custom-config rejection'

fresh_bouncer="${work}/fresh-bouncer.yaml.local"
sync_crowdsec_bouncer_lapi_url 18080 "$fresh_bouncer"
grep -Fqx "$CROWDSEC_MANAGED_MARKER" "$fresh_bouncer" || fail 'fresh bouncer marker is missing'
grep -Fqx 'api_url: http://127.0.0.1:18080/' "$fresh_bouncer" || fail 'fresh bouncer URL is wrong'

managed_bouncer="${work}/managed-bouncer.yaml.local"
cat > "$managed_bouncer" <<EOF
${CROWDSEC_MANAGED_MARKER}
api_url: http://127.0.0.1:8080/
api_key: "managed-secret"
EOF
sync_crowdsec_bouncer_lapi_url 18080 "$managed_bouncer"
grep -Fqx 'api_url: http://127.0.0.1:18080/' "$managed_bouncer" || fail 'managed bouncer URL was not updated'
grep -Fqx 'api_key: "managed-secret"' "$managed_bouncer" || fail 'managed bouncer API key changed'

legacy_bouncer="${work}/legacy-bouncer.yaml.local"
cat > "$legacy_bouncer" <<'EOF'
api_url: http://127.0.0.1:8080/
api_key: "legacy-secret"
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
sync_crowdsec_bouncer_lapi_url 18080 "$legacy_bouncer"
grep -Fqx "$CROWDSEC_MANAGED_MARKER" "$legacy_bouncer" || fail 'legacy bouncer was not adopted as managed'
grep -Fqx 'api_url: http://127.0.0.1:18080/' "$legacy_bouncer" || fail 'legacy bouncer URL was not updated'
grep -Fqx 'api_key: "legacy-secret"' "$legacy_bouncer" || fail 'legacy bouncer API key changed'

custom_bouncer="${work}/custom-bouncer.yaml.local"
printf 'api_url: http://127.0.0.1:19000/\ncustom_option: true\n' > "$custom_bouncer"
if sync_crowdsec_bouncer_lapi_url 18080 "$custom_bouncer" >/dev/null 2>&1; then
    fail 'custom bouncer override was overwritten'
fi
grep -Fqx 'api_url: http://127.0.0.1:19000/' "$custom_bouncer" || fail 'custom bouncer URL changed'

generated_bouncer="${work}/generated-bouncer.yaml.local"
write_crowdsec_bouncer_override 18080 'generated-secret' "$generated_bouncer"
grep -Fqx 'api_url: http://127.0.0.1:18080/' "$generated_bouncer" || fail 'generated bouncer URL is wrong'
grep -Fqx 'api_key: "generated-secret"' "$generated_bouncer" || fail 'generated bouncer API key is wrong'
grep -A2 '^nftables_hooks:' "$generated_bouncer" | grep -Fqx '  - input' || fail 'generated bouncer input hook is missing'
grep -A2 '^nftables_hooks:' "$generated_bouncer" | grep -Fqx '  - forward' || fail 'generated bouncer forward hook is missing'

printf 'PASS: CrowdSec LAPI port and override behavior\n'
