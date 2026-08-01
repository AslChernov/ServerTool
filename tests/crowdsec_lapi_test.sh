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

printf 'PASS: CrowdSec LAPI port and override behavior\n'
