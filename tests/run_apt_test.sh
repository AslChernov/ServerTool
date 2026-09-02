#!/usr/bin/env bash

set -Eeuo pipefail

readonly TEST_DIR=$(cd -- "${BASH_SOURCE[0]%/*}" && pwd)
readonly REPO_ROOT=$(cd -- "${TEST_DIR}/.." && pwd)

# Sourcing the script is safe because its main entry point is guarded.
# shellcheck disable=SC1091
source "${REPO_ROOT}/server_tool.sh"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

export APT_TEST_COUNT_FILE="${work}/count"
export DPKG_TEST_COUNT_FILE="${work}/dpkg-count"
export CROWDSEC_PREP_COUNT_FILE="${work}/crowdsec-prep-count"
export CROWDSEC_SYNC_COUNT_FILE="${work}/crowdsec-sync-count"
export CROWDSEC_WAIT_COUNT_FILE="${work}/crowdsec-wait-count"
APT_TEST_MODE=

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

reset_calls() {
    printf '0\n' > "$APT_TEST_COUNT_FILE"
    printf '0\n' > "$DPKG_TEST_COUNT_FILE"
    printf '0\n' > "$CROWDSEC_PREP_COUNT_FILE"
    printf '0\n' > "$CROWDSEC_SYNC_COUNT_FILE"
    printf '0\n' > "$CROWDSEC_WAIT_COUNT_FILE"
}

call_count() {
    local count
    read -r count < "$APT_TEST_COUNT_FILE"
    printf '%s\n' "$count"
}

apt-get() {
    local count package
    count=$(call_count)
    count=$((count + 1))
    printf '%s\n' "$count" > "$APT_TEST_COUNT_FILE"

    case "$APT_TEST_MODE" in
        success)
            printf 'APT completed\n'
            ;;
        lock_then_success)
            if ((count == 1)); then
                printf '%s\n' \
                    'E: Could not get lock /var/lib/apt/lists/lock. It is held by process 42 (apt-get)' \
                    'E: Unable to lock directory /var/lib/apt/lists/' >&2
                return 100
            fi
            printf 'APT completed after retry\n'
            ;;
        repository_error)
            printf 'E: The repository is not signed.\n' >&2
            return 100
            ;;
        dpkg_then_success|crowdsec_dpkg_then_success)
            if ((count == 1)); then
                package=broken-package
                [[ $APT_TEST_MODE != crowdsec_dpkg_then_success ]] || package=crowdsec
                printf '%s\n' \
                    'Setting up crowdsec (1.7.0) completed earlier in this transaction.' \
                    'Errors were encountered while processing:' \
                    " ${package}" \
                    'E: Sub-process /usr/bin/dpkg returned an error code (1)' >&2
                return 100
            fi
            printf 'APT completed after dpkg recovery\n'
            ;;
        persistent_dpkg_error)
            printf '%s\n' \
                'dpkg: error processing package broken-package (--configure):' \
                ' installed broken-package package post-installation script subprocess returned error exit status 1' \
                'E: Sub-process /usr/bin/dpkg returned an error code (1)' >&2
            return 100
            ;;
        *)
            fail "unknown APT_TEST_MODE: $APT_TEST_MODE"
            ;;
    esac
}

dpkg() {
    local count
    read -r count < "$DPKG_TEST_COUNT_FILE"
    count=$((count + 1))
    printf '%s\n' "$count" > "$DPKG_TEST_COUNT_FILE"
    [[ $APT_TEST_MODE != persistent_dpkg_error ]]
}

systemctl() { :; }

sync_crowdsec_bouncer_lapi_url() {
    local count
    read -r count < "$CROWDSEC_SYNC_COUNT_FILE"
    printf '%s\n' "$((count + 1))" > "$CROWDSEC_SYNC_COUNT_FILE"
}

wait_for_crowdsec_lapi() {
    local count
    read -r count < "$CROWDSEC_WAIT_COUNT_FILE"
    printf '%s\n' "$((count + 1))" > "$CROWDSEC_WAIT_COUNT_FILE"
}

prepare_crowdsec_lapi() {
    local count
    read -r count < "$CROWDSEC_PREP_COUNT_FILE"
    count=$((count + 1))
    printf '%s\n' "$count" > "$CROWDSEC_PREP_COUNT_FILE"
    printf '18080\n'
}

# Keep the test self-contained in minimal Bash environments.
tee() {
    local output_file="$1" line
    : > "$output_file"
    while IFS= read -r line || [[ -n $line ]]; do
        printf '%s\n' "$line"
        printf '%s\n' "$line" >> "$output_file"
    done
}

# Avoid making the lock-retry test wait five real seconds.
sleep() { :; }

APT_TEST_MODE=success
reset_calls
run_apt update >/dev/null
[[ $(call_count) == 1 ]] || fail 'successful APT command was not called exactly once'

APT_TEST_MODE=lock_then_success
reset_calls
lock_output=$(run_apt update 2>&1) || fail 'APT lock was not retried successfully'
[[ $(call_count) == 2 ]] || fail 'APT lock did not cause exactly one retry'
[[ $lock_output == *'APT занят другим процессом'* ]] || fail 'lock retry warning was not shown'

APT_TEST_MODE=repository_error
reset_calls
if run_apt update >/dev/null 2>&1; then
    fail 'non-lock APT error unexpectedly succeeded'
else
    status=$?
fi
[[ $status == 100 ]] || fail "non-lock APT status changed to $status"
[[ $(call_count) == 1 ]] || fail 'non-lock APT error was retried'

APT_TEST_MODE=dpkg_then_success
reset_calls
recovery_output=$(run_apt full-upgrade -y 2>&1) || fail 'recoverable dpkg error was not repaired'
[[ $(call_count) == 3 ]] || fail 'dpkg recovery did not run fix-broken and retry the original command'
read -r dpkg_count < "$DPKG_TEST_COUNT_FILE"
[[ $dpkg_count == 1 ]] || fail 'dpkg --configure --pending was not called exactly once'
[[ $recovery_output == *'Состояние APT/dpkg восстановлено'* ]] || fail 'dpkg recovery success was not shown'
read -r crowdsec_prep_count < "$CROWDSEC_PREP_COUNT_FILE"
[[ $crowdsec_prep_count == 0 ]] || fail 'unrelated package failure incorrectly triggered CrowdSec recovery'

APT_TEST_MODE=crowdsec_dpkg_then_success
reset_calls
run_apt full-upgrade -y >/dev/null 2>&1 || fail 'CrowdSec dpkg error was not repaired'
read -r crowdsec_prep_count < "$CROWDSEC_PREP_COUNT_FILE"
[[ $crowdsec_prep_count == 1 ]] || fail 'CrowdSec recovery context was not prepared exactly once'
read -r crowdsec_sync_count < "$CROWDSEC_SYNC_COUNT_FILE"
[[ $crowdsec_sync_count == 1 ]] || fail 'CrowdSec bouncer URL was not synchronized exactly once'
read -r crowdsec_wait_count < "$CROWDSEC_WAIT_COUNT_FILE"
[[ $crowdsec_wait_count == 1 ]] || fail 'CrowdSec LAPI readiness was not checked exactly once'

APT_TEST_MODE=persistent_dpkg_error
reset_calls
if run_apt full-upgrade -y >/dev/null 2>&1; then
    fail 'persistent dpkg error unexpectedly succeeded'
else
    status=$?
fi
[[ $status == 100 ]] || fail "persistent dpkg status changed to $status"
[[ $(call_count) == 2 ]] || fail 'persistent dpkg error caused an unexpected retry loop'
read -r dpkg_count < "$DPKG_TEST_COUNT_FILE"
[[ $dpkg_count == 1 ]] || fail 'persistent dpkg recovery ran more than once'

printf 'PASS: run_apt retry behavior\n'
