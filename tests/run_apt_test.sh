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
APT_TEST_MODE=

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

reset_calls() {
    printf '0\n' > "$APT_TEST_COUNT_FILE"
}

call_count() {
    local count
    read -r count < "$APT_TEST_COUNT_FILE"
    printf '%s\n' "$count"
}

apt-get() {
    local count
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
        *)
            fail "unknown APT_TEST_MODE: $APT_TEST_MODE"
            ;;
    esac
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

printf 'PASS: run_apt retry behavior\n'
