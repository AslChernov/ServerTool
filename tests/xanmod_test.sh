#!/usr/bin/env bash
# The installer is sourced first and replaced only for the final wizard tests.
# shellcheck disable=SC2218
set -Eeuo pipefail

TEST_ROOT=$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)
test_work=$(mktemp -d "${TMPDIR:-/tmp}/server-tool-xanmod.XXXXXX")
trap 'rm -rf -- "$test_work"' EXIT
mkdir -p "$test_work/etc" "$test_work/apt" "$test_work/keys" "$test_work/tmp"
export XANMOD_TEST_DIR="$test_work" TMPDIR="$test_work/tmp"
sed -e "s|readonly CONFIG_DIR=\"/etc/server-tool\"|readonly CONFIG_DIR=\"$test_work/etc\"|" \
    -e "s|readonly XANMOD_SOURCE=\"/etc/apt/sources.list.d/xanmod-release.list\"|readonly XANMOD_SOURCE=\"$test_work/apt/xanmod.list\"|" \
    -e "s|readonly XANMOD_KEYRING=\"/etc/apt/keyrings/xanmod-archive-keyring.gpg\"|readonly XANMOD_KEYRING=\"$test_work/keys/xanmod.gpg\"|" \
    "$TEST_ROOT/server_tool.sh" > "$test_work/source.sh"
# shellcheck disable=SC1091
source "$test_work/source.sh"

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
require_root() { :; }
ensure_packages() { :; }
package_disk_ready() { :; }
show_disk_usage() { :; }
log() { :; }
dpkg() { printf 'amd64\n'; }
lsb_release() { printf '%s\n' "${TEST_CODENAME:-resolute}"; }
detect_psabi() { printf 'v3\n'; }
uname() { printf 'stock-kernel\n'; }
if ! command -v chmod >/dev/null; then chmod() { :; }; fi

TEST_MODE=success
reset_fixture() {
    printf 'old key\n' > "$XANMOD_KEYRING"
    printf 'old source\n' > "$XANMOD_SOURCE"
    : > "$XANMOD_TEST_DIR/curl-calls"
    : > "$XANMOD_TEST_DIR/apt-calls"
}
curl() {
    local url="" target="" ipv4=no
    while (($#)); do
        case "$1" in
            --ipv4) ipv4=yes ;;
            -o) shift; target=$1 ;;
            https://*) url=$1 ;;
        esac
        shift
    done
    [[ -n $url && -n $target ]] || fail 'invalid curl arguments'
    printf '%s|%s\n' "$ipv4" "$url" >> "$XANMOD_TEST_DIR/curl-calls"
    if [[ $url == */Release ]]; then
        case "$TEST_MODE" in
            network_failure) printf 'curl: (28) Connection timed out\n' >&2; return 28 ;;
            ipv6_failure)
                if [[ $ipv4 == no ]]; then printf 'curl: (7) Failed to connect\n' >&2; return 7; fi
                ;;
            http_404) printf 'curl: (22) HTTP 404\n' >&2; return 22 ;;
            invalid_metadata) printf '<html>not a repository</html>\n' > "$target"; return 0 ;;
        esac
        printf 'Codename: resolute\nArchitectures: amd64\n' > "$target"
    else
        printf 'test key\n' > "$target"
    fi
}
gpg() {
    local target=""
    local IFS=' '
    if [[ " $* " == *' --show-keys '* ]]; then
        if [[ $TEST_MODE == invalid_key ]]; then
            printf 'fpr:::::::::BADKEY:\n'
        else
            printf 'fpr:::::::::D38D7D1DA1349567ADED882D86F7D09EE734E623:\n'
        fi
        return 0
    fi
    while (($#)); do
        if [[ $1 == -o ]]; then shift; target=$1; fi
        shift
    done
    [[ -n $target ]] || fail 'missing temporary keyring'
    printf 'verified key\n' > "$target"
}
if ! command -v install >/dev/null; then
    install() {
        if [[ $1 == -d ]]; then mkdir -p -- "${@:4}"; else cp -- "$3" "$4"; fi
    }
fi
run_apt() {
    local IFS=' '
    printf '%s\n' "$*" >> "$XANMOD_TEST_DIR/apt-calls"
    [[ ( $TEST_MODE != update_failure && $TEST_MODE != restore_failure ) || $1 != update ]] || return 100
    [[ $TEST_MODE != install_failure || $1 != install ]] || return 100
}
apt-cache() {
    if [[ $TEST_MODE == no_candidate ]]; then
        printf '  Candidate: (none)\n'
    else
        printf '  Candidate: 1.0-test\n'
    fi
}

reset_fixture
install_xanmod <<< $'2\ny' >/dev/null
grep -Fq 'https://deb.xanmod.org resolute main' "$XANMOD_SOURCE" || fail 'supported resolute repo was not configured'
grep -Fqx 'verified key' "$XANMOD_KEYRING" || fail 'verified key was not installed'
grep -Fqx 'update --error-on=any' "$XANMOD_TEST_DIR/apt-calls" || fail 'APT update is not strict'
grep -Fqx 'install -y linux-xanmod-x64v3' "$XANMOD_TEST_DIR/apt-calls" || fail 'Main branch was not installed'
if command -v stat >/dev/null; then
    [[ $(stat -c %a "$XANMOD_KEYRING") == 644 ]] || fail 'keyring is unreadable by _apt'
fi

TEST_MODE=ipv6_failure
reset_fixture
install_xanmod <<< $'1\ny' >/dev/null 2>&1
grep -Fqx 'yes|https://deb.xanmod.org/dists/resolute/Release' "$XANMOD_TEST_DIR/curl-calls" || fail 'IPv4 fallback missing'
grep -Fqx 'install -y linux-xanmod-lts-x64v3' "$XANMOD_TEST_DIR/apt-calls" || fail 'LTS branch was not installed'

for TEST_MODE in network_failure http_404 invalid_metadata invalid_key update_failure no_candidate; do
    reset_fixture
    if output=$(install_xanmod <<< $'2\ny' 2>&1); then fail "accepted $TEST_MODE"; fi
    [[ $(< "$XANMOD_KEYRING") == 'old key' ]] || fail "$TEST_MODE changed the previous key"
    [[ $(< "$XANMOD_SOURCE") == 'old source' ]] || fail "$TEST_MODE changed the previous source"
    if grep -q '^install ' "$XANMOD_TEST_DIR/apt-calls"; then fail "$TEST_MODE attempted a kernel install"; fi
    if [[ $TEST_MODE == network_failure ]]; then
        [[ $(wc -l < "$XANMOD_TEST_DIR/curl-calls") == 2 ]] || fail 'unbounded network retries'
        [[ $output == *'Connection timed out'* && $output != *'не публикует репозиторий'* ]] || fail 'network failure misreported as unsupported release'
    elif [[ $TEST_MODE == http_404 ]]; then
        [[ $(wc -l < "$XANMOD_TEST_DIR/curl-calls") == 1 ]] || fail 'HTTP 404 incorrectly retried as an IPv6 error'
    fi
done

TEST_MODE=update_failure
rm -f -- "$XANMOD_KEYRING" "$XANMOD_SOURCE"
if install_xanmod <<< $'2\ny' >/dev/null 2>&1; then fail 'fresh setup ignored failed update'; fi
[[ ! -e $XANMOD_KEYRING && ! -e $XANMOD_SOURCE ]] || fail 'failed fresh setup left broken repository files'

TEST_MODE=install_failure
reset_fixture
if install_xanmod <<< $'2\ny' >/dev/null 2>&1; then fail 'failed kernel install reported success'; fi
grep -Fq 'https://deb.xanmod.org resolute main' "$XANMOD_SOURCE" || fail 'interrupted install lost its verified repair repository'

cp() {
    local source_file="${*: -2:1}"
    if [[ $TEST_MODE == restore_failure && $source_file == */previous-keyring ]]; then return 1; fi
    command cp "$@"
}
TEST_MODE=restore_failure
reset_fixture
if output=$(install_xanmod <<< $'2\ny' 2>&1); then fail 'failed repository restore reported success'; fi
[[ $output == *'Не удалось полностью восстановить'* ]] || fail 'restore failure was hidden'
retained=$(find "$TMPDIR" -type f -name previous-keyring -print)
[[ -f $retained && $(< "$retained") == 'old key' ]] || fail 'failed restore deleted the recovery copy'

install_xanmod() { return 1; }
confirm() {
    case "$1" in
        'Запустить полный мастер?'|'Установить XanMod?') return 0 ;;
        'Включить BBR на текущем ядре?') touch "$XANMOD_TEST_DIR/bbr-reached"; return 1 ;;
        *) return 1 ;;
    esac
}
full_setup <<< 1 >/dev/null
[[ -e $XANMOD_TEST_DIR/bbr-reached ]] || fail 'failed optional kernel install aborted the wizard'
clear() { :; }
pause() { :; }
show_menu <<< $'7\n0' >/dev/null
printf 'PASS: resolute metadata, IPv4 fallback, diagnostics, key verification, repo rollback and optional XanMod failure\n'
