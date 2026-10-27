#!/usr/bin/env bash
set -Eeuo pipefail

TEST_ROOT=$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/server-tool-cleanup.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/backups" "$work/custom"
sed "s|readonly BACKUP_ROOT=\"/var/backups/server-tool\"|readonly BACKUP_ROOT=\"$work/backups\"|" \
    "$TEST_ROOT/server_tool.sh" > "$work/source.sh"
# shellcheck disable=SC1091
source "$work/source.sh"
require_root() { :; }
log() { :; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
declare -a candidates=()
if ! command -v du >/dev/null; then du() { [[ -e ${!#} ]]; }; fi
if ! command -v realpath >/dev/null; then realpath() { (cd -- "${!#}" && pwd -P); }; fi

for i in 1 2 3 4 5; do
    for kind in ssh firewall ports; do
        case "$kind" in
            ssh) name="20200101-00000${i}-ssh"; marker=sshd_config ;;
            firewall) name="20200101-00000${i}-firewall"; marker=nft-ruleset.txt ;;
            ports) name="ports.00000${i}"; marker=guard.conf ;;
        esac
        [[ $kind == ports || $i != 2 ]] || name+=.Ab1234
        mkdir "$BACKUP_ROOT/$name"
        printf 'fixture\n' > "$BACKUP_ROOT/$name/$marker"
        touch -t "20200101000$i" "$BACKUP_ROOT/$name"
    done
    printf 'archive\n' > "$work/custom/copy $i.tar.gz"
    touch -t "20200101000$i" "$work/custom/copy $i.tar.gz"
done
mkdir "$BACKUP_ROOT/unrecognized" "$BACKUP_ROOT/20200101-000000-ssh"
printf 'unfinished\n' > "$work/custom/copy.tar.gz.partial"
backup_cleanup_candidates "$BACKUP_ROOT" 30 own > "$work/plan"
mapfile -d '' -t candidates < "$work/plan"
[[ ${#candidates[@]} == 6 ]] || fail 'retention must preserve three backups per ServerTool type'
for path in "${candidates[@]}"; do
    path=${path//\\//}
    [[ $path == *000001* || $path == *000002* ]] || fail "protected or unknown backup selected: $path"
done
backup_cleanup_candidates "$work/custom" 30 custom '*.tar.gz' > "$work/plan"
mapfile -d '' -t candidates < "$work/plan"
[[ ${#candidates[@]} == 2 ]] || fail 'custom retention must preserve three completed archives'
for path in "${candidates[@]}"; do
    [[ $path == *'copy 1.tar.gz' || $path == *'copy 2.tar.gz' ]] || fail 'unexpected custom backup selected'
done
for directory in / /etc /var/lib /var/backups "$work/missing"; do
    if MSYS_NO_PATHCONV=1 backup_cleanup_candidates "$directory" 30 custom '*.tar.gz' >/dev/null 2>&1; then
        fail "unsafe root accepted: $directory"
    fi
done
for days in 0 -1 36501 abc '1; rm'; do
    if backup_cleanup_candidates "$work/custom" "$days" custom '*.tar.gz' >/dev/null 2>&1; then
        fail "invalid retention accepted: $days"
    fi
done
if backup_cleanup_candidates "$work/custom" 30 own >/dev/null 2>&1; then fail 'foreign directory accepted as ServerTool backups'; fi
if backup_cleanup_candidates "$work/custom" 30 custom '../*' >/dev/null 2>&1; then fail 'path traversal pattern accepted'; fi

if [[ $OSTYPE != msys* ]]; then
    for directory in /tmp/../etc /var/backups/../lib /tmp/../var/backups; do
        if backup_cleanup_candidates "$directory" 30 custom '*.tar.gz' >/dev/null 2>&1; then
            fail "dot-segment bypass accepted: $directory"
        fi
    done
    ln -s "$work/custom" "$work/link"
    if backup_cleanup_candidates "$work/link" 30 custom '*.tar.gz' >/dev/null 2>&1; then fail 'symlinked root accepted'; fi
    exec 8< "$work/custom/copy 1.tar.gz"
    backup_cleanup_candidates "$work/custom" 30 custom '*.tar.gz' > "$work/open-plan"
    exec 8<&-
    if grep -azq 'copy 1.tar.gz' "$work/open-plan"; then fail 'open backup selected for deletion'; fi
else
    # The Windows Python fixture returns native paths; Bash uses MSYS paths.
    eval "$(declare -f backup_cleanup_candidates | sed '1s/backup_cleanup_candidates/native_backup_candidates/')"
    backup_cleanup_candidates() {
        local path directory="$1"
        native_backup_candidates "$@" > "$work/native-plan" || return 1
        while IFS= read -r -d '' path; do
            path=${path//\\//}
            printf '%s/%s\0' "$directory" "${path##*/}"
        done < "$work/native-plan"
    }
fi
cleanup_backups <<< $'2\n'"$work/custom"$'\n*.tar.gz\n30\nn' >/dev/null
[[ -f $work/custom/copy\ 1.tar.gz ]] || fail 'declined cleanup removed a file'
cleanup_backups <<< $'2\n'"$work/custom"$'\n*.tar.gz\n30\ny' >/dev/null
[[ ! -e $work/custom/copy\ 1.tar.gz && ! -e $work/custom/copy\ 2.tar.gz ]] || fail 'confirmed cleanup did not remove the previewed archives'
[[ -f $work/custom/copy\ 3.tar.gz && -f $work/custom/copy.tar.gz.partial ]] || fail 'cleanup removed protected backups'

printf 'archive\n' > "$work/custom/old.tar.gz"
touch -t 199901010000 "$work/custom/old.tar.gz"
original_confirm=$(declare -f confirm)
confirm() { touch "$work/custom/old.tar.gz"; return 0; }
if cleanup_backups <<< $'2\n'"$work/custom"$'\n*.tar.gz\n30' >/dev/null 2>&1; then fail 'changed backup plan was not rejected'; fi
[[ -f $work/custom/old.tar.gz && -f $work/custom/copy\ 3.tar.gz ]] || fail 'changed plan caused deletion'
eval "$original_confirm"

df() {
    printf 'Filesystem blocks used available capacity mount\n'
    if [[ $1 == -Pi ]]; then
        printf '/dev/test 100000 0 %s 0%% /\n' "$TEST_FREE_INODES"
    else
        printf '/dev/test 10000000 0 %s 0%% /\n' "$TEST_FREE_KIB"
    fi
}
TEST_FREE_KIB=1048576 TEST_FREE_INODES=10000
package_disk_ready || fail 'healthy disk rejected'
TEST_FREE_KIB=0
if package_disk_ready >/dev/null 2>&1; then fail 'full disk accepted'; fi
TEST_FREE_KIB=1048576 TEST_FREE_INODES=0
if package_disk_ready >/dev/null 2>&1; then fail 'inode exhaustion accepted'; fi
TEST_FREE_INODES=10000

uname() { printf '6.8.0-1-generic\n'; }
dpkg-query() { printf 'linux-image-6.8.0-1-generic\tii \nlinux-image-6.8.0-2-generic\tii \n'; }
for version in 1 2; do
    printf 'Remv linux-image-6.8.0-%s-generic [test]\n' "$version" > "$work/autoremove"
    if autoremove_plan_is_safe "$work/autoremove" >/dev/null 2>&1; then fail 'working or fallback kernel could be removed'; fi
done
printf 'Remv linux-image-6.8.0-0-generic [test]\n' > "$work/autoremove"
autoremove_plan_is_safe "$work/autoremove" || fail 'obsolete kernel rejected'

dpkg() { return 0; }
apt-get() {
    [[ $1 == -s && $2 == autoremove ]] || fail 'unexpected APT preview'
    printf 'Remv linux-image-6.8.0-0-generic [test]\n'
}
run_apt() { local IFS=' '; printf '%s\n' "$*" >> "$work/package-calls"; }
TEST_FREE_KIB=0
cleanup_packages <<< y >/dev/null
grep -Fqx 'autoremove -y' "$work/package-calls" || fail 'full /boot prevents old-kernel cleanup'
TEST_FREE_KIB=1048576

docker() { local IFS=' '; printf '%s\n' "$*" >> "$work/docker-calls"; }
pause() { :; }
cleanup_menu <<< $'4\ny\n0' >/dev/null
grep -Fqx 'builder prune -f' "$work/docker-calls" || fail 'build cache cleanup missing'
grep -Fqx 'image prune -f' "$work/docker-calls" || fail 'dangling image cleanup missing'
if grep -Eq 'volume|container prune|system prune|--all| -a' "$work/docker-calls"; then fail 'cleanup requested destructive Docker pruning'; fi
printf 'PASS: backup retention, unsafe paths, disk/inode preflight, kernel protection and Docker cleanup scope\n'
