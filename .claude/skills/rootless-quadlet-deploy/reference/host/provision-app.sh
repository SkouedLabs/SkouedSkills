#!/usr/bin/env bash
# Provision a rootless Podman service account for one application.
# Installed as /usr/local/sbin/provision-app. Idempotent; run as root.
#
# Usage: provision-app <app-name>
#
# Creates: non-login account with a locked password, a private 65536-ID subordinate range
# that overlaps no other account, linger, and the root-owned Quadlet directory
# /etc/containers/systemd/users/<UID>/.

set -euo pipefail

readonly RANGE_SIZE=65536
readonly RANGE_FLOOR=100000

die() { echo "provision-app: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root"
[[ $# -eq 1 ]] || die "usage: provision-app <app-name>"
app="$1"
[[ "$app" =~ ^[a-z][a-z0-9-]{1,30}$ ]] || die "invalid name '$app' (expected [a-z][a-z0-9-]{1,30})"

podman_major="$(podman --version | awk '{print $3}' | cut -d. -f1)"
[[ "$podman_major" -ge 5 ]] || die "podman >= 5.0 required (found $(podman --version))"
[[ "$(stat -fc %T /sys/fs/cgroup)" == "cgroup2fs" ]] || die "cgroup v2 required"

if ! id "$app" &>/dev/null; then
    useradd --create-home --home-dir "/home/$app" --shell /usr/sbin/nologin \
            --user-group --comment "Rootless Podman application $app" "$app"
fi
passwd --lock "$app" >/dev/null
uid="$(id -u "$app")"

# Next free subordinate range: above every existing range in both files.
next_free_start() {
    awk -F: -v floor="$RANGE_FLOOR" '
        { end = $2 + $3; if (end > max) max = end }
        END { if (max < floor) max = floor; print max }
    ' /etc/subuid /etc/subgid
}

has_range() { grep -q "^${app}:" "$1" || grep -q "^${uid}:" "$1"; }

if ! has_range /etc/subuid || ! has_range /etc/subgid; then
    start="$(next_free_start)"
    end=$((start + RANGE_SIZE - 1))
    has_range /etc/subuid || usermod --add-subuids "${start}-${end}" "$app"
    has_range /etc/subgid || usermod --add-subgids "${start}-${end}" "$app"
fi

# Overlap check across all accounts.
for file in /etc/subuid /etc/subgid; do
    awk -F: '{ print $2, $2 + $3 - 1, $1 }' "$file" | sort -n | awk -v f="$file" '
        NR > 1 && $1 <= prev_end { printf "provision-app: overlap in %s: %s and %s\n", f, prev_name, $3; bad = 1 }
        { if ($2 > prev_end) { prev_end = $2; prev_name = $3 } }
        END { exit bad }
    ' || die "fix overlapping ranges in $file"
done

loginctl enable-linger "$app"
systemctl start "user@${uid}.service"

install -d -m 0755 -o root -g root "/etc/containers/systemd/users/${uid}"

# A user-level policy.json would override the system signature policy.
user_policy="/home/${app}/.config/containers/policy.json"
[[ ! -e "$user_policy" ]] || die "$user_policy exists and overrides /etc/containers/policy.json: remove it"

echo "account:      $app (uid $uid)"
echo "subuid:       $(grep "^${app}:" /etc/subuid)"
echo "subgid:       $(grep "^${app}:" /etc/subgid)"
echo "quadlet dir:  /etc/containers/systemd/users/${uid}/"
echo "next steps:   copy the Quadlet files, create secrets, then"
echo "              systemctl --user -M ${app}@ daemon-reload && systemctl --user -M ${app}@ start ${app}-pod.service"
