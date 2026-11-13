# Verification

Run on the target host as root after each first deployment and after host changes. `APP=myapp`, `UID_APP=$(id -u $APP)`.

## Rootless engine
| Check | Command | Expected |
|---|---|---|
| Rootless Podman | `app-podman $APP info --format '{{.Host.Security.Rootless}}'` | `true` |
| No rootful containers | `podman ps -a --format '{{.Names}}'` (as root) | Empty |
| No container socket | `ls /run/podman/podman.sock /var/run/docker.sock 2>&1` | Both absent |
| Network helper | `app-podman $APP info --format '{{.Host.RootlessNetworkCmd}}'` | `pasta` |
| Account cannot log in | `getent passwd $APP \| cut -d: -f7; passwd -S $APP` | `/usr/sbin/nologin`, `L` (locked) |
| Quadlet files root-owned | `stat -c '%U:%G %a %n' /etc/containers/systemd/users/$UID_APP/*` | `root:root 644` |
| No user policy override | `ls /home/$APP/.config/containers/policy.json /home/$APP/.config/containers/systemd 2>&1` | Absent |
| Linger | `loginctl show-user $APP -p Linger` | `Linger=yes` |
| Reboot | reboot, then `systemctl --user -M $APP@ is-active myapp-pod.service myapp-web.service myapp-db.service` | All `active` without any login |

## Rootless process (second layer)
| Check | Command | Expected |
|---|---|---|
| Container vs host UID | `app-podman $APP top myapp-web user huser` | `user` = `10001`, `huser` = subordinate UID (≥ 100000), never `0` nor the account UID |
| Host view | `ps -o uid,pid,comm -p <hpid from the previous command>`, then `getent passwd <uid>` | Numeric UID, `getent` returns nothing |
| Capabilities | `app-podman $APP exec myapp-web grep -E 'CapEff\|NoNewPrivs\|Seccomp' /proc/1/status` | `CapEff: 0000000000000000`, `NoNewPrivs: 1`, `Seccomp: 2` |
| Read-only root | `app-podman $APP exec myapp-web touch /probe` | `Read-only file system` |
| SELinux label (RHEL) | `ps -eZ \| grep container_t` | Each container `container_t` with distinct MCS categories (`s0:cX,cY`) |
| Limits | `app-podman $APP inspect myapp-web --format '{{.HostConfig.Memory}} {{.HostConfig.PidsLimit}}'` | Configured values, not `0` |
| Image pinned and signed | `app-podman $APP inspect myapp-web --format '{{.ImageName}}'` | Contains `@sha256:` |
| Unsigned image rejected | `app-podman $APP pull docker.io/library/alpine:latest` | Rejected by policy |

## Exposure
| Check | Command | Expected |
|---|---|---|
| Listening sockets | `ss -tlnp \| grep -E ':180[0-9]{2}'` | `127.0.0.1:18000` only, process `pasta`, owned by the account |
| Nothing else published | `ss -tlnp` | No application port on `0.0.0.0`, `[::]` or a public address |
| Database not published | `ss -tlnp \| grep 5432` | Empty |
| Reverse proxy allowed | `sudo -u nginx curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18000/` (or `www-data`) | Application response (`200`/`302`) |
| Other local users refused | `sudo -u nobody curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18000/; echo $?` | `000`, curl exit 7 (reset) |
| Remote access refused | from another machine: `curl -m 5 http://<host-ip>:18000/` | Connection refused or timeout |
| nftables counters | `nft list chain inet podman_apps output` | Reject counter increased by the previous test |
| Egress allowlist (if enabled) | `app-podman $APP exec myapp-web <tool> https://example.org` | Fails; allowed destinations succeed |
| End to end | `curl -sI https://app.example.com/` | Served through Nginx |

## Operations
| Check | Command | Expected |
|---|---|---|
| Restart on failure | `app-podman $APP exec myapp-web kill 1`, wait, `systemctl --user -M $APP@ show myapp-web.service -p NRestarts` | Incremented, service `active` |
| Health check | `app-podman $APP healthcheck run myapp-web; echo $?` | `0` |
| Logs in journal | `journalctl _UID=$UID_APP -n 5` | Container output present |
| Backup and restore | procedure from [operations.md](operations.md) on staging | Restored application passes this checklist |
| Image scan | `trivy image <web digest>` | 0 unaccepted HIGH/CRITICAL |

## Report format
`check | command | expected | actual | pass/fail`, plus the CVE gate line. Checks not executed are listed as `Not run` with the reason.
