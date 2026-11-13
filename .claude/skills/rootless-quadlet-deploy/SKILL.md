---
name: rootless-quadlet-deploy
description: Use when deploying an application to production on a Linux host with Podman Quadlet (systemd-managed containers), or when asked for rootless containers, Quadlet units, podman systemd services or a production stack without Docker, on Debian/Ubuntu or AlmaLinux/RHEL. Produces a double-rootless stack - one unprivileged service account per application running rootless Podman, non-root processes inside containers mapped to subordinate UIDs with no host identity - with pods, read-only hardened containers, published ports bound to 127.0.0.1 only and reachable by the host reverse proxy only (nftables owner match), signed digest-pinned images, Podman secrets, named volumes, journald logs, SELinux and an operations and verification procedure.
---
# Rootless Quadlet Deployment (Podman, production)

Deploys an application as systemd-managed Podman containers (Quadlet) with two independent rootless layers:

1. **Rootless engine:** Podman runs under a dedicated, unprivileged, non-login service account per application. No rootful Podman, no Docker daemon, no container socket.
2. **Rootless process:** inside the container the process runs as a non-root numeric UID. The user namespace maps it to a **subordinate UID** of the service account: on the host it is a number with no account, no file ownership outside its volumes and no privileges.

A container escape therefore lands as a nameless subordinate UID, in the user namespace of an account that cannot log in, owns no Quadlet file and can only reach the network through rules scoped to it.

Scope: the production host. Images are built and signed in CI (see the application's own build rules). The host reverse proxy in front is configured with the `reverse-proxy-hardening` skill.

## Reference files (copy, then adapt the values marked `ADAPT`)
- [reference/quadlet/](reference/quadlet/): example stack `myapp` (pod, web container, PostgreSQL container, named volumes).
- [reference/host/provision-app.sh](reference/host/provision-app.sh): creates the service account, subordinate ID range, linger and the root-owned Quadlet directory.
- [reference/host/app-podman](reference/host/app-podman): admin wrapper to run `podman` as a service account.
- [reference/host/containers/](reference/host/containers/): system `containers.conf`, `registries.conf.d/` drop-in and signature `policy.json`.
- [reference/host/nftables/](reference/host/nftables/): loopback port restriction to the reverse proxy and optional per-application egress allowlist, with its systemd loader.
- [reference/host-setup.md](reference/host-setup.md): host preparation for Debian/Ubuntu and AlmaLinux.
- [reference/operations.md](reference/operations.md): deploy, update, rollback, secrets, backups, logs.
- [reference/verification.md](reference/verification.md): mandatory checks before declaring the deployment done.

## When to Use
- "Deploy to production with Podman/Quadlet", "rootless containers", "systemd containers", "replace docker compose in production".
- Converting a development `docker-compose.yml` into production Quadlet units.
- Auditing an existing Podman host against this baseline.

## 0. Inputs
Decide from the request or the project; ask only for what cannot be inferred. Defaults in parentheses.
- OS and version, `podman --version`, cgroup version (`stat -fc %T /sys/fs/cgroup` = `cgroup2fs`).
- Application name (lowercase, `[a-z][a-z0-9-]{1,30}`), services and their images (registry, repository, **digest**).
- Port inside the pod (`8080`) and loopback port on the host, from the port registry (`18000-18999`, one block of 10 per application).
- Persistent data (named volumes), secrets, required egress destinations (SMTP, OIDC, APIs) for the optional allowlist.
- Reverse proxy user on the host (`www-data` on Debian/Ubuntu distro Nginx, `nginx` otherwise).

## 1. Namespace Model
| Namespace / control | Provided by | Effect |
|---|---|---|
| User | Rootless Podman, one subordinate range per service account | Container UIDs are unprivileged host UIDs, distinct per application; container `root` is the service account, never host root |
| Mount, PID, IPC, UTS | One set per pod | No view of host processes, mounts or other applications |
| Network | One netns per pod, `pasta` for host connectivity | Containers of a pod talk over the pod's `localhost`; only declared ports are forwarded, bound to `127.0.0.1` |
| cgroup v2 | systemd user manager delegation | Memory and PID limits per container, accounted under the user's slice |
| SELinux / AppArmor | `container_t` with unique MCS categories (RHEL), distro profile (Debian/Ubuntu) | Containers cannot read each other's files nor host files |
| seccomp | Podman default profile | Dangerous syscalls blocked; never `unconfined` |
| Capabilities | `DropCapability=all` | Empty effective set; `NoNewPrivileges` prevents regaining any |

Forbidden: `--privileged`, `Network=host`, `PodmanArgs=--pid=host`/`--ipc=host`, `UserNS=host`, `SecurityLabelDisable=true`, mounting `/run/podman/podman.sock` or any host socket, `UserNS=keep-id` unless a bind mount strictly requires it (it maps the process to the real service account and removes the second rootless layer).

## 2. Host Prerequisites
- **Podman ≥ 5.0** (`.pod` Quadlet units, `pasta` default network, `Notify=healthy`, network-online wait for user units). Debian 13, AlmaLinux 9.5+ and AlmaLinux 10 qualify. Ubuntu 24.04 (Podman 4.9) does not support `.pod` units: use a newer Ubuntu or replace the pod by an internal `.network` (see Gotchas). Debian 12 (Podman 4.3) has no Quadlet: not supported.
- Packages: `podman`, `passt` (pasta), `uidmap`/`shadow-utils` (`newuidmap`), `container-selinux` (RHEL), `crun` (default runtime). No `fuse-overlayfs` on kernels ≥ 5.13 (native rootless overlay). Never install `docker.io` or `podman-docker` on the same host.
- cgroup v2 unified hierarchy; systemd user manager delegates `memory` and `pids` (default).
- Unprivileged user namespaces enabled. On Ubuntu ≥ 23.10, `kernel.apparmor_restrict_unprivileged_userns=1` requires an AppArmor profile allowing `userns` for Podman's helpers; never set the sysctl to `0` globally.
- `net.ipv4.ip_unprivileged_port_start` stays at `1024`: applications never bind privileged ports, the reverse proxy does.
- The CVE gate of `reverse-proxy-hardening` ([cve-check.md](../reverse-proxy-hardening/reference/cve-check.md)) also covers `podman`, `crun`, `passt`, `netavark`, `aardvark-dns`, `conmon` and the kernel.

## 3. Service Account per Application
- One regular account per application (`useradd --create-home --shell /usr/sbin/nologin --user-group <app>`), home in `/home/<app>` so SELinux home-directory contexts for container storage apply. Password locked, no sudo, no SSH access, no group membership beyond its own.
- Subordinate ID range of 65536 UIDs/GIDs, non-overlapping with every other account (`/etc/subuid`, `/etc/subgid`).
- `loginctl enable-linger <app>`: the user manager starts at boot without a login session.
- Done by [provision-app.sh](reference/host/provision-app.sh); operators act through `systemctl --user -M <app>@` and the [app-podman](reference/host/app-podman) wrapper, never by opening a shell as the account.

## 4. Quadlet Layout
- Unit files live in **`/etc/containers/systemd/users/<UID>/`**, owned `root:root`, `0644`. The service account runs them but cannot modify them, so a compromised application cannot persist by editing its own units. Never use `~/.config/containers/systemd/` in production.
- One application = one `.pod` + one `.container` per service + one `.volume` per persistent dataset. File names prefixed with the application name (`myapp.pod`, `myapp-web.container`, `myapp-db.volume`).
- Dependencies: `Requires=` + `After=` on the dependency's service, and `Notify=healthy` on the dependency so dependents start only once it is healthy.
- `[Service] Restart=on-failure`, `TimeoutStartSec=300` (first pull), `[Install] WantedBy=default.target`.
- Validate before reload: `/usr/libexec/podman/quadlet -dryrun -user` run as the account (see [operations.md](reference/operations.md)).

## 5. Container Hardening (every `.container`)
| Key | Value | Why |
|---|---|---|
| `Image=` | `registry/repo:tag@sha256:<digest>` | Immutable, verified image |
| `User=` | Numeric non-root UID:GID (`10001:10001`) | Second rootless layer, even if the image forgets `USER` |
| `ReadOnly=true` | + `Tmpfs=/tmp:rw,size=64m,mode=1777` and other writable paths as tmpfs | No persistence outside volumes |
| `DropCapability=all` | no `AddCapability=` | Empty capability set |
| `NoNewPrivileges=true` | | setuid binaries cannot elevate |
| `PidsLimit=` | `256`-`1024` | Fork bombs |
| `PodmanArgs=--memory=` | per service | Memory exhaustion |
| `Ulimit=core=0:0` | | No core dumps with secrets |
| `HealthCmd=` + `HealthOnFailure=kill` | binary present in the image | Unhealthy containers restarted by systemd |
| `LogDriver=journald` | | Central, rate-limited logs |
| `Secret=` | `type=mount`, `mode=0400`, `uid=` of the process | Secrets as files, never environment values |
| `Volume=` | named `.volume` units with `:Z` | Private SELinux label, no host paths |
| `AutoUpdate=` | unset | Updates are deliberate (section 7) |

Bind mounts are limited to read-only configuration files under `/etc/<app>/` (`:ro,Z`). Never bind-mount `/`, `/etc`, `/home`, `/var/run` or a directory shared with another application.

## 6. Networking & Exposure
- The **pod** publishes the only entry point: `PublishPort=127.0.0.1:<host-port>:<pod-port>`. Containers never publish ports; databases and internal services are reachable only on the pod's `localhost`.
- **Never `0.0.0.0` or an empty host address** in `PublishPort` (`8080:8080` binds every interface). IPv6 loopback is not published.
- **Port registry:** `18000-18999` reserved for application stacks, one block of 10 per application, recorded in `/etc/containers/ports.registry` (comment + application). The same range is labeled `http_port_t` on SELinux hosts so Nginx may connect to it.
- **Reverse proxy only:** binding to `127.0.0.1` still lets any local user connect. [podman-apps.nft](reference/host/nftables/podman-apps.nft) rejects TCP connections to `127.0.0.1:18000-18999` unless the socket owner is the reverse proxy user (or root for local health checks), using `meta skuid` on the `output` hook. This works because the client socket belongs to the Nginx worker, and is independent of firewalld/ufw.
- **Egress (recommended for Internet-facing apps):** `pasta` opens outbound connections as the service account, so `meta skuid <app>` in the same table restricts each application to its allowed destinations (DNS resolver, SMTP, OIDC issuer, APIs).
- No `Network=host`, no `slirp4netns` (deprecated in Podman 5), no change to `ip_unprivileged_port_start`.

## 7. Images & Supply Chain
- Images pinned by digest; tags are informative only. An update is a digest change in the Quadlet file, reviewed like code.
- **Signature enforcement:** system [policy.json](reference/host/containers/policy.json) with `default: reject` and `sigstoreSigned` for the internal registry. Third-party images (PostgreSQL, Redis) are mirrored into the internal registry after scanning and re-signed there. No `~/.config/containers/policy.json` may exist in service accounts (it would override the system policy).
- [registries.conf.d](reference/host/containers/registries.conf.d/00-production.conf): `short-name-mode = "enforcing"`, no unqualified search registries, insecure registries forbidden.
- Before each deployment: `trivy image` on the exact digest (HIGH/CRITICAL fixed or accepted in writing); results recorded in the deployment report.
- `podman auto-update` disabled by default. If enabled on request: only with `AutoUpdate=registry`, signed images, health checks and its automatic rollback.

## 8. Secrets
- `podman secret create` as the service account, from a file or stdin, never from a command-line value; consumed with `Secret=<name>,type=mount,target=/run/secrets/<name>,mode=0400,uid=<uid>`.
- The default `file` driver stores secrets unencrypted in the account's storage (`0600`): the host disk must be encrypted, or use the `pass`/`shell` driver backed by Vault/sops when available.
- Rotation: create `<name>-v2`, switch the Quadlet reference, restart, remove the old secret.

## 9. Storage & Backups
- Rootless storage in `/home/<app>/.local/share/containers/storage`; files inside volumes are owned by subordinate UIDs. Inspect them with `podman unshare` as the account, never `chown` them from the host.
- Database backups use the engine's tool inside the container (`pg_dump` via `podman exec`) to an encrypted destination; volume-level backups with `podman volume export` while the service is stopped. Restore procedure tested (`make restore-test` equivalent documented in [operations.md](reference/operations.md)).
- `podman system prune` scheduled for unused images only (`podman image prune -f`), never `--volumes`.

## 10. Logs & Monitoring
- `LogDriver=journald`, journal persistent (`Storage=persistent`). Read as root with `journalctl _UID=<uid> --user-unit=<unit>`.
- Forward the journal to the central syslog/SIEM (`systemd-journal-upload` or the host's forwarder); alert on restart loops (`NRestarts`) and failed health checks.
- Monitoring probes reach the application through the reverse proxy, or as root on loopback (allowed by the nftables set).

## 11. Integration with the Reverse Proxy
- Nginx `upstream` points to `127.0.0.1:<host-port>` of the application; the reverse proxy user is listed in the nftables `proxy_users` set.
- SELinux: `semanage port -a -t http_port_t -p tcp 18000-18999` once per host, plus `httpd_can_network_relay`.
- The application trusts `X-Forwarded-*` only from `127.0.0.1` (the pasta-forwarded connection appears with a loopback or pod gateway source; configure the trusted proxy list accordingly and verify).

## Expected Output
1. Inputs (section 0), host versions and the CVE gate line.
2. Port registry entry, service account name, UID and subordinate range.
3. Quadlet files with their absolute target path (`/etc/containers/systemd/users/<UID>/...`); in a repository following a `deploy/` layout, under `deploy/host/etc/containers/systemd/users/<app>/` with the UID resolved at install time.
4. Host configuration (containers.conf, registries, policy.json, nftables) and ordered commands from [host-setup.md](reference/host-setup.md) and [operations.md](reference/operations.md).
5. Verification results from [verification.md](reference/verification.md), `Not run` for checks not executed. Never invent results.

## Gotchas
- `PublishPort=8080:8080` (no address) listens on all interfaces, and rootless pasta forwarding is **not** filtered by firewalld/ufw zones the way rootful ports are. Always write `127.0.0.1:` explicitly and check `ss -tlnp`.
- Official images that start as root and drop privileges (`postgres`, `redis`, `nginx`) fail with `DropCapability=all` unless run directly as their unprivileged UID (`User=70:70` for `postgres:*-alpine`, `999:999` for Debian-based) with writable paths owned by that UID.
- `systemctl --user` as root without `-M <app>@` targets root's own user manager; `sudo -u <app> systemctl --user` fails without `XDG_RUNTIME_DIR`. Use the documented commands.
- Without linger, the stack stops when the last session of the account closes and does not start at boot.
- Overlapping `/etc/subuid` ranges between accounts silently share host UIDs between applications. `provision-app.sh` allocates the next free range; check after manual edits.
- Moving the account home outside `/home` breaks SELinux labels of the container storage (AVC denials on overlay layers) unless equivalence rules are added (`semanage fcontext -a -e /home /srv/apps`).
- `HealthCmd` runs inside the container: distroless images need a health binary or an HTTP check built into the application.
- Ubuntu 24.04 / Podman 4.9 fallback: replace the `.pod` by a `myapp.network` with `Internal=true` for back-end services, publish `127.0.0.1:` on the front container only, and drop `Notify=healthy`.
- `podman system reset` or `prune --volumes` as the account deletes production data.
- Changing a Quadlet file requires `systemctl --user -M <app>@ daemon-reload` before the restart; otherwise the old generated unit keeps running.
