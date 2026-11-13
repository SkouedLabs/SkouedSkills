# Host Setup (once per host)

Run as root. `R=` is the path holding the reference files adapted for the target.

## 1. Packages
```bash
# Debian 13+ / Ubuntu with Podman >= 5
apt install -y podman passt uidmap crun nftables

# AlmaLinux 9.5+ / 10
dnf install -y podman passt crun container-selinux nftables policycoreutils-python-utils

podman --version            # >= 5.0
podman info --format '{{.Host.CgroupsVersion}} {{.Host.NetworkBackend}} {{.Host.OCIRuntime.Name}}'
                            # v2 netavark crun
```
Not installed: `docker.io`, `docker-ce`, `podman-docker`, `slirp4netns`, `fuse-overlayfs` (kernel ≥ 5.13).
Then run the CVE gate (see the `reverse-proxy-hardening` skill, `reference/cve-check.md`) for `podman crun passt netavark aardvark-dns conmon` and the kernel.

## 2. Kernel and user namespaces
```bash
sysctl user.max_user_namespaces            # > 0
sysctl net.ipv4.ip_unprivileged_port_start # 1024, leave unchanged
# Ubuntu >= 23.10:
sysctl kernel.apparmor_restrict_unprivileged_userns 2>/dev/null
# If 1 and rootless podman fails with "newuidmap: write to uid_map failed", install or enable the
# AppArmor profile shipped for podman/crun; never set the sysctl to 0 host-wide.
```

## 3. Containers configuration
```bash
install -d -m 0755 /etc/containers/containers.conf.d /etc/containers/registries.conf.d \
                   /etc/containers/registries.d /etc/containers/keys /etc/containers/systemd/users
install -m 0644 "$R/host/containers/containers.conf.d/50-production.conf" /etc/containers/containers.conf.d/
install -m 0644 "$R/host/containers/registries.conf.d/00-production.conf" /etc/containers/registries.conf.d/
install -m 0644 "$R/host/containers/registries.d/registry.example.com.yaml" /etc/containers/registries.d/
install -m 0644 /path/to/registry.example.com-cosign.pub /etc/containers/keys/
cp /etc/containers/policy.json /etc/containers/policy.json.dist
install -m 0644 "$R/host/containers/policy.json" /etc/containers/policy.json
# Internal registry CA:
install -D -m 0644 /path/to/internal-ca.crt /etc/containers/certs.d/registry.example.com/ca.crt
```

## 4. Administration tools and port registry
```bash
install -m 0755 "$R/host/provision-app.sh" /usr/local/sbin/provision-app
install -m 0755 "$R/host/app-podman"       /usr/local/sbin/app-podman
install -m 0644 "$R/host/ports.registry"   /etc/containers/ports.registry
```

## 5. Loopback restriction (reverse proxy only)
```bash
install -d -m 0755 /etc/nftables.d
install -m 0644 "$R/host/nftables/podman-apps.nft" /etc/nftables.d/podman-apps.nft
# ADAPT the proxy_users set: "www-data" (Debian/Ubuntu distro nginx) or "nginx".
nft -c -f /etc/nftables.d/podman-apps.nft
install -m 0644 "$R/host/nftables/podman-apps-nft.service" /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now podman-apps-nft.service
nft list table inet podman_apps
```
On Debian with `nftables.service`, make sure `/etc/nftables.conf` does not start with `flush ruleset` reloaded after this unit, or include `/etc/nftables.d/podman-apps.nft` from it instead of using the dedicated unit.

## 6. SELinux (AlmaLinux)
```bash
getenforce                                              # Enforcing
semanage port -a -t http_port_t -p tcp 18000-18999      # Nginx may connect to application ports
setsebool -P httpd_can_network_relay 1
```

## 7. Journal
```bash
install -d -m 0755 /etc/systemd/journald.conf.d
printf '[Journal]\nStorage=persistent\nSplitMode=uid\n' > /etc/systemd/journald.conf.d/50-persistent.conf
systemctl restart systemd-journald
```

## 8. Per application
```bash
provision-app myapp
```
Then follow [operations.md](operations.md), section "First deployment".
