# Operations

All commands run as root. `APP=myapp`, `UID_APP=$(id -u $APP)`, `Q=/etc/containers/systemd/users/$UID_APP`.
Units are managed with `systemctl --user -M $APP@` (systemd ≥ 248); podman commands go through `app-podman`.

## First deployment
```bash
provision-app "$APP"

# Secrets (values from a file or a password manager, never on the command line)
app-podman "$APP" secret create myapp-db-password - < /root/secrets/myapp-db-password
app-podman "$APP" secret create myapp-app-key     - < /root/secrets/myapp-app-key
shred -u /root/secrets/myapp-*

# Quadlet files, root-owned
install -m 0644 myapp.pod myapp-*.container myapp-*.volume "$Q/"

# Validate the generated units as the account
sudo -u "$APP" env XDG_RUNTIME_DIR=/run/user/$UID_APP \
    QUADLET_UNIT_DIRS="$Q" /usr/libexec/podman/quadlet -dryrun -user

# Verify signatures and pull before starting
app-podman "$APP" pull registry.example.com/myapp/web@sha256:<digest>

systemctl --user -M "$APP@" daemon-reload
systemctl --user -M "$APP@" start myapp-pod.service
systemctl --user -M "$APP@" list-units 'myapp*'
```
Register the port block in `/etc/containers/ports.registry`, then add the Nginx upstream `127.0.0.1:18000` (skill `reverse-proxy-hardening`).

## Status and logs
```bash
systemctl --user -M "$APP@" status myapp-web.service
app-podman "$APP" ps --pod
app-podman "$APP" healthcheck run myapp-web && echo healthy
journalctl _UID="$UID_APP" --user-unit=myapp-web.service --since -1h
app-podman "$APP" top myapp-web user huser pid hpid               # container user vs host UID
```

## Update (new image digest)
1. Scan the new digest (`trivy image registry.example.com/myapp/web@sha256:<new>`), record the result.
2. Keep the current file: `cp $Q/myapp-web.container /root/rollback/myapp-web.container.$(date +%F)`.
3. Change `Image=` in `$Q/myapp-web.container`, then:
```bash
app-podman "$APP" pull registry.example.com/myapp/web@sha256:<new>
systemctl --user -M "$APP@" daemon-reload
systemctl --user -M "$APP@" restart myapp-web.service
systemctl --user -M "$APP@" is-active myapp-web.service && app-podman "$APP" healthcheck run myapp-web
```
Database migrations run as a one-shot container (`myapp-migrate.container` with `[Service] Type=oneshot`, same image, `Exec=` migration command) started before the web restart.

## Rollback
```bash
install -m 0644 /root/rollback/myapp-web.container.<date> "$Q/myapp-web.container"
systemctl --user -M "$APP@" daemon-reload && systemctl --user -M "$APP@" restart myapp-web.service
```
Schema migrations must be backward compatible for one release, otherwise rollback requires a database restore.

## Secret rotation
```bash
app-podman "$APP" secret create myapp-app-key-v2 - < /root/secrets/myapp-app-key-v2
sed -i 's/^Secret=myapp-app-key,/Secret=myapp-app-key-v2,/' "$Q/myapp-web.container"
systemctl --user -M "$APP@" daemon-reload && systemctl --user -M "$APP@" restart myapp-web.service
app-podman "$APP" secret rm myapp-app-key
```

## Backups
```bash
# Logical database dump, streamed to an encrypted destination
app-podman "$APP" exec myapp-db pg_dump -U myapp -d myapp -Fc \
  | age -r <backup-public-key> > /var/backups/myapp/db-$(date +%F).dump.age

# Volume export (service stopped for consistency)
systemctl --user -M "$APP@" stop myapp-web.service
app-podman "$APP" volume export myapp-uploads | age -r <backup-public-key> > /var/backups/myapp/uploads-$(date +%F).tar.age
systemctl --user -M "$APP@" start myapp-web.service
```
Restore test (scheduled, on a staging host): provision the same app, import the volume (`podman volume import`), restore the dump with `pg_restore`, run the verification checklist.

## Housekeeping
```bash
app-podman "$APP" image prune -f          # unused images only; never "system prune --volumes"
```

## Decommission
```bash
systemctl --user -M "$APP@" stop myapp-pod.service
# Back up data first, then:
rm -f "$Q"/myapp*
app-podman "$APP" system reset --force     # deletes all containers, images and volumes of the account
loginctl disable-linger "$APP"
userdel --remove "$APP"                    # also remove its lines from /etc/subuid and /etc/subgid
```
Free the port block in `/etc/containers/ports.registry` and remove the Nginx site.
