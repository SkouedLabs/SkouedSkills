# Installation: Debian / Ubuntu

Run as root. `R=` is the path holding the reference files adapted for the target.

## 1. Nginx package source
```bash
apt-cache policy nginx        # distro candidate version
```
- Candidate ≥ 1.26 (Debian 13 and later): use the distro package, go to step 2.
- Otherwise (Debian 12, Ubuntu 24.04): nginx.org **stable** repository.

```bash
apt install -y curl gnupg2 ca-certificates lsb-release debian-archive-keyring   # Ubuntu: ubuntu-keyring
curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor -o /usr/share/keyrings/nginx-archive-keyring.gpg
gpg --dry-run --quiet --no-keyring --import --import-options import-show /usr/share/keyrings/nginx-archive-keyring.gpg
# Compare the fingerprints with https://nginx.org/en/linux_packages.html before continuing.

. /etc/os-release
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://nginx.org/packages/${ID} ${VERSION_CODENAME} nginx" \
  > /etc/apt/sources.list.d/nginx.list
printf 'Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n' > /etc/apt/preferences.d/99nginx
apt update
```
ModSecurity (`libnginx-mod-http-modsecurity`) only works with the distro package: see [waf.md](waf.md) before choosing nginx.org.

## 2. Packages
```bash
apt install -y nginx fail2ban python3-systemd nftables certbot unattended-upgrades needrestart
nginx -V 2>&1 | head -3 && openssl version
```
Then run the CVE gate ([cve-check.md](cve-check.md)).

## 3. Nginx files
```bash
systemctl stop nginx
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf
install -d -m 0755 /etc/nginx/snippets /etc/nginx/allowlists /var/www/acme /var/www/wellknown
install -m 0644 "$R/nginx/nginx.conf"                 /etc/nginx/nginx.conf
install -m 0644 "$R/nginx/conf.d/"*.conf              /etc/nginx/conf.d/
install -m 0644 "$R/nginx/snippets/"*.conf            /etc/nginx/snippets/
install -m 0644 "$R/nginx/allowlists/admin.geo"       /etc/nginx/allowlists/admin.geo
sed -i 's/^user nginx;/user www-data;/' /etc/nginx/nginx.conf          # distro package only
# Distro package with dynamic modules: uncomment "include /etc/nginx/modules-enabled/*.conf;"
chown -R root:root /etc/nginx
chmod 0750 /var/log/nginx
```

## 4. Certificate (first issuance)
```bash
# Comment the 443 server of the site file, then:
nginx -t && systemctl start nginx
certbot certonly --webroot -w /var/www/acme -d app.example.com --key-type ecdsa \
  --deploy-hook "systemctl reload nginx"
# Uncomment the 443 server:
nginx -t && systemctl reload nginx
systemctl list-timers 'certbot*'      # renewal timer present
```
Internal CA: install the certificate and key as `/etc/nginx/tls/<site>.{crt,key}`, key `0600 root:root`.

## 5. systemd sandbox and sysctl
```bash
install -D -m 0644 "$R/system/nginx-hardening.conf" /etc/systemd/system/nginx.service.d/hardening.conf
install -m 0644 "$R/system/60-net-hardening.conf"   /etc/sysctl.d/60-net-hardening.conf
sysctl --system
systemctl daemon-reload && systemctl restart nginx
systemctl reload nginx && nginx -s reopen && systemctl is-active nginx
```

## 6. Firewall
nftables (Debian default) or ufw (Ubuntu default): use one.
```bash
# ufw
ufw default deny incoming
ufw default allow outgoing
ufw allow from 192.0.2.0/28 to any port 22 proto tcp     # ADAPT: admin range
ufw allow 80,443/tcp
ufw enable
```
With plain nftables, write `/etc/nftables.conf` with an `inet filter` input chain (policy drop; established/related, lo, ICMP/ICMPv6 essentials, 22 from admin set, 80/443 accept) and `systemctl enable --now nftables`.

## 7. Fail2ban
```bash
install -m 0644 "$R/fail2ban/jail.local"                     /etc/fail2ban/jail.local
install -m 0644 "$R/fail2ban/fail2ban.local"                 /etc/fail2ban/fail2ban.local
install -m 0644 "$R/fail2ban/jail.d/10-banaction.debian.conf" /etc/fail2ban/jail.d/10-banaction.conf
install -m 0644 "$R/fail2ban/filter.d/"*.conf                /etc/fail2ban/filter.d/
install -m 0644 "$R/fail2ban/action.d/nginx-deny.conf"       /etc/fail2ban/action.d/   # behind a load balancer only
touch /var/log/nginx/probe.log
fail2ban-client -t && systemctl enable --now fail2ban && systemctl restart fail2ban
fail2ban-client status
```

## 8. Exposed application: blocklist and WAF
Follow [waf.md](waf.md):
```bash
install -d -m 0755 /etc/nft-blocklist
install -m 0644 "$R/blocklist/"{blocklist.nft,config.json,allow.list,manual.list} /etc/nft-blocklist/
install -m 0755 "$R/blocklist/nft-blocklist-update.py" /usr/local/sbin/nft-blocklist-update
install -m 0644 "$R/blocklist/"nft-blocklist*.{service,timer} /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now nft-blocklist.service nft-blocklist-update.timer
systemctl start nft-blocklist-update.service && journalctl -u nft-blocklist-update -n 20
```

## 9. Updates
```bash
dpkg-reconfigure -plow unattended-upgrades
# nginx.org origin is not a security origin: add it to Unattended-Upgrade::Origins-Pattern
# ("origin=nginx,codename=${distro_codename}") or upgrade it on a fixed cadence.
```

Then run [verification.md](verification.md).
