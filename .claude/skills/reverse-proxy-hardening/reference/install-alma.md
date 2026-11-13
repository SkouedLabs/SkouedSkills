# Installation: AlmaLinux / RHEL

Run as root. `R=` is the path holding the reference files adapted for the target. SELinux stays `Enforcing` throughout.

## 1. Nginx package source
```bash
getenforce                                  # Enforcing
dnf module list nginx 2>/dev/null           # AlmaLinux 9: pick the highest stream >= 1.26
dnf module enable -y nginx:1.26             # AlmaLinux 9 only; AlmaLinux 10 ships 1.26 without modules
```
If no stream ≥ 1.26 is available, use the nginx.org stable repository:
```bash
cat > /etc/yum.repos.d/nginx.repo <<'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=https://nginx.org/packages/centos/$releasever/$basearch/
gpgcheck=1
enabled=1
gpgkey=https://nginx.org/keys/nginx_signing.key
module_hotfixes=true
EOF
# dnf asks to import the key: compare its fingerprint with https://nginx.org/en/linux_packages.html.
```

## 2. Packages
```bash
dnf install -y epel-release
dnf config-manager --set-enabled crb
dnf install -y nginx fail2ban fail2ban-firewalld python3-systemd certbot policycoreutils-python-utils dnf-automatic
nginx -V 2>&1 | head -3 && openssl version
update-crypto-policies --show               # DEFAULT expected; FIPS changes the ssl_ecdh_curve list
```
Then run the CVE gate ([cve-check.md](cve-check.md)).

## 3. Nginx files
```bash
systemctl stop nginx 2>/dev/null
rm -f /etc/nginx/conf.d/default.conf
install -d -m 0755 /etc/nginx/snippets /etc/nginx/allowlists /var/www/acme /var/www/wellknown
install -m 0644 "$R/nginx/nginx.conf"           /etc/nginx/nginx.conf
install -m 0644 "$R/nginx/conf.d/"*.conf        /etc/nginx/conf.d/
install -m 0644 "$R/nginx/snippets/"*.conf      /etc/nginx/snippets/
install -m 0644 "$R/nginx/allowlists/admin.geo" /etc/nginx/allowlists/admin.geo
# AppStream package with dynamic modules: uncomment "include /usr/share/nginx/modules/*.conf;"
chown -R root:root /etc/nginx
chmod 0750 /var/log/nginx
restorecon -Rv /etc/nginx /var/www /var/log/nginx
```

## 4. SELinux
```bash
# Proxy to a local TCP upstream: label its port, then allow relaying (narrower than network_connect).
semanage port -a -t http_port_t -p tcp 8000 2>/dev/null || semanage port -m -t http_port_t -p tcp 8000
setsebool -P httpd_can_network_relay 1
# Upstreams on arbitrary ports or remote hosts: setsebool -P httpd_can_network_connect 1
# Custom content or certificate paths:
#   semanage fcontext -a -t httpd_sys_content_t '/srv/www(/.*)?' && restorecon -Rv /srv/www
#   semanage fcontext -a -t cert_t '/etc/nginx/tls(/.*)?'       && restorecon -Rv /etc/nginx/tls
ausearch -m AVC -ts recent | audit2why      # after each start/reload; must be empty
```

## 5. Certificate (first issuance)
```bash
# Comment the 443 server of the site file, then:
nginx -t && systemctl enable --now nginx
certbot certonly --webroot -w /var/www/acme -d app.example.com --key-type ecdsa \
  --deploy-hook "systemctl reload nginx"
ls -Z /etc/letsencrypt/live/app.example.com/   # readable by httpd_t (cert_t or etc_t)
# Uncomment the 443 server:
nginx -t && systemctl reload nginx
systemctl list-timers 'certbot*'
```

## 6. systemd sandbox and sysctl
```bash
install -D -m 0644 "$R/system/nginx-hardening.conf" /etc/systemd/system/nginx.service.d/hardening.conf
install -m 0644 "$R/system/60-net-hardening.conf"   /etc/sysctl.d/60-net-hardening.conf
sysctl --system
systemctl daemon-reload && systemctl restart nginx
systemctl reload nginx && nginx -s reopen && systemctl is-active nginx
```

## 7. firewalld
```bash
firewall-cmd --permanent --add-service=http --add-service=https
firewall-cmd --permanent --remove-service=cockpit --remove-service=dhcpv6-client
firewall-cmd --permanent --remove-service=ssh
firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.0.2.0/28 service name=ssh accept'   # ADAPT
firewall-cmd --reload && firewall-cmd --list-all
```

## 8. Fail2ban
```bash
install -m 0644 "$R/fail2ban/jail.local"                   /etc/fail2ban/jail.local
install -m 0644 "$R/fail2ban/fail2ban.local"               /etc/fail2ban/fail2ban.local
install -m 0644 "$R/fail2ban/jail.d/10-banaction.alma.conf" /etc/fail2ban/jail.d/10-banaction.conf
install -m 0644 "$R/fail2ban/filter.d/"*.conf              /etc/fail2ban/filter.d/
install -m 0644 "$R/fail2ban/action.d/nginx-deny.conf"     /etc/fail2ban/action.d/   # behind a load balancer only
touch /var/log/nginx/probe.log && restorecon -v /var/log/nginx/probe.log
fail2ban-client -t && systemctl enable --now fail2ban && systemctl restart fail2ban
fail2ban-client status
```

## 9. Exposed application: blocklist and WAF
Follow [waf.md](waf.md):
```bash
dnf install -y nftables          # nft CLI; the nftables service itself stays disabled under firewalld
install -d -m 0755 /etc/nft-blocklist
install -m 0644 "$R/blocklist/"{blocklist.nft,config.json,allow.list,manual.list} /etc/nft-blocklist/
install -m 0755 "$R/blocklist/nft-blocklist-update.py" /usr/local/sbin/nft-blocklist-update
install -m 0644 "$R/blocklist/"nft-blocklist*.{service,timer} /etc/systemd/system/
restorecon -Rv /etc/nft-blocklist /usr/local/sbin/nft-blocklist-update /etc/systemd/system
systemctl daemon-reload
systemctl enable --now nft-blocklist.service nft-blocklist-update.timer
systemctl start nft-blocklist-update.service && journalctl -u nft-blocklist-update -n 20
```

## 10. Updates
```bash
sed -i 's/^upgrade_type = .*/upgrade_type = security/; s/^apply_updates = .*/apply_updates = yes/' /etc/dnf/automatic.conf
systemctl enable --now dnf-automatic.timer
dnf needs-restarting -s          # services to restart after library updates
```

Then run [verification.md](verification.md).
