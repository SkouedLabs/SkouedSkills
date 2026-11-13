# Verification

Every check is run on the target (or staging) and its actual result reported. `H=app.example.com`, `IP=<public IP>`; run client-side checks from a non-allowlisted machine unless stated.

## Configuration
| Check | Command | Expected |
|---|---|---|
| Syntax | `nginx -t` | `syntax is ok`, `test is successful` |
| Effective config reviewed | `nginx -T` | No `autoindex on`, no `server_tokens on`, no `ssl_protocols` below TLSv1.2 |
| Listening sockets | `ss -tlnp` | Public: 80, 443 (and 22). Upstreams on 127.0.0.1 / private only |
| CVE gate | [cve-check.md](cve-check.md) | 0 applicable unfixed HIGH/CRITICAL, date recorded |

## TLS
| Check | Command | Expected |
|---|---|---|
| Protocols and ciphers | `testssl.sh --quiet --protocols --ciphers $H` | Only TLS 1.2/1.3, no CBC, forward secrecy everywhere |
| Hybrid PQ (OpenSSL ≥ 3.5 client) | `openssl s_client -connect $H:443 -groups X25519MLKEM768 -brief </dev/null` | `Negotiated TLS1.3 group: X25519MLKEM768` |
| Unknown SNI rejected | `openssl s_client -connect $IP:443 -servername unknown.invalid -brief </dev/null` | Handshake failure (`unrecognized name`) |
| Certificate renewal | `certbot renew --dry-run` | Success, deploy hook runs |

## HTTP behaviour
| Check | Command | Expected |
|---|---|---|
| Redirect | `curl -sI http://$H/` | `301` to `https://$H/` |
| Headers | `curl -sI https://$H/` | HSTS, CSP, nosniff, frame, referrer, permissions, COOP, CORP present; `Server: nginx` without version |
| Headers on errors | `curl -sI https://$H/does-not-exist` | Same security headers on the 404 |
| Bare IP | `curl -s -o /dev/null -w '%{http_code}\n' http://$IP/` | `000` (connection closed, 444) and a line in `probe.log` |
| Method filter | `curl -s -o /dev/null -w '%{http_code}\n' -X PROPFIND https://$H/` | `405` |
| Probe path | `curl -s -o /dev/null -w '%{http_code}\n' https://$H/.env` | `404` and a line in `probe.log` |
| Scanner UA | `curl -s -A 'sqlmap/1.8' https://$H/; echo $?` | Empty reply (curl exit 52) |
| JNDI marker | `curl -s "https://$H/?x=%24%7Bjndi:ldap://x%7D"; echo $?` | Empty reply (curl exit 52) |
| Source map | `curl -s -o /dev/null -w '%{http_code}\n' https://$H/assets/app.js.map` | `404` |
| Body limit | `head -c 2000000 /dev/zero \| curl -s -o /dev/null -w '%{http_code}\n' -X POST --data-binary @- https://$H/api/x` | `413` |

## Admin allowlist
| Check | Command | Expected |
|---|---|---|
| Non-allowed client | `curl -s -o /dev/null -w '%{http_code}\n' https://$H/admin/` | `404` |
| Allowed client (from an IP in `admin.geo`) | same command | Application response (login page or `401`) |
| Behind a load balancer | compare `$remote_addr` in the access log with the real client IP | Real client IP, not the LB |

## Rate limiting
```bash
for i in $(seq 1 15); do curl -s -o /dev/null -w '%{http_code}\n' -X POST https://$H/api/v1/auth/login; done | sort | uniq -c
```
Expected: the first requests reach the application (`401`/`400`), then `429`; `limiting requests ... zone "req_auth"` lines in the site error log.

Load test of the global zone (staging only): `hey -z 20s -c 50 https://$H/` shows `429` above the configured rate and no `5xx`.

## Fail2ban
| Check | Command | Expected |
|---|---|---|
| Config | `fail2ban-client -t` | `OK: configuration test is successful` |
| Jails active | `fail2ban-client status` | sshd, nginx-probe, nginx-limit-req-auth, nginx-limit-req, nginx-auth, nginx-4xx, nginx-http-auth, recidive |
| Filters match real lines | `fail2ban-regex /var/log/nginx/probe.log /etc/fail2ban/filter.d/nginx-probe.conf` | `Lines: N lines, 0 ignored, N matched` |
| | `fail2ban-regex /var/log/nginx/app.example.com.access.log /etc/fail2ban/filter.d/nginx-auth.conf` | Failed logins matched, successful ones not |
| | `fail2ban-regex /var/log/nginx/app.example.com.error.log 'nginx-limit-req[ngx_limit_req_zones="req_auth"]'` | Rate-limit rejections matched |
| End-to-end ban | from a throwaway client: 2 probe requests, then `fail2ban-client status nginx-probe` | Client IP listed; new connections time out |
| Ban in firewall | Debian/Ubuntu: `nft list table inet f2b-table`; AlmaLinux: `firewall-cmd --get-ipsets` and `ipset list` / `firewall-cmd --info-ipset=f2b-nginx-probe` | Banned IP present |
| Unban | `fail2ban-client set nginx-probe unbanip <ip>` | Access restored |
| ignoreip | repeat probes from an admin IP | Never banned |

## Host
| Check | Command | Expected |
|---|---|---|
| systemd sandbox | `systemd-analyze security nginx` | Exposure clearly lower than without the drop-in (record the score) |
| Reload and log reopen | `systemctl reload nginx && nginx -s reopen && systemctl is-active nginx` | `active`, no error in the journal |
| sysctl | `sysctl net.ipv4.tcp_syncookies net.ipv4.conf.all.accept_redirects` | `1`, `0` |
| SELinux (AlmaLinux) | `getenforce; ausearch -m AVC -ts today` | `Enforcing`, no nginx/fail2ban denial |
| Permissions | `stat -c '%U:%G %a %n' /etc/nginx /etc/nginx/nginx.conf <key file>` | `root:root 755`, `root:root 644`, key `600` |

## Exposed application (blocklist and WAF)
See the verification section of [waf.md](waf.md).

## Report format
`check | command | expected | actual | pass/fail`, plus the CVE gate line and the `testssl.sh` summary. Checks not executed are listed as `Not run` with the reason.
