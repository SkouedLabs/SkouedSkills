---
name: reverse-proxy-hardening
description: Use when installing, configuring or auditing an Nginx reverse proxy and Fail2ban directly on a Linux host (not in a container), on Debian/Ubuntu or AlmaLinux/RHEL. Produces an advanced hardened setup - live CVE gate on Nginx/OpenSSL at build time, modern TLS with hybrid post-quantum key exchange, catch-all default server, security headers, layered rate and connection limiting, method/user-agent/probe filtering, IP allowlists on admin endpoints, fail2ban jails with incremental bans and recidive, and for Internet-exposed apps a ModSecurity + OWASP CRS WAF and nftables threat-feed blocklists; plus systemd sandboxing, kernel network tuning, SELinux, ACME certificates and a verification procedure.
---
# Reverse Proxy Hardening (Nginx + Fail2ban, host install)

Generates an advanced, production-grade Nginx reverse proxy and Fail2ban configuration installed with the OS package manager on Debian/Ubuntu or AlmaLinux/RHEL. Sources: CIS Nginx Benchmark, Mozilla TLS guidelines, ANSSI TLS recommendations, dev-sec `nginx_hardening`, OWASP Secure Headers and Core Rule Set.

Scope: Nginx on the host, in front of one or more upstreams (local app, containers, other hosts). For an Nginx running inside a container stack, use the container's own configuration instead; this skill covers the host proxy in front of it.

## Reference files (copy, then adapt the values marked `ADAPT`)
Paths below mirror the target filesystem.
- [reference/nginx/nginx.conf](reference/nginx/nginx.conf): global and `http` context (TLS defaults, limits, logs, rate-limit zones, filtering and allowlist maps).
- [reference/nginx/conf.d/00-default.conf](reference/nginx/conf.d/00-default.conf): catch-all server rejecting unknown hosts.
- [reference/nginx/conf.d/app.example.com.conf](reference/nginx/conf.d/app.example.com.conf): virtual host template (HTTP redirect, TLS, per-location limits, admin allowlist, upstream).
- [reference/nginx/snippets/](reference/nginx/snippets/): `security-headers.conf`, `proxy-params.conf`, `block-probes.conf`, `acme.conf`.
- [reference/nginx/allowlists/admin.geo](reference/nginx/allowlists/admin.geo): networks allowed on admin endpoints.
- [reference/fail2ban/](reference/fail2ban/): `jail.local`, `fail2ban.local`, per-OS ban actions in `jail.d/`, custom filters in `filter.d/`, `action.d/nginx-deny.conf` (bans behind a load balancer).
- [reference/system/](reference/system/): systemd sandbox drop-in for `nginx.service`, sysctl network hardening.
- [reference/waf.md](reference/waf.md) and [reference/blocklist/](reference/blocklist/): WAF (ModSecurity v3 + CRS) and nftables threat-feed blocklist for exposed applications.
- [reference/cve-check.md](reference/cve-check.md): CVE gate run at build and audit time.
- [reference/install-debian.md](reference/install-debian.md) and [reference/install-alma.md](reference/install-alma.md): ordered installation commands per OS family.
- [reference/verification.md](reference/verification.md): mandatory checks before declaring the setup done.

## When to Use
- "Set up / harden Nginx", "reverse proxy", "rate limiting", "fail2ban", "WAF", "ModSecurity", "blocklist", "ban bots/scanners", "TLS config", "security headers" on a VM or bare-metal host.
- Auditing an existing host Nginx or Fail2ban configuration against this baseline.

## 0. Inputs
Decide from the request or the project; ask only for what cannot be inferred. Defaults in parentheses.
- OS and version (`/etc/os-release`), Nginx and OpenSSL versions (`nginx -V`, `openssl version`).
- Domain names and upstreams (`127.0.0.1:8000`), WebSocket paths, upload paths and max size (`1m` global).
- Login/auth endpoints and expensive endpoints (exports, search, reports).
- **Exposure:** Internet-exposed (default: WAF and blocklist included, section 10) or internal only; directly reachable (default) or behind a load balancer/CDN (its ranges become trusted proxies).
- Admin endpoints and the networks allowed to reach them (default: loopback only, so admin is closed until networks are listed); monitoring and admin IPs for `ignoreip`.
- Certificate source: ACME HTTP-01 with certbot (default), ACME DNS-01, or an internal CA.

## 1. Installation, Packages & CVE Gate
- **Version floor: Nginx ≥ 1.26** (`http2 on`, `ssl_reject_handshake`, two-stage `limit_req delay=`, HTTP/2 Rapid Reset fix). Use the distro package when it meets the floor (Debian 13, AlmaLinux 9 module `nginx:1.26`, AlmaLinux 10); otherwise the nginx.org **stable** repository with its signing key verified and an APT pin / `module_hotfixes`. Never build Nginx from source on the host or use a third-party PPA unless asked.
- **CVE gate (mandatory, live):** at every build, install, upgrade or audit, follow [cve-check.md](reference/cve-check.md): fetch the Nginx security advisories, the distro security tracker, OpenSSL advisories and the CISA KEV catalog **on the day**, compare with the installed packages (distro backports fixes without changing the upstream version) and with the modules/directives actually used (many Nginx advisories are conditional). Any applicable unfixed HIGH/CRITICAL or KEV entry blocks delivery until upgraded or mitigated. If the sources cannot be reached, report `CVE gate: not run (offline)`; never assume the host is up to date.
- **Air-gapped hosts:** packages come from an internal mirror (Nexus, Artifactory, Pulp, aptly); the same GPG key verification applies, and the CVE gate uses a mirrored vulnerability database.
- Install only what is used: no dynamic module loaded unless required. Remove the default site and the default HTML pages.
- Fail2ban from the distro (Debian/Ubuntu) or EPEL (AlmaLinux). Certbot from the same sources.
- Unattended security updates enabled (`unattended-upgrades` / `dnf-automatic` with `upgrade_type = security`), plus `needrestart` / `dnf needs-restarting` (a patched OpenSSL needs an Nginx restart).

## 2. Layout & Permissions
- Same layout on every OS: `nginx.conf` includes `conf.d/*.conf` only (one file per site, `00-default.conf` first), `snippets/` holds reusable blocks included explicitly, `allowlists/` holds IP allowlists. Do not use `sites-enabled/` symlinks.
- `/etc/nginx` owned `root:root`, directories `0755`, files `0644`; private keys `0600 root:root` (the master reads them before dropping privileges). Workers run as the unprivileged distro user (`www-data` on Debian/Ubuntu distro packages, `nginx` otherwise); that user owns nothing in `/etc/nginx`.
- Logs in `/var/log/nginx`, directory `0750`, rotated by the package's logrotate rule (covers every `*.log`, including `probe.log`).
- Upstreams listen on `127.0.0.1`/Unix sockets or a private network only, never on a public interface; the firewall exposes only 80, 443 and SSH from admin ranges.

## 3. TLS
- `TLSv1.2 TLSv1.3` with the Mozilla *intermediate* ECDHE + AEAD cipher list (no CBC, no RSA key exchange, no DHE so no `dhparam`). `TLSv1.3` only when every client is known to support it (internal, API-only).
- **Hybrid post-quantum key exchange:** `ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1:secp384r1` only when the OpenSSL linked to Nginx is ≥ 3.5; otherwise remove the first group (an unknown group prevents Nginx from starting).
- `ssl_session_tickets off`, shared session cache, `ssl_early_data off` (0-RTT is replayable).
- ECDSA P-256 certificates, full chain. Renewal is automated and reloads Nginx through a deploy hook.
- **Catch-all default server:** `ssl_reject_handshake on` on 443 and `return 444` on 80, so requests with an unknown `Host`/SNI never reach an application and scans by IP land in `probe.log`.
- HTTP vhost only serves the ACME challenge and a `301` to HTTPS. HSTS 2 years with `includeSubDomains`; `preload` only on explicit request.
- OCSP stapling only if the CA still publishes an OCSP URL in its certificates (Let's Encrypt no longer does).

## 4. HTTP Hardening
- `server_tokens off`, `autoindex off`, `ssi off`, explicit `server_name` on every server, no `if` other than `return`/`set`.
- **Request limits** (slow-loris and memory exhaustion): header/body timeouts 10 s, `send_timeout 10s`, `keepalive_timeout 15s`, `reset_timedout_connection on`, `client_max_body_size 1m` globally and raised only in upload locations, bounded header buffers.
- **Methods:** a `map` allows `GET HEAD POST PUT PATCH DELETE OPTIONS` (case-sensitive) and the server returns `405` for anything else; sensitive locations narrow further with `limit_except`.
- **Probe filtering** ([block-probes.conf](reference/nginx/snippets/block-probes.conf)): dotfiles (except `/.well-known/`), backups/dumps/keys, server-side script extensions, source maps, well-known scanner paths. Matches return `404` and are written to `/var/log/nginx/probe.log`, which feeds an aggressive Fail2ban jail. Remove any pattern the application legitimately serves.
- **Malicious requests:** maps flag scanner user agents, empty user agents, JNDI/`${` injection markers, encoded path traversal and null bytes; flagged requests get `444` (connection closed) and are logged to `probe.log`.
- **Security headers** at server level via [security-headers.conf](reference/nginx/snippets/security-headers.conf), all with `always`. A single layer owns the CSP: either the proxy (default) or the application, in which case remove it from the snippet. `X-XSS-Protection` is obsolete and not set.
- **Compression:** `gzip off` globally and enabled only for static assets (BREACH on responses mixing secrets and reflected input).

## 5. Admin Endpoints: IP Allowlist
- Every admin location (`/admin/`, `/api/v1/admin/`, management consoles, metrics, `/mcp/admin`) or a dedicated admin vhost is restricted by the `geo $admin_allowed` map fed by [allowlists/admin.geo](reference/nginx/allowlists/admin.geo): `if ($admin_allowed = 0) { return 404; }` (404 so the path is not confirmed).
- The allowlist is **in addition** to application authentication and MFA, never a replacement.
- Entries are specific networks (admin VPN egress, bastion), IPv4 and IPv6; never `0.0.0.0/0`, `::/0`, whole ISP or cloud-provider ranges. Each entry has an owner comment; the file is reviewed like any access right.
- Default content is loopback only: admin stays closed until the operator adds networks.
- Behind a load balancer the allowlist only works once `real_ip` is configured (otherwise every client appears as the LB, which would be allowlisted or blocked as a whole).
- Stronger option for highly sensitive admin: mTLS (`ssl_verify_client on` with an internal CA) on a dedicated admin vhost, or admin reachable only through the VPN interface (`listen <vpn-ip>:443`). For services without their own login, add `auth_basic` with bcrypt hashes (`htpasswd -B`), covered by the `nginx-http-auth` jail.
- Admin networks are also added to fail2ban `ignoreip` and to the nftables `allow.list` so an operator is never locked out by an automated ban.

## 6. Rate & Connection Limiting
- Zones in `http` keyed on `$rl_key`: `$binary_remote_addr` for clients, empty for exempt networks (`geo $rl_exempt`), so monitoring and internal ranges are never limited.

| Zone | Rate | Typical use | Burst |
|---|---|---|---|
| `req_global` | 30 r/s | Every location by default | 60 `nodelay` |
| `req_api` | 10 r/s | `/api/`, admin, WebSocket handshakes | 20 `delay=10` (two-stage) |
| `req_auth` | 5 r/m | Login, password reset, MFA, token endpoints | 5 `nodelay` |
| `req_heavy` | 1 r/s | Uploads, exports, search, reports | 5 `nodelay` |
| `conn_ip` | 64 concurrent | Server level (HTTP/2: each stream counts) | n/a |

- `limit_req_status 429` and `limit_conn_status 429`; rejections are logged at `error` level, which the `nginx-limit-req` jails read.
- Adapt rates to measured traffic (p99 per IP from access logs), never below what a single page load needs. Large NATs (corporate, mobile carriers) share one IP: raise `conn_ip` and `req_global` rather than exempting blindly.

## 7. Proxying
- One `upstream` block per backend with `keepalive`; [proxy-params.conf](reference/nginx/snippets/proxy-params.conf) included **inside each location** that proxies.
- At the edge, `X-Forwarded-For` is overwritten with `$remote_addr` (this proxy is the trust anchor); the backend trusts forwarded headers only from this proxy.
- **Behind a load balancer/CDN:** `set_real_ip_from` lists only the LB/CDN ranges, `real_ip_header X-Forwarded-For`, `real_ip_recursive on`. Without it, rate limits, allowlists and Fail2ban act on the LB address.
- `Proxy` header cleared (httpoxy), `X-Powered-By` hidden, `X-Request-ID` forwarded and logged, short connect timeout, no retry of non-idempotent requests.
- WebSockets via the `$connection_upgrade` map; long `proxy_read_timeout` only on WebSocket/streaming locations.
- TLS to remote upstreams: `proxy_ssl_verify on`, `proxy_ssl_trusted_certificate` with the internal CA, `proxy_ssl_server_name on`.

## 8. Logging
- `main_ext` format: `combined` prefix (parsed by Fail2ban) followed by request time, upstream address/time, host, request ID and TLS version. Optional JSON format for a SIEM in a separate file.
- Per-site access and error logs (`<site>.access.log`, `<site>.error.log`) plus the shared `probe.log`; Fail2ban globs `*access.log` and `*error.log`.
- No secrets in logs: never log `$http_authorization`, `$http_cookie` or request bodies in access logs; ModSecurity audit logs contain bodies and are `0640` with short retention.

## 9. Fail2ban
- Configuration only in `jail.local`, `fail2ban.local`, `jail.d/*.conf` and custom `filter.d`/`action.d` files; never edit `jail.conf` or stock filters.
- **Global policy:** `bantime 1h`, `findtime 10m`, `maxretry 5`, `bantime.increment` with `bantime.maxtime 1w` and `bantime.overalljails`, `dbpurgeage` ≥ `bantime.maxtime`, `ignoreip` = loopback + admin, monitoring and LB ranges.
- **Ban action:** `nftables-multiport`/`nftables-allports` on Debian/Ubuntu (works alongside ufw), `firewallcmd-ipset` on AlmaLinux (set-based, scales to thousands of IPs). Install exactly one of the files from `jail.d/`.
- **Jails:**

| Jail | Source | Trigger | Ban |
|---|---|---|---|
| `sshd` (aggressive) | journal | 4 failures / 10 min | incremental |
| `nginx-probe` | `probe.log` | 2 hits / 1 h | 1 day |
| `nginx-limit-req-auth` | `*error.log`, zone `req_auth` | 5 rejections / 10 min | 1 h |
| `nginx-limit-req` | `*error.log`, other zones | 30 rejections / 1 min | 1 h |
| `nginx-auth` | `*access.log`, login path returning 401/403 | 5 / 15 min | 1 h |
| `nginx-4xx` | `*access.log`, 400/401/403/404/405/444 | 40 / 2 min | 1 h |
| `nginx-http-auth` | `*error.log` (`auth_basic`) | 5 / 10 min | 1 h |
| `nginx-modsecurity` (exposed apps) | `*error.log`, WAF denials | 3 / 10 min | 6 h |
| `recidive` | `fail2ban.log` | 3 bans / 1 day | 1 week, all ports |

- `backend` is set per jail (`systemd` for sshd, `auto` for files), because some packages change the default backend to `systemd`, which silently disables file-based jails.
- **Behind a load balancer/CDN:** firewall bans would block the LB; use [action.d/nginx-deny.conf](reference/fail2ban/action.d/nginx-deny.conf) on HTTP jails (Nginx-level `geo` deny list, real client IP via `real_ip`), or push bans to the LB/CDN API.
- Every custom filter is validated with `fail2ban-regex` against real log lines before enabling it.

## 10. Exposed Applications: WAF & Blocklists
Applies by default to Internet-exposed applications; details in [waf.md](reference/waf.md).
- **nftables blocklist** ([blocklist/](reference/blocklist/)): dedicated `inet blocklist` table at `prerouting` priority `raw` (dropped before conntrack, Nginx and fail2ban; independent from firewalld/ufw), with `allow`, `manual` and `feed` sets. Feeds: Spamhaus DROP v4/v6 by default, FireHOL level1 optional. A hardened updater (https only, size cap, minimum entries, max 50 % shrink, private/reserved ranges discarded, `nft -c` dry run, single atomic transaction) runs every 6 hours from a systemd timer; cached sets are restored at boot before the network starts.
- **WAF:** ModSecurity v3 (OWASP-maintained libmodsecurity ≥ 3.0.12) + OWASP CRS v4, paranoia level 1, anomaly threshold 5. Rollout: `DetectionOnly` on real traffic, narrow exclusions per rule ID and parameter, then `On` with the `nginx-modsecurity` jail. The connector module must match the exact Nginx binary (distro module with distro Nginx, or built in CI against the installed version).
- **Alternative:** CrowdSec (log-based scenarios, community blocklist, nftables bouncer, AppSec WAF) for fleets; one ban source per layer.
- Country blocking only on explicit request with a documented reason.

## 11. OS Hardening Around the Proxy
- **systemd sandbox** ([nginx-hardening.conf](reference/system/nginx-hardening.conf)) as a drop-in: `ProtectSystem=strict`, minimal `CapabilityBoundingSet`, `SystemCallFilter=@system-service`, `RestrictAddressFamilies`, `NoNewPrivileges`. Check with `systemd-analyze security nginx`; reload and log reopen must still work.
- **sysctl** ([60-net-hardening.conf](reference/system/60-net-hardening.conf)): SYN cookies, larger backlogs, no redirects or source routing, reverse-path filtering, martian logging.
- **Firewall:** default deny inbound; 80/443 open; SSH limited to admin ranges. UDP 443 only if HTTP/3 is explicitly enabled (not part of this baseline).
- **SELinux (AlmaLinux):** stays `Enforcing`. Proxying needs a boolean (`httpd_can_network_relay` with the upstream port labeled `http_port_t`, or `httpd_can_network_connect`); custom paths are relabeled with `semanage fcontext` + `restorecon`. Never `setenforce 0` or `permissive` to make something work: read the AVC (`ausearch -m AVC -ts recent | audit2why`).
- **AppArmor (Debian/Ubuntu):** no Nginx profile ships by default; do not claim one is active.

## Expected Output
1. Detected or assumed inputs (section 0), chosen package source with versions, and the **CVE gate result** (date, versions, advisories reviewed, applicable unfixed issues).
2. All configuration files with their absolute target path. In a repository following a `deploy/` layout, place them under `deploy/host/` mirroring the filesystem (`deploy/host/etc/nginx/...`).
3. Ordered installation commands for the target OS from the matching install guide, including firewall, SELinux, certificate issuance and, for exposed apps, blocklist and WAF.
4. The verification checklist from [reference/verification.md](reference/verification.md) with real results, or `Not run` for each check that was not executed. Never invent results.

## Gotchas
- `add_header`, `proxy_set_header` and `limit_req` defined in a location **replace** all inherited ones. Keep headers at server level, include `proxy-params.conf` in every proxying location, and restate every `limit_req` a location needs.
- A regex location matches before prefix locations: `block-probes.conf` overrides `/api/` for `/api/.env` (intended), but also blocks any legitimate route matching a pattern (`/swagger`, `/actuator`, `/console`, `*.yml`). Review the snippet against the application routes.
- `nginx -t` before every reload; `systemctl reload` (not restart) keeps connections alive, but a library update (OpenSSL) needs a restart.
- First certificate issuance: the 443 server cannot reference a missing certificate. Enable the port-80 server alone, run `certbot certonly --webroot -w /var/www/acme`, then enable the 443 server.
- `ssl_ecdh_curve` with a group unknown to OpenSSL (MLKEM on OpenSSL < 3.5, X25519 in RHEL FIPS mode) prevents Nginx from starting. In FIPS mode use `prime256v1:secp384r1` (with `SecP256r1MLKEM768` first on OpenSSL ≥ 3.5).
- Comparing a distro package with an upstream advisory by version number gives false positives: always use the distro tracker's fixed version.
- Empty user agents and `curl`/`python-requests` are blocked or flagged only where no legitimate client uses them; health checks and monitoring often send no user agent and must be in `geo $rl_exempt` and `ignoreip`.
- Fail2ban `failregex` lines see the log line with the date removed: `[02/Nov/2026:10:00:00 +0000]` becomes `[]`, hence `\[\]` in the filters.
- `recidive` reads `/var/log/fail2ban.log`; `fail2ban.local` sets `logtarget` accordingly.
- Banning the load balancer IP takes the whole site down: real client IP first, Nginx-level bans second.
- Threat feeds such as FireHOL level1 include private ranges; loading them unfiltered cuts the host from its own network. The updater discards them, and `allow.list` always wins.
- ModSecurity in blocking mode without a detection period breaks legitimate forms and APIs; never disable the engine site-wide to fix a false positive.
- `MemoryDenyWriteExecute=yes` breaks `pcre_jit on` and some third-party modules; remove it only if such a module is required.
- OIDC/SAML cookies can exceed `large_client_header_buffers 4 8k` and return `400`; raise it to `4 16k` instead of disabling the limit.
