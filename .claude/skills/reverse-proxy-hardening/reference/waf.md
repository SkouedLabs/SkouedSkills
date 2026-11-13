# WAF and Blocklists for Exposed Applications

Applies when the application is reachable from the Internet (or any untrusted network). Internal-only proxies keep the baseline (rate limits, probe filtering, fail2ban) and skip this file unless asked.

Defense layers, from cheapest to most expensive per request:

| Layer | Component | Blocks |
|---|---|---|
| 1. Kernel (raw prerouting) | nftables `inet blocklist` table | Known-bad networks (threat feeds), operator blocks |
| 2. Kernel (filter) | fail2ban ban action | IPs caught misbehaving by the jails |
| 3. Nginx | maps, probe locations, rate limits, admin allowlist | Scanners, probes, floods, non-allowed admin access |
| 4. Nginx WAF | ModSecurity v3 + OWASP CRS v4 | Injection, XSS, RCE, protocol attacks in requests |
| 5. Application | validation, authorization | Everything else |

## 1. nftables Blocklist

Files in [blocklist/](blocklist/):

| File | Target |
|---|---|
| `blocklist.nft` | `/etc/nft-blocklist/blocklist.nft` (`0644 root:root`) |
| `config.json` | `/etc/nft-blocklist/config.json` |
| `allow.list`, `manual.list` | `/etc/nft-blocklist/` |
| `nft-blocklist-update.py` | `/usr/local/sbin/nft-blocklist-update` (`0755 root:root`) |
| `nft-blocklist.service`, `nft-blocklist-update.service`, `nft-blocklist-update.timer` | `/etc/systemd/system/` |

- Dedicated `inet blocklist` table hooked at `prerouting` priority `raw`: independent from firewalld, ufw and the fail2ban table, and a `drop` there is final whatever the other tables say. Works the same on Debian/Ubuntu and AlmaLinux (firewalld uses the nftables backend and leaves foreign tables alone).
- Sets: `allow4/6` (always accepted first), `manual4/6` (operator decisions with reason and date), `feed4/6` (threat feeds).
- **Default feeds:** Spamhaus DROP v4/v6 (hijacked and criminal networks, very low false-positive rate). FireHOL level1 is available but disabled: it includes bogons, so it is only safe because the updater discards private/reserved ranges; enable it after checking it does not cover a partner network.
- **Updater safeguards:** https only, download size cap, per-feed minimum entry count, refusal of a feed that shrinks by more than 50 %, private/reserved/too-wide prefixes discarded, CIDRs collapsed, `nft -c` dry run, then all sets replaced in a single transaction. A failing feed keeps its cached content, and the boot unit restores cached sets before the network starts.
- **Air-gapped:** point feed URLs to an internal mirror (still https) refreshed by a connected host.
- Blocking whole countries (GeoIP) is not part of the baseline: only on explicit request, with a documented business reason, via an extra set fed by a licensed GeoIP database.
- Operator workflow: add a line to `manual.list` with reason and date, then `systemctl start nft-blocklist-update`. Temporary blocks go through fail2ban (`fail2ban-client set <jail> banip <ip>`), not `manual.list`.

### Alternative: CrowdSec
For a fleet or when shared reputation is wanted, CrowdSec replaces the feed updater and complements fail2ban: the agent parses Nginx logs, the nftables firewall bouncer applies decisions and the community blocklist, and the AppSec component can act as a WAF. Keep one ban source per layer: either fail2ban or CrowdSec scenarios for log-based bans, not both on the same logs.

## 2. ModSecurity v3 + OWASP CRS

- **Engine:** OWASP ModSecurity v3 (libmodsecurity ≥ 3.0.12, maintained by OWASP since Trustwave's end of support in 2024) with the ModSecurity-nginx connector as a dynamic module. ModSecurity v2 is Apache-only.
- **Rules:** OWASP Core Rule Set v4, paranoia level 1, inbound anomaly threshold 5, outbound 4.
- **Packages:**
  - Debian/Ubuntu: `apt install libnginx-mod-http-modsecurity modsecurity-crs` with the **distro** Nginx package. The module is built for that exact binary; it does not load into nginx.org packages.
  - AlmaLinux: check `dnf search modsecurity` (EPEL). If no Nginx connector package matches the installed Nginx, build `ModSecurity-nginx` as a dynamic module (`./configure --with-compat --add-dynamic-module=...`) against the source of the exact installed Nginx version in CI, package it as an RPM and sign it. Never compile on the production host.
  - If the distro CRS package is older than the latest v4 release, install the release tarball after verifying its GPG signature.
- **Nginx:**

```nginx
# nginx.conf, main context
load_module modules/ngx_http_modsecurity_module.so;   # distro packages load it from modules-enabled/

# server or location context
modsecurity            on;
modsecurity_rules_file /etc/nginx/modsec/main.conf;
```

- **`/etc/nginx/modsec/main.conf`:**

```apache
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs-setup.conf
Include /etc/nginx/modsec/exclusions-before-crs.conf
Include /usr/share/modsecurity-crs/rules/*.conf
Include /etc/nginx/modsec/exclusions-after-crs.conf
```

- **`modsecurity.conf`** (from the recommended template) with:
  - `SecRuleEngine DetectionOnly` for the tuning period, then `On`.
  - `SecRequestBodyAccess On`, `SecRequestBodyLimit` equal to the largest `client_max_body_size` in bytes, `SecRequestBodyNoFilesLimit 131072`.
  - `SecResponseBodyAccess Off` (latency and memory; CRS outbound rules are optional).
  - `SecAuditEngine RelevantOnly`, `SecAuditLogParts ABIJDEFHZ`, `SecAuditLogFormat JSON`, `SecAuditLog /var/log/nginx/modsec_audit.log` (logrotate covers it). Audit logs contain request bodies: `0640`, short retention, treated as sensitive data.
  - `SecTmpDir` and `SecDataDir` under `/var/cache/modsecurity` owned by the worker user, added to `ReadWritePaths` of the systemd drop-in.
- **systemd drop-in:** libmodsecurity uses PCRE JIT, so remove `MemoryDenyWriteExecute=yes` from `nginx-hardening.conf` when the module is loaded.
- **`crs-setup.conf`:** `tx.blocking_paranoia_level=1`, `tx.inbound_anomaly_score_threshold=5`, `tx.allowed_methods` aligned with the Nginx method map, `tx.allowed_request_content_type` limited to what the application accepts.
- **Rollout:**
  1. `DetectionOnly` for 1 to 2 weeks of real traffic.
  2. Review the audit log by rule ID and URI; write narrow exclusions (`SecRuleUpdateTargetById` for one parameter, `ctl:ruleRemoveTargetById` for one location). Never disable a whole rule category or the engine for a whole site.
  3. Switch to `On`, enable the `nginx-modsecurity` fail2ban jail, keep monitoring false positives.
  4. Raise paranoia level only per sensitive location (admin, auth) after a new detection period.
- Excluded from inspection: WebSocket frames (not inspected by the connector) and large uploads above the body limit (Nginx limit applies first).
- Performance: measure p95 latency before and after enabling; the connector inspects in the worker, so size CPU accordingly.

## 3. Verification
- `nft list table inet blocklist` shows the six sets populated; `nft list chain inet blocklist prerouting` counters increase.
- `systemctl list-timers nft-blocklist-update.timer` shows the next run; `journalctl -u nft-blocklist-update` shows entry counts per feed.
- From an allowlisted IP added temporarily to `manual.list`: still reachable (allow wins).
- `curl "https://app.example.com/?q=<script>alert(1)</script>"` and `curl "https://app.example.com/?id=1%27%20OR%201=1--"` return `403` with the engine `On` and appear in `modsec_audit.log`.
- CRS regression: run `go-ftw` with the CRS test suite in a staging environment when upgrading CRS.
