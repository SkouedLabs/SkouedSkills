# Secure App & Offline AI Skills

Claude Code skills that make the assistant produce secure-by-design (ANSSI/CIS/FBI/OWASP ASVS), offline-first and consistently structured applications, in English by default.

## Content
| Path | Purpose |
|---|---|
| `CLAUDE.md` | Global rules: skill routing, English by default, no change-log comments, precedence, git limits. |
| `.claude/skills/secure-app-scaffolder/` | Hardened rootless stack, authorization, uploads, encryption, auth (OIDC/LDAPS/WebAuthn), tamper-evident audit, supply chain (SBOM, cosign, Trivy, OpenSCAP), MCP endpoints. `reference/` holds compose, Nginx and security-test templates. |
| `.claude/skills/offline-llm-orchestrator/` | Ollama / OpenAI-compatible connectors, model integrity, internal CA, RAG isolation, prompt-injection and exfiltration defenses, opt-in agent mode, MCP. |
| `.claude/skills/reverse-proxy-hardening/` | Host-installed Nginx reverse proxy and Fail2ban on Debian/Ubuntu and AlmaLinux: live CVE gate, TLS with hybrid PQ, rate limiting, probe filtering, admin IP allowlists, jails, ModSecurity + CRS WAF, nftables threat-feed blocklist, systemd sandbox, SELinux. `reference/` holds ready-to-adapt configuration files and install/verification guides. |
| `.claude/skills/rootless-quadlet-deploy/` | Production deployment with rootless Podman Quadlet: one non-login service account per app, non-root container processes on subordinate UIDs, pods, hardened read-only containers, ports on 127.0.0.1 reachable by the reverse proxy only (nftables owner match), signed digest-pinned images, secrets, backups, operations and verification. |
| `.claude/skills/deep-cleanup/` | Inventory-first pre-production cleanup: debug code, AI change-log comments, mock data, secrets (tree, history, image layers), PII, metadata, IPs. |
| `.claude/skills/project-blueprint/` | Canonical layout, naming, Makefile targets, code conventions, README template (`templates/README.md`), standard frontend shell and daily-use UX. |
| `examples/wiki/` | Complete kickoff example: functional specification and phase-by-phase prompts for a secure wiki. |

## Usage
Copy `CLAUDE.md` and `.claude/skills/` into the target project, add a `docs/specification.md`, then ask Claude Code for the task. Skills also trigger automatically from their descriptions. See [examples/wiki/README.md](examples/wiki/README.md) for a full walkthrough.
