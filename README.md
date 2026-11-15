# DuckSecrets

**Zero-bloat self-hosted secrets operations for modern engineering teams.**

Deploy a complete secrets vault, dynamic credential broker, automated secret rotation engine, and private network tunnel gateway in **one single static binary**—no Redis, no ZooKeeper, no external database required to start, and zero SaaS lock-in.

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Commercial License](https://img.shields.io/badge/Enterprise-Pro%20%26%20Business-7c3aed.svg)](LICENSE-EE)

---

## Why Teams Switch to DuckSecrets

Legacy secret managers force an uncomfortable trade-off: brittle `.env` files scattered across laptops and CI runners, or heavy distributed stacks requiring dedicated ops teams, multiple containers, and mandatory SaaS telemetry.

**DuckSecrets** gives security and platform teams enterprise-grade control with desktop-simple deployment:

| Capability | `.env` Files | Heavy Multi-Service Vaults | **DuckSecrets** |
| :--- | :---: | :---: | :--- |
| **Deployment footprint** | Ad-hoc files | 3–6+ containers + external DB | **1 static binary** (~20 MB) or single Docker container |
| **Embedded database + HA upgrade** | — | External DB mandatory | **SQLite out-of-the-box** + 1-click live migration to **PostgreSQL** |
| **Dynamic JIT credentials** | No | Complex plugin setup | **Built-in** (PostgreSQL, MySQL, Redis, Linux PAM) with auto-lease reaper |
| **Private VPC/NAT access** | VPN / bastion host | Separate agent infrastructure | **Network Sites** — built-in outbound WebSocket reverse tunnels |
| **Managed localhost dev tunnels** | Manual SSH tunnels | External proxies | **`ducksecrets connect`** — ephemeral localhost proxy injecting JIT creds |
| **Zero-knowledge ephemeral shares** | Slack/email plaintext | Often separate add-on | **Client-side AES-256-GCM burn-after-reading bundles** built in |
| **Automated rotation + verification** | Manual | Enterprise tier only | **Built-in scheduler** with rollback-on-failed-probe safety |
| **Offline air-gapped operation** | Yes | Often phones home | **100% air-gapped** (embedded assets, offline Ed25519 licensing) |

---

## Built for Real Production Workflows

- **Hierarchical Secret Vault**: Projects → Environments (`development`, `staging`, `production`, custom) → Nested Folders → Versioned Key-Value Secrets with diffing, instant rollback, masked UI views, and `${REF}` / dynamic interpolation.
- **Just-In-Time Dynamic Secrets**: Issue short-lived database and OS credentials (`PostgreSQL`, `MySQL`, `Redis`, `Linux PAM`) on demand and automatically revoke leases when they expire or when a session closes.
- **Network Sites & Managed Tunnels**: Connect isolated staging or production databases behind NAT/firewalls without opening inbound ports using reverse-tunnel **Site Connectors** and `ducksecrets connect`.
- **Safe Automated Rotation**: Rotate secrets on schedule and validate health via HTTP, TCP, or command verifiers before committing—automatically rolling back if a health check fails.
- **Tamper-Evident Audit Chain**: Every read, write, export, share, lease, and system change is recorded in an **HMAC-SHA256 hash-chained audit log** with integrity verification.
- **CI/CD Ready (`ducksecrets` CLI)**: Inject secrets directly into subprocesses (`ducksecrets run -- ...`) without touching disk, export `.env`/`json`/`yaml`, or scope machine tokens (`duck_st_*`) by IP CIDR allowlists and single-use execution.
- **Hardened Operations Out of the Box**:
  - **First-Login Admin Onboarding**: Set your administrator username and password securely in the browser on initial boot (or pre-seed via `DUCKSECRETS_ADMIN_PASSWORD` for unattended automation).
  - **Self-Signed TLS at Install + Hot-Reload Custom Certs**: Packages automatically provision an ECDSA P-256 self-signed certificate; upload your own PEM certificate/key in the UI with live zero-downtime hot reload, or run plain HTTP behind **Nginx / Caddy / Traefik** (`X-Forwarded-*` + WebSocket support; see [deploy/nginx/ducksecrets.conf](deploy/nginx/ducksecrets.conf)).
  - **Verified Self-Updates**: Check and apply updates directly from `latest` public releases with automatic `SHA256SUMS` verification (`ducksecrets update`, `ducksecretsd update`, or Web UI).

---

## Install in Under 60 Seconds

Download installers and static binaries from the [**Releases page**](https://github.com/leandrofus/ducksecrets-ce/releases/latest):

### Debian / Ubuntu (`.deb`)

```sh
curl -fsSLO https://github.com/leandrofus/ducksecrets-ce/releases/latest/download/ducksecrets-0.2.1-linux-amd64.deb
sudo dpkg -i ducksecrets-0.2.1-linux-amd64.deb
sudo systemctl enable --now ducksecrets
```

### RHEL / Rocky / Alma / Fedora (`.rpm`)

```sh
sudo dnf install -y https://github.com/leandrofus/ducksecrets-ce/releases/latest/download/ducksecrets-0.2.1-linux-amd64.rpm
sudo systemctl enable --now ducksecrets
```

> Linux packages install both `ducksecrets` (CLI) and `ducksecretsd` (server), configure the `ducksecrets` systemd service, generate a self-signed TLS certificate at `/etc/ducksecrets/tls.crt`, and store environment overrides in `/etc/ducksecrets/env`.

### Windows (`.msi`)

Download `ducksecrets-0.2.1-windows-amd64.msi` from [**Releases**](https://github.com/leandrofus/ducksecrets-ce/releases/latest) to install `ducksecrets.exe` and `ducksecretsd.exe` into `C:\Program Files\DuckSecrets`.

### Docker / Docker Compose

```sh
curl -fsSLO https://raw.githubusercontent.com/leandrofus/ducksecrets-ce/main/docker-compose.yml
docker compose up -d
# Or with dedicated PostgreSQL backend (set AUDIT_KEY and ENCRYPTION_KEY):
docker compose --profile postgres up -d
```

> Pulls the prebuilt multi-arch `ghcr.io/leandrofus/ducksecrets-ce:latest` image, persists data in `/data`, and auto-provisions self-signed HTTPS by default.

### First Login & Reverse Proxy

1. Open `https://<your-host>:8080` (or your reverse-proxy HTTPS domain).
2. Complete the **Initial Administrator Setup** form in the browser to define your admin password (automatically locks after completion).
3. Behind Nginx, Caddy, or Traefik terminating TLS, set `DUCKSECRETS_TLS_MODE=off` and `DUCKSECRETS_TRUSTED_PROXIES=127.0.0.1/8,::1/128` in `/etc/ducksecrets/env` (see [deploy/nginx/ducksecrets.conf](deploy/nginx/ducksecrets.conf)).

### Verified Auto-Update

Keep both CLI and daemon up to date against the latest verified `ducksecrets-ce` release (`SHA256SUMS` checked before replacing binaries):

```sh
ducksecrets update            # update developer CLI
sudo ducksecretsd update      # update server daemon, then: sudo systemctl restart ducksecrets
```

Administrators can also check and apply server updates directly under **License & System** in the Web UI.

---

## Open-Core Editions

DuckSecrets ships as a single unified build with **zero phone-home telemetry**:

| Feature / Quota | Community (`Apache-2.0`) | Pro | Business |
| :--- | :---: | :---: | :---: |
| Core KV secrets, folders, versions, diff & rollback | Included | Included | Included |
| Dynamic secret engines (`PostgreSQL`, `MySQL`, `Redis`, `PAM`) | Included | Included | Included |
| Automated rotation policies & verification probes | Included | Included | Included |
| HMAC-SHA256 audit chain & zero-knowledge ephemeral shares | Included | Included | Included |
| RBAC, project policies & CIDR-scoped service tokens (`duck_st_*`) | Included | Included | Included |
| Embedded SQLite + live PostgreSQL migration | Included | Included | Included |
| First-login setup, TLS management & verified autoupdate | Included | Included | Included |
| **Network Sites (reverse tunnel gateways)** | **Up to 2** | **Up to 25** | **Unlimited** |
| OIDC / OAuth2 Single Sign-On (`sso.oidc`) | — | Included | Included |
| Kubernetes & automated secret sync (`sync.kubernetes`) | — | Included | Included |
| Vault master key rotation (`vault.master_key_rotation`) | — | Included | Included |
| SAML 2.0 / SCIM / LDAP (`sso.saml`) | — | — | Included |
| Approval workflows / two-person rule (`governance.approvals`) | — | — | Included |
| External KMS / HSM auto-unseal (`vault.external_kms`) | — | — | Included |
| Compliance audit export (`audit.export`) | — | — | Included |

- **Community Edition needs no license key** and never expires.
- **Pro & Business** unlock cleanly offline with a cryptographically signed **Ed25519 license key (`dkl1...`)** via `-license-key`, `$DUCKSECRETS_LICENSE_KEY`, or **Admin → License** in the Web UI. See [LICENSE](LICENSE) and [LICENSE-EE](LICENSE-EE).

---

## Building from Source

Prerequisites: **Go 1.26+** and **Bun**.

```sh
make dev                  # Run gateway (:8080) + Vite hot-reload UI (:5173)
./scripts/check.sh        # Full verification: gofmt, vet, tests, OpenAPI, sqlc, tsc
make build                # Build standalone UI-embedded binaries in dist/bin/
make packages             # Build static multi-arch binaries + .deb, .rpm, .msi in dist/
```

<details>
<summary>Architecture & Repository Layout</summary>

```text
├── gateway/
│   ├── cmd/ducksecrets/       # Developer & CI/CD CLI (zero server/DB imports)
│   ├── cmd/ducksecretsd/      # Single-binary server daemon + embedded React UI
│   ├── cmd/openapi-gen/       # Contract-first OpenAPI 3.0 AST generator
│   ├── internal/vault & crypto/ # AES-256-GCM vault & HKDF/Argon2id key derivation
│   ├── internal/auth/         # Sessions, bcrypt, RBAC, CIDR-scoped service tokens
│   ├── internal/audit/        # HMAC-SHA256 tamper-evident log
│   ├── internal/dynamic/      # PostgreSQL, MySQL, Redis, PAM dynamic secret drivers
│   ├── internal/rotation/     # Scheduled rotation + HTTP/TCP/script rollback probes
│   ├── internal/sites/        # Yamux/WebSocket reverse tunnel site gateways
│   ├── internal/tlsutil/      # Install-time self-signed TLS & live PEM hot-reload
│   ├── internal/selfupdate/   # SHA256-verified self-update engine
│   └── internal/license/      # Offline Ed25519 Open-Core entitlement verification
├── web/                       # Air-gapped React 19 + TypeScript UI
├── deploy/                    # systemd service, packaging (nfpm/WiX), Nginx reverse proxy
└── scripts/                   # CI checks, .deb/.rpm/.msi packager, OSS publisher
```

</details>

---

## License

- Core platform source code: [**Apache License 2.0**](LICENSE).
- Commercial editions & enterprise modules: [**LICENSE-EE**](LICENSE-EE).
