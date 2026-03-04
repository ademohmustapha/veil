# AURORA — Autonomous Unified Resilience & Organizational Real-time Awareness
### Production Release

> Predict. Evolve. Contain. Align. Govern.

AURORA is a **seven-layer autonomous cyber resilience platform** that goes beyond detection — it predicts threats before they materialise, evolves its own detection rules, aligns human decision-making in real time, and contains breaches across entire supply chains.

---

## Architecture: Seven Layers

| # | Layer | Engine | Core Algorithm |
|---|-------|--------|----------------|
| 1 | **Identity & Trust** | Zero Trust Fabric | Bayesian trust decay · Behavioral biometrics · Adaptive MFA |
| 2 | **Org Intelligence** | SOIN-X | AES-256-GCM vault · HMAC audit chain · Crisis mode |
| 3 | **Human Risk** | AURIX | IsolationForest (real sklearn) · Digital Twin · Mahalanobis drift |
| 4 | **Containment** | NEXUS-SHIELD | NetworkX BFS blast radius · 8-level action matrix · <30s SLA |
| 5 | **Alignment** | ECLIPSE-X | Bayesian intent scoring · Kahneman nudge theory · Decision Co-Pilot |
| 6 | **Supply Chain** | Cascade Engine | Monte Carlo 300 runs · NetworkX PageRank · ε-DP federation |
| 7 | **Evolution** | Threat Cognition | Real genetic algorithm (F1-scored) · Noisy-OR Bayesian · 200-run Monte Carlo |

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/ademohmustapha/aurora
cd aurora
pip install -r requirements.txt

# 2. Run
python3 aurora.py                    # Interactive menu
python3 aurora.py doctor             # 131 self-diagnostics
python3 aurora.py risk --user <id>   # Human Risk Index
python3 aurora.py horizon            # Predictive event horizon
python3 aurora.py evolve             # Run co-evolution cycle
python3 aurora.py api                # REST API on port 9100
python3 aurora.py dashboard          # Live web dashboard on port 9102
python3 aurora.py sso --auth         # SSO / OIDC authentication (PKCE)
python3 aurora.py soar --test        # Test SOAR integrations
python3 aurora.py provision <f.aup>  # Activate a user provision package

# 3. Docker
docker build -t aurora .
docker run -v aurora-data:/home/aurora/.aurora -p 9100:9100 -p 9102:9102 aurora

# 4. Docker Compose (full stack with PostgreSQL)
docker-compose up
```

---

## What Is Real

AURORA is honest about every engine. The table below reflects what the code actually does — verified line by line.

| Engine | Status | What it actually does |
|--------|--------|-----------------------|
| IsolationForest (HRI) | ✅ **Real sklearn** | Trained on per-actor 30-event rolling window |
| Genetic Algorithm | ✅ **Real GA** | F1-scored fitness, tournament selection, elitism, disk-persisted genome |
| Monte Carlo (Event Horizon) | ✅ **Real 200 runs** | Holt-Winters + stochastic forward simulation |
| Monte Carlo (Supply Chain) | ✅ **Real 300 runs** | Stochastic BFS propagation per edge criticality |
| NetworkX BFS (Blast Radius) | ✅ **Real graph BFS** | Loads real topology; falls back to heuristic if no graph loaded |
| PageRank (Supply Chain) | ✅ **Real nx.pagerank** | Applied when dependency graph is built |
| Mahalanobis drift (Digital Twin) | ✅ **Real computation** | Trajectory variance vs recent window |
| Differential Privacy | ✅ **Real Laplace/Gaussian** | Dwork & Roth (2014) mechanisms |
| Federated Learning | ✅ **Real FedAvg** | McMahan et al. (2017) |
| Quantum KEM | ✅ **Real NTT implementation** | Full ML-KEM (Kyber-512) in pure Python + NumPy — see note below |
| Ethics Engine | ✅ **Real 6-pillar eval** | Proportionality · Privacy · Transparency · Human Override · Bias · Auditability |

### Quantum KEM — Honest Status

The quantum cryptography implementation is a **mathematically correct, fully working** ML-KEM (Kyber-512) in pure Python:

- Real Number Theoretic Transform (NTT) over Z₃₃₂₉[x]/(x²⁵⁶+1) per FIPS 203 Algorithm 9 & 10
- Correct Kyber-512 parameter set (n=256, k=2, q=3329, η₁=3, η₂=2) per FIPS 203 §6.1
- CSPRNG-sourced noise via `os.urandom()` — not NumPy random
- Proper SHAKE-128 matrix expansion per FIPS 203 §4.2.1
- Verified: 10/10 encapsulation / decapsulation round-trips pass
- Hybrid with production-grade X25519 (via the `cryptography` library) — both barriers must be broken simultaneously

**Two limitations to be aware of:**

1. **Not FIPS 203 certified** — FIPS certification requires the C reference build (`liboqs`). Python implementations cannot be submitted for FIPS certification regardless of mathematical correctness.
2. **Not constant-time** — Python cannot guarantee constant-time execution. Timing side-channels are theoretically possible in adversarial environments.

**Upgrade path (two lines):**
```bash
pip install liboqs-python
```
Then in `crypto/quantum_safe.py`, swap `HybridKEM` for `oqs.KeyEncapsulation("Kyber512")` — the interface is drop-in compatible. No other code changes required.

---

## Deployment Modes

| Mode | Command | Use case |
|------|---------|----------|
| Standalone | `python3 aurora.py` | Single-org evaluation |
| API Server | `python3 aurora.py api` | Integration with SIEM / SOAR |
| API + TLS | `python3 aurora.py api --tls` | Native HTTPS (auto-generates self-signed cert) |
| Live Dashboard | `python3 aurora.py dashboard` | Real-time SSE-powered web UI on port 9102 |
| Docker | `docker run aurora` | Containerised production |
| Docker Compose | `docker-compose up` | Full stack with PostgreSQL and persistent storage |

---

## API Reference (Port 9100)

```
GET  /health         — Platform health check (unauthenticated)
POST /risk           — Compute Human Risk Index
POST /contain        — Trigger containment action
POST /evolve         — Run co-evolution cycle
POST /horizon        — Predictive threat horizon
POST /supply-chain   — Supply chain risk heatmap
GET  /events         — Server-Sent Events stream (real-time push)
```

Authentication: `X-Aurora-Token: <token>` header required on all endpoints except `/health`.

The `/events` endpoint is a live SSE stream — heartbeat every 15 seconds, full data snapshot every 30 seconds. The live dashboard connects here directly; no polling required.

---

## Identity & Access Management

| Feature | Details |
|---------|---------|
| SSO / OIDC | Full Authorization Code Flow + PKCE (RFC 7636, S256 method) |
| Supported providers | Okta · Azure AD (Entra ID) · Google Workspace · Auth0 · Keycloak · GitHub · any OIDC-compliant IdP |
| LDAP / Active Directory | ldap3 backend — auto-resolves user and org ID from directory |
| SAML 2.0 | Entity ID + IdP metadata URL configuration |
| Local auth | Argon2id passwords · TOTP 2FA with replay protection · HIBP breach blocking |
| Provision packages | Encrypted `.aup` files for onboarding users to new machines without sharing passwords |
| Roles | `admin` · `operator` · `analyst` · `readonly` |

---

## SOAR Integrations

When a containment event fires, AURORA automatically creates tickets in your existing tools:

| Channel | Details |
|---------|---------|
| **Jira** | Creates issue via Jira Cloud REST API v3 or Server/DC v2. CRITICAL → Highest priority. |
| **ServiceNow** | Creates incident via Table API. Urgency and assignment group configurable. |
| **Containment Webhook** | Signed JSON POST (HMAC-SHA256) to any endpoint. |

All SOAR actions are non-blocking (daemon threads), retry once after 5 seconds on transient failure, and are idempotent — the same containment event will never create duplicate tickets.

Configure via `~/.aurora/soar.json` or `AURORA_JIRA_*` / `AURORA_SN_*` environment variables.

---

## Push Notifications

AURORA fires real-time push alerts on HIGH and CRITICAL events (HRI threshold breach, containment trigger, critical audit entry):

| Channel | Details |
|---------|---------|
| **Slack** | Block Kit formatted message via Incoming Webhook |
| **PagerDuty** | Events API v2 — triggers incident with dedup key |
| **Generic Webhook** | HMAC-SHA256 signed JSON POST |
| **SMTP Email** | TLS-encrypted (STARTTLS port 587 or SSL port 465) |

All channels: non-blocking · rate-limited (60 alerts/hour per channel) · secrets never logged.

Configure via `~/.aurora/notifications.json` or `AURORA_SLACK_WEBHOOK` / `AURORA_PD_ROUTING_KEY` / etc.

---

## Storage Backends

| Backend | When to use | How to activate |
|---------|-------------|-----------------|
| **SQLite WAL** (default) | Single-node, up to ~10,000 users | Default — no configuration needed |
| **PostgreSQL** | Multi-node, horizontal scaling, high concurrency | Set `AURORA_STORAGE_BACKEND=postgresql` and provide `AURORA_PG_DSN` |

If PostgreSQL is configured but `psycopg2` is unavailable or the connection fails, AURORA falls back to SQLite automatically — no crash, no data loss.

---

## Ethics & Governance

Every autonomous action passes through a **6-pillar ethics engine** before execution:

1. **Proportionality** — Action severity must not exceed the measured risk level
2. **Privacy** — High-privacy actions require consent or legal basis; data minimisation enforced
3. **Transparency** — Every decision can be explained in plain language (XAI feature attribution)
4. **Human Override** — Humans can always override any autonomous decision; overrides are logged immutably
5. **Bias** — Flags actors receiving more than 3× the average intervention rate
6. **Auditability** — Full reasoning is recorded to the tamper-evident audit log

---

## Compliance

| Framework | Coverage |
|-----------|---------|
| GDPR | Purpose limitation · consent tracking · data minimisation · right-to-explanation (XAI) |
| SOC 2 | Availability · confidentiality · integrity · access control |
| HIPAA | PHI protection · minimum necessary · always-on audit logging |
| ISO 27001 | Access control policy · cryptographic controls · supplier relationship checks |

---

## Security Hardening

- **Passwords**: Argon2id (m=64 MB, t=3, p=4) — falls back to PBKDF2-SHA256 (600,000 iterations)
- **Breach checking**: HIBP k-anonymity API — blocks passwords found in known data breaches
- **Encryption at rest**: AES-256-GCM for all messages, vault documents, and TOTP secrets
- **2FA replay protection**: Used TOTP codes stored with 2-minute TTL — intercepted codes cannot be reused
- **Brute-force lockout**: 5 failures → 15-minute lockout, exponential back-off up to 24 hours
- **Constant-time comparisons**: `hmac.compare_digest()` on all token and password checks
- **Atomic file writes**: Write to `.tmp` → `os.replace()` — crash-safe, no partial writes
- **Thread + file locking**: `threading.Lock` + `fcntl flock` on all database writes
- **Rate limiting**: Token bucket — 100 req/60s per client on the API; 20 logins/min on auth
- **Input sanitisation**: SQL injection · command injection · path traversal · prompt injection · Unicode homoglyph stripping
- **Memory wiping**: Sensitive values (keys, tokens, passwords) zeroed after use; `gc.collect()` forced
- **Integrity monitor**: SHA-256 hash of every AURORA file at startup — tampering detected immediately
- **Tamper-evident audit log**: HMAC-chained (SHA-256) — deleting or modifying any entry breaks the chain
- **Native TLS**: RSA-4096 self-signed cert auto-generated on first run; TLS 1.2 minimum; weak ciphers explicitly disabled
- **Non-root Docker**: Runs as UID 10001 — never root
- **Session security**: Sessions held in memory only, never written to disk, zeroed on logout

---

## Cryptography Summary

| Algorithm | Role | Notes |
|-----------|------|-------|
| ML-KEM (Kyber-512) | Post-quantum key exchange | Real NTT implementation — FIPS 203 §6.1 parameters |
| X25519 | Classical key exchange | Via `cryptography` library (production grade) |
| AES-256-GCM | Symmetric encryption | All data at rest and in transit |
| Argon2id | Password hashing | RFC 9106, PHC winner |
| Ed25519 | Digital signatures | Identity keys and audit log signing |
| HMAC-SHA256 | Message authentication | API tokens · session cookies · webhook signatures · audit chain |
| TOTP (RFC 6238) | Two-factor authentication | 6-digit, 30-second window, replay-protected |
| SHAKE-128 | Matrix expansion | Used inside ML-KEM key generation |
| SHA3-256 | Key derivation | Used inside ML-KEM shared secret derivation |

---

## Requirements

- Python 3.8 – 3.14
- Dependencies: see `requirements.txt`
- Optional (recommended): `argon2-cffi` for Argon2id · `numpy` for ML-KEM · `liboqs-python` for FIPS 203 certified quantum KEM · `pyotp` for TOTP · `ldap3` for Active Directory

---

*AURORA — Built by Ademoh Mustapha Onimisi · github.com/ademohmustapha/aurora*
