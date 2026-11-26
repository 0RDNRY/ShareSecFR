# SecureShare

Secure file sharing with **ciphertext-policy attribute-based encryption (CP-ABE)** and **end-to-end encryption**.

An owner encrypts a file in the browser and attaches an access policy such as

```
(dept:cse AND role:faculty) OR user:alice
```

Anyone whose attributes satisfy the policy can decrypt it. Nobody else can, including the server operator. Attributes are assigned by an administrator through a separate attribute authority.

## What it does

- **CP-ABE:** FAME (Agrawal-Chase, CCS 2017) on the BLS12-381 pairing curve, with AND/OR policies, collusion resistance, and a `user:<name>` attribute for sharing with specific people.
- **End-to-end encryption:** AES-256-GCM chunked file encryption, encrypted file names, owner-signed manifests (ECDSA P-256) checked by the recipient before decryption. The server only ever stores ciphertext.
- **Zero-knowledge accounts:** the password never leaves the browser. It derives a login key (Argon2id-hashed on the server) and a vault key that encrypts the user's private keys.
- **Two layers of access control:** cryptography plus a server-side policy gate that checks live attributes, so revoking an attribute takes effect immediately.
- **Hardening:** TLS with HSTS, strict CSP, SameSite=Strict httpOnly cookies + CSRF header and Origin checks, rate limiting and account lockout, strict input validation, audit log, non-root read-only containers, isolated internal network, per-service database users.
- **Automation:** GitHub Actions for lint, tests, end-to-end test, image build, Trivy and CodeQL scans, secret scanning, signed image releases to GHCR, and SSH deployment with health checks and automatic rollback.

## Quick start (development)

Needs Node 22.13+ (ESLint 10 requirement) and MongoDB 7 or 8 on `localhost:27017`.

```bash
npm ci
npm run setup     # creates ./secrets and .env
npm run dev       # authority :7000, API :4000, web app http://localhost:5173
```

Register a user called `admin` first (the `BOOTSTRAP_ADMIN`); it gets the Administration tab. Then:

1. Register two more users in separate browser profiles, e.g. `farid` and `sana`.
2. As `admin`, open **Administration** and give `farid` the attributes `dept:cse, role:faculty` and `sana` the attributes `dept:cse, role:student`.
3. As a third user, upload a file with policy `dept:cse AND role:faculty`.
4. `farid` sees it under **Shared with me** and can download it. `sana` cannot see it at all.
5. Change the policy to `role:student`, or remove `farid`'s `role:faculty`, and watch access change.

## Production

The default compose stack terminates TLS at **Nginx**. Certificates are mounted from `deploy/nginx/certs/`; generate a self-signed pair for a local trial or install a real certificate before starting:

```bash
npm run setup
cp deploy/.env.example deploy/.env       # set DOMAIN
npm run certs                            # local self-signed cert (skipped if one exists)
docker compose --env-file deploy/.env up -d --build
```

For a real domain, replace `deploy/nginx/certs/server.crt` and `server.key` with a CA-issued certificate (e.g. certbot webroot using the ACME challenge path already configured in `deploy/nginx/nginx.conf`). `deploy/caddy/Caddyfile` is included as an alternative automatic-HTTPS proxy if you prefer Caddy's ACME; see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for CI/CD (GHCR images, signed releases, SSH deploys with rollback).

## Jenkins (Docker)

A containerized Jenkins controller with a private Docker-in-Docker daemon can build, test, scan and deploy the whole stack end to end:

```bash
npm run jenkins:up          # or: make jenkins-up
# open http://localhost:8080, sign in as admin / admin
# run the pre-created "secureshare-deploy" job
```

The pipeline copies the mounted read-only source into its own workspace, bootstraps `.env`/secrets/certs if missing, runs `npm ci`, lint, 123 tests, build and prod audit, builds the three images, Trivy-scans them (report-only unless `FAIL_ON_VULNS=true`), starts the HTTPS stack, waits for health checks and runs the 25-check smoke test. It rolls back to the last good tag on failure. The app stack runs inside DinD and is reachable at `https://localhost` on the host. See [deploy/jenkins/README.md](deploy/jenkins/README.md); DinD runs privileged and is intended for a trusted local/dev host.

## Self-running panel demo

With the HTTPS stack up, run one command to show Swagger, Postman guidance, webhooks, HTTPS and Nginx unattended. It drives a real Edge/Chrome window through the Chrome DevTools Protocol (no Playwright install), registers a fresh demo account in the browser, steps through the in-app Integrations tabs, registers a live webhook, sends a signed ping, triggers a real login event, and saves screenshots.

```bash
npm run demo:panel          # or: make demo-panel
FAST=1 npm run demo:panel   # shorter pauses
KEEP_BROWSER=0 npm run demo:panel  # close the browser when done
```

Screenshots are written to `docs/demo-screenshots/`. Override `BASE_URL`, `DEMO_USER`, `DEMO_PASSWORD`, `WEBHOOK_SECRET`, `WEBHOOK_URL`, `JENKINS_URL`, `CDP_PORT` or `BROWSER_PATH` via environment variables. It auto-detects a webhook.site inbox, so no manual copy/paste is needed.

## Tests

```bash
npm run lint
npm test          # crypto, authority, API (real mongod via mongodb-memory-server), client
npm run build
npm run smoke     # end-to-end over HTTP against running services (25 checks)
```

| Suite | Tests | Covers |
|---|---|---|
| `packages/crypto` | 63 | policy parser and LSSS (exhaustive over attribute subsets), FAME correctness, unauthorized keys, collusion, wrong authority, envelope binding, tamper detection on every layer, ECIES, signatures, password vault, full upload/download/re-policy flow |
| `services/authority` | 13 | master key sealing and reload, wrong KEK, key issuance sealed to the device, admin-only and CSRF, forged tokens, internal endpoint isolation |
| `services/api` | 41 | Swagger UI/OpenAPI, registration/login/lockout/logout revocation, enumeration resistance, tampered JWTs, signature and manifest checks, ciphertext hash enforcement, policy gate, revocation, fail-closed, size limits, audit, SSRF protection, policy gate parity with the crypto parser |
| `client` | 6 | helpers (file name sanitising, policy validation, policy editor precedence) |
| `scripts/smoke.mjs` | 25 checks | the whole system over real HTTP |

## API documentation and clients

- **Swagger UI:** `http://localhost:4000/docs` (direct API) or `https://localhost/docs` (Docker stack). Assets are served from the API origin, so the strict CSP still applies — no CDN is involved. The machine-readable document is at `/api/openapi.json`.
- **Postman:** import [postman/SecureShareFR.postman_collection.json](postman/SecureShareFR.postman_collection.json) with either environment in [`postman/`](postman/README.md). The collection includes a pre-request script that adds the CSRF header automatically. The HTTPS environment targets `https://localhost` with the local self-signed certificate.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, flows, API reference
- [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md): every key, every construction, and the known limitations
- [docs/SECURITY.md](docs/SECURITY.md): threat model and the control for each threat
- [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md): CI/CD pipeline, server setup, operations

## Limitations worth knowing

The attribute authority can derive any user's key (inherent to single-authority ABE), so it runs as a separate service with its own secrets. Revocation cannot take back a file someone already decrypted. The FAME implementation follows the paper and is thoroughly tested but has not been externally audited. Details in [docs/CRYPTOGRAPHY.md](docs/CRYPTOGRAPHY.md#8-known-limitations).
