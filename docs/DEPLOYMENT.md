# Build and deployment

## Pipeline overview

```
push / PR ──► CI ──────────────────────────────────────────────┐
              ├ lint, unit + integration tests (real mongod)    │
              ├ client build, npm audit (prod, high)            │ all green on main
              ├ end-to-end smoke test against running services  │
              ├ build 3 images + Trivy scan                     │
              ├ compose + Nginx config validation                  │
              ├ gitleaks secret scan, dependency review (PRs)   │
              └ CodeQL (separate workflow, also weekly)         ▼
                                                    Release images
                                     build + push to GHCR (sha-<commit>, latest, semver)
                                     SBOM + provenance, Trivy scan, cosign keyless signature
                                                              │
                                                              ▼
                                                           Deploy
                                     (environment "production", optional manual approval)
                                     verify signatures ► scp compose ► pull ► up -d
                                     ► wait for health ► automatic rollback on failure
                                     ► external HTTPS health check
```

Dependabot opens weekly PRs for npm packages, GitHub Actions and base images.

## One-time server setup

On a Linux host with Docker Engine and the compose plugin, with ports 80 and 443 open and DNS for your domain pointing at it:

```bash
sudo git clone https://github.com/<owner>/<repo>.git /opt/secureshare
sudo chown -R $USER /opt/secureshare && cd /opt/secureshare
docker run --rm -v "$PWD:/w" -w /w node:22-alpine node scripts/gen-secrets.mjs   # creates ./secrets
cp deploy/.env.example deploy/.env
# edit deploy/.env: DOMAIN, IMAGE_PREFIX=ghcr.io/<owner>/<repo>, BOOTSTRAP_ADMIN
# place your TLS certificate and key in deploy/nginx/certs/server.crt and server.key
echo $GHCR_TOKEN | docker login ghcr.io -u <user> --password-stdin   # only if the packages are private
```

Nginx does not obtain certificates by itself. For a public domain, use certbot (webroot)
with the `/.well-known/acme-challenge/` location already configured, and copy the
`fullchain.pem` / `privkey.pem` pair into `deploy/nginx/certs/` before `docker compose up`.
For a local trial, `sh deploy/nginx/gen-local-cert.sh` creates a self-signed pair.

The deploy workflow overwrites `docker-compose.yml`, the MongoDB init script and `remote-deploy.sh` on each run; `secrets/` and `deploy/.env` stay on the server.

**Back up `secrets/authority_kek`** somewhere safe and separate from database backups. Without it the CP-ABE master key cannot be unsealed and no new attribute keys can be issued.

## GitHub configuration

Create an environment called `production` (Settings > Environments) and add:

| Kind | Name | Value |
|---|---|---|
| secret | `DEPLOY_SSH_KEY` | private key of a deploy user on the server |
| secret | `DEPLOY_KNOWN_HOSTS` | output of `ssh-keyscan your.server` |
| variable | `DEPLOY_HOST` | server hostname |
| variable | `DEPLOY_USER` | SSH user (in the `docker` group) |
| variable | `DEPLOY_PATH` | `/opt/secureshare` |
| variable | `DOMAIN` | public hostname |

Add required reviewers to the environment if every production deploy should wait for approval. Turn on branch protection for `main` requiring the CI checks.

After that, merging to `main` runs CI, then publishes signed images, then deploys them. To deploy or roll back a specific version manually: Actions > Deploy > Run workflow > tag `sha-<commit>`.

## First start

Register the account named in `BOOTSTRAP_ADMIN` right after the first deploy; it becomes the administrator. Then set `REGISTRATION_OPEN=false` in `deploy/.env` if accounts should only be created by invitation, and redeploy.

## Running the stack by hand

```bash
npm run setup                          # secrets + .env
cp deploy/.env.example deploy/.env     # DOMAIN=localhost for a local trial
npm run certs                          # self-signed TLS cert, if none exists yet
docker compose --env-file deploy/.env up -d --build
docker compose --env-file deploy/.env ps
BASE_URL=https://localhost NODE_EXTRA_CA_CERTS="$PWD/deploy/nginx/certs/server.crt" npm run smoke
```

The local certificate is self-signed: browsers warn until you trust
`deploy/nginx/certs/server.crt`, and Postman needs it as a CA or TLS verification
disabled **for local testing only**. Similarly, use `curl -k` if you probe the stack
by hand. Swagger UI is at `https://localhost/docs`; the Postman HTTPS environment is
in `postman/SecureShareFR.postman_environment.https.json`.

## Jenkins in Docker (alternative to GitHub Actions)

For a self-hosted controller on the same Docker host:

```bash
docker compose -f deploy/jenkins/docker-compose.yml up -d --build
# http://localhost:8080 -> admin / admin (override with JENKINS_ADMIN_PASSWORD)
# run the pre-created "secureshare-deploy" job
```

The compose file runs Jenkins alongside a privileged Docker-in-Docker daemon with its own TLS certs; Jenkins shares the `jenkins_home` volume with that daemon at the same path so bind-mounted secrets resolve. The image contains Node 22, Docker CLI + Compose plugin and Trivy. Configuration as Code creates the job from `deploy/jenkins/Jenkinsfile`: copy source → bootstrap secrets/certs (with a `docker` SAN in the local cert) → npm ci/lint/test/build/audit → build images using the host network for registry DNS → Trivy scan (report-only unless `FAIL_ON_VULNS=true`) → `docker compose up` → health checks + smoke → record last-good tag or roll back. App endpoints are published on the host at `https://localhost`. The source is mounted read-only at `/workspace`. See [deploy/jenkins/README.md](../deploy/jenkins/README.md) for parameters and caveats. DinD is privileged; use it only on a trusted local/dev host.

## Operations

- **Backups:** `mongo_data` volume (both databases), `blobs` volume, and `secrets/`. Everything in the first two is ciphertext or sealed, but keep the KEK separate from them.
- **Logs:** JSON lines on stdout (`docker compose logs`), with cookies, auth keys and vaults redacted. Health checks are not logged.
- **Secret rotation:** `node scripts/gen-secrets.mjs --force` rotates everything, which logs everyone out and needs MongoDB user passwords updated. Do **not** rotate `authority_kek` this way; re-seal the master key instead.
- **Scaling:** the API is stateless except for in-memory rate limits; put a shared store behind `express-rate-limit` before running several replicas. Blob storage is a local volume; swap `services/api/src/storage.js` for object storage if needed.
