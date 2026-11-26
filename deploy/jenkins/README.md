# Jenkins in Docker

A self-contained Jenkins controller plus a Docker-in-Docker (DinD) daemon that
builds, tests, scans and deploys the SecureShareFR stack end to end. The app
stack runs inside DinD with ports 80/443 published to the host, so
`https://localhost` works after a successful build.

## Start

```bash
# optional but recommended: choose the admin password first
export JENKINS_ADMIN_PASSWORD='something-long'      # PowerShell: $env:JENKINS_ADMIN_PASSWORD='...'
docker compose -f deploy/jenkins/docker-compose.yml up -d --build
```

Open <http://localhost:8080> (bound to loopback only) and sign in as `admin`
(password `admin` unless you set `JENKINS_ADMIN_PASSWORD`). The job
**secureshare-deploy** is created automatically from `Jenkinsfile` by
Configuration as Code. Click **Build with Parameters**.

| Parameter | Default | Meaning |
|---|---|---|
| `RUN_TESTS` | `true` | `npm ci`, lint, 123 tests (JUnit published), client build |
| `RUN_AUDIT` | `true` | `npm audit` for production dependencies |
| `AUDIT_FAILS_BUILD` | `true` | `false` marks the build UNSTABLE instead of failing it |
| `DEPLOY` | `true` | `false` gives a CI-only run: test, build images, scan, no deploy |
| `RUN_SMOKE` | `true` | 25-check end-to-end test over HTTPS after deploy |
| `FAIL_ON_VULNS` | `false` | Fail on HIGH/CRITICAL Trivy findings (report-only by default) |
| `DEPLOY_TAG` | blank | Fixed image tag; blank uses `jenkins-$BUILD_NUMBER` |

## What the pipeline does

1. **Checkout**: waits for the DinD TLS daemon, then copies the read-only source
   mounted at `/workspace` (or runs `checkout scm` in a Multibranch job).
2. **Bootstrap**: secrets, `deploy/.env` and the TLS certificate (with a `docker`
   SAN) are created **once** and kept in `jenkins_home/secureshare-state`, then
   reused. Regenerating them each build would break the existing MongoDB volume
   and the sealed ABE master key on the second deployment.
3. **Install / Lint / Test / Build client / Dependency audit** (skipped when
   `RUN_TESTS` is off). Vitest writes JUnit XML because `CI=true`; Jenkins shows
   it under *Test Result*. The mongod binary used by the tests is cached in
   `jenkins_home/.cache/mongodb-binaries`.
4. **Build images** `secureshare-{api,authority,web}:$TAG`.
5. **Scan images** with Trivy; JSON reports are archived with the build.
6. **Deploy** with `docker compose up -d` against DinD.
7. **Health and smoke**: waits for `https://docker/api/health` and
   `/authority/health`, checks `/docs`, then runs the smoke test.
8. **Post**: success records the tag as last good; failure redeploys the last
   good tag.

## Running it against a real Git repository

1. Push the project to GitHub/GitLab (secrets, `.env` and certs are git-ignored).
2. Jenkins -> **New Item -> Multibranch Pipeline**, add the repository, script
   path `deploy/jenkins/Jenkinsfile`.
3. Add a webhook (`http://<jenkins>/github-webhook/` or the Branch Source
   plugin's endpoint) so pushes trigger builds. Jenkins must be reachable from
   the Git host, so use a tunnel or a real hostname.
4. Branch and pull-request builds should normally run with `DEPLOY` unticked.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Docker daemon not reachable at tcp://docker:2376` | The `docker` network alias is missing. Recreate with `docker compose -f deploy/jenkins/docker-compose.yml up -d --force-recreate`. |
| `Hook timed out` in API/authority tests | First run downloads mongod. The hook timeout is 180 s; check the container can reach `fastdl.mongodb.org`. |
| `mongodb-memory-server` "no download URL" for the distro | Set `MONGOMS_DISTRO=ubuntu-22.04` in the Jenkinsfile `environment` block. |
| `MongoServerError: Authentication failed` after a rebuild | Secrets changed while the `mongo_data` volume kept the old users. Restore `jenkins_home/secureshare-state/secrets`, or wipe the app volumes. |
| Smoke test `403 Cross-origin` | `PUBLIC_ORIGIN` only matters when the browser sends an `Origin` header; the smoke client does not. Check `DOMAIN` in `deploy/.env`. |
| `npm audit` fails the build | Fix the advisory, or run with `AUDIT_FAILS_BUILD` unticked. |

## Notes

- `down -v` deletes Jenkins history, image cache, secrets and the last-good tag.
- After editing `Jenkinsfile` or `entrypoint.sh`, rebuild/restart Jenkins so CasC regenerates the job:
  `docker compose -f deploy/jenkins/docker-compose.yml up -d --build --force-recreate`.
- DinD runs privileged. Use this setup only on a trusted local/dev host.
