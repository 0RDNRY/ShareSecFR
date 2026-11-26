# Changes in this revision

## Bugs fixed
1. `services/api/src/routes/auth.js`: `z.record(z.unknown())` is invalid in Zod 4 (installed: 4.6.7); now `z.record(z.string(), z.unknown())`. Registration would otherwise throw.
2. `services/api/src/routes/files.js` + new `policy-gate.js`: the server-side gate used its own regex parser that dropped `-`, `.`, `@`, `&&`, `||`. Files with policies such as `dept:comp-sci` were invisible to authorised users. It now uses the crypto package's parser. Policies are also validated on create and on change.
3. `files.js`: `readBlobStream(...).pipe(res)` had no error handler; a missing blob file crashed the process. Now uses `stream/promises` `pipeline`.
4. `client/src/components/PolicyEditor.jsx`: "Add with AND" on a policy containing OR changed its meaning (`a OR b AND c`), granting wider access than intended. Now parenthesises.
5. `services/authority/src/routes/admin.js`: attribute validation now equals the policy grammar (`ATTRIBUTE_RE`).
6. `webhooks.js`: SSRF target re-checked at delivery time, not only at registration.
7. `integrations.js`: unauthenticated status endpoint no longer echoes raw driver / filesystem error text.
8. `models/index.js`: removed duplicate `username` index (Mongoose warning on every start).
9. Usernames must start with a letter or digit (`user:_name` is not a valid policy attribute).

## Tests and CI
- Timeouts: crypto 60 s, API/authority 30 s (hooks 180 s). The default 5 s / 10 s would fail on a cold mongod download and on pairing maths.
- JUnit output when `CI=true`; new `packages/crypto/vitest.config.js`.
- New tests: policy gate (5), authority attribute grammar (1), policy editor precedence (1).
- GitHub CI: MongoDB binary cache pointed at the directory mongodb-memory-server actually uses; JUnit artifact upload.
- `npm run verify` runs everything CI runs.

## Jenkins
- DinD now has the `docker` network alias (`hostname:` is not resolvable by other containers).
- Secrets, `deploy/.env` and the TLS cert persist across builds (previously regenerated whenever `secrets/` was absent from the source, which breaks the second deploy).
- Smoke stage installs dependencies when `RUN_TESTS=false`.
- Stages split (Install, Lint, Test, Build client, Audit), JUnit published, Trivy JSON archived, `DEPLOY` / `RUN_AUDIT` / `AUDIT_FAILS_BUILD` parameters, `checkout scm` for Multibranch jobs.
- Jenkins UI bound to 127.0.0.1; port 50000 removed.

## Housekeeping
- The original zip used Windows `\` path separators and shipped a `secrets/` directory; this package uses `/` and omits `secrets/`. Rotate any secrets that were shared: `node scripts/gen-secrets.mjs --force` (this changes the authority KEK, so existing encrypted data/master key must be reset).
- Added `.gitattributes` (LF endings) and ignore rules for test reports.
