# Testing

| Layer | Command | Needs | Time |
|---|---|---|---|
| Lint | `npm run lint` | Node 22.13+ | seconds |
| Crypto | `npm run test:crypto` | nothing | ~1 min (pairings are slow in JS) |
| Authority | `npm run test:authority` | internet on first run (mongod download) | ~30 s |
| API | `npm run test:api` | same | ~1 min |
| Client | `npm run test:client` | nothing | seconds |
| Everything CI runs | `npm run verify` | same | few minutes |
| End to end | `npm run smoke` | running services (`npm run dev` or the Docker stack) | ~1 min |

API and authority tests start a real `mongod` through `mongodb-memory-server`, so no
database has to be installed. The binary is downloaded once; set `MONGOMS_DOWNLOAD_DIR`
to keep it in a cacheable place (CI and Jenkins do). Behind a proxy or offline, install
MongoDB and set `MONGOMS_SYSTEM_BINARY=/usr/bin/mongod`.

## Reports

When `CI=true` (Jenkins and GitHub Actions set it) every package writes
`test-results/junit.xml`. Jenkins publishes them as *Test Result*; GitHub uploads them
as the `junit-reports` artifact.

## Timeouts

`packages/crypto` uses 60 s per test, API/authority 30 s per test and 180 s for hooks
(first mongod download). If a test times out on slow hardware, raise `testTimeout` in
that package's `vitest.config.js` rather than skipping the test.

## Adding tests

- Pure logic (parsers, helpers): put it in its own module and unit-test it without
  Mongo, as `services/api/src/policy-gate.js` and its test do.
- Route behaviour: follow `services/api/test/api.test.js` (supertest against the exported `app`).
- Security fixes need a regression test that fails without the fix.

## Not covered yet

- Coverage reporting needs `@vitest/coverage-v8`. Add it with `npm i -D @vitest/coverage-v8`
  at the root *with network access* so `package-lock.json` is regenerated, then run
  `npx vitest run --coverage` inside a package.
- Browser UI tests (Playwright). `npm run demo:panel` drives a real browser but is a demo, not an assertion suite.
