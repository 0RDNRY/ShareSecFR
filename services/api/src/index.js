import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import express from 'express';
import { mkdirSync } from 'node:fs';
import mongoose from 'mongoose';
import { importPKCS8, importSPKI } from 'jose';
import {
  readSecret, mongoUri, intFromEnv, boolFromEnv,
  applyBaseSecurity, csrfGuard, sessionVerifier, notFound, errorHandler,
  createLogger, httpLogger, sessionCookieName,
} from '@secureshare/server-common';
import { initStorage } from './storage.js';
import { buildOpenApiSpec } from './openapi.js';
import { swaggerAssetsPath, swaggerBootstrapJs, docsHtml, DOCS_CSP } from './docs.js';
import publicAuthRouter, { protectedRouter as protectedAuthRouter } from './routes/auth.js';
import filesRouter from './routes/files.js';
import adminRouter from './routes/admin.js';
import webhooksRouter from './routes/webhooks.js';
import integrationsRouter from './routes/integrations.js';

const env = process.env;
export const logger = createLogger({ level: env.LOG_LEVEL ?? 'info', name: 'api' });

// ── Config ────────────────────────────────────────────────────────────────────
export const config = {
  port: intFromEnv(env, 'PORT', 4000, { min: 1, max: 65535 }),
  trustProxy: intFromEnv(env, 'TRUST_PROXY_HOPS', 1, { min: 0, max: 10 }),
  cookieSecure: boolFromEnv(env, 'COOKIE_SECURE', false),
  publicOrigin: env.PUBLIC_ORIGIN ?? 'http://localhost:5173',
  storageDir: env.STORAGE_DIR ?? './data/blobs',
  maxUploadBytes: intFromEnv(env, 'MAX_UPLOAD_BYTES', 104857600),
  bootstrapAdmin: (env.BOOTSTRAP_ADMIN ?? 'admin').toLowerCase(),
  registrationOpen: boolFromEnv(env, 'REGISTRATION_OPEN', true),
  authorityInternalUrl: env.AUTHORITY_INTERNAL_URL ?? 'http://127.0.0.1:7001',
  jwtTtlSeconds: intFromEnv(env, 'JWT_TTL_SECONDS', 1800, { min: 60, max: 86400 }),
};

// ── Build app ─────────────────────────────────────────────────────────────────
export const app = express();
applyBaseSecurity(app, { trustProxy: config.trustProxy });
app.use(httpLogger(logger));

// ── Swagger UI (self-hosted assets, no CDN, compatible with strict CSP) ──────
const assetsPath = swaggerAssetsPath();
app.locals.swaggerEnabled = Boolean(assetsPath);
if (assetsPath) {
  app.use('/docs/assets', express.static(assetsPath, { fallthrough: true, index: false }));
} else {
  logger.warn('swagger-ui-dist not installed; /docs assets will not be available');
}

app.get('/docs/bootstrap.js', (_req, res) => {
  res.set('Content-Type', 'application/javascript; charset=utf-8');
  res.send(swaggerBootstrapJs());
});

app.get('/docs', (_req, res) => {
  if (!assetsPath) return res.status(503).type('text/plain').send('Swagger UI assets are not installed. Run npm install.');
  res.set('Content-Security-Policy', DOCS_CSP);
  res.set('Content-Type', 'text/html; charset=utf-8');
  res.send(docsHtml());
});

app.get('/api/openapi.json', (_req, res) => {
  res.json(buildOpenApiSpec({
    publicOrigin: app.locals.publicOrigin ?? config.publicOrigin,
    maxUploadBytes: app.locals.maxUploadBytes ?? config.maxUploadBytes,
    cookieName: sessionCookieName(config.cookieSecure),
  }));
});

// ── JSON body parser (for non-blob routes) ────────────────────────────────────
app.use((req, res, next) => {
  if (req.path.includes('/blob')) return next(); // skip JSON parsing for binary uploads
  express.json({ limit: '2mb' })(req, res, next);
});

// ── CSRF guard ────────────────────────────────────────────────────────────────
app.use(csrfGuard({ publicOrigin: config.publicOrigin }));

// ── Health / meta ─────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'api', version: '2.0.0', uptime: Math.round(process.uptime()) });
});
app.get('/api/meta', (_req, res) => {
  res.json({ maxUploadBytes: config.maxUploadBytes, registrationOpen: config.registrationOpen });
});

// ── Session verification ──────────────────────────────────────────────────────
let requireUser, requireAdmin;

/** Initialise session verification (also used by the tests). */
export async function initAuth({ publicKeyPem, cookieName, isRevoked }) {
  const sessionFns = await sessionVerifier({ publicKeyPem, cookieName, isRevoked });
  requireUser = sessionFns.requireUser;
  requireAdmin = sessionFns.requireAdmin;
  return sessionFns;
}

/** Populate app.locals (startup and tests). */
export function configureApp(locals) {
  Object.assign(app.locals, locals);
  return app.locals;
}

// ── Unauthenticated routes ────────────────────────────────────────────────────
app.use('/api/auth', publicAuthRouter);
app.use('/api/auth', (req, res, next) => requireUser(req, res, next), protectedAuthRouter);
app.use('/api/integrations', integrationsRouter);
app.get('/api/webhooks/events', (_req, res) => {
  res.json({ events: [
    'auth.registered', 'auth.login.succeeded', 'auth.login.failed', 'auth.account.locked',
    'file.uploaded', 'file.downloaded', 'file.access.denied', 'file.policy.updated',
    'file.deleted', 'authority.attributes.updated',
  ] });
});

// ── Authenticated routes ──────────────────────────────────────────────────────
app.use('/api/files', (req, res, next) => requireUser(req, res, next), filesRouter);
app.use('/api/admin', (req, res, next) => requireUser(req, res, next), (req, res, next) => requireAdmin(req, res, next), adminRouter);
app.use('/api/webhooks', (req, res, next) => requireUser(req, res, next), webhooksRouter);

app.use(notFound);
app.use(errorHandler(logger));

// ── Bootstrap ─────────────────────────────────────────────────────────────────
export async function start() {
  const jwtPrivatePem = readSecret(env, 'JWT_PRIVATE_KEY');
  const jwtPublicPem = readSecret(env, 'JWT_PUBLIC_KEY');
  const internalToken = readSecret(env, 'INTERNAL_TOKEN');
  const serverSecret = readSecret(env, 'SERVER_SECRET');
  const mongoPassword = readSecret(env, 'MONGODB_PASSWORD', { required: false });
  const mongoUriValue = mongoUri(env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017/secureshare', mongoPassword);

  mkdirSync(config.storageDir, { recursive: true });
  initStorage(config.storageDir);

  const [privKey] = await Promise.all([
    importPKCS8(jwtPrivatePem, 'ES256'),
    importSPKI(jwtPublicPem, 'ES256'),
  ]);

  await initAuth({
    publicKeyPem: jwtPublicPem,
    cookieName: sessionCookieName(config.cookieSecure),
    isRevoked: async (payload) => {
      const { RevokedSession } = await import('./models/index.js');
      return !!(await RevokedSession.exists({ jti: payload.jti }));
    },
  });

  configureApp({
    jwtPrivateKey: privKey,
    serverSecret,
    internalToken,
    cookieSecure: config.cookieSecure,
    bootstrapAdmin: config.bootstrapAdmin,
    registrationOpen: config.registrationOpen,
    authorityInternalUrl: config.authorityInternalUrl,
    maxUploadBytes: config.maxUploadBytes,
    jwtTtlSeconds: config.jwtTtlSeconds,
    publicOrigin: config.publicOrigin,
    storageDir: config.storageDir,
  });

  await mongoose.connect(mongoUriValue, { serverSelectionTimeoutMS: 10000 });
  logger.info('MongoDB connected');

  app.listen(config.port, () => {
    logger.info(`API listening on :${config.port}`);
    logger.info(`Swagger UI available at ${config.publicOrigin.replace(/\/$/, '')}/docs`);
  });
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  start().catch((err) => {
    logger.error({ err }, 'startup failed');
    process.exit(1);
  });
}
