import express from 'express';
import mongoose from 'mongoose';
import { importSPKI } from 'jose';
import {
  readSecret, mongoUri, intFromEnv, boolFromEnv,
  applyBaseSecurity, csrfGuard, sessionVerifier, notFound, errorHandler,
  createLogger, httpLogger, sessionCookieName, requireInternalToken,
} from '@secureshare/server-common';
import { abe } from '@secureshare/crypto';
import { MasterKey, UserAttr, AuthorityAudit } from './models/index.js';
import publicRouter from './routes/public.js';
import adminRouter from './routes/admin.js';
import internalRouter from './routes/internal.js';
import { sealMasterKey, openMasterKey } from './master-key.js';

const env = process.env;
const logger = createLogger({ level: env.LOG_LEVEL ?? 'info', name: 'authority' });

// ── Config ────────────────────────────────────────────────────────────────────
const PUBLIC_PORT = intFromEnv(env, 'AUTHORITY_PORT', 7000, { min: 1, max: 65535 });
const INTERNAL_PORT = intFromEnv(env, 'AUTHORITY_INTERNAL_PORT', 7001, { min: 1, max: 65535 });
const TRUST_PROXY = intFromEnv(env, 'TRUST_PROXY_HOPS', 1, { min: 0, max: 10 });
const COOKIE_SECURE = boolFromEnv(env, 'COOKIE_SECURE', false);
const PUBLIC_ORIGIN = env.PUBLIC_ORIGIN ?? 'http://localhost:5173';

const kek = readSecret(env, 'AUTHORITY_KEK');                           // key-encryption key (hex/base64url)
const jwtPublicPem = readSecret(env, 'JWT_PUBLIC_KEY');
const internalToken = readSecret(env, 'INTERNAL_TOKEN');
const mongoPassword = readSecret(env, 'AUTHORITY_MONGODB_PASSWORD', { required: false });
const MONGODB_URI = mongoUri(
  env.AUTHORITY_MONGODB_URI ?? 'mongodb://127.0.0.1:27017/secureshare_authority',
  mongoPassword,
);

// ── Build apps ────────────────────────────────────────────────────────────────
function makeApp(trustProxy) {
  const a = express();
  applyBaseSecurity(a, { trustProxy });
  a.use(httpLogger(logger));
  a.use(express.json({ limit: '64kb' }));
  return a;
}

const publicApp = makeApp(TRUST_PROXY);
const internalApp = makeApp(0);

publicApp.use(csrfGuard({ publicOrigin: PUBLIC_ORIGIN }));

// Health
publicApp.get('/authority/health', (_req, res) => {
  res.json({ status: 'ok', service: 'authority', version: '2.0.0', uptime: Math.round(process.uptime()) });
});

internalApp.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── Session verification ───────────────────────────────────────────────────────
let requireUser, requireAdmin;

// Public routes
publicApp.use('/authority', publicRouter);
publicApp.use('/authority/admin', (req, res, next) => requireUser(req, res, next), (req, res, next) => requireAdmin(req, res, next), adminRouter);
publicApp.use(notFound);
publicApp.use(errorHandler(logger));

// Internal routes (service-to-service, bearer token, isolated network)
internalApp.use(requireInternalToken(internalToken));
internalApp.use('/internal', internalRouter);
internalApp.use(notFound);
internalApp.use(errorHandler(logger));

// ── Bootstrap ─────────────────────────────────────────────────────────────────
let abeState = null; // { publicKey, masterSecret }

export function getAbeState() {
  if (!abeState) throw new Error('ABE master key not loaded');
  return abeState;
}

async function start() {
  const { verify: _, ...sessionFns } = await sessionVerifier({
    publicKeyPem: jwtPublicPem,
    cookieName: sessionCookieName(COOKIE_SECURE),
  });
  requireUser = sessionFns.requireUser;
  requireAdmin = sessionFns.requireAdmin;

  await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  logger.info('MongoDB connected');

  // Load or generate FAME master key
  let keyRec = await MasterKey.findById('singleton');
  if (!keyRec) {
    logger.info('Generating new FAME master key');
    const { pk, msk } = abe.setup();
    const sealed = sealMasterKey(kek, { pk, msk });
    keyRec = await MasterKey.create({ _id: 'singleton', sealed });
  }
  abeState = openMasterKey(kek, keyRec.sealed);
  logger.info('FAME master key loaded (fingerprint: %s)', masterKeyFingerprint(abeState.pk));

  publicApp.locals.abeState = abeState;
  publicApp.locals.cookieSecure = COOKIE_SECURE;
  publicApp.locals.publicOrigin = PUBLIC_ORIGIN;

  publicApp.listen(PUBLIC_PORT, () => logger.info(`Authority public API on :${PUBLIC_PORT}`));
  internalApp.listen(INTERNAL_PORT, '127.0.0.1', () => logger.info(`Authority internal API on :${INTERNAL_PORT}`));
}

function masterKeyFingerprint(pk) {
  const { createHash } = await import('node:crypto').then(m => m);
  try {
    const str = JSON.stringify(pk).slice(0, 256);
    return require('node:crypto').createHash('sha256').update(str).digest('hex').slice(0, 16);
  } catch { return 'unknown'; }
}

start().catch((err) => {
  logger.error({ err }, 'startup failed');
  process.exit(1);
});
