import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import express from 'express';
import mongoose from 'mongoose';
import { createHash } from 'node:crypto';
import {
  readSecret, mongoUri, intFromEnv, boolFromEnv,
  applyBaseSecurity, csrfGuard, sessionVerifier, notFound, errorHandler,
  createLogger, httpLogger, sessionCookieName, requireInternalToken,
} from '@secureshare/server-common';
import { abe } from '@secureshare/crypto';
import { MasterKey } from './models/index.js';
import publicRouter, { protectedRouter } from './routes/public.js';
import adminRouter from './routes/admin.js';
import internalRouter from './routes/internal.js';
import { sealMasterKey, openMasterKey } from './master-key.js';

const env = process.env;
export const logger = createLogger({ level: env.LOG_LEVEL ?? 'info', name: 'authority' });

// ── Config ────────────────────────────────────────────────────────────────────
export const config = {
  publicPort: intFromEnv(env, 'AUTHORITY_PORT', 7000, { min: 1, max: 65535 }),
  internalPort: intFromEnv(env, 'AUTHORITY_INTERNAL_PORT', 7001, { min: 1, max: 65535 }),
  trustProxy: intFromEnv(env, 'TRUST_PROXY_HOPS', 1, { min: 0, max: 10 }),
  cookieSecure: boolFromEnv(env, 'COOKIE_SECURE', false),
  publicOrigin: env.PUBLIC_ORIGIN ?? 'http://localhost:5173',
};

// ── Build apps ────────────────────────────────────────────────────────────────
function makeApp(trustProxy) {
  const a = express();
  applyBaseSecurity(a, { trustProxy });
  a.use(httpLogger(logger));
  a.use(express.json({ limit: '64kb' }));
  return a;
}

export const publicApp = makeApp(config.trustProxy);
export const internalApp = makeApp(0);

publicApp.use(csrfGuard({ publicOrigin: config.publicOrigin }));

publicApp.get('/authority/health', (_req, res) => {
  res.json({ status: 'ok', service: 'authority', version: '2.0.0', uptime: Math.round(process.uptime()) });
});

internalApp.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── Session verification ──────────────────────────────────────────────────────
let requireUser, requireAdmin;
let internalToken;

/** Set the service-to-service token (used by start() and tests). */
export function setInternalToken(token) {
  internalToken = token;
}

/** Initialise session verification (also used by the tests). */
export async function initAuth({ publicKeyPem, cookieName }) {
  const sessionFns = await sessionVerifier({ publicKeyPem, cookieName });
  requireUser = sessionFns.requireUser;
  requireAdmin = sessionFns.requireAdmin;
  publicApp.locals.cookieSecure = config.cookieSecure;
  publicApp.locals.publicOrigin = config.publicOrigin;
  return sessionFns;
}

// Public routes
publicApp.use('/authority', publicRouter);
publicApp.use('/authority', (req, res, next) => requireUser(req, res, next), protectedRouter);
publicApp.use('/authority/admin', (req, res, next) => requireUser(req, res, next), (req, res, next) => requireAdmin(req, res, next), adminRouter);
publicApp.use(notFound);
publicApp.use(errorHandler(logger));

// Internal routes (service-to-service, bearer token, isolated Docker network)
internalApp.use((req, res, next) => requireInternalToken(internalToken)(req, res, next));
internalApp.use('/internal', internalRouter);
internalApp.use(notFound);
internalApp.use(errorHandler(logger));

// ── Bootstrap ─────────────────────────────────────────────────────────────────
let abeState = null; // { publicKey, masterSecret }

export function getAbeState() {
  if (!abeState) throw new Error('ABE master key not loaded');
  return abeState;
}

/** Short stable identifier of the public key (for logs and clients). */
export function masterKeyFingerprint(pk) {
  return createHash('sha256').update(JSON.stringify(pk)).digest('hex').slice(0, 16);
}

export async function start() {
  const kek = readSecret(env, 'AUTHORITY_KEK');
  const jwtPublicPem = readSecret(env, 'JWT_PUBLIC_KEY');
  internalToken = readSecret(env, 'INTERNAL_TOKEN');
  const mongoPassword = readSecret(env, 'AUTHORITY_MONGODB_PASSWORD', { required: false });
  const mongoUriValue = mongoUri(
    env.AUTHORITY_MONGODB_URI ?? 'mongodb://127.0.0.1:27017/secureshare_authority',
    mongoPassword,
  );

  await initAuth({
    publicKeyPem: jwtPublicPem,
    cookieName: sessionCookieName(config.cookieSecure),
  });

  await mongoose.connect(mongoUriValue, { serverSelectionTimeoutMS: 10000 });
  logger.info('MongoDB connected');

  // Load or generate FAME master key
  let keyRec = await MasterKey.findById('singleton');
  if (!keyRec) {
    logger.info('Generating new FAME master key');
    const { pk, msk } = abe.fame.setup();
    const sealed = sealMasterKey(kek, { pk, msk });
    keyRec = await MasterKey.create({ _id: 'singleton', sealed });
  }
  abeState = openMasterKey(kek, keyRec.sealed);
  logger.info('FAME master key loaded (fingerprint: %s)', masterKeyFingerprint(abeState.pk));

  publicApp.locals.abeState = abeState;

  publicApp.listen(config.publicPort, () => logger.info(`Authority public API on :${config.publicPort}`));
  // The backend network is internal:true and every route is bearer-token protected.
  // Binding loopback here would make the API container unable to reach the policy gate.
  internalApp.listen(config.internalPort, '0.0.0.0', () => logger.info(`Authority internal API on :${config.internalPort}`));
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  start().catch((err) => {
    logger.error({ err }, 'startup failed');
    process.exit(1);
  });
}
