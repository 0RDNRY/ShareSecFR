import { Router } from 'express';
import argon2 from 'argon2';
import { z } from 'zod';
import { generateKeyPairSync, createHmac, timingSafeEqual } from 'node:crypto';
import { signJWT } from '../auth-helpers.js';
import { User, RevokedSession, AuditEvent } from '../models/index.js';
import { AppError, sessionCookieName, limiter, CSRF_HEADER } from '@secureshare/server-common';
import { dispatchWebhook } from '../webhooks.js';

const router = Router();

// Rate limiters
const authLimiter = limiter({ windowMs: 15 * 60 * 1000, limit: 20, message: 'Too many auth requests' });
const registerLimiter = limiter({ windowMs: 60 * 60 * 1000, limit: 10 });

const MAX_FAILED = 5;
const LOCK_MS = 15 * 60 * 1000;

// ── Argon2id params ───────────────────────────────────────────────────────────
const ARGON_OPTS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

// ── Validation schemas ────────────────────────────────────────────────────────
const KdfSchema = z.object({
  algorithm:  z.literal('pbkdf2-sha256'),
  iterations: z.number().int().min(600000).max(2000000),
  salt:       z.string().min(8),
});

const RegisterSchema = z.object({
  username:    z.string().min(3).max(32).regex(/^[A-Za-z0-9_]+$/),
  kdf:         KdfSchema,
  authKey:     z.string().min(43).max(44),          // base64url 32 bytes
  encPublicKey: z.record(z.unknown()),
  sigPublicKey: z.record(z.unknown()),
  vault:        z.string().min(1).max(8192),
});

const LoginSchema = z.object({
  username: z.string().min(1).max(32),
  authKey:  z.string().min(1),
});

// Fake KDF params (identical structure for unknown users – enumeration resistance)
function fakeKdf(username, serverSecret) {
  const mac = createHmac('sha256', serverSecret).update(`fake-kdf|${username}`).digest('base64url');
  return { algorithm: 'pbkdf2-sha256', iterations: 600000, salt: mac.slice(0, 22) };
}

function cookieOpts(env) {
  const secure = env.COOKIE_SECURE === 'true';
  return { httpOnly: true, sameSite: 'strict', secure, path: '/' };
}

async function audit(action, { username, userId, target, outcome = 'ok', meta } = {}) {
  await AuditEvent.create({ action, username, userId, target, outcome, meta }).catch(() => {});
}

// ── GET /api/auth/params?username= ────────────────────────────────────────────
router.get('/params', async (req, res, next) => {
  try {
    const username = String(req.query.username || '').toLowerCase().trim();
    if (!username) return next(new AppError(400, 'username required'));
    const user = await User.findOne({ username }).select('kdf').lean();
    const kdf = user ? user.kdf : fakeKdf(username, req.app.locals.serverSecret);
    res.json(kdf);
  } catch (err) {
    next(err);
  }
});

// ── POST /api/auth/register ───────────────────────────────────────────────────
router.post('/register', registerLimiter, async (req, res, next) => {
  try {
    if (req.app.locals.registrationOpen === false) return next(new AppError(403, 'Registration is closed'));
    const body = RegisterSchema.parse(req.body);
    const username = body.username.toLowerCase();
    const authHash = await argon2.hash(body.authKey, ARGON_OPTS);
    const role = username === req.app.locals.bootstrapAdmin ? 'admin' : 'user';
    const user = await User.create({
      username, kdf: body.kdf, authHash, role,
      encPublicKey: body.encPublicKey, sigPublicKey: body.sigPublicKey, vault: body.vault,
    });
    const { token, jti, exp } = await signJWT(user, req.app.locals);
    const cookieName = sessionCookieName(req.app.locals.cookieSecure);
    res.cookie(cookieName, token, cookieOpts({ COOKIE_SECURE: req.app.locals.cookieSecure ? 'true' : 'false' }));
    await audit('auth.registered', { username, userId: user.id });
    await dispatchWebhook('auth.registered', { actorId: user.id, username });
    res.status(201).json({
      user: { id: user.id, username: user.username, role: user.role, encPublicKey: user.encPublicKey, sigPublicKey: user.sigPublicKey },
      vault: user.vault,
    });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/auth/login ──────────────────────────────────────────────────────
router.post('/login', authLimiter, async (req, res, next) => {
  try {
    const body = LoginSchema.parse(req.body);
    const username = body.username.toLowerCase();
    const user = await User.findOne({ username });
    const invalid = new AppError(401, 'Invalid credentials');

    if (!user) {
      // Constant-time fake hash comparison to resist timing attacks
      await argon2.hash(body.authKey, ARGON_OPTS);
      await audit('auth.login.failed', { username, outcome: 'denied', meta: { reason: 'unknown_user' } });
      await dispatchWebhook('auth.login.failed', { username, reason: 'unknown_user' });
      return next(invalid);
    }

    // Check lockout
    if (user.locked && user.lockUntil && user.lockUntil > new Date()) {
      await audit('auth.login.failed', { username, userId: user.id, outcome: 'denied', meta: { reason: 'locked' } });
      await dispatchWebhook('auth.login.failed', { username, actorId: user.id, reason: 'locked' });
      return next(new AppError(401, 'Account is temporarily locked'));
    }

    const ok = await argon2.verify(user.authHash, body.authKey);
    if (!ok) {
      user.failedAttempts = (user.failedAttempts || 0) + 1;
      if (user.failedAttempts >= MAX_FAILED) {
        user.locked = true;
        user.lockUntil = new Date(Date.now() + LOCK_MS);
        await audit('auth.account.locked', { username, userId: user.id, outcome: 'ok', meta: { lockUntil: user.lockUntil } });
        await dispatchWebhook('auth.account.locked', { username, actorId: user.id, lockUntil: user.lockUntil });
      }
      await user.save();
      await audit('auth.login.failed', { username, userId: user.id, outcome: 'denied', meta: { reason: 'wrong_password' } });
      await dispatchWebhook('auth.login.failed', { username, actorId: user.id, reason: 'wrong_password' });
      return next(invalid);
    }

    // Reset failed attempts
    user.failedAttempts = 0;
    user.locked = false;
    user.lockUntil = null;
    await user.save();

    const { token, jti, exp } = await signJWT(user, req.app.locals);
    const cookieName = sessionCookieName(req.app.locals.cookieSecure);
    res.cookie(cookieName, token, cookieOpts({ COOKIE_SECURE: req.app.locals.cookieSecure ? 'true' : 'false' }));
    await audit('auth.login.succeeded', { username, userId: user.id });
    await dispatchWebhook('auth.login.succeeded', { actorId: user.id, username });
    res.json({
      user: { id: user.id, username: user.username, role: user.role, encPublicKey: user.encPublicKey, sigPublicKey: user.sigPublicKey },
      vault: user.vault,
    });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/auth/logout ─────────────────────────────────────────────────────
router.post('/logout', async (req, res, next) => {
  try {
    const session = req.session;
    if (session?.jti && session?.exp) {
      await RevokedSession.create({ jti: session.jti, exp: new Date(session.exp * 1000) }).catch(() => {});
    }
    const cookieName = sessionCookieName(req.app.locals.cookieSecure);
    res.clearCookie(cookieName, { path: '/' });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// ── GET /api/auth/me ──────────────────────────────────────────────────────────
router.get('/me', async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id).select('-authHash').lean();
    if (!user) return next(new AppError(401, 'Not signed in'));
    res.json({
      user: { id: user._id, username: user.username, role: user.role, encPublicKey: user.encPublicKey, sigPublicKey: user.sigPublicKey },
      vault: user.vault,
      kdf: user.kdf,
    });
  } catch (err) {
    next(err);
  }
});

export default router;
