import { Router } from 'express';
import { createHash } from 'node:crypto';
import { UserAttr } from '../models/index.js';
import { AppError, limiter } from '@secureshare/server-common';
import { abe, sealTo, utf8 } from '@secureshare/crypto';

const router = Router();

const keyLimiter = limiter({ windowMs: 60 * 1000, limit: 60, message: 'Too many key requests' });

function pkFingerprint(pk) {
  return createHash('sha256').update(JSON.stringify(pk)).digest('hex').slice(0, 16);
}

// ── GET /authority/params ──────────────────────────────────────────────────────
router.get('/params', (req, res) => {
  const { pk } = req.app.locals.abeState;
  res.json({ publicKey: pk, fingerprint: pkFingerprint(pk) });
});

// ── GET /authority/catalog – attribute names in use ───────────────────────────
router.get('/catalog', async (_req, res, next) => {
  try {
    const all = await UserAttr.find().select('attributes').lean();
    const attrs = new Set();
    for (const r of all) for (const a of r.attributes) attrs.add(a);
    res.json({ attributes: [...attrs].sort() });
  } catch (err) {
    next(err);
  }
});

// Routes below require a verified session (mounted behind requireUser in index.js).
export const protectedRouter = Router();

// ── GET /authority/me – current user's attributes ─────────────────────────────
protectedRouter.get('/me', async (req, res, next) => {
  try {
    const rec = await UserAttr.findOne({ userId: req.user.id }).lean();
    res.json({
      attributes: rec?.attributes ?? [],
      version: rec?.version ?? 0,
    });
  } catch (err) {
    next(err);
  }
});

// ── GET /authority/keys/me – sealed CP-ABE key ────────────────────────────────
protectedRouter.get('/keys/me', keyLimiter, async (req, res, next) => {
  try {
    const { msk } = req.app.locals.abeState;
    let rec = await UserAttr.findOne({ userId: req.user.id });
    if (!rec) {
      rec = await UserAttr.create({ userId: req.user.id, username: req.user.username, attributes: [], version: 0 });
    }

    // CP-ABE policy attributes are lower-cased; keys must use the same form.
    const userAttributes = [...(rec.attributes ?? []).map((a) => a.toLowerCase()), `user:${req.user.username.toLowerCase()}`];
    const version = rec.version ?? 0;

    // Use cached sealed key if version matches
    if (rec.sealedKey && rec.keyVersion === version) {
      return res.json({
        sealedKey: rec.sealedKey,
        attributes: rec.attributes,
        version,
        issuedAt: rec.updatedAt,
      });
    }

    // Generate and seal a new key
    const sk = abe.fame.keygen(msk, userAttributes);
    const encPublicJwk = req.session?.ek;
    if (!encPublicJwk) return next(new AppError(400, 'No ECDH key in session'));

    const aad = `secureshare/v2/abe-key|${req.user.id}|${version}`;
    const sealedKey = await sealTo(encPublicJwk, utf8.encode(JSON.stringify(sk)), aad);

    rec.sealedKey = sealedKey;
    rec.keyVersion = version;
    await rec.save();

    res.json({ sealedKey, attributes: rec.attributes, version, issuedAt: new Date() });
  } catch (err) {
    next(err);
  }
});

export default router;
