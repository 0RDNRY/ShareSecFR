import { Router } from 'express';
import { z } from 'zod';
import { policy as policyLib } from '@secureshare/crypto';
import { UserAttr, AuthorityAudit } from '../models/index.js';

const router = Router();

const AttributeUpdateSchema = z.object({
  username:   z.string().min(1).max(32),
  // Same grammar as the policy language (packages/crypto), so every assignable attribute is usable in a policy.
  attributes: z.array(
    z.string().min(1).max(100).refine((a) => policyLib.ATTRIBUTE_RE.test(a.trim().toLowerCase()), {
      message: 'Invalid attribute (expected key:value using letters, digits, _ - . @)',
    }),
  ).max(50),
});

// GET /authority/admin/users
router.get('/users', async (_req, res, next) => {
  try {
    const recs = await UserAttr.find().sort('username').lean();
    res.json({
      users: recs.map((r) => ({
        userId: r.userId, username: r.username, attributes: r.attributes,
        version: r.version, updatedAt: r.updatedAt,
      })),
    });
  } catch (err) {
    next(err);
  }
});

// PUT /authority/admin/users/:userId/attributes
router.put('/users/:userId/attributes', async (req, res, next) => {
  try {
    const body = AttributeUpdateSchema.parse(req.body);
    // Prevent assigning user: attributes via admin (they're auto-added per FAME design).
    // Normalise to lower case so the stored attributes hash identically to policy attributes.
    const userAttrs = body.attributes.map((a) => a.trim().toLowerCase()).filter((a) => !a.startsWith('user:'));

    let rec = await UserAttr.findOne({ userId: req.params.userId });
    if (!rec) {
      rec = new UserAttr({ userId: req.params.userId, username: body.username });
    }
    rec.attributes = userAttrs;
    rec.version = (rec.version ?? 0) + 1;
    rec.sealedKey = undefined; // invalidate cache
    rec.keyVersion = -1;
    await rec.save();

    await AuthorityAudit.create({
      actor: req.user.username,
      action: 'attributes.updated',
      target: body.username,
      meta: { attributes: userAttrs, version: rec.version },
    }).catch(() => {});

    // Notify API (best-effort) so the access gate refreshes
    res.json({ userId: rec.userId, username: rec.username, attributes: rec.attributes, version: rec.version });
  } catch (err) {
    next(err);
  }
});

// GET /authority/admin/audit
router.get('/audit', async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit ?? '50', 10) || 50, 200);
    const events = await AuthorityAudit.find().sort('-at').limit(limit).lean();
    res.json({
      events: events.map((e) => ({
        id: e._id, at: e.at, actor: e.actor, action: e.action, target: e.target, meta: e.meta,
      })),
    });
  } catch (err) {
    next(err);
  }
});

export default router;
