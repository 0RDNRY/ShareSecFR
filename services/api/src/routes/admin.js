import { Router } from 'express';
import { User, AuditEvent } from '../models/index.js';
import { AppError } from '@secureshare/server-common';

const router = Router();

// ── GET /api/admin/users ──────────────────────────────────────────────────────
router.get('/users', async (_req, res, next) => {
  try {
    const users = await User.find().select('username role locked lockUntil createdAt').sort('username').lean();
    res.json({
      users: users.map((u) => ({
        id: u._id, username: u.username, role: u.role,
        locked: u.locked && u.lockUntil > new Date(),
        createdAt: u.createdAt,
      })),
    });
  } catch (err) {
    next(err);
  }
});

// ── POST /api/admin/users/:id/unlock ─────────────────────────────────────────
router.post('/users/:id/unlock', async (req, res, next) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return next(new AppError(404, 'Not found'));
    user.locked = false;
    user.lockUntil = null;
    user.failedAttempts = 0;
    await user.save();
    res.json({ id: user.id, locked: false });
  } catch (err) {
    next(err);
  }
});

// ── GET /api/admin/audit ──────────────────────────────────────────────────────
router.get('/audit', async (req, res, next) => {
  try {
    const limit = Math.min(parseInt(req.query.limit ?? '100', 10) || 100, 500);
    const events = await AuditEvent.find().sort('-at').limit(limit).lean();
    res.json({
      events: events.map((e) => ({
        id: e._id, at: e.at, username: e.username, userId: e.userId,
        action: e.action, target: e.target, outcome: e.outcome, meta: e.meta,
      })),
    });
  } catch (err) {
    next(err);
  }
});

export default router;
