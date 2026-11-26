import { Router } from 'express';
import { File, AuditEvent } from '../models/index.js';
import { writeBlob, readBlobStream, deleteBlob } from '../storage.js';
import { AppError, limiter } from '@secureshare/server-common';
import { dispatchWebhook } from '../webhooks.js';
import { policy as policyLib } from '@secureshare/crypto';
import { satisfiesPolicy } from '../policy-gate.js';
import { pipeline } from 'node:stream/promises';

const router = Router();

const uploadLimiter = limiter({ windowMs: 60 * 1000, limit: 20, message: 'Upload rate limit exceeded' });

const FILE_ID_RE = /^[A-Za-z0-9_-]{22}$/;

function safeId(id) {
  if (!FILE_ID_RE.test(id)) throw new AppError(400, 'Invalid file ID');
  return id;
}

// ── Helpers ───────────────────────────────────────────────────────────────────
async function audit(action, { username, userId, target, outcome = 'ok', meta } = {}) {
  await AuditEvent.create({ action, username, userId, target, outcome, meta }).catch(() => {});
}

async function getUserAttributes(userId, authorityUrl, internalToken) {
  const r = await fetch(`${authorityUrl}/internal/users/${userId}/attributes`, {
    headers: { Authorization: `Bearer ${internalToken}` },
    signal: AbortSignal.timeout(5000),
  });
  if (!r.ok) throw new AppError(503, 'Policy gate unavailable');
  return (await r.json()).attributes ?? [];
}

// ── POST /api/files – register file (signed manifest) ────────────────────────
router.post('/', uploadLimiter, async (req, res, next) => {
  try {
    const { fileId, encMeta, abeEnvelope, ownerEnvelope, manifest, signature } = req.body ?? {};
    if (!FILE_ID_RE.test(fileId)) return next(new AppError(400, 'Invalid fileId'));
    if (!encMeta || !abeEnvelope || !ownerEnvelope || !manifest || !signature)
      return next(new AppError(400, 'Missing required fields'));

    // Check for existing file
    if (await File.exists({ _id: fileId })) return next(new AppError(409, 'File already registered'));

    // Verify manifest structure
    const { v, ownerId, ciphertext: ct } = manifest;
    if (v !== 1) return next(new AppError(400, 'Unknown manifest version'));
    if (ownerId !== req.user.id) return next(new AppError(403, 'Manifest owner does not match session'));
    if (!ct?.size || !ct?.sha256) return next(new AppError(400, 'Manifest missing ciphertext hash'));

    const policy = abeEnvelope?.policy ?? '';
    if (!policy || typeof policy !== 'string') return next(new AppError(400, 'Missing ABE policy'));
    policyLib.parsePolicy(policy); // throws PolicyError -> 400

    // Placeholder blob record (blob uploaded separately)
    const file = new File({
      _id: fileId,
      ownerId: req.user.id,
      ownerUsername: req.user.username,
      ownerSigPublicKey: req.session?.ek ?? null,
      encMeta,
      abeEnvelope,
      ownerEnvelope,
      manifest,
      signature,
      policy,
      blobName: 'pending',
      size: ct.size,
      blobHash: ct.sha256,
    });
    // Temporarily mark as pending with the actual owner sig key from the user record
    const { User } = await import('../models/index.js');
    const userRec = await User.findById(req.user.id).select('sigPublicKey').lean();
    file.ownerSigPublicKey = userRec?.sigPublicKey ?? {};
    await file.save();
    res.status(201).json({ id: fileId });
  } catch (err) {
    next(err);
  }
});

// ── PUT /api/files/:id/blob – upload ciphertext ───────────────────────────────
router.put('/:id/blob', async (req, res, next) => {
  try {
    const id = safeId(req.params.id);
    const file = await File.findOne({ _id: id, ownerId: req.user.id });
    if (!file) return next(new AppError(404, 'Not found'));
    if (file.blobName !== 'pending') return next(new AppError(409, 'Blob already uploaded'));

    const maxBytes = req.app.locals.maxUploadBytes;
    const { blobName, sha256, size } = await writeBlob(req, maxBytes);

    // Verify hash matches manifest
    if (sha256 !== file.blobHash) {
      await deleteBlob(blobName);
      return next(new AppError(400, 'Ciphertext hash does not match manifest'));
    }
    if (size !== file.size) {
      await deleteBlob(blobName);
      return next(new AppError(400, 'Ciphertext size does not match manifest'));
    }

    file.blobName = blobName;
    file.size = size;
    await file.save();
    await audit('file.uploaded', { username: req.user.username, userId: req.user.id, target: id });
    await dispatchWebhook('file.uploaded', {
      actorId: req.user.id, username: req.user.username,
      fileId: id, policy: file.policy, size,
    });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// ── GET /api/files – list ─────────────────────────────────────────────────────
router.get('/', async (req, res, next) => {
  try {
    const scope = req.query.scope;
    if (!scope) return next(new AppError(400, 'scope is required (owned|shared)'));

    let files;
    if (scope === 'owned') {
      files = await File.find({ ownerId: req.user.id, blobName: { $ne: 'pending' } })
        .sort('-createdAt').limit(200).lean();
      return res.json({
        files: files.map((f) => ({
          id: f._id, policy: f.policy, size: f.size, createdAt: f.createdAt, updatedAt: f.updatedAt,
        })),
      });
    }

    if (scope === 'shared') {
      // Find all non-owned files whose policy the user's current attributes satisfy
      const userAttrs = await getUserAttributes(
        req.user.id, req.app.locals.authorityInternalUrl, req.app.locals.internalToken,
      );
      const allFiles = await File.find({ ownerId: { $ne: req.user.id }, blobName: { $ne: 'pending' } })
        .sort('-createdAt').limit(500).lean();
      files = allFiles.filter((f) => satisfiesPolicy(f.policy, [...userAttrs, `user:${req.user.username}`]));
      return res.json({
        files: files.map((f) => ({
          id: f._id, policy: f.policy, size: f.size,
          ownerUsername: f.ownerUsername,
          createdAt: f.createdAt, updatedAt: f.updatedAt,
        })),
      });
    }

    return next(new AppError(400, 'scope must be owned or shared'));
  } catch (err) {
    next(err);
  }
});

// ── GET /api/files/:id – file record ──────────────────────────────────────────
router.get('/:id', async (req, res, next) => {
  try {
    const id = safeId(req.params.id);
    const file = await File.findById(id).lean();
    if (!file || file.blobName === 'pending') return next(new AppError(404, 'Not found'));

    const isOwner = file.ownerId === req.user.id;
    if (!isOwner) {
      const userAttrs = await getUserAttributes(
        req.user.id, req.app.locals.authorityInternalUrl, req.app.locals.internalToken,
      ).catch(() => []);
      const ok = satisfiesPolicy(file.policy, [...userAttrs, `user:${req.user.username}`]);
      if (!ok) {
        await audit('file.access', { username: req.user.username, userId: req.user.id, target: id, outcome: 'denied' });
        await dispatchWebhook('file.access.denied', { actorId: req.user.id, username: req.user.username, fileId: id, policy: file.policy });
        return next(new AppError(404, 'Not found'));
      }
    }

    res.json({
      id: file._id, ownerId: file.ownerId, ownerUsername: file.ownerUsername,
      ownerSigPublicKey: file.ownerSigPublicKey, encMeta: file.encMeta,
      abeEnvelope: file.abeEnvelope, ownerEnvelope: file.ownerEnvelope,
      manifest: file.manifest, signature: file.signature,
      policy: file.policy, size: file.size, createdAt: file.createdAt, updatedAt: file.updatedAt,
    });
  } catch (err) {
    next(err);
  }
});

// ── GET /api/files/:id/blob – download ciphertext ─────────────────────────────
router.get('/:id/blob', async (req, res, next) => {
  try {
    const id = safeId(req.params.id);
    const file = await File.findById(id).lean();
    if (!file || file.blobName === 'pending') return next(new AppError(404, 'Not found'));

    const isOwner = file.ownerId === req.user.id;
    if (!isOwner) {
      const userAttrs = await getUserAttributes(
        req.user.id, req.app.locals.authorityInternalUrl, req.app.locals.internalToken,
      ).catch(() => []);
      const ok = satisfiesPolicy(file.policy, [...userAttrs, `user:${req.user.username}`]);
      if (!ok) {
        await audit('file.access', { username: req.user.username, userId: req.user.id, target: id, outcome: 'denied' });
        await dispatchWebhook('file.access.denied', { actorId: req.user.id, username: req.user.username, fileId: id, policy: file.policy });
        return next(new AppError(404, 'Not found'));
      }
    }

    await audit('file.downloaded', { username: req.user.username, userId: req.user.id, target: id });
    await dispatchWebhook('file.downloaded', { actorId: req.user.id, username: req.user.username, fileId: id });

    res.set({
      'Content-Type': 'application/octet-stream',
      'Content-Length': String(file.size),
      'Content-Disposition': 'attachment',
    });
    await pipeline(readBlobStream(file.blobName), res);
  } catch (err) {
    next(err);
  }
});

// ── PUT /api/files/:id/policy – re-wrap ──────────────────────────────────────
router.put('/:id/policy', async (req, res, next) => {
  try {
    const id = safeId(req.params.id);
    const file = await File.findOne({ _id: id, ownerId: req.user.id });
    if (!file) return next(new AppError(404, 'Not found'));

    const { abeEnvelope, manifest, signature } = req.body ?? {};
    if (!abeEnvelope || !manifest || !signature) return next(new AppError(400, 'Missing fields'));

    if (typeof abeEnvelope.policy !== 'string') return next(new AppError(400, 'Missing ABE policy'));
    policyLib.parsePolicy(abeEnvelope.policy); // throws PolicyError -> 400

    const oldPolicy = file.policy;
    file.abeEnvelope = abeEnvelope;
    file.manifest = manifest;
    file.signature = signature;
    file.policy = abeEnvelope.policy;
    await file.save();
    await audit('file.policy.updated', { username: req.user.username, userId: req.user.id, target: id, meta: { oldPolicy, newPolicy: file.policy } });
    await dispatchWebhook('file.policy.updated', {
      actorId: req.user.id, username: req.user.username,
      fileId: id, oldPolicy, newPolicy: file.policy,
    });
    res.json({ id, policy: file.policy });
  } catch (err) {
    next(err);
  }
});

// ── DELETE /api/files/:id ─────────────────────────────────────────────────────
router.delete('/:id', async (req, res, next) => {
  try {
    const id = safeId(req.params.id);
    const file = await File.findOneAndDelete({ _id: id, ownerId: req.user.id });
    if (!file) return next(new AppError(404, 'Not found'));
    await deleteBlob(file.blobName).catch(() => {});
    await audit('file.deleted', { username: req.user.username, userId: req.user.id, target: id });
    await dispatchWebhook('file.deleted', { actorId: req.user.id, username: req.user.username, fileId: id });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

export default router;
