import { Router } from 'express';
import { z } from 'zod';
import mongoose from 'mongoose';
import { AppError } from '@secureshare/server-common';
import { WebhookEndpoint, WebhookDelivery } from '../models/index.js';
import { isSafeWebhookUrl, sign } from '../webhooks.js';
import { randomBytes } from 'node:crypto';

const router = Router();

const SUPPORTED_EVENTS = [
  'auth.registered',
  'auth.login.succeeded',
  'auth.login.failed',
  'auth.account.locked',
  'file.uploaded',
  'file.downloaded',
  'file.access.denied',
  'file.policy.updated',
  'file.deleted',
  'authority.attributes.updated',
];

const CreateSchema = z.object({
  url: z.string().url().max(2048),
  secret: z.string().min(16).max(256),
  events: z.array(z.enum(SUPPORTED_EVENTS)).min(1).max(20),
  description: z.string().max(200).optional().default(''),
});

// GET /api/webhooks – list endpoints (admin only)
router.get('/', async (req, res, next) => {
  try {
    const endpoints = await WebhookEndpoint.find({ createdBy: req.user.id })
      .select('-secret')
      .sort('-createdAt')
      .limit(50)
      .lean();
    res.json({ endpoints });
  } catch (err) {
    next(err);
  }
});

// POST /api/webhooks – register a new endpoint
router.post('/', async (req, res, next) => {
  try {
    const body = CreateSchema.parse(req.body);
    if (!isSafeWebhookUrl(body.url)) {
      return next(new AppError(400, 'Webhook URL is not allowed (blocked by SSRF protection)'));
    }
    const ep = await WebhookEndpoint.create({
      url: body.url,
      secret: body.secret,
      events: body.events,
      description: body.description,
      createdBy: req.user.id,
      enabled: true,
    });
    res.status(201).json({
      id: ep._id,
      url: ep.url,
      events: ep.events,
      description: ep.description,
      enabled: ep.enabled,
      createdAt: ep.createdAt,
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/webhooks/:id – enable/disable
router.patch('/:id', async (req, res, next) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return next(new AppError(404, 'Not found'));
    const ep = await WebhookEndpoint.findOne({ _id: req.params.id, createdBy: req.user.id });
    if (!ep) return next(new AppError(404, 'Not found'));
    const { enabled, events, description } = req.body;
    if (typeof enabled === 'boolean') ep.enabled = enabled;
    if (Array.isArray(events)) ep.events = events;
    if (typeof description === 'string') ep.description = description;
    await ep.save();
    res.json({ id: ep._id, enabled: ep.enabled, events: ep.events, description: ep.description });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/webhooks/:id
router.delete('/:id', async (req, res, next) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return next(new AppError(404, 'Not found'));
    const ep = await WebhookEndpoint.findOneAndDelete({ _id: req.params.id, createdBy: req.user.id });
    if (!ep) return next(new AppError(404, 'Not found'));
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

// POST /api/webhooks/:id/ping – test delivery
router.post('/:id/ping', async (req, res, next) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return next(new AppError(404, 'Not found'));
    const ep = await WebhookEndpoint.findOne({ _id: req.params.id, createdBy: req.user.id });
    if (!ep) return next(new AppError(404, 'Not found'));
    if (!isSafeWebhookUrl(ep.url)) return next(new AppError(400, 'URL blocked by SSRF protection'));

    const eventId = randomBytes(16).toString('hex');
    const timestamp = Math.floor(Date.now() / 1000);
    const payload = { eventId, eventType: 'ping', timestamp, message: 'SecureShareFR webhook test ping' };
    const body = JSON.stringify(payload);
    const signature = sign(ep.secret, body, timestamp, eventId);

    let statusCode, responseBody, error;
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 10000);
      try {
        const r = await fetch(ep.url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-SecureShare-Signature': `sha256=${signature}`,
            'X-SecureShare-Event-Id': eventId,
            'X-SecureShare-Timestamp': String(timestamp),
            'User-Agent': 'SecureShareFR-Webhook/2.0',
          },
          body,
          signal: ctrl.signal,
        });
        clearTimeout(timer);
        statusCode = r.status;
        responseBody = (await r.text()).slice(0, 500);
      } finally {
        clearTimeout(timer);
      }
    } catch (err) {
      error = err.message;
    }

    const success = statusCode && statusCode >= 200 && statusCode < 300;
    res.json({ success, statusCode, responseBody, error, eventId, payload });
  } catch (err) {
    next(err);
  }
});

// GET /api/webhooks/:id/deliveries – delivery log
router.get('/:id/deliveries', async (req, res, next) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return next(new AppError(404, 'Not found'));
    const ep = await WebhookEndpoint.findOne({ _id: req.params.id, createdBy: req.user.id }).lean();
    if (!ep) return next(new AppError(404, 'Not found'));
    const deliveries = await WebhookDelivery.find({ endpointId: req.params.id })
      .sort('-createdAt').limit(50).lean();
    res.json({ deliveries });
  } catch (err) {
    next(err);
  }
});

// GET /api/webhooks/events – list supported event types
router.get('/events', async (_req, res) => {
  res.json({ events: SUPPORTED_EVENTS });
});

export default router;
