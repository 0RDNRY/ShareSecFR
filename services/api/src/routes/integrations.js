import { Router } from 'express';
import { WebhookEndpoint, WebhookDelivery } from '../models/index.js';
import { AppError } from '@secureshare/server-common';
import mongoose from 'mongoose';

const router = Router();

// GET /api/integrations/status – live status checks for the dashboard
router.get('/status', async (req, res) => {
  const checks = {};

  // 1. Database connectivity
  try {
    await mongoose.connection.db.admin().ping();
    checks.database = { status: 'ok', message: 'MongoDB connected' };
  } catch (err) {
    checks.database = { status: 'error', message: err.message };
  }

  // 2. Authority connectivity (internal)
  try {
    const r = await fetch(`${req.app.locals.authorityInternalUrl.replace(':7001', ':7000')}/authority/health`, {
      signal: AbortSignal.timeout(3000),
    });
    checks.authority = { status: r.ok ? 'ok' : 'error', message: r.ok ? 'Authority reachable' : `HTTP ${r.status}` };
  } catch (err) {
    checks.authority = { status: 'error', message: 'Authority unreachable' };
  }

  // 3. File storage
  try {
    const { mkdirSync, writeFileSync, unlinkSync } = await import('node:fs');
    const testPath = `${req.app.locals.storageDir}/.health-${Date.now()}`;
    writeFileSync(testPath, 'ok');
    unlinkSync(testPath);
    checks.fileStorage = { status: 'ok', message: `Storage writable: ${req.app.locals.storageDir}` };
  } catch (err) {
    checks.fileStorage = { status: 'error', message: err.message };
  }

  // 4. Webhook system
  try {
    const count = await WebhookEndpoint.countDocuments({ enabled: true });
    const recent = await WebhookDelivery.findOne().sort('-createdAt').lean();
    checks.webhooks = {
      status: 'ok',
      message: `${count} active endpoint(s)`,
      lastDeliveryStatus: recent?.status ?? 'none',
    };
  } catch (err) {
    checks.webhooks = { status: 'error', message: err.message };
  }

  // 5. Swagger docs
  checks.swagger = { status: 'ok', message: 'OpenAPI spec available at /api/openapi.json', docsUrl: '/docs' };

  // 6. HTTPS / proxy detection
  const proto = req.headers['x-forwarded-proto'] ?? req.protocol;
  const via = req.headers['x-real-ip'] || req.headers['x-forwarded-for'];
  checks.nginx = {
    status: via ? 'ok' : 'warn',
    message: via ? `Proxied through Nginx (client IP: ${via})` : 'Direct connection (no proxy headers detected)',
    protocol: proto,
    xForwardedFor: req.headers['x-forwarded-for'] ?? null,
    xRealIp: req.headers['x-real-ip'] ?? null,
  };

  checks.https = {
    status: proto === 'https' ? 'ok' : 'warn',
    message: proto === 'https' ? 'HTTPS connection confirmed' : `Protocol: ${proto}`,
    protocol: proto,
  };

  // 7. Environment info
  checks.environment = {
    status: 'ok',
    nodeEnv: process.env.NODE_ENV ?? 'development',
    version: '2.0.0',
    uptime: Math.round(process.uptime()),
    publicOrigin: req.app.locals.publicOrigin ?? 'not set',
  };

  const allOk = Object.values(checks).every((c) => c.status !== 'error');
  res.status(allOk ? 200 : 207).json({ status: allOk ? 'ok' : 'degraded', checks });
});

// GET /api/integrations/demo/data – safe demo data for demonstration mode
router.get('/demo/data', async (_req, res) => {
  res.json({
    sampleUsers: [
      { username: 'admin', role: 'admin', note: 'First registered user becomes admin' },
      { username: 'alice', attributes: ['dept:cse', 'role:faculty'], note: 'Can access dept:cse AND role:faculty files' },
      { username: 'bob', attributes: ['dept:cse', 'role:student'], note: 'Cannot access faculty-only files' },
    ],
    samplePolicies: [
      { policy: 'dept:cse AND role:faculty', description: 'Only CSE faculty can access' },
      { policy: 'dept:cse OR dept:hr', description: 'Any CSE or HR member can access' },
      { policy: 'role:student', description: 'Any student can access' },
      { policy: 'user:alice', description: 'Only alice can access' },
    ],
    sampleWebhookEvents: [
      'file.uploaded', 'auth.login.succeeded', 'file.access.denied', 'file.policy.updated',
    ],
    apiEndpoints: [
      { method: 'GET', path: '/api/health', auth: false, description: 'API health check' },
      { method: 'GET', path: '/api/meta', auth: false, description: 'Upload limits & metadata' },
      { method: 'GET', path: '/api/auth/params', auth: false, description: 'KDF params for login' },
      { method: 'POST', path: '/api/auth/register', auth: false, description: 'Register a new account' },
      { method: 'POST', path: '/api/auth/login', auth: false, description: 'Sign in' },
      { method: 'POST', path: '/api/auth/logout', auth: true, description: 'Sign out' },
      { method: 'GET', path: '/api/auth/me', auth: true, description: 'Current session' },
      { method: 'POST', path: '/api/files', auth: true, description: 'Register encrypted file' },
      { method: 'PUT', path: '/api/files/:id/blob', auth: true, description: 'Upload ciphertext' },
      { method: 'GET', path: '/api/files', auth: true, description: 'List files' },
      { method: 'GET', path: '/api/files/:id', auth: true, description: 'Get file record' },
      { method: 'GET', path: '/api/files/:id/blob', auth: true, description: 'Download ciphertext' },
      { method: 'PUT', path: '/api/files/:id/policy', auth: true, description: 'Change access policy' },
      { method: 'DELETE', path: '/api/files/:id', auth: true, description: 'Delete file' },
      { method: 'GET', path: '/api/admin/users', auth: 'admin', description: 'List users (admin)' },
      { method: 'GET', path: '/api/admin/audit', auth: 'admin', description: 'Audit log (admin)' },
      { method: 'GET', path: '/api/webhooks/events', auth: true, description: 'Supported webhook events' },
      { method: 'POST', path: '/api/webhooks', auth: true, description: 'Register webhook endpoint' },
      { method: 'POST', path: '/api/webhooks/:id/ping', auth: true, description: 'Test webhook delivery' },
      { method: 'GET', path: '/api/webhooks/:id/deliveries', auth: true, description: 'Delivery log' },
      { method: 'GET', path: '/api/integrations/status', auth: false, description: 'Live integration status' },
      { method: 'GET', path: '/docs', auth: false, description: 'Swagger UI' },
    ],
  });
});

export default router;
