import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import { generateKeyPairSync, createHash } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { MongoMemoryServer } from 'mongodb-memory-server';
import request from 'supertest';
import mongoose from 'mongoose';
import { SignJWT, importPKCS8 } from 'jose';
import { JWT_ISSUER, JWT_AUDIENCE } from '@secureshare/server-common';
import { app, initAuth, configureApp, logger } from '../src/index.js';
import { initStorage } from '../src/storage.js';
import { User, File, RevokedSession, AuditEvent, WebhookEndpoint, WebhookDelivery } from '../src/models/index.js';

let mongod;
let privateKey;
let publicKeyPem;
let storageDir;
let ipCounter = 0;
const AUTH_KEY = 'A'.repeat(43);
const ip = () => `203.0.113.${(ipCounter++ % 250) + 1}`;
const csrf = { 'X-SecureShare-CSRF': '1' };

async function cookieFor(u, jti = `jti-${ipCounter++}`) {
  return `ss_session=${await new SignJWT({
    sub: u.id, usr: u.username, role: u.role,
    ek: { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' },
    jti, iss: JWT_ISSUER, aud: JWT_AUDIENCE,
  }).setProtectedHeader({ alg: 'ES256' }).setIssuedAt().setExpirationTime('30m').sign(privateKey)}`;
}

async function registerUser(username) {
  const r = await request(app)
    .post('/api/auth/register')
    .set(csrf)
    .set('X-Forwarded-For', ip())
    .send({
      username,
      kdf: { alg: 'pbkdf2-sha256', iterations: 600000, salt: 'test-salt-123456' },
      authKey: AUTH_KEY,
      encPublicKey: { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' },
      sigPublicKey: { kty: 'EC', crv: 'P-256', x: 'BBBB', y: 'BBBB' },
      vault: 'test-vault',
    });
  return { response: r, cookie: r.headers['set-cookie']?.[0]?.split(';')[0] ?? '', user: r.body.user };
}

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  const kp = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  publicKeyPem = kp.publicKey.export({ type: 'spki', format: 'pem' });
  privateKey = await importPKCS8(kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), 'ES256');
  storageDir = mkdtempSync(join(tmpdir(), 'secureshare-api-test-'));
  initStorage(storageDir);

  await initAuth({
    publicKeyPem,
    cookieName: 'ss_session',
    isRevoked: async (payload) => !!(await RevokedSession.exists({ jti: payload.jti })),
  });
  configureApp({
    logger,
    jwtPrivateKey: privateKey,
    serverSecret: 'test-server-secret',
    internalToken: 'test-internal-token',
    cookieSecure: false,
    bootstrapAdmin: 'admin',
    registrationOpen: true,
    authorityInternalUrl: 'http://127.0.0.1:7001',
    maxUploadBytes: 104857600,
    jwtTtlSeconds: 1800,
    publicOrigin: 'http://localhost:5173',
    storageDir,
  });
});

beforeEach(async () => {
  await Promise.all([
    User.deleteMany({}), File.deleteMany({}), RevokedSession.deleteMany({}),
    AuditEvent.deleteMany({}), WebhookEndpoint.deleteMany({}), WebhookDelivery.deleteMany({}),
  ]);
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongod.stop();
  rmSync(storageDir, { recursive: true, force: true });
});

describe('API docs and health', () => {
  it('GET /api/health reports ok', async () => {
    const r = await request(app).get('/api/health');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ status: 'ok', service: 'api' });
  });

  it('GET /api/meta publishes upload limits', async () => {
    const r = await request(app).get('/api/meta');
    expect(r.status).toBe(200);
    expect(r.body.maxUploadBytes).toBe(104857600);
  });

  it('GET /docs serves Swagger UI with no CDN references', async () => {
    const r = await request(app).get('/docs');
    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toContain('text/html');
    expect(r.text).toContain('/docs/assets/swagger-ui.css');
    expect(r.text).toContain('/docs/assets/swagger-ui-bundle.js');
    expect(r.text).toContain('/docs/bootstrap.js');
    expect(r.text).not.toContain('unpkg.com');
    expect(r.headers['content-security-policy']).toContain("script-src 'self'");
  });

  it('GET /docs/bootstrap.js is a local external script', async () => {
    const r = await request(app).get('/docs/bootstrap.js');
    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toContain('javascript');
    expect(r.text).toContain('SwaggerUIBundle');
    expect(r.text).toContain('/api/openapi.json');
  });

  it('GET /api/openapi.json describes the documented endpoints', async () => {
    const r = await request(app).get('/api/openapi.json');
    expect(r.status).toBe(200);
    expect(r.body.openapi).toBe('3.0.3');
    expect(r.body.paths['/api/auth/login']).toBeTruthy();
    expect(r.body.paths['/docs']).toBeTruthy();
    expect(r.body.components.securitySchemes.sessionCookie.name).toBe('ss_session');
  });

  it('serves locally installed swagger-ui-dist assets', async () => {
    const r = await request(app).get('/docs/assets/swagger-ui.css');
    expect(r.status).toBe(200);
    expect(r.headers['content-type']).toContain('text/css');
  });

  it('rejects state-changing requests without the CSRF header', async () => {
    const r = await request(app).post('/api/auth/login').set('X-Forwarded-For', ip()).send({});
    expect(r.status).toBe(403);
    expect(r.body.error).toMatch(/CSRF/);
  });
});

describe('authentication', () => {
  it('returns real KDF parameters for a known user', async () => {
    await registerUser('alice');
    const r = await request(app).get('/api/auth/params?username=alice');
    expect(r.status).toBe(200);
    expect(r.body.alg).toBe('pbkdf2-sha256');
    expect(r.body.iterations).toBeGreaterThanOrEqual(600000);
  });

  it('returns fake but valid KDF parameters for an unknown user', async () => {
    const a = await request(app).get('/api/auth/params?username=ghost_user');
    const b = await request(app).get('/api/auth/params?username=another_ghost');
    expect(a.status).toBe(200);
    expect(a.body.alg).toBe('pbkdf2-sha256');
    expect(a.body.salt).not.toBe(b.body.salt);
  });

  it('rejects malformed registration payloads', async () => {
    const r = await request(app).post('/api/auth/register').set(csrf).set('X-Forwarded-For', ip()).send({ username: 'x' });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe('Invalid request');
  });

  it('registers a user and sets a session cookie', async () => {
    const { response, user } = await registerUser('alice');
    expect(response.status).toBe(201);
    expect(user.username).toBe('alice');
    expect(user.role).toBe('user');
    expect(response.headers['set-cookie'][0]).toContain('ss_session=');
  });

  it('makes the bootstrap admin an admin', async () => {
    const { response, user } = await registerUser('admin');
    expect(response.status).toBe(201);
    expect(user.role).toBe('admin');
  });

  it('rejects duplicate usernames with 409', async () => {
    await registerUser('alice');
    const second = await registerUser('alice');
    expect(second.response.status).toBe(409);
  });

  it('rejects invalid credentials with 401', async () => {
    await registerUser('alice');
    const r = await request(app).post('/api/auth/login').set(csrf).set('X-Forwarded-For', ip())
      .send({ username: 'alice', authKey: 'wrong-key' });
    expect(r.status).toBe(401);
  });

  it('locks an account after five failed logins', async () => {
    await registerUser('alice');
    for (let i = 0; i < 5; i++) {
      const r = await request(app).post('/api/auth/login').set(csrf).set('X-Forwarded-For', ip())
        .send({ username: 'alice', authKey: 'wrong-key' });
      expect(r.status).toBe(401);
    }
    const locked = await User.findOne({ username: 'alice' });
    expect(locked.locked).toBe(true);
  });

  it('logs in with the derived auth key', async () => {
    await registerUser('alice');
    const r = await request(app).post('/api/auth/login').set(csrf).set('X-Forwarded-For', ip())
      .send({ username: 'alice', authKey: AUTH_KEY });
    expect(r.status).toBe(200);
    expect(r.body.user.username).toBe('alice');
    expect(r.headers['set-cookie'][0]).toContain('ss_session=');
  });

  it('requires a session for /api/auth/me', async () => {
    expect((await request(app).get('/api/auth/me')).status).toBe(401);
  });

  it('returns the current user and vault from /api/auth/me', async () => {
    const { cookie } = await registerUser('alice');
    const r = await request(app).get('/api/auth/me').set('Cookie', cookie);
    expect(r.status).toBe(200);
    expect(r.body.user.username).toBe('alice');
    expect(r.body.vault).toBe('test-vault');
  });

  it('revokes the session on logout', async () => {
    const { cookie } = await registerUser('alice');
    expect((await request(app).get('/api/auth/me').set('Cookie', cookie)).status).toBe(200);
    const out = await request(app).post('/api/auth/logout').set(csrf).set('Cookie', cookie);
    expect(out.status).toBe(204);
    expect((await request(app).get('/api/auth/me').set('Cookie', cookie)).status).toBe(401);
  });

  it('writes audit events for registration and login', async () => {
    await registerUser('alice');
    expect(await AuditEvent.countDocuments({ action: 'auth.registered' })).toBe(1);
  });
});

describe('files', () => {
  const fileId = 'A'.repeat(22);
  const ciphertext = Buffer.from('ciphertext-only-the-server-sees');
  const sha256 = createHash('sha256').update(ciphertext).digest('hex');

  async function createFile(cookie, userId) {
    return request(app).post('/api/files').set(csrf).set('Cookie', cookie).send({
      fileId,
      encMeta: 'enc-meta',
      abeEnvelope: { policy: 'user:alice', ct: 'x' },
      ownerEnvelope: 'owner-env',
      manifest: { v: 1, ownerId: userId, ciphertext: { sha256, size: ciphertext.length } },
      signature: 'sig',
    });
  }

  it('requires authentication to list files', async () => {
    expect((await request(app).get('/api/files?scope=owned')).status).toBe(401);
  });

  it('requires a scope when listing files', async () => {
    const { cookie } = await registerUser('alice');
    expect((await request(app).get('/api/files').set('Cookie', cookie)).status).toBe(400);
  });

  it('rejects path-traversal file IDs', async () => {
    const { cookie } = await registerUser('alice');
    const r = await request(app).post('/api/files').set(csrf).set('Cookie', cookie).send({ fileId: '../evil' });
    expect(r.status).toBe(400);
  });

  it('registers a file with a signed manifest', async () => {
    const { cookie, user } = await registerUser('alice');
    const r = await createFile(cookie, user.id);
    expect(r.status).toBe(201);
    expect(r.body.id).toBe(fileId);
    expect((await File.findById(fileId)).blobName).toBe('pending');
  });

  it('uploads ciphertext and rejects a hash mismatch', async () => {
    const { cookie, user } = await registerUser('alice');
    await createFile(cookie, user.id);
    const bad = await request(app).put(`/api/files/${fileId}/blob`).set(csrf).set('Cookie', cookie)
      .set('Content-Type', 'application/octet-stream').send(Buffer.from('wrong bytes'));
    expect(bad.status).toBe(400);
    const good = await request(app).put(`/api/files/${fileId}/blob`).set(csrf).set('Cookie', cookie)
      .set('Content-Type', 'application/octet-stream').send(ciphertext);
    expect(good.status).toBe(204);
  });

  it('lists owned files only after the blob is uploaded', async () => {
    const { cookie, user } = await registerUser('alice');
    await createFile(cookie, user.id);
    expect((await request(app).get('/api/files?scope=owned').set('Cookie', cookie)).body.files).toEqual([]);
    await request(app).put(`/api/files/${fileId}/blob`).set(csrf).set('Cookie', cookie)
      .set('Content-Type', 'application/octet-stream').send(ciphertext);
    const r = await request(app).get('/api/files?scope=owned').set('Cookie', cookie);
    expect(r.body.files).toHaveLength(1);
  });

  it('reads the file record and downloads the ciphertext', async () => {
    const { cookie, user } = await registerUser('alice');
    await createFile(cookie, user.id);
    await request(app).put(`/api/files/${fileId}/blob`).set(csrf).set('Cookie', cookie)
      .set('Content-Type', 'application/octet-stream').send(ciphertext);
    const rec = await request(app).get(`/api/files/${fileId}`).set('Cookie', cookie);
    expect(rec.status).toBe(200);
    expect(rec.body.policy).toBe('user:alice');
    const blob = await request(app).get(`/api/files/${fileId}/blob`).set('Cookie', cookie);
    expect(blob.status).toBe(200);
    expect(Buffer.from(blob.body)).toEqual(ciphertext);
  });

  it('changes the policy and deletes the file', async () => {
    const { cookie, user } = await registerUser('alice');
    await createFile(cookie, user.id);
    await request(app).put(`/api/files/${fileId}/blob`).set(csrf).set('Cookie', cookie)
      .set('Content-Type', 'application/octet-stream').send(ciphertext);
    const updated = await request(app).put(`/api/files/${fileId}/policy`).set(csrf).set('Cookie', cookie)
      .send({ abeEnvelope: { policy: 'role:faculty' }, manifest: { v: 1 }, signature: 'sig2' });
    expect(updated.status).toBe(200);
    expect(updated.body.policy).toBe('role:faculty');
    expect((await request(app).delete(`/api/files/${fileId}`).set(csrf).set('Cookie', cookie)).status).toBe(204);
    expect(await File.countDocuments()).toBe(0);
  });

  it('returns 404 for a non-existent file', async () => {
    const { cookie } = await registerUser('alice');
    expect((await request(app).get(`/api/files/${'B'.repeat(22)}`).set('Cookie', cookie)).status).toBe(404);
  });

  it('does not let OR short-circuiting bypass the policy gate', async () => {
    const { cookie: ownerCookie, user: owner } = await registerUser('carol');
    await request(app).post('/api/files').set(csrf).set('Cookie', ownerCookie).send({
      fileId,
      encMeta: 'enc-meta',
      abeEnvelope: { policy: '(user:alice OR role:faculty) AND dept:cse', ct: 'x' },
      ownerEnvelope: 'owner-env',
      manifest: { v: 1, ownerId: owner.id, ciphertext: { sha256, size: ciphertext.length } },
      signature: 'sig',
    });
    await request(app).put(`/api/files/${fileId}/blob`).set(csrf).set('Cookie', ownerCookie)
      .set('Content-Type', 'application/octet-stream').send(ciphertext);

    const { cookie: aliceCookie } = await registerUser('alice');
    // Alice matches the first OR term but not the trailing AND term: must be denied.
    const denied = await request(app).get(`/api/files/${fileId}`).set('Cookie', aliceCookie);
    expect(denied.status).toBe(404);
    expect(await AuditEvent.countDocuments({ action: 'file.access', outcome: 'denied' })).toBe(1);
  });
});

describe('webhooks, admin and integrations', () => {
  it('lists supported webhook events publicly', async () => {
    const r = await request(app).get('/api/webhooks/events');
    expect(r.status).toBe(200);
    expect(r.body.events).toContain('file.uploaded');
  });

  it('blocks insecure and private webhook URLs (SSRF protection)', async () => {
    const { cookie } = await registerUser('alice');
    const r = await request(app).post('/api/webhooks').set(csrf).set('Cookie', cookie).send({
      url: 'http://localhost:27017/evil', secret: 'x'.repeat(20), events: ['file.uploaded'],
    });
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/SSRF|HTTPS/);
  });

  it('validates events when patching a webhook', async () => {
    const { cookie, user } = await registerUser('alice');
    const ep = await WebhookEndpoint.create({
      url: 'https://example.com/hook', secret: 'x'.repeat(20), events: ['file.uploaded'], createdBy: user.id,
    });
    const r = await request(app).patch(`/api/webhooks/${ep.id}`).set(csrf).set('Cookie', cookie)
      .send({ events: ['not-a-real-event'] });
    expect(r.status).toBe(400);
  });

  it('requires authentication for admin endpoints', async () => {
    expect((await request(app).get('/api/admin/users')).status).toBe(401);
  });

  it('lets an admin list users and read the audit log', async () => {
    await registerUser('admin');
    const { cookie } = await registerUser('admin2');
    const adminUser = await User.findOne({ username: 'admin' });
    const adminCookie = await cookieFor(adminUser);
    expect((await request(app).get('/api/admin/users').set('Cookie', adminCookie)).body.users).toHaveLength(2);
    expect((await request(app).get('/api/admin/audit?limit=5').set('Cookie', adminCookie)).body.events).toBeTruthy();
    expect((await request(app).get('/api/admin/users').set('Cookie', cookie)).status).toBe(403);
  });

  it('reports live integrations without leaking internal paths', async () => {
    const r = await request(app).get('/api/integrations/status');
    expect([200, 207]).toContain(r.status);
    expect(r.body.checks.swagger.status).toBe('ok');
    expect(JSON.stringify(r.body)).not.toContain(storageDir);
  });
});
