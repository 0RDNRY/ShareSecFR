import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { MongoMemoryServer } from 'mongodb-memory-server';
import request from 'supertest';
import mongoose from 'mongoose';
import { SignJWT, importPKCS8 } from 'jose';
import { JWT_ISSUER, JWT_AUDIENCE } from '@secureshare/server-common';
import { abe, openSealed, utf8 } from '@secureshare/crypto';
import {
  publicApp, internalApp, initAuth, setInternalToken, masterKeyFingerprint, logger,
} from '../src/index.js';
import { UserAttr } from '../src/models/index.js';
import { sealMasterKey, openMasterKey } from '../src/master-key.js';

let mongod;
let privateKey;
const INTERNAL_TOKEN = 'test-internal-token';
const { pk, msk } = abe.fame.setup();

const user = { id: '507f1f77bcf86cd799439011', username: 'alice', role: 'user' };
const admin = { id: '507f1f77bcf86cd799439012', username: 'admin', role: 'admin' };

async function cookieFor(u, jti = 'test-jti') {
  return `ss_session=${await new SignJWT({
    sub: u.id,
    usr: u.username,
    role: u.role,
    ek: { kty: 'EC', crv: 'P-256', x: 'AAAA', y: 'AAAA' },
    jti,
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
  })
    .setProtectedHeader({ alg: 'ES256' })
    .setIssuedAt()
    .setExpirationTime('30m')
    .sign(privateKey)}`;
}

beforeAll(async () => {
  mongod = await MongoMemoryServer.create();
  await mongoose.connect(mongod.getUri());
  const kp = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKeyPem = kp.publicKey.export({ type: 'spki', format: 'pem' });
  privateKey = await importPKCS8(kp.privateKey.export({ type: 'pkcs8', format: 'pem' }), 'ES256');
  await initAuth({ publicKeyPem, cookieName: 'ss_session' });
  setInternalToken(INTERNAL_TOKEN);
  publicApp.locals.abeState = { pk, msk };
  publicApp.locals.logger = logger;
  await UserAttr.create({ userId: user.id, username: user.username, attributes: ['dept:cse'], version: 1 });
});

afterAll(async () => {
  await mongoose.disconnect();
  await mongod.stop();
});

describe('authority service', () => {
  it('reports health publicly', async () => {
    const r = await request(publicApp).get('/authority/health');
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ status: 'ok', service: 'authority' });
  });

  it('publishes the FAME public key with a stable fingerprint', async () => {
    const r = await request(publicApp).get('/authority/params');
    expect(r.status).toBe(200);
    expect(r.body.publicKey.scheme).toBe('fame-bls12381-v1');
    expect(r.body.fingerprint).toBe(masterKeyFingerprint(pk));
  });

  it('derives a deterministic 16-hex-character fingerprint', () => {
    expect(masterKeyFingerprint(pk)).toMatch(/^[0-9a-f]{16}$/);
    expect(masterKeyFingerprint(pk)).toBe(masterKeyFingerprint(pk));
  });

  it('rejects unauthenticated /authority/me', async () => {
    expect((await request(publicApp).get('/authority/me')).status).toBe(401);
  });

  it('returns the current user attributes', async () => {
    const r = await request(publicApp).get('/authority/me').set('Cookie', await cookieFor(user));
    expect(r.status).toBe(200);
    expect(r.body.attributes).toEqual(['dept:cse']);
  });

  it('issues a sealed CP-ABE key usable by the matching identity', async () => {
    const kp = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const encPublicJwk = await crypto.subtle.exportKey('jwk', await crypto.subtle.importKey(
      'spki', kp.publicKey.export({ type: 'spki', format: 'der' }),
      { name: 'ECDH', namedCurve: 'P-256' }, true, [],
    ));
    const cookie = `ss_session=${await new SignJWT({
      sub: user.id, usr: user.username, role: user.role, ek: encPublicJwk,
      jti: 'key-test', iss: JWT_ISSUER, aud: JWT_AUDIENCE,
    }).setProtectedHeader({ alg: 'ES256' }).setIssuedAt().setExpirationTime('30m').sign(privateKey)}`;

    const r = await request(publicApp).get('/authority/keys/me').set('Cookie', cookie);
    expect(r.status).toBe(200);
    expect(r.body.sealedKey).toBeTruthy();

    const encPrivateKey = await crypto.subtle.importKey(
      'pkcs8', kp.privateKey.export({ type: 'pkcs8', format: 'der' }),
      { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'],
    );
    const aad = `secureshare/v2/abe-key|${user.id}|${r.body.version}`;
    const json = utf8.decode(await openSealed(encPrivateKey, encPublicJwk, r.body.sealedKey, aad));
    expect(JSON.parse(json)).toBeTruthy();
  });

  it('requires the CSRF header for attribute updates', async () => {
    const r = await request(publicApp)
      .put(`/authority/admin/users/${user.id}/attributes`)
      .set('Cookie', await cookieFor(admin))
      .send({ username: 'alice', attributes: ['dept:cse'] });
    expect(r.status).toBe(403);
  });

  it('rejects non-admin users on admin routes', async () => {
    const r = await request(publicApp).get('/authority/admin/users').set('Cookie', await cookieFor(user));
    expect(r.status).toBe(403);
  });

  it('lets an admin list and update attributes, filtering reserved user: attributes', async () => {
    const list = await request(publicApp).get('/authority/admin/users').set('Cookie', await cookieFor(admin));
    expect(list.status).toBe(200);
    expect(list.body.users.length).toBeGreaterThan(0);

    const r = await request(publicApp)
      .put(`/authority/admin/users/${user.id}/attributes`)
      .set('Cookie', await cookieFor(admin))
      .set('X-SecureShare-CSRF', '1')
      .send({ username: 'alice', attributes: ['ROLE:FACULTY', 'user:admin'] });
    expect(r.status).toBe(200);
    expect(r.body.attributes).toEqual(['role:faculty']);
    expect(r.body.version).toBe(2);
  });

  it('accepts every attribute the policy language accepts and rejects the rest', async () => {
    const put = async (attributes) => request(publicApp)
      .put(`/authority/admin/users/${user.id}/attributes`)
      .set('Cookie', await cookieFor(admin))
      .set('X-SecureShare-CSRF', '1')
      .send({ username: 'alice', attributes });
    const ok = await put(['dept:comp-sci', 'email:alice@corp.example']);
    expect(ok.status).toBe(200);
    expect(ok.body.attributes).toEqual(['dept:comp-sci', 'email:alice@corp.example']);
    expect((await put(['_bad:value'])).status).toBe(400);
    expect((await put(['no-colon'])).status).toBe(400);
    await put(['role:faculty']); // restore state for the following tests
  });

  it('protects the internal attribute endpoint with a bearer token', async () => {
    expect((await request(internalApp).get(`/internal/users/${user.id}/attributes`)).status).toBe(401);
  });

  it('returns live attributes to the API over the internal endpoint', async () => {
    const r = await request(internalApp)
      .get(`/internal/users/${user.id}/attributes`)
      .set('Authorization', `Bearer ${INTERNAL_TOKEN}`);
    expect(r.status).toBe(200);
    expect(r.body.attributes).toEqual(['role:faculty']);
  });

  it('fails to open a master key sealed with a different KEK', () => {
    const sealed = sealMasterKey('kek-a', { pk: 'p', msk: 'm' });
    expect(() => openMasterKey('kek-b', sealed)).toThrow();
    expect(openMasterKey('kek-a', sealed)).toEqual({ pk: 'p', msk: 'm' });
  });
});
