import { SignJWT } from 'jose';
import { readFileSync } from 'node:fs';
import { importPKCS8 } from 'jose';
import { randomBytes } from 'node:crypto';
import { JWT_ISSUER, JWT_AUDIENCE } from '@secureshare/server-common';

export async function signJWT(user, locals) {
  const { jwtPrivateKey, jwtTtlSeconds = 1800 } = locals;
  const jti = randomBytes(16).toString('hex');
  const now = Math.floor(Date.now() / 1000);
  const exp = now + jwtTtlSeconds;
  const token = await new SignJWT({
    sub: String(user.id),
    usr: user.username,
    role: user.role,
    ek: user.encPublicKey,    // ECDH public key — authority uses this to seal attribute keys
    jti,
    iss: JWT_ISSUER,
    aud: JWT_AUDIENCE,
    iat: now,
    exp,
  })
    .setProtectedHeader({ alg: 'ES256' })
    .sign(jwtPrivateKey);
  return { token, jti, exp };
}
