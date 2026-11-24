import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

// Derives a 32-byte AES key from the KEK string
function deriveKey(kek) {
  return createHash('sha256').update(String(kek)).digest(); // 32 bytes
}

/**
 * Seals an arbitrary JS object under the KEK using AES-256-GCM.
 * Returns a JSON string: { nonce: base64, ciphertext: base64, tag: base64 }
 */
export function sealMasterKey(kek, obj) {
  const key = deriveKey(kek);
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const data = Buffer.from(JSON.stringify(obj));
  const ct = Buffer.concat([cipher.update(data), cipher.final()]);
  const tag = cipher.getAuthTag();
  return JSON.stringify({
    nonce: nonce.toString('base64'),
    ciphertext: ct.toString('base64'),
    tag: tag.toString('base64'),
  });
}

/**
 * Opens a sealed object produced by sealMasterKey.
 * Throws if KEK is wrong or data is tampered.
 */
export function openMasterKey(kek, sealed) {
  const key = deriveKey(kek);
  const { nonce, ciphertext, tag } = JSON.parse(sealed);
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(nonce, 'base64'));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));
  const plain = Buffer.concat([decipher.update(Buffer.from(ciphertext, 'base64')), decipher.final()]);
  return JSON.parse(plain.toString());
}
