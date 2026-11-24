import { createReadStream, createWriteStream, existsSync } from 'node:fs';
import { unlink, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { pipeline } from 'node:stream/promises';
import { Readable } from 'node:stream';

let storageDir;

export function initStorage(dir) {
  storageDir = dir;
}

export function newBlobName() {
  return randomBytes(32).toString('hex');
}

function blobPath(name) {
  if (!storageDir) throw new Error('Storage not initialised');
  // Safety: only allow hex names (no path traversal possible)
  if (!/^[0-9a-f]{64}$/.test(name)) throw new Error('Invalid blob name');
  return join(storageDir, name);
}

/**
 * Stream-write `readable` to a new blob file, computing SHA-256 and total size in flight.
 * Returns { blobName, sha256, size }.
 * On error, removes the partial file.
 */
export async function writeBlob(readable, maxBytes) {
  const name = newBlobName();
  const path = blobPath(name);
  const hash = createHash('sha256');
  let size = 0;
  const ws = createWriteStream(path);
  try {
    await pipeline(
      Readable.from(readable),
      async function* (source) {
        for await (const chunk of source) {
          size += chunk.length;
          if (size > maxBytes) throw Object.assign(new Error('Upload exceeds limit'), { status: 413 });
          hash.update(chunk);
          yield chunk;
        }
      },
      ws,
    );
  } catch (err) {
    ws.destroy();
    await unlink(path).catch(() => {});
    throw err;
  }
  return { blobName: name, sha256: hash.digest('hex'), size };
}

export function readBlobStream(name) {
  return createReadStream(blobPath(name));
}

export async function blobStat(name) {
  return stat(blobPath(name));
}

export async function deleteBlob(name) {
  const p = blobPath(name);
  if (existsSync(p)) await unlink(p);
}
