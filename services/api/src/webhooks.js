import { createHmac, randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';
import { WebhookEndpoint, WebhookDelivery } from './models/index.js';

/** True for IPv4/IPv6 addresses in ranges that must never be used for webhooks. */
function isPrivateAddress(raw) {
  let ip = raw.toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  // IPv4-mapped IPv6 (::ffff:127.0.0.1) must be checked as IPv4.
  const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) ip = mapped[1];

  if (isIP(ip) === 4) {
    const [a, b] = ip.split('.').map(Number);
    return (
      a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168) ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 192 && b === 0) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51) ||
      (a === 203 && b === 0)
    );
  }
  if (isIP(ip) === 6) {
    return (
      ip === '::' || ip === '::1' ||
      /^f[cd][0-9a-f]{2}:/.test(ip) || // unique local fc00::/7
      /^fe[89ab][0-9a-f]:/.test(ip)    // link-local fe80::/10
    );
  }
  return true;
}

/**
 * SSRF protection: HTTPS only, no private/loopback/link-local literals and no
 * internal service names. DNS results are checked separately by isSafeWebhookTarget.
 */
function isSafeWebhookUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  if (url.protocol !== 'https:') return false;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host) return false;
  if (isIP(host)) return !isPrivateAddress(host);
  const blockedHosts = new Set(['localhost', 'internal', 'api', 'authority', 'mongo']);
  return !blockedHosts.has(host) && !host.endsWith('.localhost') && !host.endsWith('.internal');
}

/** Also reject hostnames that resolve into a private address (basic DNS rebinding guard). */
export async function isSafeWebhookTarget(rawUrl) {
  if (!isSafeWebhookUrl(rawUrl)) return false;
  const host = new URL(rawUrl).hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (isIP(host)) return !isPrivateAddress(host);
  try {
    const addresses = await lookup(host, { all: true });
    return addresses.length > 0 && addresses.every((a) => !isPrivateAddress(a.address));
  } catch {
    return false;
  }
}

/** Compute HMAC-SHA256 signature for a webhook payload */
function sign(secret, body, timestamp, eventId) {
  const msg = `${timestamp}.${eventId}.${body}`;
  return createHmac('sha256', secret).update(msg).digest('hex');
}

/** Dispatch a webhook event to all matching enabled endpoints (non-blocking) */
export async function dispatchWebhook(eventType, payload) {
  const eventId = randomBytes(16).toString('hex');
  const timestamp = Math.floor(Date.now() / 1000);

  let endpoints;
  try {
    endpoints = await WebhookEndpoint.find({ enabled: true, events: eventType }).lean();
  } catch {
    return; // Never interrupt primary flow
  }

  for (const ep of endpoints) {
    const body = JSON.stringify({
      eventId,
      eventType,
      timestamp,
      ...payload,
    });
    const signature = sign(ep.secret, body, timestamp, eventId);

    const delivery = new WebhookDelivery({
      endpointId: ep._id,
      eventId: `${ep._id}-${eventId}`,
      eventType,
      payload: { eventId, eventType, timestamp, ...payload },
      status: 'pending',
      nextRetryAt: new Date(),
    });
    await delivery.save().catch(() => {});

    // Fire async – do NOT await (non-blocking)
    sendWithRetry(delivery._id, ep.url, ep.secret, body, signature, timestamp, eventId).catch(() => {});
  }
}

async function sendWithRetry(deliveryId, url, secret, body, signature, timestamp, eventId, attempt = 1) {
  const MAX_ATTEMPTS = 4;
  const BACKOFF = [0, 10000, 30000, 120000]; // ms

  if (attempt > 1) {
    await new Promise((r) => setTimeout(r, BACKOFF[Math.min(attempt - 1, BACKOFF.length - 1)]));
  }

  let statusCode, responseBody, error;
  try {
    if (!(await isSafeWebhookTarget(url))) throw new Error('Blocked by SSRF protection at delivery time');
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    try {
      const res = await fetch(url, {
        method: 'POST',
        redirect: 'error', // never follow a redirect into a private network
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
      statusCode = res.status;
      responseBody = (await res.text()).slice(0, 500);
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    error = err.message;
  }

  const success = Boolean(statusCode && statusCode >= 200 && statusCode < 300);
  const nextAttempt = attempt + 1;
  const willRetry = !success && nextAttempt <= MAX_ATTEMPTS;

  await WebhookDelivery.findByIdAndUpdate(deliveryId, {
    statusCode,
    responseBody,
    error,
    attempt,
    sentAt: new Date(),
    status: success ? 'success' : willRetry ? 'retrying' : 'failed',
    nextRetryAt: willRetry ? new Date(Date.now() + BACKOFF[Math.min(nextAttempt - 1, BACKOFF.length - 1)]) : null,
  }).catch(() => {});

  if (willRetry) {
    // Recompute signature with same timestamp/eventId for retry
    return sendWithRetry(deliveryId, url, secret, body, signature, timestamp, eventId, nextAttempt);
  }
}

export { isSafeWebhookUrl, sign };
