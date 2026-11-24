import { createHmac, randomBytes } from 'node:crypto';
import { WebhookEndpoint, WebhookDelivery } from './models/index.js';

/** SSRF protection: block private / loopback / link-local / reserved ranges */
function isSafeWebhookUrl(rawUrl) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return false;
  }
  if (!['http:', 'https:'].includes(url.protocol)) return false;
  const host = url.hostname.toLowerCase();
  // Block loopback and common private/reserved
  const blockedPatterns = [
    /^localhost$/,
    /^127\./,
    /^0\.0\.0\.0$/,
    /^10\./,
    /^192\.168\./,
    /^172\.(1[6-9]|2[0-9]|3[01])\./,
    /^169\.254\./,           // link-local
    /^::1$/,                  // IPv6 loopback
    /^fc00:/i,
    /^fe80:/i,
    /^fd[0-9a-f]{2}:/i,
    /^0+$/,
    /^internal$/,
    /^api$/,
    /^authority$/,
    /^mongo$/,
  ];
  return !blockedPatterns.some((re) => re.test(host));
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
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), 10000);
    try {
      const res = await fetch(url, {
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
      statusCode = res.status;
      responseBody = (await res.text()).slice(0, 500);
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    error = err.message;
  }

  const success = statusCode && statusCode >= 200 && statusCode < 300;
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
