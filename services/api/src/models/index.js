import mongoose from 'mongoose';
import { randomBytes } from 'node:crypto';

// ── User ─────────────────────────────────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    username:    { type: String, required: true, unique: true, lowercase: true, trim: true, minlength: 3, maxlength: 32 },
    kdf:         { type: mongoose.Schema.Types.Mixed, required: true },
    authHash:    { type: String, required: true },            // Argon2id(authKey)
    encPublicKey: { type: mongoose.Schema.Types.Mixed, required: true },  // JWK
    sigPublicKey: { type: mongoose.Schema.Types.Mixed, required: true },  // JWK
    vault:       { type: String, required: true },            // base64url ciphertext
    role:        { type: String, enum: ['user', 'admin'], default: 'user' },
    locked:      { type: Boolean, default: false },
    lockUntil:   { type: Date, default: null },
    failedAttempts: { type: Number, default: 0 },
  },
  { timestamps: true },
);
userSchema.index({ username: 1 });
export const User = mongoose.model('User', userSchema);

// ── Session deny-list (logout revocation) ────────────────────────────────────
const sessionSchema = new mongoose.Schema({
  jti: { type: String, required: true, unique: true },
  exp: { type: Date, required: true, index: { expireAfterSeconds: 0 } },
});
export const RevokedSession = mongoose.model('RevokedSession', sessionSchema);

// ── File record ───────────────────────────────────────────────────────────────
const fileSchema = new mongoose.Schema(
  {
    _id:          { type: String },   // the fileId (22-char base64url)
    ownerId:      { type: String, required: true, index: true },
    ownerUsername: { type: String, required: true },
    ownerSigPublicKey: { type: mongoose.Schema.Types.Mixed, required: true },
    encMeta:      { type: String, required: true },           // base64url AES-GCM(metaKey, {name,type,size})
    abeEnvelope:  { type: mongoose.Schema.Types.Mixed, required: true },
    ownerEnvelope:{ type: String, required: true },
    manifest:     { type: mongoose.Schema.Types.Mixed, required: true },
    signature:    { type: String, required: true },
    policy:       { type: String, required: true },           // canonical policy text (denormalised for listing)
    blobName:     { type: String, required: true },           // random hex name on disk
    size:         { type: Number, required: true },
    blobHash:     { type: String, required: true },           // sha256 hex of ciphertext
  },
  { timestamps: true, _id: false },
);
fileSchema.index({ ownerId: 1, createdAt: -1 });
export const File = mongoose.model('File', fileSchema);

// ── Audit log ─────────────────────────────────────────────────────────────────
const auditSchema = new mongoose.Schema({
  at:       { type: Date, default: Date.now, index: true },
  username: { type: String },
  userId:   { type: String },
  action:   { type: String, required: true },
  target:   { type: String },
  outcome:  { type: String, enum: ['ok', 'denied', 'error'], default: 'ok' },
  meta:     { type: mongoose.Schema.Types.Mixed },
});
auditSchema.index({ at: -1 });
export const AuditEvent = mongoose.model('AuditEvent', auditSchema);

// ── Webhook Endpoint ──────────────────────────────────────────────────────────
const webhookSchema = new mongoose.Schema(
  {
    url:        { type: String, required: true },
    secret:     { type: String, required: true },             // HMAC signing secret (stored hashed in real prod)
    events:     { type: [String], required: true },           // e.g. ['file.uploaded','auth.login.succeeded']
    enabled:    { type: Boolean, default: true },
    createdBy:  { type: String },
    description:{ type: String, default: '' },
  },
  { timestamps: true },
);
export const WebhookEndpoint = mongoose.model('WebhookEndpoint', webhookSchema);

// ── Webhook Delivery Log ───────────────────────────────────────────────────────
const deliverySchema = new mongoose.Schema({
  endpointId:   { type: mongoose.Schema.Types.ObjectId, ref: 'WebhookEndpoint', required: true, index: true },
  eventId:      { type: String, required: true, unique: true },   // idempotency key
  eventType:    { type: String, required: true },
  payload:      { type: mongoose.Schema.Types.Mixed, required: true },
  statusCode:   { type: Number },
  responseBody: { type: String },
  attempt:      { type: Number, default: 1 },
  status:       { type: String, enum: ['pending', 'success', 'failed', 'retrying'], default: 'pending' },
  sentAt:       { type: Date },
  nextRetryAt:  { type: Date },
  error:        { type: String },
}, { timestamps: true });
deliverySchema.index({ status: 1, nextRetryAt: 1 });
export const WebhookDelivery = mongoose.model('WebhookDelivery', deliverySchema);
