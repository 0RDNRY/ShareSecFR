import mongoose from 'mongoose';

// ── User attribute record ─────────────────────────────────────────────────────
const userAttrSchema = new mongoose.Schema(
  {
    userId:     { type: String, required: true, unique: true },
    username:   { type: String, required: true },
    attributes: { type: [String], default: [] },
    version:    { type: Number, default: 0 },
    sealedKey:  { type: String },              // cached sealed CP-ABE key (base64url)
    keyVersion: { type: Number, default: -1 }, // version the cached key was sealed for
  },
  { timestamps: true },
);
export const UserAttr = mongoose.model('UserAttr', userAttrSchema);

// ── Authority master key ───────────────────────────────────────────────────────
const masterKeySchema = new mongoose.Schema({
  _id:      { type: String, default: 'singleton' },
  sealed:   { type: String, required: true },     // JSON: { nonce, ciphertext } base64url
  createdAt:{ type: Date, default: Date.now },
});
export const MasterKey = mongoose.model('MasterKey', masterKeySchema, 'masterKey');

// ── Authority audit ───────────────────────────────────────────────────────────
const auditSchema = new mongoose.Schema({
  at:       { type: Date, default: Date.now, index: true },
  actor:    { type: String },
  action:   { type: String, required: true },
  target:   { type: String },
  meta:     { type: mongoose.Schema.Types.Mixed },
});
export const AuthorityAudit = mongoose.model('AuthorityAudit', auditSchema);
