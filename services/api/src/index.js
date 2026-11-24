import express from 'express';
import { mkdirSync } from 'node:fs';
import { readFileSync } from 'node:fs';
import mongoose from 'mongoose';
import { importPKCS8, importSPKI } from 'jose';
import {
  readSecret, mongoUri, intFromEnv, boolFromEnv,
  applyBaseSecurity, csrfGuard, sessionVerifier, notFound, errorHandler,
  createLogger, httpLogger, sessionCookieName,
} from '@secureshare/server-common';
import { initStorage } from './storage.js';
import authRouter from './routes/auth.js';
import filesRouter from './routes/files.js';
import adminRouter from './routes/admin.js';
import webhooksRouter from './routes/webhooks.js';
import integrationsRouter from './routes/integrations.js';

const env = process.env;
const logger = createLogger({ level: env.LOG_LEVEL ?? 'info', name: 'api' });

// ── Config ────────────────────────────────────────────────────────────────────
const PORT = intFromEnv(env, 'PORT', 4000, { min: 1, max: 65535 });
const TRUST_PROXY = intFromEnv(env, 'TRUST_PROXY_HOPS', 1, { min: 0, max: 10 });
const COOKIE_SECURE = boolFromEnv(env, 'COOKIE_SECURE', false);
const PUBLIC_ORIGIN = env.PUBLIC_ORIGIN ?? 'http://localhost:5173';
const STORAGE_DIR = env.STORAGE_DIR ?? './data/blobs';
const MAX_UPLOAD_BYTES = intFromEnv(env, 'MAX_UPLOAD_BYTES', 104857600);
const BOOTSTRAP_ADMIN = (env.BOOTSTRAP_ADMIN ?? 'admin').toLowerCase();
const REGISTRATION_OPEN = boolFromEnv(env, 'REGISTRATION_OPEN', true);
const AUTHORITY_INTERNAL_URL = env.AUTHORITY_INTERNAL_URL ?? 'http://127.0.0.1:7001';
const JWT_TTL = intFromEnv(env, 'JWT_TTL_SECONDS', 1800, { min: 60, max: 86400 });

const jwtPrivatePem = readSecret(env, 'JWT_PRIVATE_KEY');
const jwtPublicPem = readSecret(env, 'JWT_PUBLIC_KEY');
const internalToken = readSecret(env, 'INTERNAL_TOKEN');
const serverSecret = readSecret(env, 'SERVER_SECRET');
const mongoPassword = readSecret(env, 'MONGODB_PASSWORD', { required: false });
const MONGODB_URI = mongoUri(env.MONGODB_URI ?? 'mongodb://127.0.0.1:27017/secureshare', mongoPassword);

// ── Ensure storage dir ────────────────────────────────────────────────────────
mkdirSync(STORAGE_DIR, { recursive: true });
initStorage(STORAGE_DIR);

// ── Build app ─────────────────────────────────────────────────────────────────
const app = express();
applyBaseSecurity(app, { trustProxy: TRUST_PROXY });
app.use(httpLogger(logger));

// ── Swagger UI (CSP-safe: served as static assets from /docs) ─────────────────
// We serve swagger-ui-dist files directly so no CDN / external origin needed
// This is compatible with strict default-src 'self' CSP
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
let swaggerUiDist;
try {
  swaggerUiDist = require('swagger-ui-dist');
} catch {
  logger.warn('swagger-ui-dist not installed; /docs will not be available');
}

// OpenAPI spec (served at /api/openapi.json)
const openApiSpec = buildOpenApiSpec(PUBLIC_ORIGIN, MAX_UPLOAD_BYTES);

// Serve swagger UI at /docs (using raw HTML + CDN for simplicity; can be self-hosted)
app.get('/docs', (_req, res) => {
  res.set('Content-Type', 'text/html');
  res.send(`<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>SecureShareFR API Docs</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({
    url: '/api/openapi.json',
    dom_id: '#swagger-ui',
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: 'BaseLayout',
    deepLinking: true,
    displayRequestDuration: true,
    tryItOutEnabled: true,
    requestInterceptor: function(req) {
      req.headers['X-SecureShare-CSRF'] = '1';
      return req;
    }
  });
</script>
</body>
</html>`);
});

app.get('/api/openapi.json', (_req, res) => {
  res.json(openApiSpec);
});

// ── JSON body parser (for non-blob routes) ────────────────────────────────────
app.use((req, res, next) => {
  if (req.path.includes('/blob')) return next(); // skip JSON parsing for binary uploads
  express.json({ limit: '2mb' })(req, res, next);
});

// ── CSRF guard ────────────────────────────────────────────────────────────────
app.use(csrfGuard({ publicOrigin: PUBLIC_ORIGIN }));

// ── Health / meta ─────────────────────────────────────────────────────────────
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', service: 'api', version: '2.0.0', uptime: Math.round(process.uptime()) });
});
app.get('/api/meta', (_req, res) => {
  res.json({ maxUploadBytes: MAX_UPLOAD_BYTES, registrationOpen: REGISTRATION_OPEN });
});

// ── Session verification ───────────────────────────────────────────────────────
let requireUser, requireAdmin;

// ── Unauthenticated routes ────────────────────────────────────────────────────
app.use('/api/auth', authRouter);
app.use('/api/integrations', integrationsRouter);
app.use('/api/webhooks/events', (req, res, next) => {
  if (req.method === 'GET') return res.json({ events: ['auth.registered','auth.login.succeeded','auth.login.failed','auth.account.locked','file.uploaded','file.downloaded','file.access.denied','file.policy.updated','file.deleted','authority.attributes.updated'] });
  next();
});

// ── Authenticated routes ──────────────────────────────────────────────────────
app.use('/api/files', (req, res, next) => requireUser(req, res, next), filesRouter);
app.use('/api/admin', (req, res, next) => requireUser(req, res, next), (req, res, next) => requireAdmin(req, res, next), adminRouter);
app.use('/api/webhooks', (req, res, next) => requireUser(req, res, next), webhooksRouter);

app.use(notFound);
app.use(errorHandler(logger));

// ── Bootstrap ─────────────────────────────────────────────────────────────────
async function start() {
  const [privKey, pubKey] = await Promise.all([
    importPKCS8(jwtPrivatePem, 'ES256'),
    importSPKI(jwtPublicPem, 'ES256'),
  ]);

  const { verify: _, ...sessionFns } = await sessionVerifier({
    publicKeyPem: jwtPublicPem,
    cookieName: sessionCookieName(COOKIE_SECURE),
    isRevoked: async (payload) => {
      const { RevokedSession } = await import('./models/index.js');
      return !!(await RevokedSession.exists({ jti: payload.jti }));
    },
  });
  requireUser = sessionFns.requireUser;
  requireAdmin = sessionFns.requireAdmin;

  app.locals.jwtPrivateKey = privKey;
  app.locals.serverSecret = serverSecret;
  app.locals.internalToken = internalToken;
  app.locals.cookieSecure = COOKIE_SECURE;
  app.locals.bootstrapAdmin = BOOTSTRAP_ADMIN;
  app.locals.registrationOpen = REGISTRATION_OPEN;
  app.locals.authorityInternalUrl = AUTHORITY_INTERNAL_URL;
  app.locals.maxUploadBytes = MAX_UPLOAD_BYTES;
  app.locals.jwtTtlSeconds = JWT_TTL;
  app.locals.publicOrigin = PUBLIC_ORIGIN;
  app.locals.storageDir = STORAGE_DIR;

  await mongoose.connect(MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
  logger.info('MongoDB connected');

  app.listen(PORT, () => {
    logger.info(`API listening on :${PORT}`);
    logger.info(`Swagger UI available at http://localhost:${PORT}/docs`);
  });
}

start().catch((err) => {
  logger.error({ err }, 'startup failed');
  process.exit(1);
});

// ── OpenAPI spec builder ──────────────────────────────────────────────────────
function buildOpenApiSpec(publicOrigin, maxUploadBytes) {
  return {
    openapi: '3.0.3',
    info: {
      title: 'SecureShareFR API',
      version: '2.0.0',
      description: `SecureShareFR is a zero-knowledge, end-to-end encrypted file sharing platform using CP-ABE (Ciphertext-Policy Attribute-Based Encryption).

**Key features:**
- Files are encrypted in the browser — the server never sees plaintext
- Access is controlled by cryptographic attribute policies (e.g. \`dept:cse AND role:faculty\`)
- Webhook notifications for key application events
- All state-changing requests require the \`X-SecureShare-CSRF: 1\` header

**Max upload size:** ${Math.round(maxUploadBytes / 1024 / 1024)} MiB`,
      contact: { name: 'SecureShareFR', url: 'https://github.com/0RDNRY/ShareSecFR' },
    },
    servers: [
      { url: publicOrigin, description: 'Production' },
      { url: 'http://localhost:4000', description: 'Local development (API direct)' },
      { url: 'http://localhost:5173', description: 'Local development (Vite proxy)' },
    ],
    tags: [
      { name: 'health', description: 'Service health and metadata' },
      { name: 'auth', description: 'Authentication — registration, login, session management' },
      { name: 'files', description: 'Encrypted file operations' },
      { name: 'admin', description: 'Administrator operations (admin role required)' },
      { name: 'webhooks', description: 'Webhook endpoint management and delivery logs' },
      { name: 'integrations', description: 'Live integration status and demo data' },
    ],
    components: {
      securitySchemes: {
        sessionCookie: {
          type: 'apiKey', in: 'cookie',
          name: 'ss_session',
          description: 'Session JWT set by /api/auth/login or /api/auth/register. HttpOnly, SameSite=Strict.',
        },
        csrfHeader: {
          type: 'apiKey', in: 'header',
          name: 'X-SecureShare-CSRF',
          description: 'Must be set to "1" on all state-changing requests (POST, PUT, DELETE, PATCH).',
        },
      },
      schemas: {
        Error: {
          type: 'object',
          required: ['error'],
          properties: {
            error: { type: 'string', example: 'Not signed in' },
            details: { type: 'array', items: { type: 'string' } },
            code: { type: 'string' },
          },
        },
        User: {
          type: 'object',
          properties: {
            id: { type: 'string', example: '507f1f77bcf86cd799439011' },
            username: { type: 'string', example: 'alice' },
            role: { type: 'string', enum: ['user', 'admin'] },
            encPublicKey: { type: 'object', description: 'JWK ECDH P-256 public key' },
            sigPublicKey: { type: 'object', description: 'JWK ECDSA P-256 public key' },
          },
        },
        KdfParams: {
          type: 'object',
          required: ['algorithm', 'iterations', 'salt'],
          properties: {
            algorithm: { type: 'string', enum: ['pbkdf2-sha256'] },
            iterations: { type: 'integer', minimum: 600000, example: 600000 },
            salt: { type: 'string', example: 'base64url-salt' },
          },
        },
        FileRecord: {
          type: 'object',
          properties: {
            id: { type: 'string', description: 'Base64url file ID (22 chars)', example: 'Abc123XyzDefGhiJklMno' },
            ownerId: { type: 'string' },
            ownerUsername: { type: 'string' },
            policy: { type: 'string', example: 'dept:cse AND role:faculty' },
            size: { type: 'integer', description: 'Ciphertext size in bytes' },
            encMeta: { type: 'string', description: 'Encrypted file metadata (base64url)' },
            abeEnvelope: { type: 'object', description: 'CP-ABE wrapped file secret' },
            ownerEnvelope: { type: 'string', description: 'ECIES-wrapped owner copy of file secret' },
            manifest: { type: 'object', description: 'Signed manifest binding all ciphertext components' },
            signature: { type: 'string', description: 'ECDSA P-256 signature over the manifest' },
            createdAt: { type: 'string', format: 'date-time' },
            updatedAt: { type: 'string', format: 'date-time' },
          },
        },
        WebhookEndpoint: {
          type: 'object',
          properties: {
            id: { type: 'string' },
            url: { type: 'string', format: 'uri', example: 'https://example.com/webhook' },
            events: { type: 'array', items: { type: 'string' }, example: ['file.uploaded', 'auth.login.succeeded'] },
            enabled: { type: 'boolean' },
            description: { type: 'string' },
            createdAt: { type: 'string', format: 'date-time' },
          },
        },
      },
    },
    paths: {
      '/api/health': {
        get: {
          tags: ['health'],
          summary: 'API health check',
          description: 'Returns 200 when the API service is running.',
          operationId: 'getApiHealth',
          responses: {
            200: { description: 'Service is healthy', content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string', example: 'ok' }, service: { type: 'string', example: 'api' }, version: { type: 'string', example: '2.0.0' }, uptime: { type: 'integer' } } } } } },
          },
        },
      },
      '/api/meta': {
        get: {
          tags: ['health'],
          summary: 'Application metadata',
          description: 'Returns the maximum upload size and registration status.',
          operationId: 'getMeta',
          responses: {
            200: { description: 'Metadata', content: { 'application/json': { schema: { type: 'object', properties: { maxUploadBytes: { type: 'integer', example: maxUploadBytes }, registrationOpen: { type: 'boolean' } } } } } },
          },
        },
      },
      '/api/auth/params': {
        get: {
          tags: ['auth'],
          summary: 'Get KDF parameters for login',
          description: 'Returns PBKDF2 parameters for the given username. Returns fake (but structurally valid) parameters for unknown users to prevent account enumeration.',
          operationId: 'getAuthParams',
          parameters: [{ name: 'username', in: 'query', required: true, schema: { type: 'string', example: 'alice' } }],
          responses: {
            200: { description: 'KDF parameters', content: { 'application/json': { schema: { $ref: '#/components/schemas/KdfParams' } } } },
            400: { description: 'Missing username', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/auth/register': {
        post: {
          tags: ['auth'],
          summary: 'Register a new account',
          description: 'Creates a user account. The password never leaves the browser — only the derived authKey and encrypted vault are sent.',
          operationId: 'register',
          security: [{ csrfHeader: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['username', 'kdf', 'authKey', 'encPublicKey', 'sigPublicKey', 'vault'],
                  properties: {
                    username: { type: 'string', minLength: 3, maxLength: 32, pattern: '^[A-Za-z0-9_]+$', example: 'alice' },
                    kdf: { $ref: '#/components/schemas/KdfParams' },
                    authKey: { type: 'string', description: 'PBKDF2+HKDF derived authentication key (base64url)', example: 'base64url-auth-key' },
                    encPublicKey: { type: 'object', description: 'JWK ECDH P-256 public key' },
                    sigPublicKey: { type: 'object', description: 'JWK ECDSA P-256 public key' },
                    vault: { type: 'string', description: 'AES-256-GCM encrypted private key vault (base64url)' },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'Account created', content: { 'application/json': { schema: { type: 'object', properties: { user: { $ref: '#/components/schemas/User' }, vault: { type: 'string' } } } } } },
            400: { description: 'Validation error', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            403: { description: 'Registration closed', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            409: { description: 'Username already taken', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/auth/login': {
        post: {
          tags: ['auth'],
          summary: 'Sign in',
          description: 'Authenticates the user and sets a session cookie. Rate limited: 20 requests per 15 minutes per IP. Account locked after 5 failed attempts for 15 minutes.',
          operationId: 'login',
          security: [{ csrfHeader: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['username', 'authKey'],
                  properties: {
                    username: { type: 'string', example: 'alice' },
                    authKey: { type: 'string', example: 'base64url-auth-key' },
                  },
                },
                examples: {
                  validLogin: { summary: 'Valid login', value: { username: 'alice', authKey: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' } },
                  invalidLogin: { summary: 'Invalid credentials', value: { username: 'alice', authKey: 'wrong-key-value' } },
                },
              },
            },
          },
          responses: {
            200: { description: 'Signed in — session cookie set', content: { 'application/json': { schema: { type: 'object', properties: { user: { $ref: '#/components/schemas/User' }, vault: { type: 'string' } } } } } },
            400: { description: 'Missing or invalid fields', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            401: { description: 'Invalid credentials or account locked', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            403: { description: 'Missing CSRF header', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            429: { description: 'Rate limit exceeded', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/auth/logout': {
        post: {
          tags: ['auth'],
          summary: 'Sign out',
          description: 'Revokes the current session JWT and clears the session cookie.',
          operationId: 'logout',
          security: [{ sessionCookie: [], csrfHeader: [] }],
          responses: {
            204: { description: 'Signed out' },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/auth/me': {
        get: {
          tags: ['auth'],
          summary: 'Get current session',
          description: 'Returns the authenticated user profile and encrypted vault for key re-derivation after page reload.',
          operationId: 'getMe',
          security: [{ sessionCookie: [] }],
          responses: {
            200: { description: 'Current user', content: { 'application/json': { schema: { type: 'object', properties: { user: { $ref: '#/components/schemas/User' }, vault: { type: 'string' }, kdf: { $ref: '#/components/schemas/KdfParams' } } } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/files': {
        get: {
          tags: ['files'],
          summary: 'List files',
          description: 'Lists files. scope=owned: files you uploaded. scope=shared: files whose policy your current attributes satisfy (live server gate check).',
          operationId: 'listFiles',
          security: [{ sessionCookie: [] }],
          parameters: [{ name: 'scope', in: 'query', required: true, schema: { type: 'string', enum: ['owned', 'shared'] } }],
          responses: {
            200: { description: 'File list', content: { 'application/json': { schema: { type: 'object', properties: { files: { type: 'array', items: { $ref: '#/components/schemas/FileRecord' } } } } } } },
            400: { description: 'Missing scope', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
        post: {
          tags: ['files'],
          summary: 'Register encrypted file',
          description: 'Registers a new file with its signed manifest. The ciphertext blob is uploaded separately via PUT /api/files/:id/blob.',
          operationId: 'createFile',
          security: [{ sessionCookie: [], csrfHeader: [] }],
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['fileId', 'encMeta', 'abeEnvelope', 'ownerEnvelope', 'manifest', 'signature'], properties: { fileId: { type: 'string', description: '22-char base64url random ID' }, encMeta: { type: 'string' }, abeEnvelope: { type: 'object' }, ownerEnvelope: { type: 'string' }, manifest: { type: 'object' }, signature: { type: 'string' } } } } } },
          responses: {
            201: { description: 'File registered', content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string' } } } } } },
            400: { description: 'Invalid input', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            409: { description: 'File ID already exists', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/files/{id}': {
        get: {
          tags: ['files'],
          summary: 'Get file record',
          description: 'Returns the file record. Only accessible to the owner or users whose current attributes satisfy the policy.',
          operationId: 'getFile',
          security: [{ sessionCookie: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            200: { description: 'File record', content: { 'application/json': { schema: { $ref: '#/components/schemas/FileRecord' } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            404: { description: 'Not found or access denied (always 404 to prevent oracle)', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
        delete: {
          tags: ['files'],
          summary: 'Delete file',
          description: 'Deletes the file and its ciphertext blob. Owner only.',
          operationId: 'deleteFile',
          security: [{ sessionCookie: [], csrfHeader: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            204: { description: 'Deleted' },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            404: { description: 'Not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/files/{id}/blob': {
        get: {
          tags: ['files'],
          summary: 'Download ciphertext',
          description: 'Downloads the encrypted file blob. Access control identical to GET /api/files/:id.',
          operationId: 'downloadBlob',
          security: [{ sessionCookie: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            200: { description: 'Ciphertext blob', content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } } },
            404: { description: 'Not found or access denied', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
        put: {
          tags: ['files'],
          summary: 'Upload ciphertext',
          description: `Streams the encrypted ciphertext blob. SHA-256 and size must match the signed manifest. Max size: ${Math.round(maxUploadBytes/1024/1024)} MiB. Owner only.`,
          operationId: 'uploadBlob',
          security: [{ sessionCookie: [], csrfHeader: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: { required: true, content: { 'application/octet-stream': { schema: { type: 'string', format: 'binary' } } } },
          responses: {
            204: { description: 'Uploaded' },
            400: { description: 'Hash mismatch', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            404: { description: 'File not registered', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            413: { description: 'Upload too large', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/files/{id}/policy': {
        put: {
          tags: ['files'],
          summary: 'Change access policy',
          description: 'Re-wraps the file secret under a new ABE policy and re-signs the manifest. Owner only.',
          operationId: 'changePolicy',
          security: [{ sessionCookie: [], csrfHeader: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          requestBody: { required: true, content: { 'application/json': { schema: { type: 'object', required: ['abeEnvelope', 'manifest', 'signature'], properties: { abeEnvelope: { type: 'object' }, manifest: { type: 'object' }, signature: { type: 'string' } } } } } },
          responses: {
            200: { description: 'Policy updated', content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string' }, policy: { type: 'string' } } } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            404: { description: 'Not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/admin/users': {
        get: {
          tags: ['admin'],
          summary: 'List users',
          description: 'Returns all users. Admin role required.',
          operationId: 'adminListUsers',
          security: [{ sessionCookie: [] }],
          responses: {
            200: { description: 'User list', content: { 'application/json': { schema: { type: 'object', properties: { users: { type: 'array', items: { $ref: '#/components/schemas/User' } } } } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            403: { description: 'Admin required', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/admin/users/{id}/unlock': {
        post: {
          tags: ['admin'],
          summary: 'Unlock account',
          description: 'Clears the account lockout. Admin role required.',
          operationId: 'adminUnlockUser',
          security: [{ sessionCookie: [], csrfHeader: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            200: { description: 'Account unlocked', content: { 'application/json': { schema: { type: 'object', properties: { id: { type: 'string' }, locked: { type: 'boolean' } } } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            403: { description: 'Admin required', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            404: { description: 'User not found', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/admin/audit': {
        get: {
          tags: ['admin'],
          summary: 'Audit log',
          description: 'Returns the most recent audit events. Admin role required.',
          operationId: 'adminAudit',
          security: [{ sessionCookie: [] }],
          parameters: [{ name: 'limit', in: 'query', schema: { type: 'integer', default: 100, maximum: 500 } }],
          responses: {
            200: { description: 'Audit events', content: { 'application/json': { schema: { type: 'object', properties: { events: { type: 'array', items: { type: 'object', properties: { id: { type: 'string' }, at: { type: 'string', format: 'date-time' }, username: { type: 'string' }, action: { type: 'string' }, target: { type: 'string' }, outcome: { type: 'string', enum: ['ok', 'denied', 'error'] } } } } } } } } },
            401: { description: 'Not signed in', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
            403: { description: 'Admin required', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/webhooks': {
        get: {
          tags: ['webhooks'],
          summary: 'List webhook endpoints',
          operationId: 'listWebhooks',
          security: [{ sessionCookie: [] }],
          responses: {
            200: { description: 'Webhook endpoints', content: { 'application/json': { schema: { type: 'object', properties: { endpoints: { type: 'array', items: { $ref: '#/components/schemas/WebhookEndpoint' } } } } } } },
          },
        },
        post: {
          tags: ['webhooks'],
          summary: 'Register webhook endpoint',
          description: 'Registers a new webhook endpoint. The URL must be a public HTTPS endpoint (SSRF protection blocks private/loopback addresses). The secret is used to compute HMAC-SHA256 signatures for delivery verification.',
          operationId: 'createWebhook',
          security: [{ sessionCookie: [], csrfHeader: [] }],
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  required: ['url', 'secret', 'events'],
                  properties: {
                    url: { type: 'string', format: 'uri', example: 'https://example.com/webhook' },
                    secret: { type: 'string', minLength: 16, example: 'my-webhook-secret-min-16-chars' },
                    events: { type: 'array', items: { type: 'string', enum: ['auth.registered','auth.login.succeeded','auth.login.failed','auth.account.locked','file.uploaded','file.downloaded','file.access.denied','file.policy.updated','file.deleted','authority.attributes.updated'] }, example: ['file.uploaded', 'auth.login.succeeded'] },
                    description: { type: 'string', maxLength: 200 },
                  },
                },
              },
            },
          },
          responses: {
            201: { description: 'Webhook endpoint registered', content: { 'application/json': { schema: { $ref: '#/components/schemas/WebhookEndpoint' } } } },
            400: { description: 'Invalid URL or SSRF blocked', content: { 'application/json': { schema: { $ref: '#/components/schemas/Error' } } } },
          },
        },
      },
      '/api/webhooks/events': {
        get: {
          tags: ['webhooks'],
          summary: 'List supported event types',
          operationId: 'listWebhookEvents',
          responses: {
            200: { description: 'Supported events', content: { 'application/json': { schema: { type: 'object', properties: { events: { type: 'array', items: { type: 'string' } } } } } } },
          },
        },
      },
      '/api/webhooks/{id}/ping': {
        post: {
          tags: ['webhooks'],
          summary: 'Test webhook delivery',
          description: 'Sends a test ping event to the webhook endpoint and returns the result synchronously.',
          operationId: 'pingWebhook',
          security: [{ sessionCookie: [], csrfHeader: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            200: { description: 'Ping result', content: { 'application/json': { schema: { type: 'object', properties: { success: { type: 'boolean' }, statusCode: { type: 'integer' }, responseBody: { type: 'string' }, error: { type: 'string' }, eventId: { type: 'string' } } } } } },
          },
        },
      },
      '/api/webhooks/{id}/deliveries': {
        get: {
          tags: ['webhooks'],
          summary: 'Webhook delivery log',
          operationId: 'getWebhookDeliveries',
          security: [{ sessionCookie: [] }],
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }],
          responses: {
            200: { description: 'Delivery history', content: { 'application/json': { schema: { type: 'object', properties: { deliveries: { type: 'array', items: { type: 'object', properties: { eventId: { type: 'string' }, eventType: { type: 'string' }, status: { type: 'string', enum: ['pending', 'success', 'failed', 'retrying'] }, statusCode: { type: 'integer' }, attempt: { type: 'integer' }, sentAt: { type: 'string', format: 'date-time' } } } } } } } } },
          },
        },
      },
      '/api/integrations/status': {
        get: {
          tags: ['integrations'],
          summary: 'Live integration status',
          description: 'Returns real-time status of all integrations: database, authority, file storage, webhooks, HTTPS, and Nginx proxy detection.',
          operationId: 'getIntegrationStatus',
          responses: {
            200: { description: 'All integrations healthy' },
            207: { description: 'Some integrations degraded' },
          },
        },
      },
      '/api/integrations/demo/data': {
        get: {
          tags: ['integrations'],
          summary: 'Demo data',
          description: 'Returns safe sample data for the demonstration mode.',
          operationId: 'getDemoData',
          responses: {
            200: { description: 'Demo data' },
          },
        },
      },
    },
  };
}
