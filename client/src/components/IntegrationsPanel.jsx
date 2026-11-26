import { useCallback, useEffect, useState } from 'react';
import { api } from '../api.js';

const STATUS_LABEL = { ok: '✅ Operational', warn: '⚠️ Warning', error: '❌ Error', loading: '⏳ Checking...' };
const STATUS_CLASS = { ok: 'ok', warn: 'warn', error: 'danger', loading: 'muted' };

function StatusBadge({ status }) {
  const cls = STATUS_CLASS[status] || 'muted';
  return <span className={cls}>{STATUS_LABEL[status] || status}</span>;
}

function IntegrationCard({ title, description, status, details, link, linkLabel, children }) {
  return (
    <div className="card" style={{ display: 'grid', gap: '0.5rem' }}>
      <div className="row-between">
        <h3 style={{ margin: 0, fontSize: '1rem' }}>{title}</h3>
        <StatusBadge status={status} />
      </div>
      <p className="hint" style={{ margin: 0 }}>{description}</p>
      {details && <p className="muted" style={{ margin: 0, fontSize: '0.88rem' }}>{details}</p>}
      {link && (
        <a href={link} target="_blank" rel="noopener noreferrer" className="link" style={{ fontSize: '0.88rem' }}>
          {linkLabel || link} ↗
        </a>
      )}
      {children}
    </div>
  );
}

function StatusRow({ label, check }) {
  if (!check) return null;
  return (
    <tr>
      <td style={{ width: '40%' }}><strong>{label}</strong></td>
      <td><StatusBadge status={check.status} /></td>
      <td className="muted" style={{ fontSize: '0.85rem' }}>{check.message}</td>
    </tr>
  );
}

export default function IntegrationsPanel() {
  const [status, setStatus] = useState(null);
  const [demoData, setDemoData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [webhookSecret, setWebhookSecret] = useState('');
  const [webhookResult, setWebhookResult] = useState(null);
  const [webhookRegistered, setWebhookRegistered] = useState(null);
  const [pingResult, setPingResult] = useState(null);
  const [pingBusy, setPingBusy] = useState(false);
  const [tab, setTab] = useState('overview');

  const refresh = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [s, d] = await Promise.all([
        api.get('/api/integrations/status'),
        api.get('/api/integrations/demo/data'),
      ]);
      setStatus(s);
      setDemoData(d);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const id = setTimeout(() => { refresh(); }, 0);
    return () => clearTimeout(id);
  }, [refresh]);

  async function registerWebhook(e) {
    e.preventDefault();
    setWebhookResult(null);
    try {
      const r = await api.post('/api/webhooks', {
        url: webhookUrl,
        secret: webhookSecret || 'demo-webhook-secret-min-16-chars',
        events: ['file.uploaded', 'auth.login.succeeded', 'file.access.denied', 'file.policy.updated', 'file.deleted', 'auth.account.locked'],
        description: 'SecureShareFR live demonstration webhook',
      });
      setWebhookRegistered(r);
      setWebhookResult({ ok: `Webhook registered! ID: ${r.id}` });
    } catch (err) {
      setWebhookResult({ error: err.message });
    }
  }

  async function pingWebhook() {
    if (!webhookRegistered) return;
    setPingBusy(true);
    setPingResult(null);
    try {
      const r = await api.post(`/api/webhooks/${webhookRegistered.id}/ping`);
      setPingResult(r);
    } catch (err) {
      setPingResult({ error: err.message });
    } finally {
      setPingBusy(false);
    }
  }

  const checks = status?.checks ?? {};
  const overallStatus = status?.status ?? 'loading';

  const infoTabs = [
    ['overview', '📊 Overview'],
    ['swagger', '📖 Swagger'],
    ['postman', '📮 Postman'],
    ['webhooks', '🔔 Webhooks'],
    ['https', '🔒 HTTPS'],
    ['nginx', '⚙️ Nginx'],
    ['cloud', '☁️ Deployment'],
  ];

  return (
    <div className="stack-lg">
      {/* Header */}
      <section className="card">
        <div className="row-between">
          <div>
            <h2 style={{ margin: 0 }}>System Integrations &amp; Infrastructure</h2>
            <p className="muted" style={{ margin: '0.3rem 0 0' }}>
              Live status of all six production integrations — SecureShareFR v2.0.0
            </p>
          </div>
          <button type="button" onClick={refresh} disabled={loading}>
            {loading ? 'Refreshing…' : '↻ Refresh All'}
          </button>
        </div>
        {error && <p className="error" role="alert">{error}</p>}

        {/* Overall system status banner */}
        <div style={{ marginTop: '0.75rem', padding: '0.6rem 1rem', borderRadius: 6, background: overallStatus === 'ok' ? 'color-mix(in srgb, var(--ok) 15%, transparent)' : overallStatus === 'loading' ? 'var(--bg)' : 'color-mix(in srgb, var(--warn) 15%, transparent)', border: '1px solid', borderColor: overallStatus === 'ok' ? 'var(--ok)' : 'var(--warn)' }}>
          <strong>Overall system status: </strong>
          <StatusBadge status={loading ? 'loading' : overallStatus} />
          {status && <span className="muted" style={{ marginLeft: '1rem', fontSize: '0.88rem' }}>
            Uptime: {status.checks.environment?.uptime}s · Node: {status.checks.environment?.nodeEnv} · Origin: {status.checks.environment?.publicOrigin}
          </span>}
        </div>
      </section>

      {/* Tab navigation */}
      <nav className="tabs" role="tablist" style={{ gap: '0.15rem', flexWrap: 'wrap' }}>
        {infoTabs.map(([id, label]) => (
          <button key={id} type="button" role="tab" aria-selected={tab === id}
            className={tab === id ? 'on' : ''} onClick={() => setTab(id)}
            style={{ padding: '0.4rem 0.75rem', fontSize: '0.9rem' }}>
            {label}
          </button>
        ))}
      </nav>

      {/* ── Overview ── */}
      {tab === 'overview' && (
        <section className="card">
          <h3>Live Integration Status</h3>
          <table>
            <thead>
              <tr><th>Component</th><th>Status</th><th>Details</th></tr>
            </thead>
            <tbody>
              <StatusRow label="🗄️ MongoDB Database" check={checks.database} />
              <StatusRow label="🔑 Attribute Authority" check={checks.authority} />
              <StatusRow label="📁 File Storage" check={checks.fileStorage} />
              <StatusRow label="🔔 Webhook System" check={checks.webhooks} />
              <StatusRow label="📖 Swagger / OpenAPI" check={checks.swagger} />
              <StatusRow label="⚙️ Nginx Proxy" check={checks.nginx} />
              <StatusRow label="🔒 HTTPS / TLS" check={checks.https} />
              <StatusRow label="🖥️ Runtime" check={checks.environment} />
            </tbody>
          </table>

          {demoData && (
            <>
              <h3 style={{ marginTop: '1.25rem' }}>Demo Data — Sample Attribute Policies</h3>
              <table className="compact">
                <thead><tr><th>Policy</th><th>Description</th></tr></thead>
                <tbody>
                  {demoData.samplePolicies.map((p) => (
                    <tr key={p.policy}>
                      <td><code className="policy">{p.policy}</code></td>
                      <td className="muted">{p.description}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </>
          )}
        </section>
      )}

      {/* ── Swagger ── */}
      {tab === 'swagger' && (
        <div className="stack-lg">
          <IntegrationCard
            title="1. Swagger / OpenAPI"
            description="Interactive API documentation generated from the live OpenAPI 3.0.3 specification. Documents all endpoints, request/response schemas, authentication, and error codes."
            status={checks.swagger?.status ?? 'loading'}
            details={checks.swagger?.message}
            link="/docs"
            linkLabel="Open Swagger UI (/docs)"
          >
            <div className="inline" style={{ marginTop: '0.5rem' }}>
              <a href="/docs" target="_blank" rel="noopener noreferrer">
                <button type="button" className="primary">🔗 Open Swagger UI</button>
              </a>
              <a href="/api/openapi.json" target="_blank" rel="noopener noreferrer">
                <button type="button">📄 Raw OpenAPI JSON</button>
              </a>
            </div>
          </IntegrationCard>
          <section className="card">
            <h3>What to demonstrate</h3>
            <ol style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.5rem' }}>
              <li>Open <strong>/docs</strong> in a browser — the Swagger UI loads</li>
              <li>Expand <strong>GET /api/health</strong> → click "Try it out" → "Execute"</li>
              <li>Show the <strong>200 response</strong> with <code>{`{"status":"ok"}`}</code></li>
              <li>Try <strong>POST /api/auth/login</strong> with empty body → show <strong>400 validation error</strong></li>
              <li>Try <strong>POST /api/auth/login</strong> without the CSRF header override → show <strong>403</strong></li>
              <li>Show the <strong>cookie-based session</strong> and <strong>CSRF security scheme</strong> in the spec</li>
            </ol>
          </section>
        </div>
      )}

      {/* ── Postman ── */}
      {tab === 'postman' && (
        <div className="stack-lg">
          <IntegrationCard
            title="2. Postman API Testing"
            description="Comprehensive test collection with 7 organized folders covering health, auth, authority, files, webhooks, admin, and security/error scenarios."
            status="ok"
            details="Collection file: postman/SecureShareFR.postman_collection.json"
          >
            <dl className="kv" style={{ marginTop: '0.5rem' }}>
              <dt>Collection file</dt>
              <dd><code>postman/SecureShareFR.postman_collection.json</code></dd>
              <dt>Environment file</dt>
              <dd><code>postman/SecureShareFR.postman_environment.json</code></dd>
              <dt>Folders</dt>
              <dd>7 (Health, Auth, Authority, Files, Webhooks, Admin, Security)</dd>
              <dt>CSRF handling</dt>
              <dd>Auto-added via collection pre-request script</dd>
            </dl>
          </IntegrationCard>
          <section className="card">
            <h3>What to demonstrate</h3>
            <ol style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.5rem' }}>
              <li>Import both JSON files into Postman</li>
              <li>Select <strong>"SecureShareFR Local"</strong> environment</li>
              <li>Run <strong>1. Health &amp; Meta → API Health</strong> — show 200 + test results ✅</li>
              <li>Run <strong>1. Health &amp; Meta → Integration Status</strong> — show live checks</li>
              <li>Run <strong>2. Auth &amp; Sessions → Login (invalid credentials)</strong> — show 401 ✗</li>
              <li>Run <strong>2. Auth &amp; Sessions → Login (missing CSRF)</strong> — show 403 ✗</li>
              <li>Run <strong>5. Webhooks → List Supported Events</strong> — show event types</li>
            </ol>
          </section>
        </div>
      )}

      {/* ── Webhooks ── */}
      {tab === 'webhooks' && (
        <div className="stack-lg">
          <IntegrationCard
            title="3. Webhook Event System"
            description="HMAC-SHA256 signed event notifications triggered by real application events. Non-blocking delivery with exponential backoff retries and SSRF protection."
            status={checks.webhooks?.status ?? 'loading'}
            details={`${checks.webhooks?.message ?? ''} · Last delivery: ${checks.webhooks?.lastDeliveryStatus ?? 'none'}`}
          >
            <div style={{ marginTop: '0.5rem' }}>
              <h4 style={{ margin: '0 0 0.5rem' }}>Supported Events</h4>
              <div className="chips">
                {(demoData?.sampleWebhookEvents ?? ['file.uploaded','auth.login.succeeded','file.access.denied','file.policy.updated']).map((e) => (
                  <span key={e} className="chip static">{e}</span>
                ))}
                <span className="chip static">file.deleted</span>
                <span className="chip static">auth.registered</span>
                <span className="chip static">auth.account.locked</span>
                <span className="chip static">authority.attributes.updated</span>
              </div>
            </div>
          </IntegrationCard>

          {/* Live webhook demo */}
          <section className="card">
            <h3>Live Webhook Demonstration</h3>
            <p className="hint">
              To demonstrate webhooks, use <a href="https://webhook.site" target="_blank" rel="noopener noreferrer">webhook.site</a> (free public webhook receiver).
              Copy your unique URL from that site and paste it below.
            </p>
            {!webhookRegistered ? (
              <form onSubmit={registerWebhook} className="stack" style={{ maxWidth: 480 }}>
                <label>
                  Webhook destination URL
                  <input
                    type="url"
                    value={webhookUrl}
                    onChange={(e) => setWebhookUrl(e.target.value)}
                    placeholder="https://webhook.site/your-unique-id"
                    required
                  />
                </label>
                <label>
                  Signing secret (min 16 chars)
                  <input
                    type="text"
                    value={webhookSecret}
                    onChange={(e) => setWebhookSecret(e.target.value)}
                    placeholder="demo-webhook-secret-min-16-chars"
                  />
                </label>
                <button type="submit" className="primary">Register Webhook Endpoint</button>
              </form>
            ) : (
              <div className="stack">
                <p className="success">✅ Webhook registered — ID: <code>{webhookRegistered.id}</code></p>
                <p className="hint">Events subscribed: {webhookRegistered.events?.join(', ')}</p>
                <div className="inline">
                  <button type="button" className="primary" onClick={pingWebhook} disabled={pingBusy}>
                    {pingBusy ? 'Pinging…' : '📤 Send Test Ping'}
                  </button>
                  <button type="button" onClick={() => { setWebhookRegistered(null); setWebhookUrl(''); setPingResult(null); setWebhookResult(null); }}>
                    Reset
                  </button>
                </div>
                {pingResult && (
                  <div className="card" style={{ background: 'var(--bg)', fontSize: '0.88rem' }}>
                    <strong>{pingResult.success ? '✅ Delivered!' : '❌ Failed'}</strong>
                    <dl className="kv" style={{ marginTop: '0.5rem' }}>
                      <dt>HTTP status</dt><dd>{pingResult.statusCode ?? 'N/A'}</dd>
                      <dt>Event ID</dt><dd><code>{pingResult.eventId}</code></dd>
                      <dt>Response</dt><dd>{pingResult.responseBody || pingResult.error || '(empty)'}</dd>
                    </dl>
                    <p className="hint" style={{ marginTop: '0.5rem' }}>
                      Payload includes: <code>eventId</code>, <code>eventType: "ping"</code>, <code>timestamp</code>, HMAC-SHA256 signature in <code>X-SecureShare-Signature</code> header.
                    </p>
                  </div>
                )}
                <p className="hint">Now perform an action in the app (upload a file, sign out) and check webhook.site for the notification.</p>
              </div>
            )}
            {webhookResult?.error && <p className="error">{webhookResult.error}</p>}
          </section>

          <section className="card">
            <h3>Security features</h3>
            <ul style={{ margin: 0, paddingLeft: '1.25rem' }}>
              <li>HMAC-SHA256 signatures (<code>X-SecureShare-Signature: sha256=...</code>)</li>
              <li>SSRF protection — private/loopback IPs and reserved ranges are blocked</li>
              <li>10-second timeout per delivery attempt</li>
              <li>Exponential backoff: retries at 0s, 10s, 30s, 120s</li>
              <li>Non-blocking — webhook delivery never interrupts the primary request</li>
              <li>Idempotency keys (<code>X-SecureShare-Event-Id</code>) for deduplication</li>
              <li>Payloads never include plaintext file names, keys, or passwords</li>
            </ul>
          </section>
        </div>
      )}

      {/* ── HTTPS ── */}
      {tab === 'https' && (
        <div className="stack-lg">
          <IntegrationCard
            title="4. HTTPS / TLS"
            description="All traffic is encrypted using TLS 1.2+. Local Docker stack uses a self-signed certificate. Production uses Let's Encrypt via certbot."
            status={checks.https?.status ?? 'loading'}
            details={checks.https?.message}
          >
            <dl className="kv" style={{ marginTop: '0.5rem' }}>
              <dt>Protocol detected</dt><dd><code>{checks.https?.protocol ?? '…'}</code></dd>
              <dt>HSTS</dt><dd>max-age=63072000; includeSubDomains</dd>
              <dt>TLS ciphers</dt><dd>TLSv1.2+, ECDHE + AES-GCM / ChaCha20</dd>
              <dt>Cookies</dt><dd><code>HttpOnly; SameSite=Strict; Secure; Path=/</code></dd>
              <dt>Cookie name</dt><dd><code>__Host-ss_session</code> (in production), <code>ss_session</code> (dev)</dd>
            </dl>
          </IntegrationCard>
          <section className="card">
            <h3>What to demonstrate</h3>
            <ol style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.5rem' }}>
              <li>Open <strong>https://localhost</strong> (through Nginx) — browser shows 🔒 padlock</li>
              <li>Click the padlock → <strong>Certificate</strong> → show Subject, SANs (localhost / 127.0.0.1)</li>
              <li>Try <strong>http://localhost</strong> → should automatically redirect to HTTPS (301)</li>
              <li>Open DevTools → Network → any request → Response Headers → show <code>Strict-Transport-Security</code></li>
              <li>Show <code>X-Content-Type-Options: nosniff</code>, <code>X-Frame-Options: DENY</code>, <code>Content-Security-Policy</code></li>
              <li>Show the session cookie: DevTools → Application → Cookies → <code>ss_session</code> (HttpOnly, Secure checked)</li>
            </ol>
          </section>
          <section className="card">
            <h3>TLS Certificate Setup</h3>
            <p className="muted" style={{ fontSize: '0.88rem' }}>For local Docker development (self-signed):</p>
            <pre style={{ background: 'var(--bg)', padding: '0.75rem', borderRadius: 6, fontSize: '0.82rem', overflow: 'auto' }}>
{`# Generate self-signed cert (run once)
cd deploy/nginx
sh gen-local-cert.sh localhost

# Then start the stack
npm run setup
cp deploy/.env.example deploy/.env
docker compose --env-file deploy/.env up -d --build`}
            </pre>
            <p className="muted" style={{ fontSize: '0.88rem', marginTop: '0.5rem' }}>For production with Let's Encrypt, replace cert paths in <code>deploy/nginx/nginx.conf</code> with <code>/etc/letsencrypt/live/DOMAIN/</code>.</p>
          </section>
        </div>
      )}

      {/* ── Nginx ── */}
      {tab === 'nginx' && (
        <div className="stack-lg">
          <IntegrationCard
            title="5. Nginx Reverse Proxy"
            description="Nginx handles HTTPS termination, HTTP→HTTPS redirect (301), security headers, and routes traffic to the API, Authority, and static React app."
            status={checks.nginx?.status ?? 'loading'}
            details={checks.nginx?.message}
          >
            <dl className="kv" style={{ marginTop: '0.5rem' }}>
              <dt>Client IP header</dt><dd><code>{checks.nginx?.xRealIp ?? '(not set — direct connection)'}</code></dd>
              <dt>Forwarded for</dt><dd><code>{checks.nginx?.xForwardedFor ?? '(none)'}</code></dd>
              <dt>Protocol via proxy</dt><dd><code>{checks.nginx?.protocol ?? '…'}</code></dd>
              <dt>Upload limit</dt><dd>110 MiB (matches 100 MiB app limit + overhead)</dd>
              <dt>Streaming</dt><dd>proxy_request_buffering off (direct stream to API)</dd>
            </dl>
          </IntegrationCard>
          <section className="card">
            <h3>Routing Configuration</h3>
            <table className="compact">
              <thead><tr><th>Path</th><th>Destination</th><th>Notes</th></tr></thead>
              <tbody>
                <tr><td><code>/api/*</code></td><td><code>http://api:4000</code></td><td>110 MiB body, streaming</td></tr>
                <tr><td><code>/authority/*</code></td><td><code>http://authority:7000</code></td><td>64 KiB body limit</td></tr>
                <tr><td><code>/docs</code></td><td><code>http://api:4000/docs</code></td><td>Swagger UI</td></tr>
                <tr><td><code>/api/openapi.json</code></td><td><code>http://api:4000/api/openapi.json</code></td><td>OpenAPI spec</td></tr>
                <tr><td><code>/</code></td><td><code>/usr/share/nginx/html</code></td><td>React SPA, try_files</td></tr>
                <tr><td><code>:80 → :443</code></td><td>301 redirect</td><td>HTTP→HTTPS</td></tr>
              </tbody>
            </table>
          </section>
          <section className="card">
            <h3>What to demonstrate</h3>
            <ol style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.5rem' }}>
              <li>Show <code>deploy/nginx/nginx.conf</code> — point out TLS, proxy_pass rules, security headers</li>
              <li>Try <strong>http://localhost</strong> → watch redirect to <strong>https://localhost</strong> (301)</li>
              <li>Show API request headers in DevTools — look for <code>X-Forwarded-Proto: https</code></li>
              <li>Visit <code>/api/integrations/status</code> — Nginx check shows "Proxied through Nginx"</li>
              <li>Show MongoDB on <code>backend</code> Docker network (no external port) — Nginx prevents direct DB access</li>
              <li>Show API is NOT exposed on port 4000 externally (only port 80/443 are published)</li>
            </ol>
          </section>
        </div>
      )}

      {/* ── Cloud Deployment ── */}
      {tab === 'cloud' && (
        <div className="stack-lg">
          <IntegrationCard
            title="6. Cloud Deployment (Docker)"
            description="Complete containerized stack with Docker Compose: Nginx (web), API (Node.js), Attribute Authority (Node.js), and MongoDB. All services are hardened with read-only containers, non-root users, capability drops, and resource limits."
            status="ok"
            details={`Environment: ${checks.environment?.nodeEnv ?? '…'} | Version: ${checks.environment?.version ?? '2.0.0'} | Uptime: ${checks.environment?.uptime ?? '…'}s`}
          />
          <section className="card">
            <h3>Service Architecture</h3>
            <table className="compact">
              <thead><tr><th>Service</th><th>Image</th><th>Ports</th><th>Network</th></tr></thead>
              <tbody>
                <tr><td><strong>web</strong> (Nginx)</td><td><code>nginx:1.27-alpine</code></td><td>80, 443 (public)</td><td>frontend</td></tr>
                <tr><td><strong>api</strong></td><td><code>node:22-alpine</code></td><td>4000 (internal)</td><td>frontend + backend</td></tr>
                <tr><td><strong>authority</strong></td><td><code>node:22-alpine</code></td><td>7000, 7001 (internal)</td><td>frontend + backend</td></tr>
                <tr><td><strong>mongo</strong></td><td><code>mongo:8.0</code></td><td>27017 (internal only)</td><td>backend only</td></tr>
              </tbody>
            </table>
            <h3 style={{ marginTop: '1rem' }}>Persistent Volumes</h3>
            <ul style={{ margin: 0, paddingLeft: '1.25rem' }}>
              <li><code>blobs</code> — encrypted file ciphertext (mounted into api service)</li>
              <li><code>mongo_data</code> — MongoDB databases (secureshare + secureshare_authority)</li>
            </ul>
          </section>
          <section className="card">
            <h3>Quick Start (Docker)</h3>
            <pre style={{ background: 'var(--bg)', padding: '0.75rem', borderRadius: 6, fontSize: '0.82rem', overflow: 'auto' }}>
{`# 1. Generate secrets (once)
npm run setup

# 2. Generate TLS certificate (once)
cd deploy/nginx && sh gen-local-cert.sh && cd ../..

# 3. Configure environment
cp deploy/.env.example deploy/.env
# Edit deploy/.env if needed (DOMAIN, BOOTSTRAP_ADMIN, etc.)

# 4. Start the full stack
docker compose --env-file deploy/.env up -d --build

# 5. Check status
docker compose --env-file deploy/.env ps

# 6. View logs
docker compose --env-file deploy/.env logs -f

# 7. Health checks
curl -k https://localhost/api/health
curl -k https://localhost/authority/health`}
            </pre>
          </section>
          <section className="card">
            <h3>What to demonstrate</h3>
            <ol style={{ margin: 0, paddingLeft: '1.25rem', display: 'grid', gap: '0.5rem' }}>
              <li>Show <code>docker compose ps</code> — all 4 services running and healthy</li>
              <li>Open <strong>https://localhost</strong> — SecureShareFR loads through Docker</li>
              <li>Show <code>docker compose logs api --tail 20</code> — structured JSON logs</li>
              <li>Hit <code>GET /api/health</code> — demonstrates health check endpoint</li>
              <li>Show <code>docker compose logs</code> — no plaintext passwords or keys in logs</li>
              <li>Show <code>docker inspect</code> — read-only FS, non-root user, all caps dropped</li>
              <li>Show <code>docker volume ls</code> — persistent volumes for blobs and MongoDB</li>
            </ol>
          </section>
        </div>
      )}
    </div>
  );
}
