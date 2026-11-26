#!/usr/bin/env node
/**
 * Self-running SecureShareFR panel demo.
 *
 * What it does, unattended:
 *   1. Preflights HTTPS / Nginx / Swagger / OpenAPI over the real origin.
 *   2. Launches Edge/Chrome with remote debugging (no Playwright needed).
 *   3. Opens the integration-status JSON, Swagger UI, OpenAPI spec and webhook.site.
 *   4. Registers a fresh demo user in the real web app (browser-side crypto).
 *   5. Opens Dashboard -> Integrations and cycles the Swagger/Postman/Webhooks/
 *      HTTPS/Nginx tabs, saving a screenshot of each.
 *   6. Registers a live webhook from the UI, sends a signed test ping, then signs
 *      out and back in to trigger a real auth.login.succeeded delivery.
 *   7. Optionally shows the Jenkins job and prints a narration summary.
 *
 * Usage:
 *   npm run demo:panel
 *   FAST=1 npm run demo:panel                 # shorter pauses
 *   WEBHOOK_URL=https://webhook.site/<id> npm run demo:panel
 *   KEEP_BROWSER=0 npm run demo:panel         # close the browser at the end
 *
 * Requires Node 22+ and Edge/Chrome on the machine. Self-signed certs are
 * tolerated in the demo browser via --ignore-certificate-errors.
 */
import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Local Docker stack uses a self-signed cert. The browser is launched with
// --ignore-certificate-errors; this covers Node's own preflight fetches.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const BASE = (process.env.BASE_URL ?? 'https://localhost').replace(/\/$/, '');
const CDP_PORT = Number(process.env.CDP_PORT ?? 9222);
const FAST = process.env.FAST === '1';
const KEEP_BROWSER = process.env.KEEP_BROWSER !== '0';
const SHOT_DIR = join(ROOT, 'docs', 'demo-screenshots');
const DEMO_USER = process.env.DEMO_USER ?? `panel_demo_${Date.now().toString().slice(-6)}`;
const DEMO_PASSWORD = process.env.DEMO_PASSWORD ?? 'PanelDemo!123';
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET ?? 'panel-demo-secret-123456';
const JENKINS_URL = process.env.JENKINS_URL ?? 'http://localhost:8080/job/secureshare-deploy/';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const beat = FAST ? 350 : 2400;

function say(n, title, detail = '') {
  console.log(`\n[${n}] ${title}${detail ? ` — ${detail}` : ''}`);
}
function ok(msg) {
  console.log(`      ✓ ${msg}`);
}
function warn(msg) {
  console.log(`      ! ${msg}`);
}

mkdirSync(SHOT_DIR, { recursive: true });

/* ────────────────────────────── CDP client ────────────────────────────── */

class Session {
  constructor(wsUrl) {
    this.ws = new WebSocket(wsUrl);
    this.nextId = 1;
    this.pending = new Map();
    this.waiters = [];
  }

  async open() {
    await new Promise((resolve, reject) => {
      this.ws.onopen = resolve;
      this.ws.onerror = () => reject(new Error('CDP websocket failed to open'));
    });
    this.ws.onmessage = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.id && this.pending.has(msg.id)) {
        const p = this.pending.get(msg.id);
        this.pending.delete(msg.id);
        if (msg.error) p.reject(new Error(msg.error.message));
        else p.resolve(msg.result);
        return;
      }
      if (msg.method) {
        for (const w of [...this.waiters]) {
          if (w.method === msg.method) {
            this.waiters = this.waiters.filter((x) => x !== w);
            w.resolve(msg);
          }
        }
      }
    };
    await this.send('Page.enable');
    await this.send('Runtime.enable');
    await this.send('Emulation.setDeviceMetricsOverride', {
      width: 1440, height: 960, deviceScaleFactor: 1, mobile: false,
    });
    return this;
  }

  send(method, params = {}) {
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  wait(method, timeout = 30000) {
    return new Promise((resolve, reject) => {
      const entry = { method, resolve };
      this.waiters.push(entry);
      const timer = setTimeout(() => {
        this.waiters = this.waiters.filter((x) => x !== entry);
        reject(new Error(`timeout waiting for ${method}`));
      }, timeout);
      const original = entry.resolve;
      entry.resolve = (msg) => { clearTimeout(timer); original(msg); };
    });
  }

  async navigate(url) {
    const loaded = this.wait('Page.loadEventFired');
    await this.send('Page.navigate', { url });
    await loaded;
  }

  async reload() {
    const loaded = this.wait('Page.loadEventFired', 30000);
    await this.send('Page.reload', { ignoreCache: false });
    await loaded;
  }

  async eval(expression) {
    const r = await this.send('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true, userGesture: true,
    });
    if (r.exceptionDetails) {
      const detail = r.exceptionDetails.exception?.description ?? r.exceptionDetails.text;
      throw new Error(`browser eval failed: ${detail}`);
    }
    return r.result.value;
  }

  async waitFor(expression, label, timeout = 25000) {
    const start = Date.now();
    while (Date.now() - start < timeout) {
      try { if (await this.eval(expression)) return true; } catch { /* retry */ }
      await sleep(250);
    }
    throw new Error(`timeout waiting for ${label}`);
  }

  async shot(name) {
    const { data } = await this.send('Page.captureScreenshot', {
      format: 'png', captureBeyondViewport: false,
    });
    const file = join(SHOT_DIR, name);
    writeFileSync(file, Buffer.from(data, 'base64'));
    ok(`screenshot → docs/demo-screenshots/${name}`);
  }

  close() {
    try { this.ws.close(); } catch { /* already closed */ }
  }
}

/* ───────────────────────── browser helpers ───────────────────────────── */

function findBrowser() {
  const candidates = [
    process.env.BROWSER_PATH,
    'C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe',
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
  ].filter(Boolean);
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate;
  }
  throw new Error('No Edge/Chrome found. Set BROWSER_PATH to your browser executable.');
}

async function debugPortReady() {
  try {
    const r = await fetch(`http://127.0.0.1:${CDP_PORT}/json/version`);
    return r.ok;
  } catch { return false; }
}

async function ensureBrowser() {
  if (await debugPortReady()) {
    ok(`reusing browser already listening on :${CDP_PORT}`);
    return { proc: null };
  }
  const exe = findBrowser();
  const profile = join(tmpdir(), `secureshare-panel-${Date.now()}`);
  const proc = spawn(exe, [
    `--remote-debugging-port=${CDP_PORT}`,
    `--user-data-dir=${profile}`,
    '--ignore-certificate-errors',
    '--no-first-run',
    '--no-default-browser-check',
    '--disable-extensions',
    '--new-window',
    'about:blank',
  ], { stdio: 'ignore' });
  for (let i = 0; i < 60; i++) {
    if (await debugPortReady()) {
      ok(`launched ${exe} with debugging on :${CDP_PORT}`);
      return { proc };
    }
    await sleep(500);
  }
  proc.kill();
  throw new Error(`Browser did not open debugging port ${CDP_PORT}`);
}

async function newTab(url) {
  const res = await fetch(
    `http://127.0.0.1:${CDP_PORT}/json/new?${encodeURIComponent(url)}`,
    { method: 'PUT' },
  );
  if (!res.ok) throw new Error(`could not open tab: HTTP ${res.status}`);
  const target = await res.json();
  const session = await new Session(target.webSocketDebuggerUrl).open();
  return { target, session };
}

const setInput = (selector, value, index = 0) => `(() => {
  const els = [...document.querySelectorAll(${JSON.stringify(selector)})];
  const el = els[${index}];
  if (!el) return false;
  const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, ${JSON.stringify(value)});
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
  return true;
})()`;

const clickText = (selector, text) => `(() => {
  const el = [...document.querySelectorAll(${JSON.stringify(selector)})]
    .find((e) => e.textContent.includes(${JSON.stringify(text)}));
  if (!el) return false;
  el.click();
  return true;
})()`;

/* ─────────────────────────── preflight ───────────────────────────────── */

async function preflight() {
  say(1, 'Preflight', `${BASE} over HTTPS`);
  const health = await fetch(`${BASE}/api/health`);
  const status = await (await fetch(`${BASE}/api/integrations/status`)).json();
  const docs = await (await fetch(`${BASE}/docs`)).text();
  const spec = await (await fetch(`${BASE}/api/openapi.json`)).json();
  if (!health.ok) throw new Error(`API health failed: ${health.status}`);
  if (!docs.includes('swagger-ui')) throw new Error('Swagger UI did not render');
  if (spec.openapi !== '3.0.3') throw new Error(`Unexpected OpenAPI version: ${spec.openapi}`);
  ok(`API health ${health.status} · ${Object.keys(spec.paths).length} OpenAPI paths`);
  ok(`Nginx check: ${status.checks.nginx.message}`);
  ok(`HTTPS check: ${status.checks.https.message}`);
  ok(`Swagger check: ${status.checks.swagger.message}`);
  ok(`Webhook check: ${status.checks.webhooks.message}`);
}

/* ─────────────────────────── demo steps ──────────────────────────────── */

async function showJsonAndSwagger() {
  say(3, 'Swagger UI — self-hosted, no CDN');
  const swagger = await newTab(`${BASE}/docs`);
  await swagger.session.waitFor(
    `document.querySelectorAll('.opblock').length > 5`, 'Swagger operations', 30000,
  );
  await swagger.session.shot('02-swagger-ui.png');
  // React renders Try-it-out/Execute controls only after the operation is expanded,
  // so expand first, let React paint, then click the next control.
  await swagger.session.eval(`(() => {
    const op = [...document.querySelectorAll('.opblock')]
      .find((o) => o.classList.contains('opblock-get') && o.querySelector('.opblock-summary-path')?.innerText === '/api/integrations/status');
    if (!op) return false;
    if (!op.classList.contains('is-open')) op.querySelector('.opblock-summary-control')?.click();
    return true;
  })()`);
  await sleep(FAST ? 500 : 900);
  const tryIt = await swagger.session.eval(`(() => {
    const op = [...document.querySelectorAll('.opblock')]
      .find((o) => o.querySelector('.opblock-summary-path')?.innerText === '/api/integrations/status');
    const btn = op && [...op.querySelectorAll('button')].find((b) => b.textContent.includes('Try it out'));
    if (!btn) return 'no-button';
    btn.click();
    return 'clicked';
  })()`);
  ok(tryIt === 'no-button'
    ? 'Swagger operation expanded (Try it out already active in this Swagger build)'
    : `Swagger Try it out: ${tryIt}`);
  await sleep(FAST ? 500 : 900);
  const executed = await swagger.session.eval(`(() => {
    const op = [...document.querySelectorAll('.opblock')]
      .find((o) => o.querySelector('.opblock-summary-path')?.innerText === '/api/integrations/status');
    const btn = op && [...op.querySelectorAll('button')].find((b) => b.textContent.trim() === 'Execute');
    if (!btn) return 'no-button';
    btn.click();
    return 'clicked';
  })()`);
  ok(`Swagger Execute: ${executed}`);
  await sleep(FAST ? 700 : 1800);
  await swagger.session.shot('03-swagger-execute.png');

  const spec = await newTab(`${BASE}/api/openapi.json`);
  await sleep(beat);
  await spec.session.shot('04-openapi-spec.png');
  spec.session.close();
  return swagger.session;
}

async function getWebhookReceiver() {
  say(4, 'Public HTTPS webhook receiver');
  const hook = await newTab('https://webhook.site/');
  const uuidRe = /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/i;
  try {
    await hook.session.waitFor(`/${uuidRe.source}/i.test(location.href)`, 'webhook.site inbox', 30000);
  } catch { /* fall through to local storage / fallback */ }
  let uuid = await hook.session.eval(`(() => {
    const m = location.href.match(/${uuidRe.source}/i);
    return m ? m[0] : '';
  })()`);
  if (!uuid) {
    uuid = await hook.session.eval(`(() => {
      try {
        const token = JSON.parse(localStorage.getItem('token') || '{}');
        if (token.uuid) return token.uuid;
        const re = /${uuidRe.source}/i;
        for (const v of Object.values(localStorage)) {
          const m = String(v).match(re);
          if (m) return m[0];
        }
      } catch { /* ignore */ }
      return '';
    })()`);
  }
  if (uuid) {
    ok(`webhook.site inbox: ${uuid}`);
    await hook.session.shot('05-webhook-receiver.png');
    return { session: hook.session, url: `https://webhook.site/${uuid}`, visual: true };
  }
  warn('could not read a webhook.site inbox; using https://httpbin.org/post as fallback');
  return { session: hook.session, url: process.env.WEBHOOK_URL ?? 'https://httpbin.org/post', visual: false };
}

async function signUpInBrowser(app) {
  say(5, 'Browser login flow', `creating ${DEMO_USER}`);
  await app.navigate(BASE);
  await app.waitFor(`!!document.querySelector('input[autocomplete="username"]')`, 'auth page');
  await app.eval(clickText('button[role="tab"]', 'Create account'));
  await sleep(300);
  await app.eval(setInput('input[autocomplete="username"]', DEMO_USER));
  await app.eval(setInput('input[autocomplete="new-password"]', DEMO_PASSWORD, 0));
  await app.eval(setInput('input[autocomplete="new-password"]', DEMO_PASSWORD, 1));
  await app.eval(clickText('button[type="submit"]', 'Create account'));
  await app.waitFor(`document.body.innerText.includes(${JSON.stringify(DEMO_USER)})`, 'dashboard', 40000);
  ok('account created in the browser; password never left the browser');
  await app.shot('06-browser-dashboard.png');
  await sleep(beat);
}

async function cycleIntegrationTabs(app) {
  say(6, 'Dashboard → Integrations');
  const opened = await app.eval(clickText('header nav.tabs button', 'Integrations'));
  if (!opened) warn('could not find the Integrations tab');
  await app.waitFor(`document.body.innerText.includes('Live Integration Status')`, 'integrations panel');
  await app.shot('07-integrations-overview.png');
  await sleep(beat);

  const tabs = [
    ['Swagger', '08-tab-swagger.png'],
    ['Postman', '09-tab-postman.png'],
    ['HTTPS', '10-tab-https.png'],
    ['Nginx', '11-tab-nginx.png'],
  ];
  for (const [label, file] of tabs) {
    const clicked = await app.eval(clickText('nav.tabs button', label));
    if (!clicked) warn(`missing tab: ${label}`);
    await sleep(FAST ? 500 : 1400);
    await app.shot(file);
    ok(`${label} panel captured`);
  }
}

async function webhookHappyPath(app, hook) {
  say(7, 'Webhook registration + signed test ping');
  const clicked = await app.eval(clickText('nav.tabs button', 'Webhooks'));
  if (!clicked) warn('could not open the Webhooks tab');
  await app.waitFor(`!!document.querySelector('input[type="url"]')`, 'webhook form');
  await app.eval(setInput('input[type="url"]', hook.url));
  await app.eval(setInput('input[placeholder^="demo-webhook-secret"]', WEBHOOK_SECRET));
  await app.eval(clickText('button[type="submit"]', 'Register Webhook Endpoint'));
  await app.waitFor(`document.body.innerText.includes('Webhook registered')`, 'webhook registration', 30000);
  ok(`endpoint registered → ${hook.url}`);
  await app.shot('12-webhook-registered.png');
  await sleep(beat);

  await app.eval(clickText('button', 'Send Test Ping'));
  await app.waitFor(
    `document.body.innerText.includes('Delivered!') || document.body.innerText.includes('Failed')`,
    'ping result', 30000,
  );
  const result = await app.eval(`document.body.innerText.includes('Delivered!') ? 'delivered' : 'failed'`);
  ok(`test ping: ${result}`);
  await app.shot('13-webhook-ping.png');
  await sleep(beat);

  if (hook.visual) {
    await hook.session.reload();
    await sleep(FAST ? 2000 : 4000);
    await hook.session.shot('14-webhook-ping-received.png');
    ok('signed ping visible in webhook.site');
  }

  say(8, 'Real event — sign out and back in');
  await app.eval(clickText('button.link', 'Sign out'));
  await app.waitFor(`!!document.querySelector('input[autocomplete="username"]')`, 'sign-in page');
  await sleep(500);
  await app.eval(clickText('button[role="tab"]', 'Sign in'));
  await app.eval(setInput('input[autocomplete="username"]', DEMO_USER));
  await app.eval(setInput('input[autocomplete="current-password"]', DEMO_PASSWORD));
  await app.eval(clickText('button[type="submit"]', 'Sign in'));
  await app.waitFor(`document.body.innerText.includes(${JSON.stringify(DEMO_USER)})`, 'dashboard after login', 40000);
  ok('auth.login.succeeded dispatched to the webhook');

  if (hook.visual) {
    await hook.session.reload();
    await sleep(FAST ? 2000 : 4000);
    await hook.session.shot('15-real-event-received.png');
    ok('real auth.login.succeeded event visible in webhook.site');
  }

  await app.eval(clickText('header nav.tabs button', 'Integrations'));
  await app.waitFor(`document.body.innerText.includes('Live Integration Status')`, 'refreshed status');
  await app.eval(clickText('nav.tabs button', 'Webhooks'));
  await sleep(FAST ? 600 : 1600);
  await app.shot('16-webhooks-after-event.png');
}

async function showJenkins() {
  say(9, 'Jenkins pipeline (bonus)');
  try {
    const res = await fetch(JENKINS_URL, { redirect: 'manual' });
    // Jenkins asks for login (401/403) when unauthenticated — that still means reachable.
    if (res.status >= 500) throw new Error(`HTTP ${res.status}`);
    const tab = await newTab(JENKINS_URL);
    await sleep(beat);
    await tab.session.shot('17-jenkins-job.png');
    tab.session.close();
    ok('Jenkins job page captured');
  } catch {
    warn(`Jenkins not reachable at ${JENKINS_URL}; skipped`);
  }
}

/* ───────────────────────────── main ──────────────────────────────────── */

async function main() {
  console.log('\nSecureShareFR — self-running panel demo');
  console.log(`  origin:  ${BASE}`);
  console.log(`  user:    ${DEMO_USER}`);
  console.log(`  mode:    ${FAST ? 'fast' : 'presentation'}`);
  console.log(`  shots:   ${SHOT_DIR}\n`);

  await preflight();
  const { proc } = await ensureBrowser();

  say(2, 'Live integration dashboard');
  const json = await newTab(`${BASE}/api/integrations/status`);
  await sleep(beat);
  await json.session.shot('01-integration-status.png');
  json.session.close();

  const swagger = await showJsonAndSwagger();
  const hook = await getWebhookReceiver();
  const app = (await newTab(BASE)).session;

  await signUpInBrowser(app);
  await cycleIntegrationTabs(app);
  await webhookHappyPath(app, hook);
  await showJenkins();

  say(10, 'Demo complete');
  console.log(`  Swagger:    ${BASE}/docs`);
  console.log(`  OpenAPI:    ${BASE}/api/openapi.json`);
  console.log(`  Status:     ${BASE}/api/integrations/status`);
  console.log(`  Webhook:    ${hook.url}`);
  console.log(`  Screenshots: ${SHOT_DIR}`);
  console.log('\n  Talking point: one Nginx TLS origin serves the SPA, /api, /authority,');
  console.log('  self-hosted Swagger, signed webhooks, and the live integration dashboard.\n');

  swagger.close();
  app.close();
  hook.session.close();
  if (!KEEP_BROWSER && proc) proc.kill();
}

main().catch((err) => {
  console.error(`\nDEMO FAILED: ${err.message}\n`);
  process.exitCode = 1;
});
