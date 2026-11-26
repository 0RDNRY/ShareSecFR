import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

/**
 * Locate the locally installed swagger-ui-dist package. Keeping the assets on
 * this origin is what makes /docs work under the application's strict CSP.
 */
export function swaggerAssetsPath() {
  try {
    return require('swagger-ui-dist').getAbsoluteFSPath();
  } catch {
    return null;
  }
}

/** CSP for /docs only: local scripts/styles, no inline scripts, no CDNs. */
export const DOCS_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "connect-src 'self'",
  "font-src 'self' data:",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join('; ');

export function docsHtml() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecureShareFR API Docs</title>
  <link rel="stylesheet" href="/docs/assets/swagger-ui.css">
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="/docs/assets/swagger-ui-bundle.js"></script>
  <script src="/docs/assets/swagger-ui-standalone-preset.js"></script>
  <script src="/docs/bootstrap.js"></script>
</body>
</html>`;
}

/** External bootstrap script — no inline JS, therefore compatible with CSP. */
export function swaggerBootstrapJs() {
  return `window.addEventListener('DOMContentLoaded', function () {
  if (typeof SwaggerUIBundle !== 'function') {
    document.getElementById('swagger-ui').textContent = 'Swagger UI assets failed to load.';
    return;
  }
  window.ui = SwaggerUIBundle({
    url: '/api/openapi.json',
    dom_id: '#swagger-ui',
    deepLinking: true,
    displayRequestDuration: true,
    tryItOutEnabled: true,
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
    plugins: [SwaggerUIBundle.plugins.DownloadUrl],
    layout: 'StandaloneLayout',
    requestInterceptor: function (req) {
      if (!/^(GET|HEAD|OPTIONS)$/i.test(req.method || '')) {
        req.headers['X-SecureShare-CSRF'] = '1';
      }
      return req;
    }
  });
});`;
}
