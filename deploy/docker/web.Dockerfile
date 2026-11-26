# syntax=docker/dockerfile:1.7
# Web container: Nginx reverse proxy + TLS termination + React static app
ARG NODE_IMAGE=node:22-alpine
ARG NGINX_IMAGE=nginx:1.27-alpine

# ── Stage 1: Build the React client ─────────────────────────────────────────
FROM ${NODE_IMAGE} AS build
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/server-common/package.json packages/server-common/
COPY services/api/package.json services/api/
COPY services/authority/package.json services/authority/
COPY client/package.json client/
RUN npm ci --workspace client --no-audit --no-fund
COPY packages/crypto packages/crypto
COPY client client
RUN npm run build -w client

# ── Stage 2: Nginx + TLS ─────────────────────────────────────────────────────
FROM ${NGINX_IMAGE} AS runtime
# Copy Nginx config
COPY deploy/nginx/nginx.conf /etc/nginx/nginx.conf
# Copy built React app
COPY --from=build /app/client/dist /usr/share/nginx/html
# TLS certs directory (mount via Docker volume or bind mount in production)
RUN mkdir -p /etc/nginx/certs

EXPOSE 80 443
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -qO- --no-check-certificate https://127.0.0.1:443/api/health > /dev/null 2>&1 || exit 1

CMD ["nginx", "-g", "daemon off;"]
