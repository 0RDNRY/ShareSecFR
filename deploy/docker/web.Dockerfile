# syntax=docker/dockerfile:1.7
# Static web client served by Caddy, which also terminates TLS and reverse-proxies the APIs.
FROM node:22-alpine AS build
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

FROM caddy:2-alpine
COPY deploy/caddy/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/client/dist /srv
RUN caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
