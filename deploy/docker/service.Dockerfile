# syntax=docker/dockerfile:1.7
# Builds either backend service:  docker build --build-arg SERVICE=api|authority -f deploy/docker/service.Dockerfile .
ARG NODE_IMAGE=node:22-alpine

FROM ${NODE_IMAGE} AS deps
ARG SERVICE
WORKDIR /app
# Only manifests first, so dependency layers are cached between code changes.
COPY package.json package-lock.json ./
COPY packages/crypto/package.json packages/crypto/
COPY packages/server-common/package.json packages/server-common/
COPY services/api/package.json services/api/
COPY services/authority/package.json services/authority/
COPY client/package.json client/
RUN test -n "$SERVICE" \
 && npm ci --omit=dev --workspace "services/${SERVICE}" --no-audit --no-fund \
 && npm cache clean --force

FROM ${NODE_IMAGE} AS runtime
ARG SERVICE
ENV NODE_ENV=production \
    SERVICE=${SERVICE}
WORKDIR /app
COPY --from=deps --chown=root:root /app/node_modules ./node_modules
COPY --chown=root:root package.json ./
COPY --chown=root:root packages/crypto packages/crypto
COPY --chown=root:root packages/server-common packages/server-common
COPY --chown=root:root services/${SERVICE} services/${SERVICE}
RUN rm -rf services/${SERVICE}/test \
 && mkdir -p /data/blobs && chown node:node /data/blobs
# Code is owned by root and read-only to the runtime user.
USER node
EXPOSE 4000 7000 7001
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "const p=process.env.SERVICE==='api'?'4000/api':(process.env.AUTHORITY_PORT||7000)+'/authority';fetch('http://127.0.0.1:'+p+'/health').then(r=>process.exit(r.ok?0:1),()=>process.exit(1))"
CMD ["sh", "-c", "exec node services/${SERVICE}/src/index.js"]
