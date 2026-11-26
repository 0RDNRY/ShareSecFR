# syntax=docker/dockerfile:1.7
# Jenkins controller that can build/test this repo and drive the local Docker stack.
# NOTE: this image mounts the host Docker socket in compose, which is root-equivalent.
# Use it only on a trusted host / network.

FROM node:22-bookworm-slim AS node
FROM docker:27-cli AS dockercli

FROM jenkins/jenkins:lts-jdk21

USER root

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq openssh-client tar \
    && rm -rf /var/lib/apt/lists/*

# Node 22 for npm ci / tests / smoke (copied from the official image, no external script).
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules
# npm/npx are symlinks in the Node image; recreate them so relative requires resolve.
RUN ln -sf ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm; \
    ln -sf ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx; \
    npm --version

# Docker CLI from the official CLI image.
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

ARG TARGETARCH=amd64
ARG COMPOSE_VERSION=v2.29.7
ARG TRIVY_VERSION=0.76.2

# Compose v2 plugin + Trivy for image scanning.
# Compose uses x86_64/aarch64 asset names; Trivy uses 64bit/ARM64.
RUN set -eux; \
    mkdir -p /usr/local/lib/docker/cli-plugins; \
    case "${TARGETARCH}" in \
      amd64) compose_arch=x86_64; trivy_arch=64bit ;; \
      arm64) compose_arch=aarch64; trivy_arch=ARM64 ;; \
      *) compose_arch=x86_64; trivy_arch=64bit ;; \
    esac; \
    curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${compose_arch}" \
      -o /usr/local/lib/docker/cli-plugins/docker-compose; \
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz" \
      -o /tmp/trivy.tgz; \
    tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy; \
    rm -f /tmp/trivy.tgz; \
    trivy --version

# Plugins needed by the generated CasC job (Job DSL -> Declarative Pipeline).
RUN jenkins-plugin-cli --plugins \
      workflow-aggregator:latest \
      git:latest \
      job-dsl:latest \
      configuration-as-code:latest \
      credentials:latest \
      ssh-agent:latest \
      junit:latest \
      timestamper:latest \
      ws-cleanup:latest

COPY deploy/jenkins/entrypoint.sh /usr/local/bin/secureshare-entrypoint.sh
RUN chmod +x /usr/local/bin/secureshare-entrypoint.sh

ENTRYPOINT ["/usr/local/bin/secureshare-entrypoint.sh"]
# docker-compose.yml overrides this to root so Windows bind mounts are writable.
USER jenkins
