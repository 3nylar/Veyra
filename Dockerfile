# Veyra watch-only API.
#
# ⚠️ This image is for WATCH-ONLY deployment. It is built to run with an xpub
# and no seed. Setting VEYRA_MNEMONIC would make it custodial — the entrypoint
# refuses to start in that configuration, because a container image is exactly
# the wrong place for a private key: it ends up in a registry, in layer caches,
# and in anyone's `docker history`.

FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
# `npm ci` installs exactly the lockfile. `npm install` may resolve different
# versions, which for cryptographic dependencies is a supply-chain risk.
RUN npm ci
COPY . .
RUN npx tsc --noEmit && npx vitest run tests/cryptography/ tests/security/ --reporter=basic

FROM node:22-alpine
WORKDIR /app

# Run as a non-root user. If the process is compromised, the attacker inherits
# an account that owns nothing.
RUN addgroup -S veyra && adduser -S veyra -G veyra

COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force
COPY --chown=veyra:veyra core ./core
COPY --chown=veyra:veyra api ./api
COPY --chown=veyra:veyra tsconfig.json ./

USER veyra
ENV NODE_ENV=production
ENV VEYRA_HOST=0.0.0.0
EXPOSE 3000

# A failing health check restarts the container rather than leaving a process
# that is listening but not serving.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.VEYRA_PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["npx", "tsx", "api/src/index.ts"]
