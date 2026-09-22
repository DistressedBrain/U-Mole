# Native modules (argon2, better-sqlite3) are compiled in a builder stage so
# that no toolchain ships in the image that actually faces the internet.
FROM node:22-bookworm-slim AS builder

WORKDIR /app
RUN apt-get update \
 && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci --omit=dev


FROM node:22-bookworm-slim AS runtime

# tini reaps zombies and forwards SIGTERM, so the graceful shutdown in
# src/server.js actually runs.
RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY package.json ./
COPY src ./src
COPY public ./public
COPY scripts ./scripts

# The database lives on a mounted volume, not in the image layer.
RUN mkdir -p /data && chown node:node /data

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000 \
    DATABASE_PATH=/data/umole.sqlite3

# Never run as root. The process needs no privileges beyond writing /data.
USER node

EXPOSE 3000

# The sign-in page is the cheapest honest proof that the app and its database
# are both answering.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/login').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["node", "src/server.js"]
