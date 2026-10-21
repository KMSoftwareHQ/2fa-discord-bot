# better-sqlite3 is a native addon, which drives the shape of this file.
#
# The obvious layout — `npm ci --omit=dev` in the runtime stage — does not work
# here: the runtime stage has no python3/make/g++ to build the addon from
# source. Instead we build everything once, then `npm prune --omit=dev` to drop
# devDependencies while KEEPING the compiled .node binary, and copy the pruned
# node_modules across. Both stages use the same base image so the addon stays
# ABI-compatible.
FROM node:22.23.4-bookworm-slim AS build

WORKDIR /app

RUN apt-get update \
	&& apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
	&& rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src/ src/
RUN npm run build && npm prune --omit=dev


FROM node:22.23.4-bookworm-slim

WORKDIR /app

COPY --from=build /app/node_modules node_modules/
COPY --from=build /app/dist dist/
COPY package.json ./

# data/ holds vault.db and the heartbeat file; it is a volume at runtime.
RUN mkdir -p /app/data /app/config && chown -R node:node /app

USER node

# No EXPOSE: the bot connects out to Discord's gateway and serves no ports.

# Liveness alone would miss the failure that actually happens — a wedged
# gateway with the process still alive. The heartbeat only advances while the
# Discord client reports ready.
HEALTHCHECK --interval=60s --timeout=5s --start-period=45s --retries=3 \
	CMD node -e "const{statSync}=require('fs');const age=Date.now()-statSync('/app/data/heartbeat').mtimeMs;if(age>180000)process.exit(1)"

CMD ["node", "dist/index.js"]
