# Portcall itself, running *inside* the hostile network.
#
# The build context is the repo root, so the image is the working tree rather
# than a published artifact - the suite is meant to fail on the code being
# changed, not on the last release. The Node tag is pinned at or above the
# `engines.node` floor (>=22.18.0), which is where type stripping became the
# default and therefore where `node src/cli/index.ts` starts working at all.
FROM node:22.18.0-bookworm-slim

WORKDIR /app

# Dependencies first so an edit to `src/` or `test/` does not re-resolve the
# tree. `npm ci` and not `npm install`: the lockfile is the input.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Overridden by docker-compose.yml; spelled out here so `docker run` on this
# image alone does the same thing.
CMD ["npm", "run", "test:integration"]
