# Portcall itself, running *inside* the hostile network.
#
# The build context is the repo root, so the image is the working tree rather
# than a published artifact - the suite is meant to fail on the code being
# changed, not on the last release. The Node tag is pinned at or above the
# `engines.node` floor (>=22.18.0), which is where type stripping became the
# default and therefore where `node src/cli/index.ts` starts working at all.
FROM node:22.18.0-bookworm-slim

WORKDIR /app

# The slim image ships no OS trust store at all - none of the six paths
# `src/net/os-truststore.ts` reads exist - so the truststore probe's OS read
# comes back empty and it suppresses its whole runtime cross-check. Without a
# store there is nothing for the mitmproxy root to be planted *in*, and M4's
# headline behaviour (a root the machine trusts and Node does not) cannot be
# provoked live. `apt-get update` in the same layer because the slim image also
# ships no package lists, and before the dependency copy so an edit to `src/`
# does not re-pay it. Measured: +8 MB, ~5 s, once per image build.
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Dependencies first so an edit to `src/` or `test/` does not re-resolve the
# tree. `npm ci` and not `npm install`: the lockfile is the input.
COPY package.json package-lock.json ./
RUN npm ci

COPY . .

# Installs the run-mounted mitmproxy root into this container's own OS trust
# store before handing off to the command (ADR-0041). Already in the image via
# `COPY . .` above; invoked through `sh` because the repo commits its scripts
# mode 644 and the exec bit does not survive - the same reason
# `origin/Dockerfile` runs `sh /generate-pki.sh`.
ENTRYPOINT ["sh", "/app/test/harness/portcall-entrypoint.sh"]

# Overridden by docker-compose.yml; spelled out here so `docker run` on this
# image alone does the same thing - the entrypoint above is a no-op unless
# PORTCALL_HARNESS=1, so the image alone still reaches this CMD and fails with
# `requireHarness()`'s own message.
CMD ["npm", "run", "test:integration"]
