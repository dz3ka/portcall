#!/bin/sh
# Plants the fifth hostile condition: a root the *machine* trusts and the
# runtime does not.
#
# mitmproxy generates its root CA at run time into the `mitm-ca` volume, so
# container start is the earliest moment those bytes exist - a Dockerfile
# `COPY` cannot see them, which is why this is an ENTRYPOINT and not a build
# step (ADR-0041).
#
# Runs as PID 1 of the ephemeral harness container only. Never on a host: no
# npm script invokes it and it exists only inside the image.
set -eu

# Gated on PORTCALL_HARNESS so `docker run` on the image alone still behaves as
# portcall.Dockerfile promises - it reaches the CMD and fails with
# requireHarness()'s own message naming the three-command fix, rather than dying
# here with a less useful one.
if [ "${PORTCALL_HARNESS:-}" = "1" ]; then
  : "${PORTCALL_HARNESS_MITM_CA:?PORTCALL_HARNESS_MITM_CA is unset; see test/harness/docker-compose.yml}"
  [ -r "$PORTCALL_HARNESS_MITM_CA" ] || { echo "mitm CA not readable: $PORTCALL_HARNESS_MITM_CA" >&2; exit 1; }

  # The .crt suffix is load-bearing: update-ca-certificates ignores every other
  # extension, and mitmproxy's file is named .pem.
  install -m 0644 "$PORTCALL_HARNESS_MITM_CA" /usr/local/share/ca-certificates/portcall-harness-mitm.crt
  # Prints `rehash: warning: skipping ca-certificates.crt, it does not contain
  # exactly one certificate or CRL` on stderr every run: c_rehash works per
  # certificate and the bundle holds many. Expected, not a failure. stderr stays
  # open deliberately - it is the only channel a real failure has before the
  # openssl gate below, since update-ca-certificates exits 0 either way.
  update-ca-certificates > /dev/null

  # Proves the planted condition, not the step. update-ca-certificates exits 0
  # even when it ignores a file, so its exit code cannot catch a silently
  # skipped root; verifying against the store the OS itself assembled can.
  openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt "$PORTCALL_HARNESS_MITM_CA" > /dev/null
fi

exec "$@"
