#!/bin/sh
# A two-certificate chain: a self-signed root, and a leaf carrying the names the
# harness profile asks for.
#
# The root is served *with* the leaf. That matters to what portcall concludes:
# `classifyRoot` calls an anchor `private` on `self-signed-anchor-not-bundled`
# when the peer presents it, and only falls back to `indeterminate` when the
# anchor is missing (ADR-0021 - portcall verifies no signatures, so an absent
# anchor is a question it refuses to answer). Serving the full chain is also
# what a competently configured endpoint does.
set -eu

PKI=/etc/nginx/pki
mkdir -p "$PKI"

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 3650 \
  -keyout "$PKI/root.key" -out "$PKI/root.crt" \
  -subj '/O=Portcall Harness/CN=Portcall Harness Origin Root' \
  -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'

openssl req -newkey rsa:2048 -nodes -sha256 \
  -keyout "$PKI/leaf.key" -out "$PKI/leaf.csr" \
  -subj '/O=Portcall Harness/CN=api.anthropic.com'

cat > "$PKI/leaf.ext" <<'EXT'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:api.anthropic.com,DNS:registry.npmjs.org,DNS:origin
EXT

openssl x509 -req -in "$PKI/leaf.csr" -sha256 -days 825 \
  -CA "$PKI/root.crt" -CAkey "$PKI/root.key" -CAcreateserial \
  -extfile "$PKI/leaf.ext" -out "$PKI/leaf.crt"

cat "$PKI/leaf.crt" "$PKI/root.crt" > "$PKI/chain.crt"

# The signing key is not needed at runtime and the CSR never was.
rm -f "$PKI/root.key" "$PKI/leaf.csr" "$PKI/leaf.ext" "$PKI/root.srl"
chmod 644 "$PKI/leaf.key"
