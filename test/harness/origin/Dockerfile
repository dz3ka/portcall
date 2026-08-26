# The endpoint the profile names, serving a chain rooted in a CA that no runtime
# ships. The key material is generated at *image build* time rather than by an
# init container, for two reasons: a one-shot service makes `docker compose up
# --wait` ambiguous (it waits for containers to be running, and a container that
# has correctly exited is neither running nor unhealthy), and a chain that is
# fixed for the life of the image is a chain the suite can reason about.
#
# Nothing here is a secret. The private key exists for the length of a test run
# on a network that only exists for the length of a test run.
FROM nginx:1.27.3-alpine

RUN apk add --no-cache openssl

COPY generate-pki.sh /generate-pki.sh
RUN sh /generate-pki.sh && rm /generate-pki.sh

COPY nginx.conf /etc/nginx/conf.d/default.conf
