# Built from a pinned Alpine rather than pulled from one of the community
# dnsmasq images: the zone below is the whole point of the service, and a
# third-party image that repoints its tag would silently change the answers
# this harness is supposed to plant. BusyBox also gives the healthcheck an
# `nslookup` to prove the planted answer with.
FROM alpine:3.20.3

# The base image is pinned; the apk version deliberately is not. Pinning a
# package revision inside a branch that still receives security bumps buys no
# reproducibility that the pinned base does not already give, and buys a build
# that breaks the day the revision is superseded.
RUN apk add --no-cache dnsmasq

COPY dnsmasq.conf /etc/dnsmasq.conf

EXPOSE 53/udp 53/tcp
# `--keep-in-foreground`, no daemonising: the container *is* the process.
CMD ["dnsmasq", "--keep-in-foreground", "--log-facility=-", "--conf-file=/etc/dnsmasq.conf"]
