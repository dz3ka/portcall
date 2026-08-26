# A proxy that demands Basic authentication and never gets any.
#
# There is no official squid image, so this builds from the same pinned Alpine
# the DNS service uses rather than trusting a community tag. `curl` is installed
# for the healthcheck, which proves the 407 challenge itself rather than the
# process being alive.
FROM alpine:3.20.3

RUN apk add --no-cache squid apache2-utils curl

COPY squid.conf /etc/squid/squid.conf

# The password file is generated here, in the image, and is never committed.
# Portcall's whole trust story is that it does not read or send credentials
# (SPEC.md §4), and a repo that carries a checked-in password file - even a fake
# one - invites exactly the reading of the code that story cannot afford. This
# credential is also never used: the suite asserts that portcall reports the
# challenge and stops, so nothing in this repo knows or needs the value.
RUN htpasswd -bcB /etc/squid/passwords harness-user please-do-not-authenticate \
    && chown squid:squid /etc/squid/passwords \
    && chmod 600 /etc/squid/passwords \
    && install -d -o squid -g squid /var/cache/squid /var/log/squid

EXPOSE 3128
CMD ["squid", "--foreground", "-f", "/etc/squid/squid.conf"]
