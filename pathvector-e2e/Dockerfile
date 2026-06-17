# GoBGP image for pathvector-e2e tests.
#
# Both gobgpd and pathvectord run as containers on the same Docker bridge
# network, so BGP traffic is container-to-container and never touches the
# macOS Docker Desktop TCP proxy.  Only pathvectord's gRPC management port
# is exposed to the host (for PathvectorClient).
#
# TARGETARCH is passed by `just e2e` so the correct linux binary is fetched.
# Supported values: amd64, arm64.

FROM alpine:3.19

ARG GOBGP_VERSION=4.6.0
ARG TARGETARCH

RUN apk add --no-cache wget \
    && wget -q \
       "https://github.com/osrg/gobgp/releases/download/v${GOBGP_VERSION}/gobgp_${GOBGP_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && tar xf "gobgp_${GOBGP_VERSION}_linux_${TARGETARCH}.tar.gz" \
    && mv gobgpd gobgp /usr/local/bin/ \
    && rm -f "gobgp_${GOBGP_VERSION}_linux_${TARGETARCH}.tar.gz"

# 179  — BGP (container-to-container, never mapped to host)
# 50051 — gRPC management API (accessed via `docker exec`, not host mapping)
EXPOSE 179 50051

# Use gobgp CLI to verify the gRPC API is accepting connections.
HEALTHCHECK --interval=1s --timeout=3s --retries=30 \
    CMD gobgp global >/dev/null 2>&1 || exit 1

CMD ["gobgpd", "-f", "/etc/gobgp/gobgpd.conf", "--pprof-disable"]
