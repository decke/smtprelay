#* Create basic runtime
# Inspired by Dart runtime preparation.
FROM debian:sid-slim AS runtime_base

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
    ; \
    rm -rf /var/lib/apt/lists/*

# Create a minimal runtime environment for executing compiled go code
# with the smallest possible image size.
# usage: COPY --from=runtime_base /runtime/ /
# Uses hard links here to save space.
RUN set -eux; \
    case "$(dpkg --print-architecture)" in \
        amd64) \
            TRIPLET="x86_64-linux-gnu" ; \
            FILES="/lib64/ld-linux-x86-64.so.2" ;; \
        armhf) \
            TRIPLET="arm-linux-gnueabihf" ; \
            FILES="/lib/ld-linux-armhf.so.3 \
                /lib/arm-linux-gnueabihf/ld-linux-armhf.so.3";; \
        arm64) \
            TRIPLET="aarch64-linux-gnu" ; \
            FILES="/lib/ld-linux-aarch64.so.1 \
                /lib/aarch64-linux-gnu/ld-linux-aarch64.so.1" ;; \
        *) \
            echo "Unsupported architecture" ; \
            exit 5;; \
    esac; \
    FILES="$FILES \
        /etc/nsswitch.conf \
        /etc/ssl/certs \
        /usr/share/ca-certificates \
        /lib/$TRIPLET/libc.so.6 \
        /lib/$TRIPLET/libdl.so.2 \
        /lib/$TRIPLET/libm.so.6 \
        /lib/$TRIPLET/libnss_dns.so.2 \
        /lib/$TRIPLET/libpthread.so.0 \
        /lib/$TRIPLET/libresolv.so.2 \
        /lib/$TRIPLET/librt.so.1"; \
    for f in $FILES; do \
        dir=$(dirname "$f"); \
        mkdir -p "/runtime$dir"; \
        cp --archive --link --dereference --no-target-directory "$f" "/runtime$f"; \
    done

#* Build
FROM golang:latest AS build

# Create non-root user.
ENV USER=notroot
ENV UID=10001
RUN set -eux; adduser \
    --disabled-password \
    --gecos "" \
    --home "/nil" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    "${USER}"

WORKDIR /go/src/app

# Resolve app dependencies.
COPY go.mod ./
COPY go.sum ./
RUN set -eux; go mod download; go mod verify

# Copy app source code (except anything in .dockerignore).
COPY . .

# Build smtprelay.
RUN set -eux; go build -ldflags="-w -s" -o smtprelay

#* Deploy
# Build minimal serving image from compiled `smtprelay`
# and the pre-built runtime in the `/runtime/` directory of the base image.
FROM scratch

WORKDIR /

# Copy previously created user and gorup files to avoid running as root.
COPY --from=build /etc/passwd /etc/passwd
COPY --from=build /etc/group /etc/group

# Copy basic runtime.
COPY --from=runtime_base /runtime/ /

# Copy built binary and config.
COPY --from=build /go/src/app/smtprelay /smtprelay
COPY --from=build /go/src/app/smtprelay.ini /smtprelay.ini

# Run as unprivileged user.
USER notroot:notroot

# Expose listening port and run server.
#EXPOSE 25
CMD ["/smtprelay", "-config", "/smtprelay.ini"]
