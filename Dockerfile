FROM --platform=$BUILDPLATFORM debian:bullseye-slim

ARG TARGETPLATFORM
ARG BUILDPLATFORM
ARG REPOSITORY_OWNER=decke/smtprelay
ARG
RUN set -eux; \
    apt-get update ; \
    apt-get install -y \
      ca-certificates \
      coreutils \
      curl \
      netcat-openbsd ; \
    apt-get clean ; \
    rm -rf /var/lib/apt/lists/*
ARG


https://github.com/decke/smtprelay/releases/download/v1.8.0/smtprelay-v1.8.0-linux-arm64.tar.gz.md5
ENV RELEASE_BASE_URL=https://github.com/decke/smtprelay/releases/download/v1.8.0/smtprelay-v1.8.0-linux-arm64.tar.gz.md5

  REALSE=${TARGETPLATFORM/\//-}
RUN set -eux; \


$TARGETPLATFORM
RUN echo "I am running on $BUILDPLATFORM, building for $TARGETPLATFORM" > /log
