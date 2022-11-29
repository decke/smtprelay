FROM golang:1.18-stretch as build
ARG GOARCH="amd64"
COPY . /build_dir
WORKDIR /build_dir
RUN go clean && go build

FROM alpine:latest
ARG HTTPS_PROXY=""
ARG HTTP_PROXY=""
RUN https_proxy="${HTTPS_PROXY}" \
  http_proxy="${HTTP_PROXY}" \
  apk update \
  && apk add ca-certificates \
  && rm -rf /var/cache/apk/* \
  && update-ca-certificates

COPY --from=build /build_dir/smtprelay /usr/local/bin/smtprelay
# users need to mount config file at /usr/local/smtprelay.ini
ENTRYPOINT ["/usr/local/bin/smtprelay"]
