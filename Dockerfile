FROM golang:1.14.10-alpine3.12@sha256:0e691cd2b47d20f0c5b4ce55385b9d02fb9c66b78dcbaa4ce5a56d41b1c16491

WORKDIR /workspace/source

COPY go.* ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -ldflags '-w -extldflags "-static"'

FROM gcr.io/distroless/base:nonroot@sha256:2261b65122adb19da72084617c03a9084c24b33fcd90edd74739f0fd631f0f60

COPY --from=0 /workspace/source/smtprelay /usr/local/bin/smtprelay

ENTRYPOINT [ "smtprelay", "-logfile=/proc/self/fd/1" ]
CMD [ "--help" ]
EXPOSE 25
