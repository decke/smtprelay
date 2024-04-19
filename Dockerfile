FROM golang:1.22-alpine AS build

WORKDIR /app

COPY go.mod ./
COPY go.sum ./

RUN go mod download

COPY *.go ./

RUN go build -o smtprelay

FROM golang:1.22-alpine

WORKDIR /app

COPY --from=build /app/smtprelay ./

EXPOSE 25

ENTRYPOINT ["./smtprelay"]