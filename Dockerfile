FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

ENV CGO_ENABLED=0
RUN go build -o dns-proxy ./cmd/dns-proxy

FROM alpine:3.20

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/dns-proxy .

VOLUME ["/app/data"]

EXPOSE 15353/udp
EXPOSE 15353/tcp
EXPOSE 1853/tcp
EXPOSE 1443/tcp
EXPOSE 8443/tcp

ENTRYPOINT ["./dns-proxy"]
