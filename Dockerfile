FROM golang:1.26-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -buildvcs=false -o /out/caddy ./cmd/caddy

FROM caddy:2.11.9-alpine
COPY --from=builder /out/caddy /usr/bin/caddy
COPY examples/Caddyfile /etc/caddy/Caddyfile
EXPOSE 9987/udp
