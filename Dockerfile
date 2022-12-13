FROM golang:1.19 AS builder

WORKDIR /app

COPY . .

RUN go build main.go

# Stage 2

FROM debian:buster-slim

WORKDIR /app

COPY --from=builder /app/main .

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

ENTRYPOINT ["./main"]