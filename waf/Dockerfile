FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o waf ./cmd/waf

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/waf .
COPY --from=builder /app/config.yaml .
COPY --from=builder /app/rules.yaml .

EXPOSE 8080

CMD ["./waf"]
