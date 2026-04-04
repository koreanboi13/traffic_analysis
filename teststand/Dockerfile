FROM golang:1.22-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o teststand .

FROM alpine:latest

WORKDIR /app

COPY --from=builder /app/teststand .
COPY --from=builder /app/templates ./templates

EXPOSE 8888

CMD ["./teststand"]
