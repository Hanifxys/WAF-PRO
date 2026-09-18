FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY main.go .
RUN go build -o origin-mock main.go

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/origin-mock .

EXPOSE 8081
CMD ["./origin-mock"]
