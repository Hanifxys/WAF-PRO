FROM golang:alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o management-api .

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/management-api .
EXPOSE 8082
CMD ["./management-api"]
