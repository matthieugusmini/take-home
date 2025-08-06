# --- Build Stage ---
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Copy go mod and sum first (for caching)
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o crypto-api 

# --- Final Stage ---
FROM scratch

WORKDIR /app

# Copy binary
COPY --from=builder /app/crypto-api .

EXPOSE 3000

# Start the API server
ENTRYPOINT ["./crypto-api"]
