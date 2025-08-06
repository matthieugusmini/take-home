# Crypto API

A minimal Go HTTP API for encryption (default: Base64 encoding/decoding), HMAC signing, and verification of JSON payloads.

## Features

- **/encrypt**: POST any JSON to receive an object with all depth-1 properties Base64 encoded.
- **/decrypt**: POST a previously encoded JSON to decode depth-1 fields, restoring the original JSON.
- **/sign**: POST any JSON and get an HMAC signature (deterministic for logically equivalent objects).
- **/verify**: POST `{signature, data}` to verify its HMAC; succeeds (204) or fails (400).

See the [OpenAPI spec](api/openapi.yaml) for detailed schemas, input/output, and example payloads. You can also use an [online editor](https://editor.swagger.io/) for a more human readable documentation.

## Quick Start

### Requirements
- [Go 1.24+](https://golang.org/dl/)

### Building

```bash
make build   # builds a static binary (crypto-api)
```

### Running Locally

```bash
make run     # runs main.go
# or
./crypto-api # after build (default port 3000)
```

### Running via Docker

```bash
docker build -t crypto-api .
docker run -p 3000:3000 crypto-api
```

## Configuration

Configuration can be set via CLI flags or environment variables. **Flags always take priority over environment variables**. The following options are available:

| Option         | CLI Flag      | Environment Variable         | Default  | Description                                       |
|----------------|--------------|------------------------------|----------|---------------------------------------------------|
| Port           | `-port`      | `CRYPTO_API_PORT`            | `3000`   | Port the server listens on                        |
| Encryption Key | `-encrypt_key`       | `CRYPTO_API_ENCRYPTION_KEY`  | `secret` | Key used for encryption by the server |
| Algorithm      | `-encrypt_alg`       | `CRYPTO_API_ENCRYPTION_ALGORITHM`             | `base64` | Algorithm to use: "base64" (default), "aesgcm", etc. |


## Development

- **Build:** `make build`
- **Run:** `make run`
- **Test:** `make test` or `go test ./...`
- **Lint:** `golangci-lint run`
- **Generate API code:** `make generate`

## Repo Layout

```bash
.
├── api/             # OpenAPI spec & generated API code 
├── crypto/          # HMAC signing/verification implementations
├── encoding/        # Base64 encode/decode logic
├── http/            # HTTP handlers and service logic
├── main.go          # Entrypoint 
├── main_test.go     # Integration tests
├── Dockerfile
├── Makefile
├── go.mod
├── go.sum
```

## Notes
- All cryptography is for demonstration only. For production use, replace implementations with secure cryptographic algorithms and manage secrets appropriately.
