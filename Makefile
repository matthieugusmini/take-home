BINARY=crypto-api

# The default goal is to build.
all: build

## build: Build the binary
.PHONY: build
build:
	go build -o $(BINARY) .

## clean: Remove build artifacts
.PHONY: clean
clean:
	rm -f $(BINARY)

## run: Build and run the API server
.PHONY: run
run:
	go run main.go

## test: Run tests
.PHONY: test
test:
	go test -v -race ./...

## generate: Generate the server code
.PHONY: generate
generate:
	go generate ./...

## help: Print this help message
.PHONY: help
help:
	@echo 'Usage:'
	@sed -n 's/^##//p' ${MAKEFILE_LIST} | column -t -s ':' |  sed -e 's/^/ /'
