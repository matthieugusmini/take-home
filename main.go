package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	nethttp "net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/matthieugusmini/take-home/api"
	"github.com/matthieugusmini/take-home/crypto"
	"github.com/matthieugusmini/take-home/encoding"
	"github.com/matthieugusmini/take-home/http"
)

const (
	defaultServerShutdownTimeout   = 5 * time.Second
	defaultServerReadTimeout       = 15 * time.Second
	defaultServerReadHeaderTimeout = 15 * time.Second
)

func main() {
	ctx := context.Background()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cfg := loadConfigFromEnv()
	if err := initFlags(&cfg, args); err != nil {
		return fmt.Errorf("init flags: %w", err)
	}

	cipher, err := initCipher(cfg.EncryptionAlgorithm, cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("init cipher: %w", err)
	}
	signer := crypto.NewHMACSigner(cfg.EncryptionKey)
	cryptoService := http.NewCryptoAPI(cipher, signer)
	apiHandler := api.HandlerWithOptions(cryptoService, api.StdHTTPServerOptions{
		BaseURL: "/v1",
	})

	addr := net.JoinHostPort("", cfg.Port)
	server := &nethttp.Server{
		Addr:              addr,
		Handler:           apiHandler,
		ReadTimeout:       defaultServerReadTimeout,
		ReadHeaderTimeout: defaultServerReadHeaderTimeout,
	}

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	serverErr := make(chan error)
	go func() {
		log.Printf("Starting server on %s", addr)
		serverErr <- server.ListenAndServe()
		close(serverErr)
	}()

	select {
	case <-ctx.Done():
		log.Println("Shutting down...")
	case err := <-serverErr:
		if err != nil && !errors.Is(err, nethttp.ErrServerClosed) {
			return fmt.Errorf("HTTP server error: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), defaultServerShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("server forced to shutdown: %w", err)
	}

	log.Println("Server shutdown gracefully")
	return nil
}

func initCipher(alg, key string) (http.Cipher, error) {
	var (
		cipher http.Cipher
		err    error
	)
	switch alg {
	case "base64":
		cipher = encoding.NewBase64Codec()
	case "aesgcm":
		cipher, err = crypto.NewAESGCMCipher([]byte(key))
		if err != nil {
			return nil, fmt.Errorf("create AES-GCM cipher: %w", err)
		}
	// We use base64 codec as cipher as the assignment states that it should be the default.
	default:
		cipher = encoding.NewBase64Codec()
	}

	return cipher, nil
}

// Config represents the configuration of the Crypto API.
type Config struct {
	// Port the server listen on.
	Port string

	// EncryptionKey is the key used to encrypt JSON payloads.
	EncryptionKey string

	// EncryptionAlgorithm is the encryption algorithm used by
	// the /encrypt and /decrypt endpoint.
	EncryptionAlgorithm string
}

var DefaultConfig = Config{
	Port:                "3000",
	EncryptionKey:       "secret",
	EncryptionAlgorithm: "base64",
}

func loadConfigFromEnv() Config {
	cfg := DefaultConfig

	// For bigger project we could think of using a library like https://github.com/caarlos0/env
	// But for the sake of simplicity we will just get env var 1 by 1 manually.
	cfg.Port = getenv("CRYPTO_API_PORT", cfg.Port)
	cfg.EncryptionKey = getenv("CRYPTO_API_ENCRYPTION_KEY", cfg.EncryptionKey)
	cfg.EncryptionAlgorithm = getenv("CRYPTO_API_ENCRYPTION_ALGORITHM", cfg.EncryptionAlgorithm)
	return cfg
}

func initFlags(cfg *Config, args []string) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.StringVar(&cfg.Port, "port", cfg.Port, "Port to listen on")
	fs.StringVar(
		&cfg.EncryptionAlgorithm,
		"encrypt_alg",
		cfg.EncryptionAlgorithm,
		"Encryption algorithm used by the server (e.g. base64, aesgcm, etc.",
	)
	fs.StringVar(
		&cfg.EncryptionKey,
		"encrypt_key",
		cfg.EncryptionKey,
		"Key used by the server for encryption",
	)

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Crypto API Server")
		fmt.Fprintln(os.Stderr, "Usage:\n  crypto-api [flags]\n\nFlags:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil && !errors.Is(err, flag.ErrHelp) {
		return fmt.Errorf("parse flags: %w", err)
	}

	return nil
}

func getenv(key, fallback string) string {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	return v
}
