package crypto_test

import (
	"encoding/hex"
	"testing"

	"github.com/matthieugusmini/take-home/crypto"
)

func TestHMACSigner_SignAndVerify(t *testing.T) {
	key := "supersecret"
	signer := crypto.NewHMACSigner(key)
	data := []byte("hello world")

	t.Run("Sign returns deterministic result", func(t *testing.T) {
		sig1, err := signer.Sign(data)
		if err != nil {
			t.Fatalf("Sign error: %v", err)
		}
		sig2, err := signer.Sign(data)
		if err != nil {
			t.Fatalf("Sign error: %v", err)
		}
		if sig1 != sig2 {
			t.Errorf("Signatures do not match: %s vs %s", sig1, sig2)
		}
	})

	t.Run("Verify accepts valid signature", func(t *testing.T) {
		sig, _ := signer.Sign(data)
		ok, err := signer.Verify(data, sig)
		if err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if !ok {
			t.Errorf("Verify failed for valid signature")
		}
	})

	t.Run("Verify rejects tampered data", func(t *testing.T) {
		sig, _ := signer.Sign(data)
		tamperedData := []byte("h3llo world")
		ok, err := signer.Verify(tamperedData, sig)
		if err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if ok {
			t.Errorf("Verify succeeded for tampered data")
		}
	})

	t.Run("Verify rejects tampered signature", func(t *testing.T) {
		sig, _ := signer.Sign(data)
		raw, _ := hex.DecodeString(sig)
		raw[len(raw)-1] ^= 0xFF // flip last byte
		tamperedSig := hex.EncodeToString(raw)
		ok, err := signer.Verify(data, tamperedSig)
		if err != nil {
			t.Fatalf("Verify error: %v", err)
		}
		if ok {
			t.Errorf("Verify succeeded for tampered signature")
		}
	})

	t.Run("Verify returns error on malformed signature", func(t *testing.T) {
		_, err := signer.Verify(data, "nothex!!!")
		if err == nil {
			t.Error("Expected error for malformed hex signature")
		}
	})

	t.Run("Signatures differ with different keys", func(t *testing.T) {
		other := crypto.NewHMACSigner("othersecret")
		sig1, _ := signer.Sign(data)
		sig2, _ := other.Sign(data)
		if sig1 == sig2 {
			t.Errorf("Signatures should differ for different keys")
		}
	})
}
