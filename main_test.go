package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/matthieugusmini/take-home/api"
)

func TestDecrypt(t *testing.T) {
	addr := startTestServer(t)

	testCases := []struct {
		name     string
		input    []byte
		expected map[string]any
	}{
		{
			name: "mixed encoded and non-encoded fields",
			input: []byte(`{
				"name": "Sm9obiBEb2U=",
				"age": "MzA=",
				"contact": "eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9",
				"birth_date": "1998-11-19"
			}`),
			expected: map[string]any{
				"name": "John Doe",
				"age":  float64(30),
				"contact": map[string]any{
					"email": "john@example.com",
					"phone": "123-456-7890",
				},
				"birth_date": "1998-11-19",
			},
		},
		{
			name: "all encoded",
			input: []byte(`{
				"name": "Sm9obiBEb2U=",
				"age": "MzA=",
				"contact": "eyJlbWFpbCI6ImpvaG5AZXhhbXBsZS5jb20iLCJwaG9uZSI6IjEyMy00NTYtNzg5MCJ9"
			}`),
			expected: map[string]any{
				"name": "John Doe",
				"age":  float64(30),
				"contact": map[string]any{
					"email": "john@example.com",
					"phone": "123-456-7890",
				},
			},
		},
		{
			name: "all unencoded primitives",
			input: []byte(`{
				"foo": 1,
				"bar": 2.2,
				"baz": "Hello world!"
			}`),
			expected: map[string]any{
				"foo": float64(1),
				"bar": 2.2,
				"baz": "Hello world!",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := http.Post(
				"http://"+addr+"/v1/decrypt",
				"application/json",
				bytes.NewReader(tc.input),
			)
			if err != nil {
				t.Fatalf("POST /decrypt: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("POST /decrypt: status=%d, want=200, body=%s", resp.StatusCode, body)
			}

			var got map[string]any
			if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
				t.Fatalf("Decode response: %v", err)
			}
			if !reflect.DeepEqual(got, tc.expected) {
				t.Errorf("Response mismatch.\nGot:  %#v\nWant: %#v", got, tc.expected)
			}
		})
	}
}

func TestEncryptDecryptFlow(t *testing.T) {
	addr := startTestServer(t)

	// Encrypt
	input := []byte(`{
  "name": "John Doe",
  "age": 30,
  "contact": {
    "email": "john@example.com",
    "phone": "123-456-7890"
  }
}`)
	resp, err := http.Post(
		"http://"+addr+"/v1/encrypt",
		"application/json",
		bytes.NewBuffer(input),
	)
	if err != nil {
		t.Fatalf("POST /encrypt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /encrypt: status=%d, want=200, body=%s", resp.StatusCode, body)
	}
	encrypted, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Reading /encrypt response: %v", err)
	}

	// Ensure that /decrypt returns the original payload.
	resp, err = http.Post(
		"http://"+addr+"/v1/decrypt",
		"application/json",
		bytes.NewBuffer(encrypted),
	)
	if err != nil {
		t.Fatalf("POST /decrypt: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /decrypt: status=%d, want=200, body=%s", resp.StatusCode, body)
	}

	var out any
	err = json.NewDecoder(resp.Body).Decode(&out)
	if err != nil {
		t.Fatalf("Reading /decrypt response: %v", err)
	}

	var in any
	err = json.Unmarshal(input, &in)
	if err != nil {
		t.Fatalf("Deserialize input: %v", err)
	}

	if !reflect.DeepEqual(out, in) {
		t.Errorf("Decrypted = %v, got = %v", out, in)
	}
}

func TestSignVerifyFlow(t *testing.T) {
	addr := startTestServer(t)

	in := []byte(`{"message":"Hello World","timestamp":1616161616}`)
	resp, err := http.Post("http://"+addr+"/v1/sign", "application/json", bytes.NewReader(in))
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /sign: status=%d, want=200, body=%s", resp.StatusCode, body)
	}
	var out api.SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("Decode /sign response: %v", err)
	}
	if out.Signature == "" {
		t.Fatal("Empty signature from /sign")
	}

	testCases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "same payload",
			payload: []byte(`{"message":"Hello World","timestamp":1616161616}`),
		},
		// Ensure the order of the keys does not affect the signature.
		{
			name:    "different key order",
			payload: []byte(`{"timestamp":1616161616,"message":"Hello World"}`),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Construct the payload manually instead of using `json.Marshal` as it would
			// change the key order.
			payload := []byte(
				`{"signature":"` + out.Signature + `","data":` + string(tc.payload) + `}`,
			)
			resp, err := http.Post(
				"http://"+addr+"/v1/verify",
				"application/json",
				bytes.NewReader(payload),
			)
			if err != nil {
				t.Fatalf("POST /verify: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusNoContent {
				body, _ := io.ReadAll(resp.Body)
				t.Errorf("Verify failed: status=%d, want=204, body=%s", resp.StatusCode, body)
			}
		})
	}
}

func TestSignVerifyTampered(t *testing.T) {
	addr := startTestServer(t)

	payload := []byte(`{"message":"Hello World","timestamp":1616161616}`)
	resp, err := http.Post("http://"+addr+"/v1/sign", "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("POST /sign: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("POST /sign: status=%d, want=200, body=%s", resp.StatusCode, body)
	}

	var out api.SignResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("Decode /sign response: %v", err)
	}

	// Message changed
	tamperedPayload := []byte(`{"message":"Goodbye World","timestamp":1616161616}`)
	verify := []byte(`{"signature":"` + out.Signature + `","data":` + string(tamperedPayload) + `}`)
	resp, err = http.Post("http://"+addr+"/v1/verify", "application/json", bytes.NewReader(verify))
	if err != nil {
		t.Fatalf("POST /verify (tampered): %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(resp.Body)
		t.Errorf("POST /verify: status=%d, want=400, body=%s", resp.StatusCode, body)
	}
}

func startTestServer(t *testing.T) string {
	t.Helper()

	// // Listen on a random OS-assigned port so we can run the test in parallel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close() // IMPORTANT: free the port!
	_, port, _ := net.SplitHostPort(addr)

	go func() {
		if err := run(t.Context(), []string{"-port", port}); err != nil &&
			!errors.Is(err, http.ErrServerClosed) {
			t.Logf("Server exited: %v", err)
		}
	}()
	waitForServer(t, addr)

	return addr
}

func waitForServer(t *testing.T, addr string) {
	t.Helper()

	for i := range 10 {
		t.Logf("Attempting to dial with %s (attempt %d)", addr, i)

		conn, err := net.Dial("tcp", addr)
		if err == nil {
			conn.Close()
			return
		}

		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("Server could not start")
}
