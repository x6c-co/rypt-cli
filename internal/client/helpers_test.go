package client

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	// testSecret is the secret part of testToken. Neither may ever appear
	// in an error string.
	testSecret = "S3cr3tT0k3nMustN3v3rL3akQwErTy12"
	testToken  = "ry_Tst0Pfx9_" + testSecret
	testKeyID  = "6f1c2b3a-9d8e-4f70-a1b2-c3d4e5f60718"
	testUA     = "rypt-test/1.0"
	// leakMarker is put into server bodies that must not be echoed.
	leakMarker = "LEAKMARKER"
)

func noBackoff(int) time.Duration { return 0 }

// newTestClient returns a client for base that never sleeps between retries.
func newTestClient(t *testing.T, base string) *Client {
	t.Helper()
	c, err := New(Options{BaseURL: base, Token: testToken, UserAgent: testUA, Backoff: noBackoff})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// asError returns err as an *Error, failing the test if it is not one.
func asError(t *testing.T, err error) *Error {
	t.Helper()
	if err == nil {
		t.Fatal("got nil error, want *Error")
	}
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("got %T (%v), want *Error", err, err)
	}
	return e
}

// assertNoSecrets fails if err's text holds the token or any of the given
// strings.
func assertNoSecrets(t *testing.T, err error, secrets ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, text := range []string{err.Error(), fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err)} {
		for _, s := range append([]string{testToken, testSecret}, secrets...) {
			if s != "" && strings.Contains(text, s) {
				t.Errorf("error text %q contains a secret (%q)", text, s)
			}
		}
	}
}

// envelope returns an API error body.
func envelope(code, message, requestID string) string {
	b, _ := json.Marshal(map[string]string{"error": code, "message": message, "request_id": requestID})
	return string(b)
}

// fixedDEK is the DEK the scripted servers return.
var fixedDEK = []byte("0123456789abcdef0123456789abcdef")

// step answers one request of a scriptServer. n is the 1-based request
// number.
type step func(w http.ResponseWriter, r *http.Request, n int)

// scriptServer answers request n with steps[n-1]; the last step repeats.
type scriptServer struct {
	*httptest.Server
	hits    atomic.Int32
	arrived chan struct{} // receives once per request, if there is room

	mu       sync.Mutex
	requests []recorded // every request, in order of arrival
}

func newScriptServer(t *testing.T, steps ...step) *scriptServer {
	t.Helper()
	s := &scriptServer{arrived: make(chan struct{}, 16)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, recorded{
			method:      r.Method,
			escapedPath: r.URL.EscapedPath(),
			rawQuery:    r.URL.RawQuery,
			header:      r.Header.Clone(),
			body:        body,
		})
		s.mu.Unlock()
		n := int(s.hits.Add(1))
		select {
		case s.arrived <- struct{}{}:
		default:
		}
		steps[min(n, len(steps))-1](w, r, n)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *scriptServer) count() int { return int(s.hits.Load()) }

func (s *scriptServer) recorded() []recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recorded(nil), s.requests...)
}

// respond writes status and body with a JSON content type and an
// x-request-id header of "hdr-<n>".
func respond(status int, body string) step {
	return func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Request-Id", fmt.Sprintf("hdr-%d", n))
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

// okWrap answers a wrap or unwrap with fixedDEK.
func okWrap() step {
	b, _ := json.Marshal(map[string]any{"dek": fixedDEK, "wrapped": "CiQAwrapped"})
	return respond(http.StatusOK, string(b))
}

// hangup closes the connection without answering.
func hangup() step {
	return func(w http.ResponseWriter, r *http.Request, n int) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		conn.Close()
	}
}

// cutBody sends a 200 whose Content-Length promises more than is sent, and
// closes the connection.
func cutBody() step {
	return func(w http.ResponseWriter, r *http.Request, n int) {
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			panic(err)
		}
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{\"dek\":\"MDEy")
		_ = buf.Flush()
		conn.Close()
	}
}

// stall waits until the client goes away.
func stall() step {
	return func(w http.ResponseWriter, r *http.Request, n int) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
		}
	}
}

// recorded is a request seen by mockServer.
type recorded struct {
	method      string
	escapedPath string
	rawQuery    string
	header      http.Header
	body        []byte
}

// mockServer implements wrap and unwrap with an in-memory AES-256-GCM key,
// following the behavior recorded in docs/api-notes.md.
type mockServer struct {
	*httptest.Server
	t      *testing.T
	prefix string
	aead   cipher.AEAD

	mu       sync.Mutex
	requests []recorded
}

func newMockServer(t *testing.T, prefix string) *mockServer {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockServer{t: t, prefix: prefix, aead: aead}
	m.Server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.Close)
	return m
}

func (m *mockServer) recorded() []recorded {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]recorded(nil), m.requests...)
}

func (m *mockServer) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 128<<10+1))
	m.mu.Lock()
	m.requests = append(m.requests, recorded{
		method:      r.Method,
		escapedPath: r.URL.EscapedPath(),
		rawQuery:    r.URL.RawQuery,
		header:      r.Header.Clone(),
		body:        body,
	})
	reqID := fmt.Sprintf("mock-%d", len(m.requests))
	m.mu.Unlock()
	w.Header().Set("X-Request-Id", reqID)

	fail := func(status int, code, message string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, envelope(code, message, reqID))
	}

	rest, ok := strings.CutPrefix(r.URL.Path, m.prefix+"/v1/keys/")
	keyID, op, _ := strings.Cut(rest, "/")
	if !ok || (op != "wrap" && op != "unwrap") {
		fail(http.StatusNotFound, "not_found", "not found")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		fail(http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+testToken {
		fail(http.StatusUnauthorized, "unauthorized", "unauthorized")
		return
	}
	if mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mt != "application/json" {
		fail(http.StatusUnsupportedMediaType, "unsupported_media_type", "content-type must be application/json")
		return
	}
	if len(body) > 128<<10 {
		fail(http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
		return
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(body, &fields) != nil {
		fail(http.StatusBadRequest, "invalid_request", "invalid JSON")
		return
	}
	allowed := map[string]bool{"aad": true, "wrapped": op == "unwrap"}
	for name := range fields {
		if !allowed[name] {
			// Above all, the client must never send "dek".
			m.t.Errorf("%s request has unexpected field %q", op, name)
			fail(http.StatusBadRequest, "invalid_request", "unexpected field")
			return
		}
	}
	if keyID != testKeyID {
		fail(http.StatusNotFound, "not_found", "not found")
		return
	}
	var aad []byte // absent, null and "" all mean no aad
	if raw, ok := fields["aad"]; ok && json.Unmarshal(raw, &aad) != nil {
		fail(http.StatusBadRequest, "invalid_base64", "aad is not valid base64")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if op == "wrap" {
		dek := make([]byte, 32)
		nonce := make([]byte, m.aead.NonceSize())
		_, _ = rand.Read(dek)
		_, _ = rand.Read(nonce)
		sealed := m.aead.Seal(nonce, nonce, dek, aad)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dek":     dek,
			"wrapped": base64.StdEncoding.EncodeToString(sealed),
		})
		return
	}
	var wrapped string
	if json.Unmarshal(fields["wrapped"], &wrapped) != nil || wrapped == "" {
		fail(http.StatusBadRequest, "invalid_request", "wrapped is required")
		return
	}
	sealed, err := base64.StdEncoding.DecodeString(wrapped)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_base64", "wrapped is not valid base64")
		return
	}
	ns := m.aead.NonceSize()
	if len(sealed) < ns {
		fail(http.StatusBadRequest, "invalid_ciphertext", "ciphertext or aad invalid")
		return
	}
	dek, err := m.aead.Open(nil, sealed[:ns], sealed[ns:], aad)
	if err != nil {
		fail(http.StatusBadRequest, "invalid_ciphertext", "ciphertext or aad invalid")
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"dek": dek})
}

// ctxTimeout returns a context that fails the test's wait after a while,
// so a bug cannot hang the run.
func ctxTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}
