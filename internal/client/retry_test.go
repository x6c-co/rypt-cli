package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/iotest"
	"time"
)

func TestRetryOnGatewayStatus(t *testing.T) {
	for _, status := range []int{http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s := newScriptServer(t, respond(status, envelope("unavailable", "busy", "r1")), okWrap())
			res, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			if !bytes.Equal(res.DEK, fixedDEK) {
				t.Error("wrong DEK")
			}
			if s.count() != 2 {
				t.Errorf("server saw %d requests, want 2", s.count())
			}
		})
	}
}

func TestRetryTwiceThenSucceed(t *testing.T) {
	s := newScriptServer(t,
		respond(http.StatusServiceUnavailable, envelope("unavailable", "busy", "r1")),
		respond(http.StatusBadGateway, "<html>bad gateway</html>"),
		okWrap())
	var retries []int
	c := newTestClient(t, s.URL)
	c.backoff = func(n int) time.Duration { retries = append(retries, n); return 0 }

	dek, err := c.Unwrap(ctxTimeout(t), testKeyID, "CiQAwrapped", nil)
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if !bytes.Equal(dek, fixedDEK) {
		t.Error("wrong DEK")
	}
	if s.count() != 3 {
		t.Errorf("server saw %d requests, want 3", s.count())
	}
	if fmt.Sprint(retries) != "[1 2]" {
		t.Errorf("backoff called with %v, want [1 2]", retries)
	}
}

func TestRetryGivesUp(t *testing.T) {
	s := newScriptServer(t, respond(http.StatusServiceUnavailable, envelope("unavailable", "queue full", "req-503")))
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.Kind != KindAPI || e.StatusCode != http.StatusServiceUnavailable || e.Attempts != MaxAttempts ||
		e.Code != "unavailable" || e.Message != "queue full" || e.RequestID != "req-503" {
		t.Errorf("got %+v", e)
	}
	if s.count() != MaxAttempts {
		t.Errorf("server saw %d requests, want %d", s.count(), MaxAttempts)
	}
	want := "API error unavailable (HTTP 503): queue full (request_id req-503)"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err, want)
	}
}

func TestNoRetryOnOtherStatus(t *testing.T) {
	for _, status := range []int{400, 401, 402, 403, 404, 405, 409, 413, 415, 429, 500, 501, 505, 201, 204, 304} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := envelope("some_code", "some message", "req-x")
			if status == 204 || status == 304 {
				body = ""
			}
			s := newScriptServer(t, respond(status, body), okWrap())
			_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
			e := asError(t, err)
			if e.Kind != KindAPI || e.StatusCode != status || e.Attempts != 1 {
				t.Errorf("got %+v", e)
			}
			if s.count() != 1 {
				t.Errorf("server saw %d requests, want 1", s.count())
			}
		})
	}
}

func TestRetryStopsAtNonRetryableStatus(t *testing.T) {
	s := newScriptServer(t,
		respond(http.StatusBadGateway, ""),
		respond(http.StatusNotFound, envelope("not_found", "not found", "req-404")),
		okWrap())
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.StatusCode != http.StatusNotFound || e.Attempts != 2 || s.count() != 2 {
		t.Errorf("got %+v after %d requests", e, s.count())
	}
}

func TestTransportErrors(t *testing.T) {
	tests := []struct {
		name  string
		steps []step
		ok    bool
		hits  int
	}{
		{"hangup", []step{hangup()}, false, 3},
		{"hangup once", []step{hangup(), okWrap()}, true, 2},
		{"hangup twice", []step{hangup(), hangup(), okWrap()}, true, 3},
		{"body cut short", []step{cutBody()}, false, 3},
		{"body cut short once", []step{cutBody(), okWrap()}, true, 2},
		{"503 then hangups", []step{respond(503, ""), hangup()}, false, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScriptServer(t, tt.steps...)
			res, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
			if s.count() != tt.hits {
				t.Errorf("server saw %d requests, want %d", s.count(), tt.hits)
			}
			if tt.ok {
				if err != nil || !bytes.Equal(res.DEK, fixedDEK) {
					t.Fatalf("Wrap: %v", err)
				}
				return
			}
			e := asError(t, err)
			if e.Kind != KindTransport || e.StatusCode != 0 || e.Attempts != MaxAttempts || e.Err == nil {
				t.Errorf("got %+v", e)
			}
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("transport error %v matches a context error", err)
			}
			assertNoSecrets(t, err)
		})
	}
}

func TestBodyCutShortIsUnexpectedEOF(t *testing.T) {
	s := newScriptServer(t, cutBody())
	_, err := newTestClient(t, s.URL).Unwrap(ctxTimeout(t), testKeyID, "w", nil)
	if e := asError(t, err); e.Kind != KindTransport || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Errorf("got %+v (%v), want KindTransport wrapping io.ErrUnexpectedEOF", e, err)
	}
}

func TestConnectionRefused(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	url := s.URL
	s.Close()

	_, err := newTestClient(t, url).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.Kind != KindTransport || e.Attempts != MaxAttempts {
		t.Errorf("got %+v", e)
	}
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Errorf("error %v does not wrap a *net.OpError", err)
	}
	assertNoSecrets(t, err)
}

func TestClientTimeoutIsRetried(t *testing.T) {
	s := newScriptServer(t, stall())
	c, err := New(Options{
		BaseURL:    s.URL,
		Token:      testToken,
		HTTPClient: &http.Client{Timeout: 50 * time.Millisecond},
		Backoff:    noBackoff,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.Kind != KindTransport || e.Attempts != MaxAttempts {
		t.Errorf("got %+v", e)
	}
	if s.count() != MaxAttempts {
		t.Errorf("server saw %d requests, want %d", s.count(), MaxAttempts)
	}
	// net/http's timeout error unwraps to context.DeadlineExceeded, so err
	// matches it through Error.Unwrap. Callers must check for *Error before
	// checking for context errors.
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Errorf("error %v: want a match for context.DeadlineExceeded only", err)
	}
}

func TestContextCanceledDuringBackoff(t *testing.T) {
	s := newScriptServer(t, respond(http.StatusServiceUnavailable, ""))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := newTestClient(t, s.URL)
	c.backoff = func(int) time.Duration {
		cancel()
		return time.Hour
	}

	start := time.Now()
	_, err := c.Wrap(ctx, testKeyID, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	var e *Error
	if errors.As(err, &e) {
		t.Errorf("got *Error %+v, want a bare context error", e)
	}
	if time.Since(start) > 5*time.Second {
		t.Error("backoff did not stop when ctx was canceled")
	}
	if s.count() != 1 {
		t.Errorf("server saw %d requests, want 1", s.count())
	}
}

func TestContextCanceledDuringRequest(t *testing.T) {
	s := newScriptServer(t, stall())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		<-s.arrived
		cancel()
	}()

	_, err := newTestClient(t, s.URL).Unwrap(ctx, testKeyID, "w", nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if s.count() != 1 {
		t.Errorf("server saw %d requests, want 1", s.count())
	}
}

func TestContextCanceledDuringLastAttempt(t *testing.T) {
	// A failure on the last attempt must still report the cancellation, not
	// a transport error.
	s := newScriptServer(t, respond(http.StatusServiceUnavailable, ""), respond(http.StatusServiceUnavailable, ""), stall())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for range MaxAttempts {
			<-s.arrived
		}
		cancel()
	}()

	_, err := newTestClient(t, s.URL).Wrap(ctx, testKeyID, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	var e *Error
	if errors.As(err, &e) {
		t.Errorf("got *Error %+v, want a bare context error", e)
	}
	if s.count() != MaxAttempts {
		t.Errorf("server saw %d requests, want %d", s.count(), MaxAttempts)
	}
}

func TestContextAlreadyCanceled(t *testing.T) {
	s := newScriptServer(t, okWrap())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newTestClient(t, s.URL).Wrap(ctx, testKeyID, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
	if s.count() != 0 {
		t.Errorf("server saw %d requests, want 0", s.count())
	}
}

func TestContextDeadline(t *testing.T) {
	s := newScriptServer(t, stall())
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := newTestClient(t, s.URL).Wrap(ctx, testKeyID, nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v, want context.DeadlineExceeded", err)
	}
	var e *Error
	if errors.As(err, &e) {
		t.Errorf("got *Error %+v, want a bare context error", e)
	}
	if s.count() != 1 {
		t.Errorf("server saw %d requests, want 1", s.count())
	}
}

// connCounter counts the connections a server accepts.
type connCounter struct {
	mu sync.Mutex
	n  int
}

func (c *connCounter) track(_ net.Conn, state http.ConnState) {
	if state == http.StateNew {
		c.mu.Lock()
		c.n++
		c.mu.Unlock()
	}
}

func (c *connCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

func TestUntrustedCertificateNotRetried(t *testing.T) {
	var hits atomic.Int32
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		okWrap()(w, r, 1)
	}))
	var conns connCounter
	s.Config.ConnState = conns.track
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.StartTLS()
	t.Cleanup(s.Close)

	// The default client does not trust the test certificate.
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.Kind != KindTransport || e.Attempts != 1 {
		t.Errorf("got %+v", e)
	}
	var verifyErr *tls.CertificateVerificationError
	if !errors.As(err, &verifyErr) {
		t.Errorf("error %v does not wrap a certificate verification error", err)
	}
	if conns.count() != 1 || hits.Load() != 0 {
		t.Errorf("server saw %d connections and %d requests, want 1 and 0", conns.count(), hits.Load())
	}
	assertNoSecrets(t, err)
}

func TestTrustedTLS(t *testing.T) {
	m := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		okWrap()(w, r, 1)
	}))
	t.Cleanup(m.Close)
	c, err := New(Options{BaseURL: m.URL, Token: testToken, HTTPClient: m.Client(), Backoff: noBackoff})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wrap(ctxTimeout(t), testKeyID, nil); err != nil {
		t.Fatalf("Wrap over https: %v", err)
	}
}

func TestHTTPSToPlainServerNotRetried(t *testing.T) {
	s := httptest.NewUnstartedServer(http.NotFoundHandler())
	var conns connCounter
	s.Config.ConnState = conns.track
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.Start()
	t.Cleanup(s.Close)

	_, err := newTestClient(t, "https://"+s.Listener.Addr().String()).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.Kind != KindTransport || e.Attempts != 1 {
		t.Errorf("got %+v (%v)", e, err)
	}
	if conns.count() != 1 {
		t.Errorf("server saw %d connections, want 1", conns.count())
	}
}

func TestRetryableErr(t *testing.T) {
	if !retryableErr(io.ErrUnexpectedEOF) || !retryableErr(&net.OpError{Op: "dial", Err: errors.New("refused")}) {
		t.Error("connection errors must be retryable")
	}
	for _, err := range []error{
		&tls.CertificateVerificationError{Err: errors.New("x")},
		fmt.Errorf("wrapped: %w", http.ErrSchemeMismatch),
		tls.RecordHeaderError{Msg: "first record does not look like a TLS handshake"},
	} {
		if retryableErr(err) {
			t.Errorf("retryableErr(%v) = true", err)
		}
	}
}

func TestSleep(t *testing.T) {
	if err := sleep(context.Background(), time.Millisecond); err != nil {
		t.Errorf("sleep: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if err := sleep(ctx, time.Hour); !errors.Is(err, context.Canceled) {
		t.Errorf("sleep on a canceled ctx = %v", err)
	}
	if err := sleep(ctx, 0); !errors.Is(err, context.Canceled) {
		t.Errorf("zero sleep on a canceled ctx = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Error("sleep ignored ctx")
	}
}

// TestRetrySendsSameRequest checks that every attempt carries the whole
// body and the same headers: the body must be rebuilt for each attempt.
func TestRetrySendsSameRequest(t *testing.T) {
	tests := []struct {
		name string
		call func(c *Client) error
		path string
		body string
	}{
		{"wrap", func(c *Client) error {
			_, err := c.Wrap(ctxTimeout(t), testKeyID, []byte("label"))
			return err
		}, "/v1/keys/" + testKeyID + "/wrap", `{"aad":"bGFiZWw="}`},
		{"unwrap", func(c *Client) error {
			_, err := c.Unwrap(ctxTimeout(t), testKeyID, "CiQAwrapped", nil)
			return err
		}, "/v1/keys/" + testKeyID + "/unwrap", `{"wrapped":"CiQAwrapped"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScriptServer(t, respond(http.StatusServiceUnavailable, ""), hangup(), okWrap())
			if err := tt.call(newTestClient(t, s.URL)); err != nil {
				t.Fatal(err)
			}
			got := s.recorded()
			if len(got) != MaxAttempts {
				t.Fatalf("server saw %d requests, want %d", len(got), MaxAttempts)
			}
			for i, r := range got {
				if r.method != http.MethodPost || r.escapedPath != tt.path || string(r.body) != tt.body {
					t.Errorf("attempt %d: %s %s %q, want POST %s %q", i+1, r.method, r.escapedPath, r.body, tt.path, tt.body)
				}
				for name, value := range map[string]string{
					"Authorization": "Bearer " + testToken,
					"Content-Type":  "application/json",
					"Accept":        "application/json",
					"User-Agent":    testUA,
				} {
					if v := r.header.Get(name); v != value {
						t.Errorf("attempt %d: header %s = %q, want %q", i+1, name, v, value)
					}
				}
			}
		})
	}
}

// trackedBody is a response body that records whether it was closed.
type trackedBody struct {
	io.Reader
	closed atomic.Bool
}

func (b *trackedBody) Close() error {
	b.closed.Store(true)
	return nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestResponseBodiesClosed(t *testing.T) {
	dek := base64.StdEncoding.EncodeToString(fixedDEK)
	text := func(s string) func() io.Reader {
		return func() io.Reader { return strings.NewReader(s) }
	}
	tests := []struct {
		name   string
		status int
		body   func() io.Reader
		hits   int
	}{
		{"success", 200, text(`{"dek":"` + dek + `","wrapped":"w"}`), 1},
		{"malformed", 200, text(`{}`), 1},
		{"too large", 200, func() io.Reader { return bytes.NewReader(make([]byte, maxResponseBytes+10)) }, 1},
		{"api error", 404, text(envelope("not_found", "not found", "r")), 1},
		{"retried status", 503, text(""), MaxAttempts},
		{"read error", 200, func() io.Reader {
			return io.MultiReader(strings.NewReader(`{"dek"`), iotest.ErrReader(io.ErrUnexpectedEOF))
		}, MaxAttempts},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var (
				mu     sync.Mutex
				bodies []*trackedBody
			)
			rt := roundTripFunc(func(r *http.Request) (*http.Response, error) {
				b := &trackedBody{Reader: tt.body()}
				mu.Lock()
				bodies = append(bodies, b)
				mu.Unlock()
				return &http.Response{StatusCode: tt.status, Header: http.Header{}, Body: b, ContentLength: -1, Request: r}, nil
			})
			c, err := New(Options{BaseURL: "http://127.0.0.1:1", Token: testToken, HTTPClient: &http.Client{Transport: rt}, Backoff: noBackoff})
			if err != nil {
				t.Fatal(err)
			}
			_, _ = c.Wrap(ctxTimeout(t), testKeyID, nil)
			mu.Lock()
			defer mu.Unlock()
			if len(bodies) != tt.hits {
				t.Fatalf("%d responses, want %d", len(bodies), tt.hits)
			}
			for i, b := range bodies {
				if !b.closed.Load() {
					t.Errorf("response %d body was not closed", i+1)
				}
			}
		})
	}
}
