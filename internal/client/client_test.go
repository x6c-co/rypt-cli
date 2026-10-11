package client

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRoundTrip(t *testing.T) {
	for _, aad := range [][]byte{nil, {}, []byte("label"), bytes.Repeat([]byte{0xff, 0x00}, 512)} {
		m := newMockServer(t, "")
		c := newTestClient(t, m.URL)
		ctx := ctxTimeout(t)

		res, err := c.Wrap(ctx, testKeyID, aad)
		if err != nil {
			t.Fatalf("Wrap(aad len %d): %v", len(aad), err)
		}
		if len(res.DEK) != 32 || res.Wrapped == "" {
			t.Fatalf("Wrap returned DEK len %d, wrapped len %d", len(res.DEK), len(res.Wrapped))
		}
		dek, err := c.Unwrap(ctx, testKeyID, res.Wrapped, aad)
		if err != nil {
			t.Fatalf("Unwrap(aad len %d): %v", len(aad), err)
		}
		if !bytes.Equal(dek, res.DEK) {
			t.Fatalf("Unwrap returned a different DEK")
		}
		if n := len(m.recorded()); n != 2 {
			t.Fatalf("server saw %d requests, want 2", n)
		}
	}
}

func TestRequestShape(t *testing.T) {
	m := newMockServer(t, "")
	c := newTestClient(t, m.URL)
	ctx := ctxTimeout(t)

	plain, err := c.Wrap(ctx, testKeyID, nil)
	if err != nil {
		t.Fatal(err)
	}
	labeled, err := c.Wrap(ctx, testKeyID, []byte("label"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unwrap(ctx, testKeyID, plain.Wrapped, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unwrap(ctx, testKeyID, labeled.Wrapped, []byte("label")); err != nil {
		t.Fatal(err)
	}

	wrappedJSON := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	want := []struct{ path, body string }{
		{"/v1/keys/" + testKeyID + "/wrap", `{}`},
		{"/v1/keys/" + testKeyID + "/wrap", `{"aad":"bGFiZWw="}`},
		{"/v1/keys/" + testKeyID + "/unwrap", `{"wrapped":` + wrappedJSON(plain.Wrapped) + `}`},
		{"/v1/keys/" + testKeyID + "/unwrap", `{"wrapped":` + wrappedJSON(labeled.Wrapped) + `,"aad":"bGFiZWw="}`},
	}
	got := m.recorded()
	if len(got) != len(want) {
		t.Fatalf("server saw %d requests, want %d", len(got), len(want))
	}
	for i, w := range want {
		r := got[i]
		if r.method != http.MethodPost || r.escapedPath != w.path || r.rawQuery != "" {
			t.Errorf("request %d: %s %s?%s, want POST %s", i, r.method, r.escapedPath, r.rawQuery, w.path)
		}
		if string(r.body) != w.body {
			t.Errorf("request %d body = %s, want %s", i, r.body, w.body)
		}
		for name, value := range map[string]string{
			"Authorization": "Bearer " + testToken,
			"Content-Type":  "application/json",
			"Accept":        "application/json",
			"User-Agent":    testUA,
		} {
			if got := r.header.Values(name); len(got) != 1 || got[0] != value {
				t.Errorf("request %d header %s = %q, want %q", i, name, got, value)
			}
		}
		// The token goes only in the Authorization header.
		for name, values := range r.header {
			if name == "Authorization" {
				continue
			}
			for _, v := range values {
				if strings.Contains(v, testSecret) {
					t.Errorf("request %d header %s carries the token", i, name)
				}
			}
		}
		if strings.Contains(r.escapedPath+r.rawQuery+string(r.body), testSecret) {
			t.Errorf("request %d carries the token outside the Authorization header", i)
		}
	}
}

func TestDefaultUserAgent(t *testing.T) {
	m := newMockServer(t, "")
	c, err := New(Options{BaseURL: m.URL, Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Wrap(ctxTimeout(t), testKeyID, nil); err != nil {
		t.Fatal(err)
	}
	if ua := m.recorded()[0].header.Get("User-Agent"); ua != defaultUserAgent {
		t.Errorf("User-Agent = %q, want %q", ua, defaultUserAgent)
	}
}

func TestBasePathPrefix(t *testing.T) {
	for _, base := range []string{"/api/rypt", "/api/rypt/"} {
		m := newMockServer(t, "/api/rypt")
		c := newTestClient(t, m.URL+base)
		res, err := c.Wrap(ctxTimeout(t), testKeyID, nil)
		if err != nil {
			t.Fatalf("base %q: Wrap: %v", base, err)
		}
		if _, err := c.Unwrap(ctxTimeout(t), testKeyID, res.Wrapped, nil); err != nil {
			t.Fatalf("base %q: Unwrap: %v", base, err)
		}
		got := m.recorded()
		if got[0].escapedPath != "/api/rypt/v1/keys/"+testKeyID+"/wrap" ||
			got[1].escapedPath != "/api/rypt/v1/keys/"+testKeyID+"/unwrap" {
			t.Errorf("base %q: paths %q and %q", base, got[0].escapedPath, got[1].escapedPath)
		}
	}
}

func TestKeyIDIsPathEscaped(t *testing.T) {
	m := newMockServer(t, "")
	c := newTestClient(t, m.URL)
	_, err := c.Wrap(ctxTimeout(t), "a/b?c#d e", nil)
	if e := asError(t, err); e.Kind != KindAPI || e.StatusCode != http.StatusNotFound {
		t.Fatalf("got %v, want a 404 KindAPI error", err)
	}
	got := m.recorded()
	if len(got) != 1 || got[0].escapedPath != "/v1/keys/a%2Fb%3Fc%23d%20e/wrap" || got[0].rawQuery != "" {
		t.Fatalf("recorded %+v", got)
	}
}

func TestAPIErrorsFromMock(t *testing.T) {
	m := newMockServer(t, "")
	c := newTestClient(t, m.URL)
	ctx := ctxTimeout(t)

	res, err := c.Wrap(ctx, testKeyID, []byte("label"))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		call   func() error
		status int
		code   string
	}{
		{"aad mismatch", func() error {
			_, err := c.Unwrap(ctx, testKeyID, res.Wrapped, []byte("other"))
			return err
		}, http.StatusBadRequest, "invalid_ciphertext"},
		{"aad missing", func() error {
			_, err := c.Unwrap(ctx, testKeyID, res.Wrapped, nil)
			return err
		}, http.StatusBadRequest, "invalid_ciphertext"},
		{"tampered wrapped", func() error {
			// Still valid base64, but a different ciphertext.
			b := []byte(res.Wrapped)
			if b[20] == 'A' {
				b[20] = 'B'
			} else {
				b[20] = 'A'
			}
			_, err := c.Unwrap(ctx, testKeyID, string(b), []byte("label"))
			return err
		}, http.StatusBadRequest, "invalid_ciphertext"},
		{"unknown key", func() error {
			_, err := c.Wrap(ctx, "00000000-0000-4000-8000-000000000000", nil)
			return err
		}, http.StatusNotFound, "not_found"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := len(m.recorded())
			err := tt.call()
			e := asError(t, err)
			if e.Kind != KindAPI || e.StatusCode != tt.status || e.Code != tt.code || e.Attempts != 1 {
				t.Fatalf("got %+v", e)
			}
			if e.RequestID == "" || !strings.Contains(err.Error(), "(request_id "+e.RequestID+")") {
				t.Errorf("Error() = %q, want request_id %q", err, e.RequestID)
			}
			if !strings.Contains(err.Error(), tt.code) {
				t.Errorf("Error() = %q, want the code %q", err, tt.code)
			}
			if n := len(m.recorded()) - before; n != 1 {
				t.Errorf("sent %d requests, want 1", n)
			}
			assertNoSecrets(t, err, res.Wrapped)
		})
	}

	t.Run("wrong token", func(t *testing.T) {
		bad, err := New(Options{BaseURL: m.URL, Token: "ry_Wrong000_" + strings.Repeat("x", 32), Backoff: noBackoff})
		if err != nil {
			t.Fatal(err)
		}
		_, err = bad.Wrap(ctx, testKeyID, nil)
		if e := asError(t, err); e.Kind != KindAPI || e.StatusCode != http.StatusUnauthorized || e.Code != "unauthorized" {
			t.Fatalf("got %+v", e)
		}
		if strings.Contains(err.Error(), "xxxxxxxx") {
			t.Errorf("Error() = %q contains the token", err)
		}
	})
}

func TestDefaultHTTPClient(t *testing.T) {
	c, err := New(Options{Token: testToken})
	if err != nil {
		t.Fatal(err)
	}
	if c.base.String() != DefaultBaseURL {
		t.Errorf("base = %q, want %q", c.base, DefaultBaseURL)
	}
	if c.http.Timeout != RequestTimeout {
		t.Errorf("Timeout = %v, want %v", c.http.Timeout, RequestTimeout)
	}
	if c.http.CheckRedirect == nil || !errors.Is(c.http.CheckRedirect(nil, nil), http.ErrUseLastResponse) {
		t.Error("CheckRedirect does not stop redirects")
	}
	tr, ok := c.http.Transport.(*http.Transport)
	if !ok || tr == http.DefaultTransport || tr.Proxy == nil {
		t.Fatalf("Transport = %T %p; want a clone of http.DefaultTransport with a proxy func", c.http.Transport, c.http.Transport)
	}
	// Plain http never goes through a proxy, whatever the environment says.
	// (The environment is read once per process, so cmd/rypt tests that.)
	for _, raw := range []string{"http://localhost:8080/v1/keys/k/wrap", "http://127.0.0.1/x", "http://[::1]/x"} {
		req := httptest.NewRequest("POST", raw, nil)
		if p, err := tr.Proxy(req); p != nil || err != nil {
			t.Errorf("Proxy(%s) = %v, %v; want no proxy", raw, p, err)
		}
	}
	if got := []time.Duration{c.backoff(1), c.backoff(2)}; got[0] != 250*time.Millisecond || got[1] != 750*time.Millisecond {
		t.Errorf("default backoff = %v", got)
	}

	custom := &http.Client{}
	c, err = New(Options{Token: testToken, HTTPClient: custom})
	if err != nil {
		t.Fatal(err)
	}
	if c.http != custom {
		t.Error("Options.HTTPClient was not used")
	}
}

// TestHTTPSOnlyProxy: the environment's proxy is used for https and never
// for plain http, where it would see the token in clear text.
func TestHTTPSOnlyProxy(t *testing.T) {
	envProxy := &url.URL{Scheme: "http", Host: "proxy.example:3128"}
	proxy := httpsOnlyProxy(func(*http.Request) (*url.URL, error) { return envProxy, nil })
	for _, tt := range []struct {
		url  string
		want *url.URL
	}{
		{"https://api.rypt.dev/v1/keys/k/wrap", envProxy},
		{"http://localhost:8080/v1/keys/k/wrap", nil},
		{"http://LOCALHOST:8080/v1/keys/k/wrap", nil},
		{"http://127.0.0.1/x", nil},
	} {
		got, err := proxy(httptest.NewRequest("POST", tt.url, nil))
		if got != tt.want || err != nil {
			t.Errorf("proxy(%s) = %v, %v; want %v", tt.url, got, err, tt.want)
		}
	}
	if got, err := httpsOnlyProxy(nil)(httptest.NewRequest("POST", "https://api.rypt.dev/", nil)); got != nil || err != nil {
		t.Errorf("with no proxy function: %v, %v", got, err)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	for _, status := range []int{
		http.StatusMovedPermanently, http.StatusFound, http.StatusSeeOther,
		http.StatusTemporaryRedirect, http.StatusPermanentRedirect,
	} {
		var elsewhere atomic.Int32
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			elsewhere.Add(1)
			okWrap()(w, r, 1)
		}))
		t.Cleanup(target.Close)
		var hits atomic.Int32
		origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("X-Request-Id", "redirect-1")
			http.Redirect(w, r, target.URL+r.URL.Path, status)
		}))
		t.Cleanup(origin.Close)

		// The default HTTP client, as the program uses it.
		c, err := New(Options{BaseURL: origin.URL, Token: testToken, Backoff: noBackoff})
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Wrap(ctxTimeout(t), testKeyID, nil)
		e := asError(t, err)
		if e.Kind != KindAPI || e.StatusCode != status || e.Code != "" || e.RequestID != "redirect-1" {
			t.Errorf("HTTP %d: got %+v", status, e)
		}
		if hits.Load() != 1 || elsewhere.Load() != 0 {
			t.Errorf("HTTP %d: origin saw %d requests, redirect target %d; want 1 and 0", status, hits.Load(), elsewhere.Load())
		}
		assertNoSecrets(t, err)
	}
}

func TestErrorText(t *testing.T) {
	tests := []struct {
		err  *Error
		want string
	}{
		{&Error{Kind: KindAPI, StatusCode: 429, Code: "ops_cap_reached", Message: "monthly cap reached", RequestID: "abc", Cap: 10000, ResetsAt: "2026-11-01T00:00:00Z"},
			"API error ops_cap_reached (HTTP 429): monthly cap reached; cap 10000, resets at 2026-11-01T00:00:00Z (request_id abc)"},
		{&Error{Kind: KindAPI, StatusCode: 429, Code: "ops_cap_reached", ResetsAt: "2026-11-01T00:00:00Z"},
			"API error ops_cap_reached (HTTP 429); resets at 2026-11-01T00:00:00Z"},
		{&Error{Kind: KindAPI, StatusCode: 502, Message: "unexpected HTTP 502 response", RequestID: "abc"},
			"API error (HTTP 502): unexpected HTTP 502 response (request_id abc)"},
		{&Error{Kind: KindAPI, StatusCode: 404, Code: "not_found", RequestID: "abc"},
			"API error not_found (HTTP 404) (request_id abc)"},
		{&Error{Kind: KindResponse, StatusCode: 200, Message: "dek is not 32 bytes", RequestID: "abc"},
			"malformed API response (HTTP 200): dek is not 32 bytes (request_id abc)"},
		{&Error{Kind: KindTransport, Message: "cannot reach the rypt API", Attempts: 3, Err: errors.New("connection refused")},
			"cannot reach the rypt API after 3 attempts: connection refused"},
		{&Error{Kind: KindTransport, Attempts: 1, Err: errors.New("x509: bad")},
			"cannot reach the rypt API after 1 attempt: x509: bad"},
		{&Error{Kind: KindTransport, Err: errors.New("bad \x1b[2J\u202ething\r\n")},
			"cannot reach the rypt API: bad [2Jthing"},
	}
	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("Error() = %q, want %q", got, tt.want)
		}
	}
	inner := errors.New("inner")
	if !errors.Is(&Error{Kind: KindTransport, Err: inner}, inner) {
		t.Error("Error does not unwrap to Err")
	}
}

func TestWrappedLengthLimit(t *testing.T) {
	dek := base64.StdEncoding.EncodeToString(fixedDEK)
	s := newScriptServer(t, respond(http.StatusOK, `{"dek":"`+dek+`","wrapped":"`+strings.Repeat("A", maxWrappedLen)+`"}`))
	res, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	if err != nil {
		t.Fatalf("a wrapped value of exactly %d bytes: %v", maxWrappedLen, err)
	}
	if len(res.Wrapped) != maxWrappedLen || !bytes.Equal(res.DEK, fixedDEK) {
		t.Fatalf("got wrapped len %d", len(res.Wrapped))
	}
}

// TestSecretHygiene drives every error path and checks that no error text
// holds the token or a DEK that the server sent.
func TestSecretHygiene(t *testing.T) {
	dekB64 := base64.StdEncoding.EncodeToString(fixedDEK)
	dek33 := base64.StdEncoding.EncodeToString(append(append([]byte(nil), fixedDEK...), '!'))
	closed := httptest.NewServer(http.NotFoundHandler())
	closedURL := closed.URL
	closed.Close()

	steps := map[string][]step{
		"401":           {respond(401, envelope("unauthorized", "unauthorized", "r"))},
		"429 cap":       {respond(429, `{"error":"ops_cap_reached","message":"m","cap":1,"resets_at":"t"}`)},
		"503 x3":        {respond(503, "")},
		"html 502":      {respond(502, "<html>"+dekB64+"</html>")},
		"hangup":        {hangup()},
		"cut body":      {cutBody()},
		"short dek":     {respond(200, `{"dek":"`+base64.StdEncoding.EncodeToString(fixedDEK[:16])+`","wrapped":"w"}`)},
		"long dek":      {respond(200, `{"dek":"`+dek33+`","wrapped":"w"}`)},
		"no wrapped":    {respond(200, `{"dek":"`+dekB64+`"}`)},
		"bad json":      {respond(200, `{"dek":"`+dekB64+`",`)},
		"error has dek": {respond(400, envelope("invalid_request", "dek "+dekB64, "r"))},
	}
	var errs []error
	for name, st := range steps {
		s := newScriptServer(t, st...)
		c := newTestClient(t, s.URL)
		if _, err := c.Wrap(ctxTimeout(t), testKeyID, []byte("label")); err != nil {
			errs = append(errs, err)
		} else {
			t.Errorf("%s: Wrap succeeded", name)
		}
		if _, err := c.Unwrap(ctxTimeout(t), testKeyID, "w", nil); err != nil {
			errs = append(errs, err)
		}
	}
	if _, err := newTestClient(t, closedURL).Wrap(ctxTimeout(t), testKeyID, nil); err != nil {
		errs = append(errs, err)
	}
	if _, err := New(Options{Token: testToken + "\n"}); err != nil {
		errs = append(errs, err)
	}
	if len(errs) < len(steps)+2 {
		t.Fatalf("only %d errors collected", len(errs))
	}
	for _, err := range errs {
		// The "error has dek" case is the server's own message; the client
		// cannot know it holds a key. Every other path must be clean.
		if e, ok := err.(*Error); ok && e.Code == "invalid_request" {
			assertNoSecrets(t, err)
			continue
		}
		assertNoSecrets(t, err, dekB64, dek33, string(fixedDEK))
	}
}
