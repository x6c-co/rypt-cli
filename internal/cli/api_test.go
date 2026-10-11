package cli

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// apiScenario runs one encrypt (op "wrap") or decrypt (op "unwrap") with a
// file output, the API scripted by faults.
type apiScenario struct {
	h      *harness
	op     string
	pt     []byte
	out    string
	inputs []string
}

func newAPIScenario(t *testing.T, op string) *apiScenario {
	h := newHarness(t)
	s := &apiScenario{h: h, op: op, pt: testData(70000, 11)}
	if op == "wrap" {
		h.writeFile("in", s.pt)
		s.out, s.inputs = "in.rypt", []string{"in"}
	} else {
		ct, _ := h.craft(cipherAES, 65536, "lbl", s.pt)
		h.writeFile("in.rypt", ct)
		s.out, s.inputs = "in", []string{"in.rypt"}
	}
	return s
}

func (s *apiScenario) run() result {
	s.h.t.Helper()
	cmd := "encrypt"
	if s.op == "unwrap" {
		cmd = "decrypt"
	}
	return s.h.run(cmd, s.h.path(s.inputs[0]))
}

// assertFailedCleanly checks a failed run left only the input behind.
func (s *apiScenario) assertFailedCleanly() {
	s.h.t.Helper()
	s.h.assertMissing(s.out)
	s.h.assertEntries("", s.inputs...)
}

func (s *apiScenario) assertSucceeded() {
	s.h.t.Helper()
	if s.op == "wrap" {
		s.h.verifyEncrypted(s.h.readFile(s.out), cipherAES, testKeyID, "")
	} else {
		s.h.assertContent(s.out, s.pt)
	}
	s.h.assertMode0600(s.out)
}

func (s *apiScenario) wantRequests(n int) {
	s.h.t.Helper()
	if s.op == "wrap" {
		s.h.wantCalls(n, 0)
	} else {
		s.h.wantCalls(0, n)
	}
}

// requestIDs returns the request IDs of every request to the op.
func (s *apiScenario) requestIDs() []string {
	var ids []string
	for _, c := range s.h.api.callsOf(s.op) {
		ids = append(ids, c.requestID)
	}
	return ids
}

// TestAPIErrors: API refusals exit 1 with the error code and request ID, and
// are not retried.
func TestAPIErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		status int
		code   string
		ops    []string
	}{
		{400, "invalid_request", []string{"wrap", "unwrap"}},
		{400, "invalid_ciphertext", []string{"unwrap"}},
		{402, "billing_required", []string{"wrap"}},
		{403, "ip_not_allowed", []string{"wrap", "unwrap"}},
		{403, "key_not_allowed", []string{"wrap", "unwrap"}},
		{404, "not_found", []string{"wrap", "unwrap"}},
		{409, "key_pending_deletion", []string{"wrap", "unwrap"}},
		{413, "payload_too_large", []string{"wrap"}},
		{429, "rate_limited", []string{"wrap", "unwrap"}},
		{500, "internal_error", []string{"wrap", "unwrap"}},
		{501, "not_implemented", []string{"wrap"}},
	}
	for _, c := range cases {
		for _, op := range c.ops {
			t.Run(fmt.Sprintf("%s/%d-%s", op, c.status, c.code), func(t *testing.T) {
				t.Parallel()
				s := newAPIScenario(t, op)
				s.h.api.script(op, apiErr(c.status, c.code, "the server says no"))
				res := s.run()
				expect(t, res, ExitAPI)
				s.wantRequests(1)
				s.assertFailedCleanly()
				if !strings.Contains(res.stderr, c.code) {
					t.Errorf("stderr does not name the API error code %q:\n%s", c.code, res.stderr)
				}
				if id := s.requestIDs()[0]; !strings.Contains(res.stderr, id) {
					t.Errorf("stderr does not include the request_id %q:\n%s", id, res.stderr)
				}
			})
		}
	}
}

// TestAPIErrorsNatural drives the mock into its own refusals.
func TestAPIErrorsNatural(t *testing.T) {
	t.Parallel()

	t.Run("401 wrong token", func(t *testing.T) {
		t.Parallel()
		for _, op := range []string{"wrap", "unwrap"} {
			s := newAPIScenario(t, op)
			s.h.env["RYPT_TOKEN"] = wrongToken
			res := s.run()
			expect(t, res, ExitAPI)
			s.wantRequests(1)
			s.assertFailedCleanly()
			if !strings.Contains(res.stderr, "unauthorized") || !strings.Contains(res.stderr, s.requestIDs()[0]) {
				t.Errorf("%s: stderr lacks the code or request_id:\n%s", op, res.stderr)
			}
		}
	})

	t.Run("404 unknown key on wrap", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.writeFile("in", []byte("x"))
		res := h.run("encrypt", "-k", unknownKeyID, h.path("in"))
		expect(t, res, ExitAPI)
		h.wantCalls(1, 0)
		h.assertEntries("", "in")
		if !strings.Contains(res.stderr, "not_found") {
			t.Errorf("stderr lacks not_found:\n%s", res.stderr)
		}
	})

	t.Run("404 unknown key in header", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		ct, hdr := h.craft(cipherAES, 65536, "", []byte("x"))
		copy(ct[offKeyID:], keyIDBytes(unknownKeyID))
		_ = hdr
		h.writeFile("in.rypt", ct)
		res := h.run("decrypt", h.path("in.rypt"))
		expect(t, res, ExitAPI)
		h.wantCalls(0, 1)
		h.assertEntries("", "in.rypt")
		if u := h.api.lastCall(t, "unwrap"); u.keyID != unknownKeyID {
			t.Errorf("unwrap went to %s, want the header's key %s", u.keyID, unknownKeyID)
		}
		if !strings.Contains(res.stderr, "not_found") {
			t.Errorf("stderr lacks not_found:\n%s", res.stderr)
		}
	})
}

// TestOpsCapReached: 429 ops_cap_reached is not retried and its resets_at
// is printed.
func TestOpsCapReached(t *testing.T) {
	t.Parallel()
	for _, op := range []string{"wrap", "unwrap"} {
		s := newAPIScenario(t, op)
		const resetsAt = "2026-11-01T00:00:00Z"
		s.h.api.script(op, apiErrExtra(429, "ops_cap_reached", "monthly operation cap reached",
			map[string]any{"cap": 1000, "resets_at": resetsAt}))
		res := s.run()
		expect(t, res, ExitAPI)
		s.wantRequests(1)
		s.assertFailedCleanly()
		for _, want := range []string{"ops_cap_reached", resetsAt, s.requestIDs()[0]} {
			if !strings.Contains(res.stderr, want) {
				t.Errorf("%s: stderr does not contain %q:\n%s", op, want, res.stderr)
			}
		}
	}
}

// TestRetries: connection errors and 502, 503 and 504 are retried up to two
// more times; nothing else is.
func TestRetries(t *testing.T) {
	t.Parallel()
	html502 := rawResponse(502, "text/html", "<html><body>502 Bad Gateway</body></html>")
	html504 := rawResponse(504, "text/html", "<html>gateway timeout</html>")
	unavailable := apiErr(503, "unavailable", "queue full; retry")
	cases := []struct {
		name     string
		faults   []fault
		code     int
		requests int
	}{
		{"503 then success", []fault{unavailable}, ExitOK, 2},
		{"502 then success", []fault{html502}, ExitOK, 2},
		{"504 then success", []fault{html504}, ExitOK, 2},
		{"502 504 then success", []fault{html502, html504}, ExitOK, 3},
		{"503 x3", []fault{unavailable, unavailable, unavailable}, ExitAPI, 3},
		{"502 x3 then would succeed", []fault{html502, html502, html502}, ExitAPI, 3},
		{"504 x3", []fault{html504, html504, html504}, ExitAPI, 3},
		{"drop then success", []fault{dropConn()}, ExitOK, 2},
		{"drop drop then success", []fault{dropConn(), dropConn()}, ExitOK, 3},
		{"drop x3", []fault{dropConn(), dropConn(), dropConn()}, ExitAPI, 3},
		{"truncated body then success", []fault{truncatedBody()}, ExitOK, 2},
		{"drop then 503 then 404", []fault{dropConn(), unavailable, apiErr(404, "not_found", "no")}, ExitAPI, 3},
		{"503 then 400 is final", []fault{unavailable, apiErr(400, "invalid_request", "bad")}, ExitAPI, 2},
		{"429 rate_limited not retried", []fault{apiErr(429, "rate_limited", "slow down")}, ExitAPI, 1},
		{"500 not retried", []fault{apiErr(500, "internal_error", "boom")}, ExitAPI, 1},
		{"501 not retried", []fault{apiErr(501, "not_implemented", "no")}, ExitAPI, 1},
		{"505 not retried", []fault{rawResponse(505, "", "")}, ExitAPI, 1},
	}
	for _, c := range cases {
		for _, op := range []string{"wrap", "unwrap"} {
			t.Run(op+"/"+c.name, func(t *testing.T) {
				t.Parallel()
				s := newAPIScenario(t, op)
				s.h.api.script(op, c.faults...)
				// A fourth request would succeed, so an extra retry shows.
				res := s.run()
				expect(t, res, c.code)
				s.wantRequests(c.requests)
				if c.code == ExitOK {
					s.assertSucceeded()
					return
				}
				s.assertFailedCleanly()
				// The message names the last response.
				ids := s.requestIDs()
				if last := ids[len(ids)-1]; !strings.Contains(res.stderr, last) && !strings.HasPrefix(c.name, "drop") {
					t.Errorf("stderr does not include the last request_id %q:\n%s", last, res.stderr)
				}
			})
		}
	}
}

// TestNonEnvelopeError: a proxy error page without the JSON envelope still
// gives the HTTP status and the x-request-id header.
func TestNonEnvelopeError(t *testing.T) {
	t.Parallel()
	s := newAPIScenario(t, "wrap")
	page := rawResponse(502, "text/html", "<html><body><h1>502 Bad Gateway</h1>cloudflare</body></html>")
	s.h.api.script("wrap", page, page, page)
	res := s.run()
	expect(t, res, ExitAPI)
	s.wantRequests(3)
	ids := s.requestIDs()
	if !strings.Contains(res.stderr, "502") || !strings.Contains(res.stderr, ids[2]) {
		t.Errorf("stderr lacks the status or the x-request-id %q:\n%s", ids[2], res.stderr)
	}
	if strings.Contains(res.stderr, "<html>") {
		t.Errorf("stderr quotes the HTML page:\n%s", res.stderr)
	}
}

// TestUnreachable: a closed port exits 1.
func TestUnreachable(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	for _, op := range []string{"wrap", "unwrap"} {
		s := newAPIScenario(t, op)
		s.h.env["RYPT_API_URL"] = "http://" + addr
		res := s.run()
		expect(t, res, ExitAPI)
		s.assertFailedCleanly()
		s.wantRequests(0)
	}
}

// TestMalformedSuccess: a 200 whose body is not what the API documents
// exits 1, is not retried, and writes nothing.
func TestMalformedSuccess(t *testing.T) {
	t.Parallel()
	b64 := base64.StdEncoding.EncodeToString
	str := func(s string) func([]byte, string) any { return func([]byte, string) any { return s } }
	wrapCases := map[string]func(dek []byte, wrapped string) any{
		"not JSON":       str("<html>ok</html>"),
		"empty body":     str(""),
		"JSON array":     str(`["dek","wrapped"]`),
		"JSON null":      str(`null`),
		"truncated JSON": str(`{"dek":"AAAA`),
		"missing dek":    func(dek []byte, w string) any { return map[string]any{"wrapped": w} },
		"null dek":       func(dek []byte, w string) any { return map[string]any{"dek": nil, "wrapped": w} },
		"16-byte dek":    func(dek []byte, w string) any { return map[string]any{"dek": b64(dek[:16]), "wrapped": w} },
		"24-byte dek":    func(dek []byte, w string) any { return map[string]any{"dek": b64(dek[:24]), "wrapped": w} },
		"31-byte dek":    func(dek []byte, w string) any { return map[string]any{"dek": b64(dek[:31]), "wrapped": w} },
		"33-byte dek":    func(dek []byte, w string) any { return map[string]any{"dek": b64(append(dek, 1)), "wrapped": w} },
		"empty dek":      func(dek []byte, w string) any { return map[string]any{"dek": "", "wrapped": w} },
		"dek not base64": func(dek []byte, w string) any { return map[string]any{"dek": "!!not base64!!", "wrapped": w} },
		"dek unpadded": func(dek []byte, w string) any {
			return map[string]any{"dek": base64.RawStdEncoding.EncodeToString(dek), "wrapped": w}
		},
		"dek is a number": func(dek []byte, w string) any { return map[string]any{"dek": 42, "wrapped": w} },
		"missing wrapped": func(dek []byte, w string) any { return map[string]any{"dek": b64(dek)} },
		"null wrapped":    func(dek []byte, w string) any { return map[string]any{"dek": b64(dek), "wrapped": nil} },
		"empty wrapped":   func(dek []byte, w string) any { return map[string]any{"dek": b64(dek), "wrapped": ""} },
		"wrapped number":  func(dek []byte, w string) any { return map[string]any{"dek": b64(dek), "wrapped": 7} },
		"wrapped object":  func(dek []byte, w string) any { return map[string]any{"dek": b64(dek), "wrapped": map[string]any{}} },
		"wrapped over limit": func(dek []byte, w string) any {
			return map[string]any{"dek": b64(dek), "wrapped": strings.Repeat("A", 65537)}
		},
	}
	unwrapCases := map[string]func(dek []byte, wrapped string) any{
		"not JSON":        str("<html>ok</html>"),
		"empty body":      str(""),
		"JSON string":     str(`"dek"`),
		"missing dek":     func(dek []byte, _ string) any { return map[string]any{} },
		"null dek":        func(dek []byte, _ string) any { return map[string]any{"dek": nil} },
		"16-byte dek":     func(dek []byte, _ string) any { return map[string]any{"dek": b64(dek[:16])} },
		"33-byte dek":     func(dek []byte, _ string) any { return map[string]any{"dek": b64(append(dek, 0))} },
		"dek not base64":  func(dek []byte, _ string) any { return map[string]any{"dek": "%%%%"} },
		"dek is a number": func(dek []byte, _ string) any { return map[string]any{"dek": 1} },
	}
	for op, cases := range map[string]map[string]func([]byte, string) any{"wrap": wrapCases, "unwrap": unwrapCases} {
		for name, body := range cases {
			t.Run(op+"/"+name, func(t *testing.T) {
				t.Parallel()
				s := newAPIScenario(t, op)
				s.h.api.script(op, okBody(body))
				res := s.run()
				expect(t, res, ExitAPI)
				s.wantRequests(1)
				s.assertFailedCleanly()
			})
		}
	}
}

// TestWrappedAtHeaderLimit: a wrapped value of exactly 65536 bytes fits in
// the header and round-trips.
func TestWrappedAtHeaderLimit(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	pt := testData(1000, 5)
	big := strings.Repeat("Q", 65532) + "abc="
	h.api.script("wrap", func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
		dek := m.issueCustom(testKeyID, nil, big)
		m.mu.Lock()
		c.dek, c.wrapped = dek, big
		m.mu.Unlock()
		writeJSON(w, 200, map[string]any{"dek": base64.StdEncoding.EncodeToString(dek), "wrapped": big})
	})
	h.writeFile("in", pt)
	expect(t, h.run("encrypt", h.path("in")), ExitOK)
	ct := h.readFile("in.rypt")
	h.verifyEncrypted(ct, cipherAES, testKeyID, "")
	expect(t, h.run("decrypt", "-o", h.path("out"), h.path("in.rypt")), ExitOK)
	h.assertContent("out", pt)
	if u := h.api.lastCall(t, "unwrap"); u.wrapped != big {
		t.Errorf("unwrap sent a %d-byte wrapped value, want the 65536-byte one from the header", len(u.wrapped))
	}
}

// TestWrongDEKFromAPI: an unwrap that returns a different 32-byte key fails
// authentication of the first chunk: exit 4, nothing written.
func TestWrongDEKFromAPI(t *testing.T) {
	t.Parallel()
	s := newAPIScenario(t, "unwrap")
	s.h.api.script("unwrap", okBody(func(dek []byte, _ string) any {
		return map[string]any{"dek": base64.StdEncoding.EncodeToString(dek)}
	}))
	res := s.run()
	expect(t, res, ExitIntegrity)
	s.wantRequests(1)
	s.assertFailedCleanly()
}

// TestServerTextSanitized: control characters, escape sequences and
// invisible format characters from the server never reach stderr (the
// harness checks every run); the visible text does.
func TestServerTextSanitized(t *testing.T) {
	t.Parallel()
	nasty := "visible-start\x1b[2J\x1b]0;pwned\x07\r\nFAKE: rypt: success\x00\u009b31m\u202Eevil\u200Bvisible-end"
	cases := map[string]fault{
		"message": apiErr(400, "invalid_request", nasty),
		"code":    apiErr(400, "invalid_request\x1b[31m\u202E", "m"),
		"request_id": func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
			writeAPIError(w, 400, "invalid_request", "m", "rid\x1b[1m\x07\r\n-1", nil)
		},
		"x-request-id header": rawConn("HTTP/1.1 400 Bad Request\r\nX-Request-Id: rid\x1b[31m\x07-2\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno"),
		"status line":         rawConn("HTTP/1.1 4\x1b[31m00 \x1b]0;t\x07Bad\r\n\r\n"),
		"error page":          rawResponse(400, "text/plain", nasty),
	}
	for name, f := range cases {
		for _, op := range []string{"wrap", "unwrap"} {
			t.Run(op+"/"+name, func(t *testing.T) {
				t.Parallel()
				s := newAPIScenario(t, op)
				s.h.api.script(op, f, f, f)
				res := s.run()
				expect(t, res, ExitAPI)
				s.assertFailedCleanly()
				if name == "message" && (!strings.Contains(res.stderr, "visible-start") || !strings.Contains(res.stderr, "visible-end")) {
					t.Errorf("the printable part of the message is missing:\n%s", res.stderr)
				}
				if strings.Contains(res.stderr, "FAKE: rypt: success\n") {
					t.Errorf("a server message forged a line of output:\n%q", res.stderr)
				}
			})
		}
	}
}

// TestTokenEchoedByServer: a server that echoes the bearer token back does
// not get it printed.
func TestTokenEchoedByServer(t *testing.T) {
	t.Parallel()
	cases := map[string]fault{
		"message and request_id": echoToken(),
		"status line": func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			rawConn("HTTP/1.1 4xx "+tok+"\r\n\r\n")(m, w, r, c)
		},
		"header": func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
			w.Header().Set("X-Request-Id", r.Header.Get("Authorization"))
			rawResponse(403, "text/plain", "nope")(m, w, r, c)
		},
		"control characters inside the echoed token": func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
			tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			split := tok[:20] + "\x1b[0m" + tok[20:]
			writeAPIError(w, 400, "invalid_request", "token "+split, "id", nil)
		},
	}
	for name, f := range cases {
		for _, op := range []string{"wrap", "unwrap"} {
			t.Run(op+"/"+name, func(t *testing.T) {
				t.Parallel()
				s := newAPIScenario(t, op)
				s.h.api.script(op, f, f, f)
				res := s.run()
				expect(t, res, ExitAPI)
				s.assertFailedCleanly()
				// The harness asserts the token is absent from stdout and stderr.
			})
		}
	}
}

// TestRedirectsNotFollowed: the token and body are never re-sent to a
// redirect target.
func TestRedirectsNotFollowed(t *testing.T) {
	t.Parallel()
	var elsewhere atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		elsewhere.Add(1)
		writeJSON(w, 200, map[string]any{"dek": base64.StdEncoding.EncodeToString(make([]byte, 32)), "wrapped": "x"})
	}))
	defer other.Close()

	for _, status := range []int{301, 302, 307, 308} {
		for _, op := range []string{"wrap", "unwrap"} {
			for _, target := range []string{other.URL + "/v1/keys/" + testKeyID + "/" + op, "/v1/keys/" + otherKeyID + "/" + op} {
				s := newAPIScenario(t, op)
				s.h.api.script(op, redirect(status, target))
				res := s.run()
				if res.code != ExitAPI {
					t.Errorf("%s redirect %d to %s: exit %d, want 1\n%s", op, status, target, res.code, res.stderr)
				}
				s.wantRequests(1)
				s.assertFailedCleanly()
			}
		}
	}
	if n := elsewhere.Load(); n != 0 {
		t.Errorf("the redirect target received %d requests", n)
	}
}

// TestFailingStdout: a write error on stdout is a local I/O error.
func TestFailingStdout(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	pt := testData(100000, 2)
	ct, _ := h.craft(cipherAES, 65536, "", pt)
	res := h.invoke(invocation{args: []string{"encrypt"}, stdin: bytes.NewReader(pt), stdout: errWriter{}})
	expect(t, res, ExitIO)
	res = h.invoke(invocation{args: []string{"decrypt"}, stdin: bytes.NewReader(ct), stdout: errWriter{}})
	expect(t, res, ExitIO)
	h.wantCalls(1, 1)
}

// TestLabelAsAAD: spec §6 sends aad only when there is a label, on both
// operations.
func TestLabelAsAAD(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		args  []string
		label string
	}{
		{"no label", nil, ""},
		{"empty label", []string{"--label", ""}, ""},
		{"label", []string{"--label", "invoices/2026"}, "invoices/2026"},
		{"label with NUL and newline", []string{"--label", "a\x00b\nc"}, "a\x00b\nc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			pt := []byte("aad test")
			ct := h.encryptFixture("f.rypt", pt, c.args...)
			h.verifyEncrypted(ct, cipherAES, testKeyID, c.label)
			w := h.api.lastCall(t, "wrap")
			if c.label == "" {
				if w.aadPresent {
					t.Errorf("wrap request had an aad field (%q) without a label", w.aad)
				}
			} else if !w.aadPresent || string(w.aad) != c.label {
				t.Errorf("wrap aad = %q (present %v), want %q", w.aad, w.aadPresent, c.label)
			}

			res := h.runIn(ct, "decrypt")
			expect(t, res, ExitOK)
			if !bytes.Equal(res.stdout, pt) {
				t.Error("wrong plaintext")
			}
			u := h.api.lastCall(t, "unwrap")
			if u.wrapped != w.wrapped {
				t.Errorf("unwrap sent a wrapped value that is not the header's")
			}
			if c.label == "" {
				if u.aadPresent {
					t.Errorf("unwrap request had an aad field (%q) for a header without a label", u.aad)
				}
			} else if !u.aadPresent || string(u.aad) != c.label {
				t.Errorf("unwrap aad = %q (present %v), want %q", u.aad, u.aadPresent, c.label)
			}
			h.wantCalls(1, 1)
		})
	}
}

// TestHeaderBindingFieldsTampered: a changed label, wrapped DEK or key ID is
// refused by unwrap (exit 1) before any chunk is decrypted.
func TestHeaderBindingFieldsTampered(t *testing.T) {
	t.Parallel()
	pt := testData(140000, 4)
	cases := []struct {
		name   string
		mutate func(ct []byte, hdr specHeader)
		code   string
	}{
		{"label byte flipped", func(ct []byte, hdr specHeader) { ct[offLabel+2] ^= 0x01 }, "invalid_ciphertext"},
		{"label last byte flipped", func(ct []byte, hdr specHeader) { ct[offLabel+len(hdr.Label)-1] ^= 0x02 }, "invalid_ciphertext"},
		{"wrapped character changed", func(ct []byte, hdr specHeader) {
			p := hdr.offWrappedLen() + 4 + 100
			if ct[p] == 'A' {
				ct[p] = 'B'
			} else {
				ct[p] = 'A'
			}
		}, "invalid_ciphertext"},
		{"key ID changed to an unknown key", func(ct []byte, hdr specHeader) { ct[offKeyID+15] ^= 0x01 }, "not_found"},
		{"key ID changed to another key", func(ct []byte, hdr specHeader) { copy(ct[offKeyID:], keyIDBytes(otherKeyID)) }, "invalid_ciphertext"},
	}
	for _, c := range cases {
		for _, toStdout := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stdout=%v", c.name, toStdout), func(t *testing.T) {
				t.Parallel()
				h := newHarness(t)
				ct, hdr := h.craft(cipherAES, 65536, "label-bound", pt)
				c.mutate(ct, hdr)
				h.writeFile("f.rypt", ct)
				var res result
				if toStdout {
					res = h.run("decrypt", "-o", "-", h.path("f.rypt"))
					if len(res.stdout) != 0 {
						t.Errorf("wrote %d bytes to stdout", len(res.stdout))
					}
				} else {
					res = h.run("decrypt", h.path("f.rypt"))
				}
				expect(t, res, ExitAPI)
				h.wantCalls(0, 1)
				h.assertEntries("", "f.rypt")
				if !strings.Contains(res.stderr, c.code) {
					t.Errorf("stderr lacks %q:\n%s", c.code, res.stderr)
				}
			})
		}
	}
}
