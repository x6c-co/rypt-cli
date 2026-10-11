package cli

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// This file is an in-memory stand-in for the rypt API's wrap and unwrap
// operations, built from docs/api-notes.md. It is deliberately strict: any
// request the real API would refuse because the client got the protocol
// wrong is recorded as a violation, and every test fails on a violation.

const (
	// testToken has the documented shape: "ry_", an 8-character prefix,
	// "_", and a 32-character secret.
	testToken  = "ry_T3stPre1_Zq8vWm2nXc5bLk7jHg4fDs9aPo1iUy6t"
	testSecret = "Zq8vWm2nXc5bLk7jHg4fDs9aPo1iUy6t"
	// wrongToken is well formed but unknown to the mock.
	wrongToken = "ry_0therPfx_aaaaBBBBccccDDDDeeeeFFFFggggHHHH"

	testKeyID    = "0f8fad5b-d9cb-469f-a165-70867728950e"
	otherKeyID   = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	unknownKeyID = "123e4567-e89b-12d3-a456-426614174000"

	maxRequestBody = 128 << 10
)

var canonicalKeyID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// apiCall records one request to a wrap or unwrap path.
type apiCall struct {
	op         string // "wrap" or "unwrap"
	keyID      string // as it appeared in the path
	requestID  string
	aadPresent bool   // the request body had an "aad" field
	aad        []byte // the decoded aad ("aad": null and "" decode to nil)
	wrapped    string // unwrap: the request's wrapped value; wrap: the response's
	dek        []byte // the DEK the mock handed out on a successful response
}

// fault replaces the mock's normal response to one request.
type fault func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall)

type mockAPI struct {
	srv   *httptest.Server
	token string

	mu         sync.Mutex
	seq        int
	keys       map[string]cipher.AEAD // by lower-case key ID
	calls      []*apiCall
	otherReqs  []string // requests to any path that is not wrap or unwrap
	violations []string
	faults     map[string][]fault
	custom     map[string]customWrap // wrapped value -> DEK, for hand-made values
	deks       [][]byte              // every DEK handed out
	hook       func(op string, r *http.Request)
}

type customWrap struct {
	keyID string
	aad   string
	dek   []byte
}

// newMockAPI starts a mock that knows the given key IDs. It is closed, and
// its violations reported, when the test ends.
func newMockAPI(t testing.TB, keyIDs ...string) *mockAPI {
	t.Helper()
	m := &mockAPI{
		token:  testToken,
		keys:   map[string]cipher.AEAD{},
		faults: map[string][]fault{},
		custom: map[string]customWrap{},
	}
	for _, id := range keyIDs {
		k := make([]byte, 32)
		rand.Read(k)
		block, err := aes.NewCipher(k)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		m.keys[id] = aead
	}
	m.srv = httptest.NewServer(m)
	// Cleanups run last-in first-out: the server closes before the check.
	t.Cleanup(func() { m.checkViolations(t) })
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockAPI) URL() string { return m.srv.URL }

// script queues faults for the next requests to op ("wrap" or "unwrap").
// Each request consumes one; when the queue is empty the mock answers
// normally.
func (m *mockAPI) script(op string, fs ...fault) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.faults[op] = append(m.faults[op], fs...)
}

// setHook installs a function that runs for every wrap or unwrap request
// after the request is validated and before the response is written.
func (m *mockAPI) setHook(f func(op string, r *http.Request)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.hook = f
}

func (m *mockAPI) count(op string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.calls {
		if c.op == op {
			n++
		}
	}
	return n
}

// total is the number of HTTP requests the mock received on any path.
func (m *mockAPI) total() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.calls) + len(m.otherReqs)
}

// callsOf returns copies of the recorded calls to op, oldest first.
func (m *mockAPI) callsOf(op string) []apiCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []apiCall
	for _, c := range m.calls {
		if c.op == op {
			out = append(out, *c)
		}
	}
	return out
}

// lastCall returns the most recent call to op, failing the test if none.
func (m *mockAPI) lastCall(t testing.TB, op string) apiCall {
	t.Helper()
	cs := m.callsOf(op)
	if len(cs) == 0 {
		t.Fatalf("mock: no %s request was received", op)
	}
	return cs[len(cs)-1]
}

// issuedDEKs returns every DEK the mock has handed out.
func (m *mockAPI) issuedDEKs() [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([][]byte(nil), m.deks...)
}

func (m *mockAPI) checkViolations(t testing.TB) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, v := range m.violations {
		t.Errorf("mock API: protocol violation: %s", v)
	}
	m.violations = nil
}

func (m *mockAPI) violate(format string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.violations = append(m.violations, fmt.Sprintf(format, args...))
}

// issue wraps a new DEK under keyID with aad directly, without HTTP and
// without counting a request. Tests use it to build files for decrypt.
func (m *mockAPI) issue(keyID string, aad []byte) (dek []byte, wrapped string) {
	dek = make([]byte, 32)
	rand.Read(dek)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deks = append(m.deks, dek)
	return dek, m.seal(keyID, aad, dek)
}

// issueCustom makes unwrap of exactly wrapped (under keyID and aad) return a
// new DEK, so tests can use wrapped values of any shape.
func (m *mockAPI) issueCustom(keyID string, aad []byte, wrapped string) []byte {
	dek := make([]byte, 32)
	rand.Read(dek)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deks = append(m.deks, dek)
	m.custom[wrapped] = customWrap{keyID: keyID, aad: string(aad), dek: dek}
	return dek
}

// The wrapped value is 188 base64 characters, like the live hsm-tier
// values: a 79-byte prefix (starting 0a 24 00, as observed), a 12-byte
// nonce and the 48-byte AES-GCM sealing of the DEK. The key ID and the aad
// are bound as associated data, so a changed aad, key ID or wrapped value
// is refused with invalid_ciphertext.
const wrapPrefixLen = 79

func wrapPrefix(keyID string) []byte {
	p := make([]byte, 0, wrapPrefixLen)
	p = append(p, 0x0a, 0x24, 0x00)
	for len(p) < wrapPrefixLen {
		s := sha256.Sum256(append([]byte(keyID), byte(len(p))))
		p = append(p, s[:]...)
	}
	return p[:wrapPrefixLen]
}

func wrapAD(prefix []byte, keyID string, aad []byte) []byte {
	ad := []byte("rypt-mock-wrap")
	ad = append(ad, prefix...)
	ad = append(ad, keyID...)
	ad = binary.BigEndian.AppendUint32(ad, uint32(len(aad)))
	return append(ad, aad...)
}

// seal is called with m.mu held.
func (m *mockAPI) seal(keyID string, aad, dek []byte) string {
	aead := m.keys[keyID]
	if aead == nil {
		// An unknown key: a value of the right shape that never unwraps.
		b := make([]byte, wrapPrefixLen+12+48)
		rand.Read(b)
		return base64.StdEncoding.EncodeToString(b)
	}
	prefix := wrapPrefix(keyID)
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)
	out := append(append([]byte{}, prefix...), nonce...)
	out = aead.Seal(out, nonce, dek, wrapAD(prefix, keyID, aad))
	return base64.StdEncoding.EncodeToString(out)
}

// open is called with m.mu held.
func (m *mockAPI) open(keyID string, aad []byte, wrapped string) ([]byte, bool) {
	if c, ok := m.custom[wrapped]; ok {
		if c.keyID == keyID && c.aad == string(aad) {
			return c.dek, true
		}
		return nil, false
	}
	aead := m.keys[keyID]
	if aead == nil {
		return nil, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(wrapped)
	if err != nil || len(raw) < wrapPrefixLen+aead.NonceSize()+aead.Overhead() {
		return nil, false
	}
	prefix := raw[:wrapPrefixLen]
	nonce := raw[wrapPrefixLen : wrapPrefixLen+aead.NonceSize()]
	dek, err := aead.Open(nil, nonce, raw[wrapPrefixLen+aead.NonceSize():], wrapAD(prefix, keyID, aad))
	if err != nil {
		return nil, false
	}
	return dek, true
}

var opPath = regexp.MustCompile(`^/v1/keys/([^/]+)/(wrap|unwrap)$`)

func (m *mockAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.seq++
	requestID := fmt.Sprintf("req-%04d-%s", m.seq, randomHex(6))
	m.mu.Unlock()
	w.Header().Set("X-Request-Id", requestID)

	match := opPath.FindStringSubmatch(r.URL.EscapedPath())
	if match == nil {
		m.mu.Lock()
		m.otherReqs = append(m.otherReqs, r.Method+" "+r.URL.String())
		m.mu.Unlock()
		m.violate("request to unexpected path %s %s", r.Method, r.URL.String())
		writeAPIError(w, http.StatusNotFound, "not_found", "not found", requestID, nil)
		return
	}
	c := &apiCall{op: match[2], keyID: match[1], requestID: requestID}
	m.mu.Lock()
	m.calls = append(m.calls, c)
	m.mu.Unlock()

	if !m.validate(w, r, c) {
		return
	}

	m.mu.Lock()
	hook := m.hook
	m.mu.Unlock()
	if hook != nil {
		hook(c.op, r)
	}

	m.mu.Lock()
	var f fault
	if q := m.faults[c.op]; len(q) > 0 {
		f, m.faults[c.op] = q[0], q[1:]
	}
	m.mu.Unlock()
	if f != nil {
		f(m, w, r, c)
		return
	}

	m.respond(w, c)
}

// validate checks the request the way the API does. It records a violation
// for anything a correct client never sends, writes the API's error
// response, and returns false when the request cannot proceed.
func (m *mockAPI) validate(w http.ResponseWriter, r *http.Request, c *apiCall) bool {
	fail := func(status int, code, msg string) bool {
		writeAPIError(w, status, code, msg, c.requestID, nil)
		return false
	}
	if r.Method != http.MethodPost {
		m.violate("%s %s: method is not POST", r.Method, r.URL.Path)
		w.Header().Set("Allow", "POST")
		return fail(http.StatusMethodNotAllowed, "method_not_allowed", "method not allowed")
	}
	if !canonicalKeyID.MatchString(c.keyID) {
		m.violate("%s: key ID %q in the path is not a lower-case canonical UUID", c.op, c.keyID)
	}
	if r.URL.RawQuery != "" {
		m.violate("%s: unexpected query %q", c.op, r.URL.RawQuery)
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+m.token {
		if !strings.HasPrefix(got, "Bearer ry_") {
			m.violate("%s: Authorization header is not a bearer ry_ token", c.op)
		}
		return fail(http.StatusUnauthorized, "unauthorized", "missing or invalid API key")
	}
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		m.violate("%s: Content-Type is %q, not application/json", c.op, r.Header.Get("Content-Type"))
		return fail(http.StatusUnsupportedMediaType, "unsupported_media_type", "content-type must be application/json")
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRequestBody+1))
	if err != nil {
		m.violate("%s: reading the body: %v", c.op, err)
		return fail(http.StatusBadRequest, "invalid_request", "cannot read body")
	}
	if len(body) > maxRequestBody {
		m.violate("%s: body over 128 KiB", c.op)
		return fail(http.StatusRequestEntityTooLarge, "payload_too_large", "request body too large")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil || fields == nil {
		m.violate("%s: body is not a JSON object: %q", c.op, body)
		return fail(http.StatusBadRequest, "invalid_request", "invalid JSON body")
	}
	allowed := map[string]bool{"aad": true}
	if c.op == "unwrap" {
		allowed["wrapped"] = true
	}
	for name := range fields {
		if !allowed[name] {
			// This includes "dek" on wrap: the program never supplies one.
			m.violate("%s: unexpected field %q in the request body", c.op, name)
			return fail(http.StatusBadRequest, "invalid_request", "unexpected field "+name)
		}
	}
	if raw, ok := fields["aad"]; ok {
		c.aadPresent = true
		var s *string
		if err := json.Unmarshal(raw, &s); err != nil {
			m.violate("%s: aad is not a string: %s", c.op, raw)
			return fail(http.StatusBadRequest, "invalid_request", "aad must be a string")
		}
		if s != nil && *s != "" {
			aad, err := base64.StdEncoding.Strict().DecodeString(*s)
			if err != nil {
				m.violate("%s: aad is not standard padded base64: %q", c.op, *s)
				return fail(http.StatusBadRequest, "invalid_base64", "aad is not valid base64")
			}
			c.aad = aad
		}
	}
	if c.op == "unwrap" {
		raw, ok := fields["wrapped"]
		if !ok || json.Unmarshal(raw, &c.wrapped) != nil || c.wrapped == "" {
			m.violate("unwrap: wrapped is missing, empty or not a string")
			return fail(http.StatusBadRequest, "invalid_request", "wrapped is required")
		}
	}
	return true
}

// respond writes the normal answer of a working API.
func (m *mockAPI) respond(w http.ResponseWriter, c *apiCall) {
	keyID := strings.ToLower(c.keyID)
	m.mu.Lock()
	_, known := m.keys[keyID]
	m.mu.Unlock()
	if !known {
		writeAPIError(w, http.StatusNotFound, "not_found", "key not found", c.requestID, nil)
		return
	}
	switch c.op {
	case "wrap":
		dek := make([]byte, 32)
		rand.Read(dek)
		m.mu.Lock()
		wrapped := m.seal(keyID, c.aad, dek)
		m.deks = append(m.deks, dek)
		c.wrapped, c.dek = wrapped, dek
		m.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{
			"dek":     base64.StdEncoding.EncodeToString(dek),
			"wrapped": wrapped,
		})
	case "unwrap":
		m.mu.Lock()
		dek, ok := m.open(keyID, c.aad, c.wrapped)
		if ok {
			c.dek = dek
		}
		m.mu.Unlock()
		if !ok {
			writeAPIError(w, http.StatusBadRequest, "invalid_ciphertext", "ciphertext or aad invalid", c.requestID, nil)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"dek": base64.StdEncoding.EncodeToString(dek)})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(body)
}

func writeAPIError(w http.ResponseWriter, status int, code, msg, requestID string, extra map[string]any) {
	body := map[string]any{"error": code, "message": msg, "request_id": requestID}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Faults.

// apiErr answers with the API error envelope.
func apiErr(status int, code, msg string) fault {
	return apiErrExtra(status, code, msg, nil)
}

func apiErrExtra(status int, code, msg string, extra map[string]any) fault {
	return func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
		writeAPIError(w, status, code, msg, c.requestID, extra)
	}
}

// rawResponse answers with an arbitrary body.
func rawResponse(status int, contentType, body string) fault {
	return func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}
}

// okBody answers 200 with the JSON built by body from a real DEK and wrapped
// value for the request (wrapped is empty for unwrap). The DEK is recorded
// as issued.
func okBody(body func(dek []byte, wrapped string) any) fault {
	return func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
		dek, wrapped := m.issue(strings.ToLower(c.keyID), c.aad)
		if c.op == "unwrap" {
			wrapped = ""
		}
		v := body(dek, wrapped)
		if s, ok := v.(string); ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			io.WriteString(w, s)
			return
		}
		writeJSON(w, http.StatusOK, v)
	}
}

// hijack takes over the connection and hands it to f, then closes it.
func hijack(f func(conn net.Conn, buf *bufio.ReadWriter)) fault {
	return func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			panic("mock: response writer cannot hijack")
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			panic(err)
		}
		defer conn.Close()
		if f != nil {
			f(conn, buf)
			buf.Flush()
		}
	}
}

// dropConn closes the connection without answering.
func dropConn() fault { return hijack(nil) }

// truncatedBody sends a 200 whose body ends early.
func truncatedBody() fault {
	return hijack(func(conn net.Conn, buf *bufio.ReadWriter) {
		buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 400\r\n\r\n{\"dek\":\"AAAA")
	})
}

// rawConn writes raw bytes as the whole response and closes the connection.
func rawConn(raw string) fault {
	return hijack(func(conn net.Conn, buf *bufio.ReadWriter) {
		buf.WriteString(raw)
	})
}

// redirect answers with a redirect to location.
func redirect(status int, location string) fault {
	return func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
		w.Header().Set("Location", location)
		w.WriteHeader(status)
	}
}

// echoToken answers 400 with the bearer token echoed in the message and the
// request ID, as a careless server might.
func echoToken() fault {
	return func(m *mockAPI, w http.ResponseWriter, r *http.Request, c *apiCall) {
		auth := r.Header.Get("Authorization")
		tok := strings.TrimPrefix(auth, "Bearer ")
		writeAPIError(w, http.StatusBadRequest, "invalid_request",
			"bad token "+tok+" ("+auth+")", "rid-"+tok, nil)
	}
}

// bytesContainAny reports whether any of needles occurs in haystack.
func bytesContainAny(haystack []byte, needles ...[]byte) bool {
	for _, n := range needles {
		if len(n) > 0 && bytes.Contains(haystack, n) {
			return true
		}
	}
	return false
}
