package client

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
)

// b64 is the standard padded base64 of n bytes of 0xfb, which encodes with
// '+' and '/' characters.
func b64(n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, n))
}

func TestMalformedOK(t *testing.T) {
	dek := b64(32)
	urlDEK := base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))
	rawDEK := base64.RawStdEncoding.EncodeToString(bytes.Repeat([]byte{0xfb}, 32))
	tests := []struct {
		name   string
		wrap   bool
		body   string
		prefix string // of the expected Message
	}{
		{"not JSON", true, "<html>" + leakMarker + " " + dek + "</html>", "response is not valid JSON"},
		{"empty body", true, "", "response is not valid JSON"},
		{"trailing data", true, `{"dek":"` + dek + `","wrapped":"w"} ` + leakMarker, "response is not valid JSON"},
		{"JSON array", true, `["` + leakMarker + `"]`, "response is not a JSON object"},
		{"JSON string", false, `"` + leakMarker + `"`, "response is not a JSON object"},
		{"missing dek", true, `{"wrapped":"w"}`, "dek is missing"},
		{"null dek", true, `{"dek":null,"wrapped":"w"}`, "dek is missing"},
		{"empty dek", true, `{"dek":"","wrapped":"w"}`, "dek is not 32 bytes"},
		{"16-byte dek", true, `{"dek":"` + b64(16) + `","wrapped":"w"}`, "dek is not 32 bytes"},
		{"33-byte dek", true, `{"dek":"` + b64(33) + `","wrapped":"w"}`, "dek is not 32 bytes"},
		{"invalid base64 dek", true, `{"dek":"` + leakMarker + `!!","wrapped":"w"}`, "dek is not"},
		{"url-safe base64 dek", true, `{"dek":"` + urlDEK + `","wrapped":"w"}`, "dek is not"},
		{"unpadded dek", true, `{"dek":"` + rawDEK + `","wrapped":"w"}`, "dek is not"},
		{"numeric dek", true, `{"dek":12345,"wrapped":"w"}`, "dek is not"},
		{"missing wrapped", true, `{"dek":"` + dek + `"}`, "wrapped is missing or empty"},
		{"empty wrapped", true, `{"dek":"` + dek + `","wrapped":""}`, "wrapped is missing or empty"},
		{"null wrapped", true, `{"dek":"` + dek + `","wrapped":null}`, "wrapped is missing or empty"},
		{"numeric wrapped", true, `{"dek":"` + dek + `","wrapped":12345}`, "wrapped is not a string"},
		// encoding/json would turn both into U+FFFD, changing the value.
		{"wrapped invalid UTF-8", true, `{"dek":"` + dek + `","wrapped":"CiQA` + "\xff\xfe" + `AA=="}`, "wrapped is not valid UTF-8"},
		{"wrapped lone surrogate", true, `{"dek":"` + dek + `","wrapped":"CiQA\udc00AA=="}`, "wrapped is not valid UTF-8"},
		{"wrapped too long", true, `{"dek":"` + dek + `","wrapped":"` + strings.Repeat("A", maxWrappedLen+1) + `"}`, "wrapped is longer than 65536 bytes"},
		{"unwrap null", false, `null`, "dek is missing"},
		{"unwrap empty object", false, `{}`, "dek is missing"},
		{"unwrap 31-byte dek", false, `{"dek":"` + b64(31) + `"}`, "dek is not 32 bytes"},
		{"unwrap invalid base64 dek", false, `{"dek":"` + leakMarker + `"}`, "dek is not"},
		{"unwrap too large", false, `{"dek":"` + dek + `","pad":"` + strings.Repeat(" ", maxResponseBytes) + `"}`, "response too large"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScriptServer(t, respond(http.StatusOK, tt.body), okWrap())
			c := newTestClient(t, s.URL)
			var err error
			if tt.wrap {
				var res *WrapResult
				res, err = c.Wrap(ctxTimeout(t), testKeyID, nil)
				if res != nil {
					t.Error("got a result with the error")
				}
			} else {
				var got []byte
				got, err = c.Unwrap(ctxTimeout(t), testKeyID, "w", nil)
				if got != nil {
					t.Error("got a DEK with the error")
				}
			}
			e := asError(t, err)
			if e.Kind != KindResponse || e.StatusCode != http.StatusOK || e.Attempts != 1 || e.RequestID != "hdr-1" {
				t.Errorf("got %+v", e)
			}
			if !strings.HasPrefix(e.Message, tt.prefix) {
				t.Errorf("Message = %q, want prefix %q", e.Message, tt.prefix)
			}
			if !strings.HasPrefix(err.Error(), "malformed API response (HTTP 200): ") ||
				!strings.HasSuffix(err.Error(), " (request_id hdr-1)") {
				t.Errorf("Error() = %q", err)
			}
			if s.count() != 1 {
				t.Errorf("server saw %d requests, want 1", s.count())
			}
			assertNoSecrets(t, err, leakMarker, dek, urlDEK, rawDEK, "illegal", "base64 data", "json")
		})
	}
}

func TestResponseSizeLimit(t *testing.T) {
	dek := base64.StdEncoding.EncodeToString(fixedDEK)
	head := `{"dek":"` + dek + `","wrapped":"w",`
	pad := func(total int) string {
		// "x":"<spaces>"} padded to total bytes.
		return head + `"x":"` + strings.Repeat(" ", total-len(head)-len(`"x":""}`)) + `"}`
	}
	exact, over := pad(maxResponseBytes), pad(maxResponseBytes+1)
	if len(exact) != maxResponseBytes || len(over) != maxResponseBytes+1 {
		t.Fatal("bad padding")
	}

	// chunked sends the body without a Content-Length.
	chunked := func(body string) step {
		return func(w http.ResponseWriter, r *http.Request, n int) {
			w.Header().Set("X-Request-Id", "hdr")
			w.WriteHeader(http.StatusOK)
			for b := []byte(body); len(b) > 0; {
				k := min(len(b), 4000)
				_, _ = w.Write(b[:k])
				w.(http.Flusher).Flush()
				b = b[k:]
			}
		}
	}
	withLength := func(body string) step {
		return func(w http.ResponseWriter, r *http.Request, n int) {
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, body)
		}
	}
	for name, st := range map[string]func(string) step{"chunked": chunked, "content-length": withLength} {
		s := newScriptServer(t, st(exact))
		if res, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil); err != nil || !bytes.Equal(res.DEK, fixedDEK) {
			t.Errorf("%s: a %d-byte response: %v", name, maxResponseBytes, err)
		}
		s = newScriptServer(t, st(over))
		_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
		if e := asError(t, err); e.Kind != KindResponse || e.Message != "response too large" {
			t.Errorf("%s: a %d-byte response: got %+v", name, maxResponseBytes+1, e)
		}
		if s.count() != 1 {
			t.Errorf("%s: server saw %d requests, want 1", name, s.count())
		}
	}
}

func TestReadBody(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), 2000)
	for _, hint := range []int64{-1, 0, 5, int64(len(data)), int64(len(data)) + 10, maxResponseBytes, 1 << 40} {
		buf, tooLarge, err := readBody(iotest.OneByteReader(bytes.NewReader(data)), hint)
		if err != nil || tooLarge || !bytes.Equal(buf, data) {
			t.Errorf("hint %d: got %d bytes, tooLarge %v, err %v", hint, len(buf), tooLarge, err)
		}
	}
	buf, tooLarge, err := readBody(bytes.NewReader(make([]byte, maxResponseBytes+10)), -1)
	if err != nil || !tooLarge || len(buf) != maxResponseBytes+1 {
		t.Errorf("oversize: got %d bytes, tooLarge %v, err %v", len(buf), tooLarge, err)
	}
	boom := errors.New("boom")
	if _, _, err := readBody(io.MultiReader(bytes.NewReader(data), iotest.ErrReader(boom)), -1); !errors.Is(err, boom) {
		t.Errorf("read error: got %v", err)
	}
}

// recordingReader remembers every slice it filled.
type recordingReader struct {
	r     io.Reader
	reads [][]byte
}

func (rr *recordingReader) Read(p []byte) (int, error) {
	n, err := rr.r.Read(p)
	rr.reads = append(rr.reads, p[:n])
	return n, err
}

func TestReadBodyClearsOutgrownBuffers(t *testing.T) {
	data := bytes.Repeat([]byte{0xa5}, 50000)
	rr := &recordingReader{r: bytes.NewReader(data)}
	buf, _, err := readBody(rr, -1)
	if err != nil || !bytes.Equal(buf, data) {
		t.Fatalf("readBody: %v", err)
	}
	// Slices that share the final buffer's backing array end where it ends.
	end := &buf[:cap(buf)][cap(buf)-1]
	outgrown := 0
	for _, p := range rr.reads {
		if len(p) == 0 || &p[:cap(p)][cap(p)-1] == end {
			continue
		}
		outgrown++
		if !bytes.Equal(p, make([]byte, len(p))) {
			t.Fatal("an outgrown buffer still holds body bytes")
		}
	}
	if outgrown == 0 {
		t.Fatal("the buffer never grew; the test checks nothing")
	}
}

func TestDecodeDEKZeroesOnError(t *testing.T) {
	for _, body := range []string{
		`{"dek":"` + b64(32) + `"}`,                 // wrapped missing
		`{"dek":"` + b64(32) + `","wrapped":5}`,     // wrapped not a string
		`{"dek":"` + b64(32) + `","wrapped":""}`,    // wrapped empty
		`{"dek":"` + b64(32) + `","dek":7}`,         // decode error after the DEK
		`{"dek":"` + b64(32) + `","wrapped":"w"} x`, // trailing data
		`{"dek":"` + b64(33) + `","wrapped":"w"}`,   // wrong length
	} {
		var res dekFields
		wrapped, problem := decodeDEK([]byte(body), true, &res)
		if problem == "" || wrapped != "" {
			t.Errorf("%.40s...: got %q, %q", body, wrapped, problem)
		}
		if !bytes.Equal(res.DEK, make([]byte, len(res.DEK))) {
			t.Errorf("%.40s...: DEK not zeroed after %q", body, problem)
		}
	}

	var res dekFields
	if _, problem := decodeDEK([]byte(`{"dek":"`+b64(32)+`"}`), false, &res); problem != "" || len(res.DEK) != 32 {
		t.Errorf("unwrap shape: %q, %d bytes", problem, len(res.DEK))
	}
	// An unwrap response may carry other fields of any type.
	res = dekFields{}
	if _, problem := decodeDEK([]byte(`{"dek":"`+b64(32)+`","wrapped":5,"extra":[1]}`), false, &res); problem != "" {
		t.Errorf("extra fields: %q", problem)
	}
}

func TestReplyDecodeClearsBody(t *testing.T) {
	tests := []struct {
		body        string
		wantWrapped bool
		problem     string
	}{
		{`{"dek":"` + b64(32) + `","wrapped":"w"}`, true, ""},
		{`{"dek":"` + b64(32) + `"}`, false, ""},
		{`{"dek":"` + b64(32) + `"}`, true, "wrapped is missing or empty"},
		{`{"dek":"` + b64(16) + `"}`, false, "dek is not 32 bytes"},
		{`not JSON ` + b64(32), false, "response is not valid JSON"},
	}
	for _, tt := range tests {
		rep := &reply{body: []byte(tt.body), requestID: "r", attempts: 2}
		var res dekFields
		wrapped, err := rep.decode(tt.wantWrapped, &res)
		if !bytes.Equal(rep.body, make([]byte, len(rep.body))) {
			t.Errorf("%.30s...: the body was not cleared", tt.body)
		}
		if tt.problem != "" {
			e := asError(t, err)
			if e.Kind != KindResponse || e.Message != tt.problem || e.RequestID != "r" || e.Attempts != 2 || wrapped != "" {
				t.Errorf("%.30s...: got %q, %+v", tt.body, wrapped, e)
			}
			continue
		}
		// The DEK must not share memory with the cleared body.
		if err != nil || !bytes.Equal(res.DEK, bytes.Repeat([]byte{0xfb}, 32)) {
			t.Errorf("%.30s...: got DEK %x, %v", tt.body, res.DEK, err)
		}
		if tt.wantWrapped && wrapped != "w" {
			t.Errorf("%.30s...: wrapped = %q", tt.body, wrapped)
		}
	}
}

func TestOpsCapReached(t *testing.T) {
	body := `{"error":"ops_cap_reached","message":"monthly operation cap reached","request_id":"req-cap-1",` +
		`"cap":10000,"resets_at":"2026-11-01T00:00:00Z"}`
	s := newScriptServer(t, respond(http.StatusTooManyRequests, body), okWrap())
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.Kind != KindAPI || e.StatusCode != 429 || e.Code != "ops_cap_reached" || e.Cap != 10000 ||
		e.ResetsAt != "2026-11-01T00:00:00Z" || e.RequestID != "req-cap-1" || e.Attempts != 1 {
		t.Errorf("got %+v", e)
	}
	want := "API error ops_cap_reached (HTTP 429): monthly operation cap reached; cap 10000, resets at 2026-11-01T00:00:00Z (request_id req-cap-1)"
	if err.Error() != want {
		t.Errorf("Error() = %q, want %q", err, want)
	}
	for _, s := range []string{"ops_cap_reached", "2026-11-01T00:00:00Z", "req-cap-1"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("Error() lacks %q", s)
		}
	}
	if s.count() != 1 {
		t.Errorf("server saw %d requests, want 1", s.count())
	}
}

func TestRateLimitedNotRetried(t *testing.T) {
	s := newScriptServer(t, respond(http.StatusTooManyRequests, envelope("rate_limited", "slow down", "req-rl")), okWrap())
	_, err := newTestClient(t, s.URL).Unwrap(ctxTimeout(t), testKeyID, "w", nil)
	e := asError(t, err)
	if e.Code != "rate_limited" || e.StatusCode != 429 || e.Cap != 0 || e.ResetsAt != "" || s.count() != 1 {
		t.Errorf("got %+v after %d requests", e, s.count())
	}
	if want := "API error rate_limited (HTTP 429): slow down (request_id req-rl)"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err, want)
	}
}

func TestErrorBodies(t *testing.T) {
	tests := []struct {
		name    string
		status  int
		body    string
		code    string
		message string
		reqID   string
		cap     int64
		resets  string
	}{
		{"html", 400, "<html>" + leakMarker + "</html>", "", "unexpected HTTP 400 response", "hdr-1", 0, ""},
		{"empty", 404, "", "", "unexpected HTTP 404 response", "hdr-1", 0, ""},
		{"JSON without error", 400, `{"message":"` + leakMarker + `","request_id":"body-id"}`, "", "unexpected HTTP 400 response", "hdr-1", 0, ""},
		{"error not a string", 400, `{"error":{"code":"x"},"message":"` + leakMarker + `"}`, "", "unexpected HTTP 400 response", "hdr-1", 0, ""},
		{"no request_id in body", 404, `{"error":"not_found","message":"not found"}`, "not_found", "not found", "hdr-1", 0, ""},
		{"no message", 404, `{"error":"not_found","request_id":"body-id"}`, "not_found", "", "body-id", 0, ""},
		{"body request_id wins", 409, envelope("key_pending_deletion", "pending", "body-id"), "key_pending_deletion", "pending", "body-id", 0, ""},
		{"cap of wrong type", 429, `{"error":"ops_cap_reached","message":"m","cap":"lots","resets_at":"2026-11-01T00:00:00Z"}`,
			"ops_cap_reached", "m", "hdr-1", 0, "2026-11-01T00:00:00Z"},
		{"message of wrong type", 429, `{"error":"ops_cap_reached","message":5,"cap":7}`, "ops_cap_reached", "", "hdr-1", 7, ""},
		{"too large", 400, `{"error":"invalid_request","message":"` + strings.Repeat("a", maxResponseBytes) + `"}`,
			"", "unexpected HTTP 400 response", "hdr-1", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newScriptServer(t, respond(tt.status, tt.body))
			_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
			e := asError(t, err)
			if e.Kind != KindAPI || e.StatusCode != tt.status || e.Code != tt.code || e.Message != tt.message ||
				e.RequestID != tt.reqID || e.Cap != tt.cap || e.ResetsAt != tt.resets {
				t.Errorf("got %+v", e)
			}
			assertNoSecrets(t, err, leakMarker)
		})
	}
}

func TestNonJSONGatewayErrorAfterRetries(t *testing.T) {
	s := newScriptServer(t, respond(http.StatusBadGateway, "<html><body>502 Bad Gateway "+leakMarker+"</body></html>"))
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.Kind != KindAPI || e.StatusCode != 502 || e.Code != "" || e.Attempts != MaxAttempts || e.RequestID != "hdr-3" {
		t.Errorf("got %+v", e)
	}
	if want := "API error (HTTP 502): unexpected HTTP 502 response (request_id hdr-3)"; err.Error() != want {
		t.Errorf("Error() = %q, want %q", err, want)
	}
	if s.count() != MaxAttempts {
		t.Errorf("server saw %d requests, want %d", s.count(), MaxAttempts)
	}
	assertNoSecrets(t, err, leakMarker, "html")
}
