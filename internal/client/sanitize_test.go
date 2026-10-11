package client

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// assertPrintable fails if s holds a rune that sanitize must remove, or
// invalid UTF-8.
func assertPrintable(t *testing.T, what, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Errorf("%s %q is not valid UTF-8", what, s)
	}
	for _, r := range s {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			t.Errorf("%s %q contains %U", what, s, r)
		}
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"plain text", "plain text"},
		{"\x1b[31mred\x1b[0m", "[31mred[0m"},
		{"\x1b]0;title\x07x", "]0;titlex"},
		{"a\r\nb\tc\x00d\x7fe\x08f", "abcdef"},
		{"C1: \u0085\u009b2J\u0090end", "C1: 2Jend"},
		{"rtl \u202egnp.exe\u202c zw\u200bsp\u200c\u200d\u2060 bom\ufeff shy\u00ad", "rtl gnp.exe zwsp bom shy"},
		{"iso \u2066x\u2069 lsep\u2028psep\u2029", "iso x lseppsep"},
		{"bad \xff\xfe utf8", "bad \ufffd\ufffd utf8"},
		{"  \t padded \n ", "padded"},
		{"unicode ok: \u00e9 \u00fc \u65e5\u672c \U0001f600", "unicode ok: \u00e9 \u00fc \u65e5\u672c \U0001f600"},
	}
	for _, tt := range tests {
		if got := sanitize(tt.in); got != tt.want {
			t.Errorf("sanitize(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSanitizeTruncates(t *testing.T) {
	for _, unit := range []string{"a", "\u00e9", "\u65e5", "\U0001f600", "a\x1b"} {
		in := strings.Repeat(unit, 2000)
		got := sanitize(in)
		if len(got) > maxServerText || !strings.HasSuffix(got, "...") {
			t.Errorf("unit %q: got %d bytes, suffix %q", unit, len(got), got[max(0, len(got)-3):])
		}
		if len(got) < maxServerText-8 {
			t.Errorf("unit %q: cut too short, %d bytes", unit, len(got))
		}
		assertPrintable(t, "truncated", got)
	}
	exact := strings.Repeat("a", maxServerText)
	if got := sanitize(exact); got != exact {
		t.Errorf("a %d-byte string was changed", maxServerText)
	}
	// Removed characters do not count toward the cap.
	if got := sanitize(strings.Repeat("\x1b", 1000) + exact); got != exact {
		t.Error("control characters counted toward the cap")
	}
}

// nasty holds every kind of character that must not reach a terminal.
const nasty = "\x1b[2J\x1b]8;;http://evil\x07\r\n\t\x00\x7f\u0085\u009b\u202e\u200b\u2028\xff"

func TestServerTextSanitizedEndToEnd(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"error":      "ops_" + nasty + "cap_reached",
		"message":    "msg" + nasty + strings.Repeat("m", 2000),
		"request_id": "id" + nasty + "-1",
		"cap":        10,
		"resets_at":  "2026-11-01" + nasty + "T00:00:00Z",
	})
	s := newScriptServer(t, respond(http.StatusTooManyRequests, string(body)))
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	// json.Marshal turns the invalid byte into U+FFFD, which is kept.
	if e.Code != "ops_[2J]8;;http://evil\ufffdcap_reached" {
		t.Errorf("Code = %q", e.Code)
	}
	if e.RequestID != "id[2J]8;;http://evil\ufffd-1" {
		t.Errorf("RequestID = %q", e.RequestID)
	}
	if e.ResetsAt != "2026-11-01[2J]8;;http://evil\ufffdT00:00:00Z" {
		t.Errorf("ResetsAt = %q", e.ResetsAt)
	}
	if len(e.Message) > maxServerText || !strings.HasPrefix(e.Message, "msg[2J]") {
		t.Errorf("Message has %d bytes: %.40q", len(e.Message), e.Message)
	}
	for what, v := range map[string]string{
		"Code": e.Code, "Message": e.Message, "RequestID": e.RequestID, "ResetsAt": e.ResetsAt, "Error()": err.Error(),
	} {
		assertPrintable(t, what, v)
	}
}

func TestRequestIDHeaderSanitized(t *testing.T) {
	// Of the runes sanitize removes, these are the ones net/http lets
	// through in a header value; the rest make the response malformed.
	header := "hdr\t\u202e\u200b\u0085\u2028\xff-9"
	step := func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header()["X-Request-Id"] = []string{header}
		w.WriteHeader(http.StatusBadGateway)
	}
	s := newScriptServer(t, step)
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if e.RequestID != "hdr\ufffd-9" {
		t.Errorf("RequestID = %q", e.RequestID)
	}
	assertPrintable(t, "Error()", err.Error())

	// The same header on a malformed 200.
	step = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header()["X-Request-Id"] = []string{header}
		_, _ = w.Write([]byte("{}"))
	}
	s = newScriptServer(t, step)
	_, err = newTestClient(t, s.URL).Unwrap(ctxTimeout(t), testKeyID, "w", nil)
	if e := asError(t, err); e.Kind != KindResponse || e.RequestID != "hdr\ufffd-9" {
		t.Errorf("got %+v", e)
	}
}

func TestMalformedHeaderTransportError(t *testing.T) {
	// net/http refuses an ESC in a header and quotes the line in its error.
	step := func(w http.ResponseWriter, r *http.Request, n int) {
		conn, buf, _ := w.(http.Hijacker).Hijack()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nX-Request-Id: a\x1b[2Jb\u202e\r\nContent-Length: 2\r\n\r\n{}")
		_ = buf.Flush()
		conn.Close()
	}
	s := newScriptServer(t, step)
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	if e := asError(t, err); e.Kind != KindTransport {
		t.Errorf("got %+v", e)
	}
	assertPrintable(t, "Error()", err.Error())
}

func TestServerEchoedTokenRedacted(t *testing.T) {
	// A server that echoes the token, even split by control characters,
	// must not get it into an error.
	split := testToken[:20] + "\x1b\u200b" + testToken[20:]
	// Without redaction, the second token would straddle the truncation
	// point, 20 bytes of it before the cut.
	filler := strings.Repeat("x", maxServerText-len("...")-20-len("bad token ")-len(testToken)-1)
	body, _ := json.Marshal(map[string]string{
		"error":      "unauthorized",
		"message":    "bad token " + split + " " + filler + testToken,
		"request_id": testToken,
		"resets_at":  "Bearer " + testToken,
	})
	step := func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("X-Request-Id", "id-"+testToken)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write(body)
	}
	s := newScriptServer(t, step)
	_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	e := asError(t, err)
	if !strings.Contains(e.Message, "[redacted]") || e.RequestID != "[redacted]" {
		t.Errorf("got %+v", e)
	}
	// Every 8-byte piece of the secret, so that a truncated token is caught.
	for i := 0; i+8 <= len(testSecret); i++ {
		if piece := testSecret[i : i+8]; strings.Contains(err.Error(), piece) {
			t.Errorf("Error() %q holds part of the token (%q)", err, piece)
		}
	}
	assertNoSecrets(t, err)

	// A header-only echo, on a non-JSON body.
	step = func(w http.ResponseWriter, r *http.Request, n int) {
		w.Header().Set("X-Request-Id", testToken)
		w.WriteHeader(http.StatusForbidden)
	}
	s = newScriptServer(t, step)
	_, err = newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
	if e := asError(t, err); e.RequestID != "[redacted]" {
		t.Errorf("got %+v", e)
	}
	assertNoSecrets(t, err)
}

func TestTransportErrorRedactsToken(t *testing.T) {
	// net/http quotes a malformed status or header line in its error, so a
	// server that echoes the token there must not get it into an error.
	for name, raw := range map[string]string{
		"header line": "HTTP/1.1 200 OK\r\nX-Echo " + testToken + "\r\nContent-Length: 2\r\n\r\n{}",
		"version":     testToken + " 200 OK\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			step := func(w http.ResponseWriter, r *http.Request, n int) {
				conn, buf, _ := w.(http.Hijacker).Hijack()
				_, _ = buf.WriteString(raw)
				_ = buf.Flush()
				conn.Close()
			}
			s := newScriptServer(t, step)
			_, err := newTestClient(t, s.URL).Wrap(ctxTimeout(t), testKeyID, nil)
			e := asError(t, err)
			if e.Kind != KindTransport || !strings.Contains(err.Error(), "[redacted]") {
				t.Errorf("got %v", err)
			}
			for _, text := range []string{err.Error(), e.Err.Error()} {
				for i := 0; i+8 <= len(testSecret); i++ {
					if piece := testSecret[i : i+8]; strings.Contains(text, piece) {
						t.Fatalf("error text %q holds part of the token (%q)", text, piece)
					}
				}
				assertPrintable(t, "error text", text)
			}
			assertNoSecrets(t, err)
		})
	}
}
