//go:build ignore

// probe exercises the rypt wrap and unwrap endpoints against a live server
// and prints the observed request and response shapes, for docs/api-notes.md.
//
// It reads RYPT_TOKEN and RYPT_KEY_ID (and optionally RYPT_API_URL) from the
// environment. It never prints the token or any data key: a "dek" value is
// shown only as its decoded length, and data keys are compared by hash.
//
// Each successful wrap or unwrap call costs one operation against the key's
// monthly allowance. A full run spends about ten. With -limits, the probe
// instead searches for the largest aad that wrap accepts on the key, which
// takes about twenty requests.
//
// RYPT_API_URL is checked with the same rules as rypt's: https, or plain
// http to localhost only. Redirects are not followed, and text from the
// server is printed quoted, so control characters show as escapes.
//
//	go run scripts/probe.go [-limits]
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/x6c-co/rypt"
)

var (
	base       string
	token      string
	keyID      string
	httpClient = &http.Client{
		Timeout: 30 * time.Second,
		// A redirect would re-send the token, possibly over plain http.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
)

type result struct {
	status    int
	requestID string
	headers   http.Header
	body      map[string]any
	raw       []byte
}

func main() {
	token = os.Getenv("RYPT_TOKEN")
	keyID = os.Getenv("RYPT_KEY_ID")
	if token == "" || keyID == "" {
		fmt.Fprintln(os.Stderr, "probe: RYPT_TOKEN and RYPT_KEY_ID must be set")
		os.Exit(2)
	}
	// rypt.NewClient checks the base URL with the rules rypt uses. The
	// probe sends its own requests, to see the raw responses.
	base = os.Getenv("RYPT_API_URL")
	if _, err := rypt.NewClient(token, rypt.WithBaseURL(base)); err != nil {
		fmt.Fprintln(os.Stderr, "probe: RYPT_API_URL:", strings.TrimPrefix(err.Error(), "rypt: "))
		os.Exit(2)
	}
	if base == "" {
		base = rypt.DefaultBaseURL
	}
	baseURL, _ := url.Parse(base) // valid: NewClient accepted it
	if baseURL.Scheme == "http" {
		// net/http bypasses a proxy only for the exact name "localhost".
		baseURL.Host = strings.ToLower(baseURL.Host)
	}
	base = strings.TrimRight(baseURL.String(), "/")
	fmt.Printf("base URL: %s\n\n", base)

	// Key metadata is not a metered operation.
	r := do("GET", "/v1/keys/"+keyID, nil, true)
	show("GET key metadata", r, "tier", "state", "versions", "primary_version")

	if len(os.Args) > 1 && os.Args[1] == "-limits" {
		limits()
		return
	}

	// 1. wrap with an empty object: the server generates the DEK.
	r1 := do("POST", "/v1/keys/"+keyID+"/wrap", map[string]any{}, true)
	show("wrap {}", r1)
	w1, dek1 := wrapFields(r1)

	// 2. wrap with an aad.
	aad := base64.StdEncoding.EncodeToString([]byte("probe-label"))
	r2 := do("POST", "/v1/keys/"+keyID+"/wrap", map[string]any{"aad": aad}, true)
	show("wrap {aad}", r2)
	w2, dek2 := wrapFields(r2)

	// 3. wrap with an aad of exactly 1024 bytes, the CLI's label limit.
	big := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("L"), 1024))
	r3 := do("POST", "/v1/keys/"+keyID+"/wrap", map[string]any{"aad": big}, true)
	show("wrap {aad: 1024 bytes}", r3)
	w3, dek3 := wrapFields(r3)

	// 4. unwrap #1 with no aad field.
	r4 := do("POST", "/v1/keys/"+keyID+"/unwrap", map[string]any{"wrapped": w1}, true)
	show("unwrap #1 (aad omitted)", r4)
	compare("unwrap #1 dek matches wrap #1 dek", r4, dek1)

	// 5. unwrap #2 with the right aad.
	r5 := do("POST", "/v1/keys/"+keyID+"/unwrap", map[string]any{"wrapped": w2, "aad": aad}, true)
	show("unwrap #2 (correct aad)", r5)
	compare("unwrap #2 dek matches wrap #2 dek", r5, dek2)

	// 6. unwrap #2 with the aad omitted: expect 400 invalid_ciphertext.
	r6 := do("POST", "/v1/keys/"+keyID+"/unwrap", map[string]any{"wrapped": w2}, true)
	show("unwrap #2 (aad omitted, expect refusal)", r6)

	// 7. unwrap #3 with the 1024-byte aad.
	r7 := do("POST", "/v1/keys/"+keyID+"/unwrap", map[string]any{"wrapped": w3, "aad": big}, true)
	show("unwrap #3 (1024-byte aad)", r7)
	compare("unwrap #3 dek matches wrap #3 dek", r7, dek3)

	// 8. unwrap #1 with aad "" (documented as equivalent to omitted).
	r8 := do("POST", "/v1/keys/"+keyID+"/unwrap", map[string]any{"wrapped": w1, "aad": ""}, true)
	show("unwrap #1 (aad \"\")", r8)
	compare("unwrap #1 with aad \"\" matches", r8, dek1)

	// 9. unwrap a tampered wrapped value: flip one character.
	if w1 != "" {
		t := []byte(w1)
		mid := len(t) / 2
		if t[mid] == 'A' {
			t[mid] = 'B'
		} else {
			t[mid] = 'A'
		}
		r9 := do("POST", "/v1/keys/"+keyID+"/unwrap", map[string]any{"wrapped": string(t)}, true)
		show("unwrap tampered wrapped (expect refusal)", r9)
	}

	// 10. unwrap on a random, unknown key id: expect 404.
	var u [16]byte
	rand.Read(u[:])
	u[6] = u[6]&0x0f | 0x40
	u[8] = u[8]&0x3f | 0x80
	other := fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
	r10 := do("POST", "/v1/keys/"+other+"/unwrap", map[string]any{"wrapped": w1}, true)
	show("unwrap on unknown key id (expect 404)", r10)

	// 11. wrap with no content-type header: expect 415.
	r11 := doRaw("POST", "/v1/keys/"+keyID+"/wrap", []byte("{}"), "", true)
	show("wrap without content-type (expect 415)", r11)

	// 12. wrap with invalid JSON: expect 400.
	r12 := doRaw("POST", "/v1/keys/"+keyID+"/wrap", []byte("{"), "application/json", true)
	show("wrap with invalid JSON (expect 400)", r12)

	// 13. wrap with an aad over 65,536 bytes: expect 413.
	huge := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), 65537))
	r13 := do("POST", "/v1/keys/"+keyID+"/wrap", map[string]any{"aad": huge}, true)
	show("wrap with 65,537-byte aad (expect 413)", r13)

	// 14. a body over 128 KiB: expect 413.
	r14 := doRaw("POST", "/v1/keys/"+keyID+"/wrap", append([]byte(`{"aad":"`), append(bytes.Repeat([]byte("A"), 132000), '"', '}')...), "application/json", true)
	show("wrap with a body over 128 KiB (expect 413)", r14)

	// 15. a malformed bearer token: expect 401.
	r15 := do("POST", "/v1/keys/"+keyID+"/wrap", map[string]any{}, false)
	show("wrap with a wrong token (expect 401)", r15)
}

// limits binary-searches the largest aad that wrap accepts with a generated
// DEK and checks that unwrap accepts that aad. Its last request is an unwrap
// with a one-byte-longer aad, which must fail since the aad differs; the
// status shows whether unwrap checks the size first (413) or only finds the
// mismatch (400). It does not measure unwrap's own aad limit.
func limits() {
	wrapOK := func(n int) (bool, result) {
		aad := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), n))
		r := do("POST", "/v1/keys/"+keyID+"/wrap", map[string]any{"aad": aad}, true)
		return r.status == 200, r
	}
	lo, hi := 1024, 65537 // lo is known to succeed; hi is known to fail.
	var lastFail result
	for hi-lo > 1 {
		mid := (lo + hi) / 2
		ok, r := wrapOK(mid)
		fmt.Printf("   wrap aad %6d bytes: HTTP %d\n", mid, r.status)
		if ok {
			lo = mid
		} else {
			hi, lastFail = mid, r
		}
	}
	fmt.Printf("\nlargest aad wrap accepts with a generated DEK: %d bytes\n", lo)
	if lastFail.body != nil {
		show(fmt.Sprintf("wrap with a %d-byte aad", hi), lastFail)
	}

	aad := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), lo))
	rw := do("POST", "/v1/keys/"+keyID+"/wrap", map[string]any{"aad": aad}, true)
	w, dek := wrapFields(rw)
	ru := do("POST", "/v1/keys/"+keyID+"/unwrap", map[string]any{"wrapped": w, "aad": aad}, true)
	show(fmt.Sprintf("unwrap with the %d-byte aad", lo), ru)
	compare("unwrap dek matches", ru, dek)

	over := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("a"), lo+1))
	ro := do("POST", "/v1/keys/"+keyID+"/unwrap", map[string]any{"wrapped": w, "aad": over}, true)
	show(fmt.Sprintf("unwrap with a %d-byte aad", lo+1), ro)
}

func do(method, path string, body map[string]any, auth bool) result {
	var b []byte
	if body != nil {
		b, _ = json.Marshal(body)
	}
	ct := ""
	if body != nil {
		ct = "application/json"
	}
	return doRaw(method, path, b, ct, auth)
}

func doRaw(method, path string, body []byte, contentType string, auth bool) result {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		fmt.Fprintln(os.Stderr, "probe:", err)
		os.Exit(1)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if auth {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		req.Header.Set("Authorization", "Bearer ry_AAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		// The error text names the URL, never the Authorization header, but
		// it can quote bytes the server sent.
		fmt.Fprintf(os.Stderr, "probe: request failed: %+q\n", err.Error())
		return result{}
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	return result{status: resp.StatusCode, requestID: resp.Header.Get("x-request-id"), headers: resp.Header, body: m, raw: raw}
}

// show prints the status and the body with every "dek" replaced by its
// decoded length and every "wrapped" replaced by a description.
func show(title string, r result, only ...string) {
	fmt.Printf("== %s\n", title)
	fmt.Printf("   HTTP %d, content-type %q, x-request-id present: %v\n", r.status, r.headers.Get("content-type"), r.requestID != "")
	if ra := r.headers.Get("retry-after"); ra != "" {
		fmt.Printf("   retry-after: %+q\n", ra)
	}
	if r.body == nil {
		fmt.Printf("   body (not JSON, %d bytes)\n\n", len(r.raw))
		return
	}
	keys := make([]string, 0, len(r.body))
	for k := range r.body {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Printf("   fields: %+q\n", keys)
	for _, k := range keys {
		if len(only) > 0 && !contains(only, k) {
			continue
		}
		v := r.body[k]
		switch k {
		case "dek":
			s, _ := v.(string)
			d, err := base64.StdEncoding.Strict().DecodeString(s)
			fmt.Printf("   dek: <redacted> string of %d chars, std base64 with padding: %v, decodes to %d bytes\n", len(s), err == nil, len(d))
		case "wrapped":
			s, _ := v.(string)
			fmt.Printf("   wrapped: %s\n", describeWrapped(s))
		case "request_id":
			fmt.Printf("   request_id: <%d chars, equals x-request-id: %v>\n", len(fmt.Sprint(v)), fmt.Sprint(v) == r.requestID)
		default:
			fmt.Printf("   %s: %+q\n", k, fmt.Sprint(v))
		}
	}
	fmt.Println()
}

func describeWrapped(s string) string {
	d, err := base64.StdEncoding.Strict().DecodeString(s)
	head := d
	if len(head) > 6 {
		head = head[:6]
	}
	pfx := s
	if len(pfx) > 6 {
		pfx = pfx[:6]
	}
	return fmt.Sprintf("string of %d chars (prefix %q), std base64 with padding: %v, decodes to %d bytes (first bytes %x)", len(s), pfx, err == nil, len(d), head)
}

func wrapFields(r result) (wrapped string, dekHash [32]byte) {
	if r.body == nil {
		return "", dekHash
	}
	wrapped, _ = r.body["wrapped"].(string)
	s, _ := r.body["dek"].(string)
	d, _ := base64.StdEncoding.DecodeString(s)
	dekHash = sha256.Sum256(d)
	clear(d)
	return wrapped, dekHash
}

func compare(title string, r result, want [32]byte) {
	_, got := wrapFields(r)
	fmt.Printf("   %s: %v\n\n", title, r.status == 200 && got == want)
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
