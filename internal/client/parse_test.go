package client

import (
	"strings"
	"testing"
)

func TestParseBaseURL(t *testing.T) {
	ok := []struct{ in, want string }{
		{"", "https://api.rypt.dev"},
		{"https://api.rypt.dev", "https://api.rypt.dev"},
		{"https://api.rypt.dev/", "https://api.rypt.dev"},
		{"HTTPS://api.rypt.dev", "https://api.rypt.dev"},
		{"https://example.com:8443/prefix/", "https://example.com:8443/prefix"},
		{"https://example.com/a/b//", "https://example.com/a/b"},
		{"https://example.com/a%2Fb/", "https://example.com/a%2Fb"},
		{"https://127.0.0.1:9000", "https://127.0.0.1:9000"},
		{"https://[2001:db8::1]:443/x", "https://[2001:db8::1]:443/x"},
		{"http://localhost", "http://localhost"},
		{"http://localhost:8080/", "http://localhost:8080"},
		{"http://LocalHost:8080", "http://localhost:8080"},
		{"http://LOCALHOST", "http://localhost"},
		{"http://127.0.0.1:8080/api", "http://127.0.0.1:8080/api"},
		{"http://[::1]:8080", "http://[::1]:8080"},
		{"http://[::1]", "http://[::1]"},
	}
	for _, tt := range ok {
		u, err := ParseBaseURL(tt.in)
		if err != nil {
			t.Errorf("ParseBaseURL(%q): %v", tt.in, err)
			continue
		}
		if got := u.String(); got != tt.want {
			t.Errorf("ParseBaseURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
			t.Errorf("ParseBaseURL(%q) kept extra parts: %#v", tt.in, u)
		}
	}

	bad := []string{
		"http://example.com",
		"http://api.rypt.dev",
		"http://localhost.evil.com",
		"http://localhost.",
		"http://localhoſt",
		"http://LOCALHOſT:8080",
		"http://evil.com#@localhost",
		"http://127.0.0.2",
		"http://127.1",
		"http://0.0.0.0:8080",
		"http://[::2]",
		"http://[::ffff:127.0.0.1]",
		"http://[0:0:0:0:0:0:0:1]",
		"ftp://api.rypt.dev",
		"file:///etc/passwd",
		"ws://localhost",
		"api.rypt.dev",
		"//api.rypt.dev",
		"https://",
		"https:///path",
		"https:api.rypt.dev",
		"https://user:hunter2@api.rypt.dev",
		"https://user@api.rypt.dev",
		"https://:hunter2@api.rypt.dev",
		"https://api.rypt.dev?x=1",
		"https://api.rypt.dev/?",
		"https://api.rypt.dev#frag",
		"https://api.rypt.dev/#",
		"https://api.rypt.dev:port",
		"https://api.rypt.dev\n",
		" https://api.rypt.dev",
		"https://api rypt.dev",
	}
	for _, in := range bad {
		u, err := ParseBaseURL(in)
		if err == nil {
			t.Errorf("ParseBaseURL(%q) = %q, want an error", in, u)
			continue
		}
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("ParseBaseURL(%q) error %q echoes the password", in, err)
		}
	}
}

func TestParseBaseURLReturnsCopy(t *testing.T) {
	a, _ := ParseBaseURL("")
	a.Path = "/changed"
	if b, _ := ParseBaseURL(""); b.Path != "" {
		t.Error("ParseBaseURL returned shared state")
	}
}

func TestNew(t *testing.T) {
	if _, err := New(Options{Token: testToken}); err != nil {
		t.Errorf("New with the default base URL: %v", err)
	}
	if _, err := New(Options{BaseURL: "http://example.com", Token: testToken}); err == nil {
		t.Error("New accepted an http base URL that is not loopback")
	}
	if _, err := New(Options{BaseURL: "http://127.0.0.1:1"}); err == nil {
		t.Error("New accepted an empty token")
	}
	// The token's format is the server's business...
	for _, tok := range []string{"x", "not-a-ry-token", strings.Repeat("z", 200), "ry_\u00fcn\u00efcode"} {
		if _, err := New(Options{Token: tok}); err != nil {
			t.Errorf("New(token %q): %v", tok, err)
		}
	}
	// ...but a control character cannot go in a header.
	for _, tok := range []string{testToken + "\n", testToken + "\r", "ry_a\x00b", "ry_a\tb", "ry_\x7f"} {
		_, err := New(Options{Token: tok})
		if err == nil {
			t.Errorf("New accepted token %q", tok)
			continue
		}
		assertNoSecrets(t, err)
	}
}
