package cli

import (
	"bytes"
	"strings"
	"testing"
)

// TestEncryptRefusesTerminal: encrypt never writes ciphertext to a terminal,
// and refuses before any API call.
func TestEncryptRefusesTerminal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("in", []byte("secret"))
	for _, args := range [][]string{
		{"encrypt"},
		{"encrypt", "-"},
		{"encrypt", "-o", "-"},
		{"encrypt", "-o", "-", h.path("in")},
		{"encrypt", "--label", "x", "--cipher", "xchacha20-poly1305"},
	} {
		res := h.invoke(invocation{args: args, stdin: strings.NewReader("secret"), terminal: true})
		if res.code != ExitUsage {
			t.Errorf("rypt %q to a terminal: exit %d, want 2\n%s", args, res.code, res.stderr)
		}
		if len(res.stdout) != 0 {
			t.Errorf("rypt %q to a terminal wrote %d bytes to stdout", args, len(res.stdout))
		}
	}
	h.wantCalls(0, 0)
	h.assertEntries("", "in")
}

// TestUsageErrors: every one exits 2 before any API call and writes
// nothing.
func TestUsageErrors(t *testing.T) {
	t.Parallel()
	label1025 := strings.Repeat("a", 1025)
	cases := []struct {
		name string
		env  map[string]string // "" deletes the variable
		args []string
	}{
		{"no args", nil, []string{}},
		{"unknown command", nil, []string{"encrpyt", "IN"}},
		{"command spelled in caps", nil, []string{"ENCRYPT", "IN"}},

		{"missing token encrypt", map[string]string{"RYPT_TOKEN": ""}, []string{"encrypt", "IN"}},
		{"missing token decrypt", map[string]string{"RYPT_TOKEN": ""}, []string{"decrypt", "CT"}},
		{"missing token stdin", map[string]string{"RYPT_TOKEN": ""}, []string{"encrypt", "-o", "OUT"}},
		{"token with space", map[string]string{"RYPT_TOKEN": "ry_T3stPre1_Zq8vWm2nXc5bLk7j Hg4fDs9aPo1iUy6t"}, []string{"encrypt", "IN"}},
		{"token with tab", map[string]string{"RYPT_TOKEN": "ry_T3stPre1_Zq8vWm2nXc5bLk7j\tHg4fDs9aPo1iUy6t"}, []string{"encrypt", "IN"}},
		{"token with newline", map[string]string{"RYPT_TOKEN": testToken + "\n"}, []string{"encrypt", "IN"}},
		{"token with CR LF", map[string]string{"RYPT_TOKEN": testToken + "\r\nX-Evil: 1"}, []string{"encrypt", "IN"}},
		{"token with escape", map[string]string{"RYPT_TOKEN": "ry_T3stPre1_\x1b[31mZq8vWm2nXc5bLk7jHg4fDs9a"}, []string{"encrypt", "IN"}},
		{"token with DEL", map[string]string{"RYPT_TOKEN": testToken + "\x7f"}, []string{"decrypt", "CT"}},
		{"token with NUL", map[string]string{"RYPT_TOKEN": testToken + "\x00"}, []string{"decrypt", "CT"}},

		{"no key ID", map[string]string{"RYPT_KEY_ID": ""}, []string{"encrypt", "IN"}},
		{"no key ID stdin", map[string]string{"RYPT_KEY_ID": ""}, []string{"encrypt", "-o", "OUT"}},
		{"empty -k", map[string]string{"RYPT_KEY_ID": ""}, []string{"encrypt", "-k", "", "IN"}},
		{"empty -k with env", nil, []string{"encrypt", "-k", "", "IN"}},
		{"malformed -k word", nil, []string{"encrypt", "-k", "not-a-uuid", "IN"}},
		{"malformed -k no dashes", nil, []string{"encrypt", "-k", "0f8fad5bd9cb469fa16570867728950e", "IN"}},
		{"malformed -k braces", nil, []string{"encrypt", "-k", "{" + testKeyID + "}", "IN"}},
		{"malformed -k urn", nil, []string{"encrypt", "-k", "urn:uuid:" + testKeyID, "IN"}},
		{"malformed -k short", nil, []string{"encrypt", "-k", testKeyID[:35], "IN"}},
		{"malformed -k long", nil, []string{"encrypt", "-k", testKeyID + "0", "IN"}},
		{"malformed -k non-hex", nil, []string{"encrypt", "-k", "0f8fad5b-d9cb-469f-a165-70867728950g", "IN"}},
		{"malformed -k spaces", nil, []string{"encrypt", "-k", " " + testKeyID, "IN"}},
		{"malformed -k dash moved", nil, []string{"encrypt", "-k", "0f8fad5bd-9cb-469f-a165-70867728950e", "IN"}},
		{"malformed --key-id", nil, []string{"encrypt", "--key-id", "1234", "IN"}},
		{"malformed RYPT_KEY_ID", map[string]string{"RYPT_KEY_ID": "not-a-uuid"}, []string{"encrypt", "IN"}},
		{"malformed RYPT_KEY_ID path traversal", map[string]string{"RYPT_KEY_ID": "../../v1/admin"}, []string{"encrypt", "IN"}},

		{"unknown flag", nil, []string{"encrypt", "--bogus", "IN"}},
		{"unknown short flag", nil, []string{"encrypt", "-x", "IN"}},
		{"unknown flag decrypt", nil, []string{"decrypt", "--verbose", "CT"}},
		{"flag case", nil, []string{"encrypt", "--Force", "IN"}},
		{"-k without value", nil, []string{"encrypt", "IN", "-k"}},
		{"-o without value", nil, []string{"encrypt", "IN", "-o"}},
		{"--output without value", nil, []string{"decrypt", "CT", "--output"}},
		{"--label without value", nil, []string{"encrypt", "IN", "--label"}},
		{"--cipher without value", nil, []string{"encrypt", "IN", "--cipher"}},
		{"two files encrypt", nil, []string{"encrypt", "IN", "IN2"}},
		{"two files decrypt", nil, []string{"decrypt", "CT", "CT2"}},
		{"file and stdin", nil, []string{"encrypt", "IN", "-"}},

		{"label 1025 bytes", nil, []string{"encrypt", "--label", label1025, "IN"}},
		{"label 1025 bytes multibyte", nil, []string{"encrypt", "--label", strings.Repeat("a", 1023) + "é", "IN"}},
		{"label far too long", nil, []string{"encrypt", "--label", strings.Repeat("ü", 40000), "IN"}},
		{"label invalid UTF-8", nil, []string{"encrypt", "--label", "abc\xff\xfe", "IN"}},
		{"label lone continuation byte", nil, []string{"encrypt", "--label", "\x80", "IN"}},
		{"label surrogate encoding", nil, []string{"encrypt", "--label", "\xed\xa0\x80", "IN"}},

		{"unknown cipher", nil, []string{"encrypt", "--cipher", "aes-128-gcm", "IN"}},
		{"empty cipher", nil, []string{"encrypt", "--cipher", "", "IN"}},
		{"cipher chacha20", nil, []string{"encrypt", "--cipher", "chacha20-poly1305", "IN"}},
		{"cipher on decrypt", nil, []string{"decrypt", "--cipher", "aes-256-gcm", "CT"}},
		{"label on decrypt", nil, []string{"decrypt", "--label", "x", "CT"}},
		{"empty label on decrypt", nil, []string{"decrypt", "--label", "", "CT"}},

		{"api url http remote", map[string]string{"RYPT_API_URL": "http://api.rypt.dev"}, []string{"encrypt", "IN"}},
		{"api url http private ip", map[string]string{"RYPT_API_URL": "http://10.0.0.1:8080"}, []string{"encrypt", "IN"}},
		{"api url http 127.0.0.2", map[string]string{"RYPT_API_URL": "http://127.0.0.2:8080"}, []string{"encrypt", "IN"}},
		{"api url http localhost lookalike", map[string]string{"RYPT_API_URL": "http://localhost.example.com"}, []string{"encrypt", "IN"}},
		{"api url http decrypt", map[string]string{"RYPT_API_URL": "http://example.com"}, []string{"decrypt", "CT"}},
		{"api url user info", map[string]string{"RYPT_API_URL": "https://user:hunter2pw@127.0.0.1:1"}, []string{"encrypt", "IN"}},
		{"api url user only", map[string]string{"RYPT_API_URL": "https://user@api.rypt.dev"}, []string{"encrypt", "IN"}},
		{"api url ftp", map[string]string{"RYPT_API_URL": "ftp://127.0.0.1"}, []string{"encrypt", "IN"}},
		{"api url no scheme", map[string]string{"RYPT_API_URL": "api.rypt.dev"}, []string{"encrypt", "IN"}},
		{"api url garbage", map[string]string{"RYPT_API_URL": "::not a url::"}, []string{"encrypt", "IN"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.writeFile("in", []byte("plaintext"))
			ct, _ := h.craft(cipherAES, 65536, "", []byte("plaintext"))
			h.writeFile("ct.rypt", ct)
			for k, v := range c.env {
				if v == "" {
					delete(h.env, k)
				} else {
					h.env[k] = v
				}
			}
			args := make([]string, len(c.args))
			for i, a := range c.args {
				switch a {
				case "IN":
					a = h.path("in")
				case "IN2":
					a = h.path("in2")
				case "CT":
					a = h.path("ct.rypt")
				case "CT2":
					a = h.path("ct2.rypt")
				case "OUT":
					a = h.path("out")
				}
				args[i] = a
			}
			res := h.runIn([]byte("plaintext"), args...)
			expect(t, res, ExitUsage)
			h.wantCalls(0, 0)
			h.assertEntries("", "in", "ct.rypt")
			if len(res.stdout) != 0 {
				t.Errorf("a usage error wrote %d bytes to stdout", len(res.stdout))
			}
			if strings.Contains(res.stderr, "hunter2pw") {
				t.Errorf("stderr shows the password from RYPT_API_URL:\n%s", res.stderr)
			}
		})
	}
}

// TestBoundaryArgsAccepted: the limits themselves are fine.
func TestBoundaryArgsAccepted(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("in", []byte("p"))
	for i, label := range []string{strings.Repeat("a", 1024), strings.Repeat("a", 1022) + "é", ""} {
		out := h.path("o" + string(rune('0'+i)))
		expect(t, h.run("encrypt", "--label", label, "-o", out, h.path("in")), ExitOK)
	}
	h.wantCalls(3, 0)
}

func TestHelp(t *testing.T) {
	t.Parallel()
	for _, args := range [][]string{
		{"help"},
		{"-h"},
		{"--help"},
		{"encrypt", "--help"},
		{"encrypt", "-h"},
		{"decrypt", "--help"},
		{"decrypt", "-h"},
		{"encrypt", "-o", "x", "--help"},
	} {
		h := newHarness(t)
		// Help needs no credentials.
		delete(h.env, "RYPT_TOKEN")
		delete(h.env, "RYPT_KEY_ID")
		res := h.run(args...)
		expect(t, res, ExitOK)
		h.wantCalls(0, 0)
		h.assertEntries("")
		out := string(res.stdout)
		for _, want := range []string{
			"rypt encrypt", "rypt decrypt", "rypt version", "rypt help",
			"-k", "--key-id", "-o", "--output", "-f", "--force", "--cipher", "--label",
			"aes-256-gcm", "xchacha20-poly1305",
			"RYPT_TOKEN", "RYPT_KEY_ID", "RYPT_API_URL",
			".rypt",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("rypt %q: help does not mention %q", args, want)
			}
		}
		// Spec §6: the stdout truncation limitation must be in the help.
		lower := strings.ToLower(strings.Join(strings.Fields(out), " "))
		for _, want := range []string{"stdout", "truncat", "partial", "exit"} {
			if !strings.Contains(lower, want) {
				t.Errorf("rypt %q: help does not explain the partial output on truncation (no %q)", args, want)
			}
		}
	}
}

func TestVersion(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	delete(h.env, "RYPT_TOKEN")
	res := h.run("version")
	expect(t, res, ExitOK)
	if !bytes.Contains(res.stdout, []byte(testVersion)) {
		t.Errorf("rypt version printed %q, want it to contain %q", res.stdout, testVersion)
	}
	if bytes.Count(res.stdout, []byte("\n")) != 1 || !bytes.HasSuffix(res.stdout, []byte("\n")) {
		t.Errorf("rypt version printed %q, want one line", res.stdout)
	}
	h.wantCalls(0, 0)
}

// TestNoArgsShowsUsage: with no arguments, rypt shows usage on stderr.
func TestNoArgsShowsUsage(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	res := h.run()
	expect(t, res, ExitUsage)
	if !strings.Contains(res.stderr, "rypt encrypt") {
		t.Errorf("stderr does not show usage:\n%s", res.stderr)
	}
	if len(res.stdout) != 0 {
		t.Errorf("stdout is not empty: %q", res.stdout)
	}
}
