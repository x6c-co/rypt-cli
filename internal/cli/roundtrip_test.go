package cli

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var roundTripSizes = []int{0, 1, 65535, 65536, 65537, 131072}

var ciphers = []struct {
	name string // the --cipher value; "" uses the default
	id   byte
}{
	{"", cipherAES},
	{"aes-256-gcm", cipherAES},
	{"xchacha20-poly1305", cipherXChaCha},
}

// TestRoundTripFiles encrypts FILE to FILE.rypt, checks the result against
// spec §5, removes FILE, and decrypts FILE.rypt back to FILE.
func TestRoundTripFiles(t *testing.T) {
	for _, c := range ciphers {
		for _, size := range roundTripSizes {
			for _, label := range []string{"", "project-x ✓ 2026"} {
				name := fmt.Sprintf("cipher=%s/size=%d/label=%t", c.name, size, label != "")
				if c.name == "" {
					name = fmt.Sprintf("default-cipher/size=%d/label=%t", size, label != "")
				}
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					h := newHarness(t)
					pt := testData(size, uint64(size)+uint64(c.id)<<32)
					h.writeFile("data.bin", pt)

					args := []string{"encrypt"}
					if c.name != "" {
						args = append(args, "--cipher", c.name)
					}
					if label != "" {
						args = append(args, "--label", label)
					}
					args = append(args, h.path("data.bin"))
					res := h.run(args...)
					expect(t, res, ExitOK)
					if len(res.stdout) != 0 {
						t.Errorf("encrypt to a file wrote %d bytes to stdout", len(res.stdout))
					}
					h.wantCalls(1, 0)
					h.assertEntries("", "data.bin", "data.bin.rypt")
					h.assertMode0600("data.bin.rypt")
					h.assertContent("data.bin", pt) // the input is untouched

					ct := h.readFile("data.bin.rypt")
					if got := h.verifyEncrypted(ct, c.id, testKeyID, label); !bytes.Equal(got, pt) {
						t.Fatalf("the spec decoding of the output does not give the plaintext")
					}

					if err := os.Remove(h.path("data.bin")); err != nil {
						t.Fatal(err)
					}
					res = h.run("decrypt", h.path("data.bin.rypt"))
					expect(t, res, ExitOK)
					if len(res.stdout) != 0 {
						t.Errorf("decrypt to a file wrote %d bytes to stdout", len(res.stdout))
					}
					h.wantCalls(1, 1)
					h.assertEntries("", "data.bin", "data.bin.rypt")
					h.assertContent("data.bin", pt)
					h.assertMode0600("data.bin")
					h.assertContent("data.bin.rypt", ct)
				})
			}
		}
	}
}

// TestRoundTripStdio covers stdin and stdout: no FILE, FILE "-", and -o -.
func TestRoundTripStdio(t *testing.T) {
	for _, c := range ciphers[1:] {
		for _, size := range roundTripSizes {
			t.Run(fmt.Sprintf("%s/%d", c.name, size), func(t *testing.T) {
				t.Parallel()
				h := newHarness(t)
				pt := testData(size, uint64(size)^0xabcdef)

				// No FILE: stdin to stdout.
				res := h.runIn(pt, "encrypt", "--cipher", c.name)
				expect(t, res, ExitOK)
				ct := res.stdout
				if got := h.verifyEncrypted(ct, c.id, testKeyID, ""); !bytes.Equal(got, pt) {
					t.Fatal("stdout ciphertext does not decode to the plaintext")
				}

				// FILE "-": stdin to stdout.
				res = h.runIn(ct, "decrypt", "-")
				expect(t, res, ExitOK)
				if !bytes.Equal(res.stdout, pt) {
					t.Fatalf("decrypt - wrote %d bytes, want the %d-byte plaintext", len(res.stdout), len(pt))
				}

				// No FILE on decrypt; FILE "-" on encrypt with a label.
				res = h.runIn(pt, "encrypt", "--cipher", c.name, "--label", "stdio", "-")
				expect(t, res, ExitOK)
				ct2 := res.stdout
				if got := h.verifyEncrypted(ct2, c.id, testKeyID, "stdio"); !bytes.Equal(got, pt) {
					t.Fatal("stdout ciphertext with a label does not decode to the plaintext")
				}
				res = h.runIn(ct2, "decrypt")
				expect(t, res, ExitOK)
				if !bytes.Equal(res.stdout, pt) {
					t.Fatal("decrypt from stdin did not reproduce the plaintext")
				}

				h.wantCalls(2, 2)
				h.assertEntries("")
			})
		}
	}
}

// TestOutputFlag covers -o with files, stdin and stdout in every
// combination.
func TestOutputFlag(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	pt := testData(70000, 7)
	h.writeFile("in.txt", pt)
	if err := os.Mkdir(h.path("sub"), 0o755); err != nil {
		t.Fatal(err)
	}

	// FILE to -o PATH: only PATH is written, not FILE.rypt.
	expect(t, h.run("encrypt", "-o", h.path("sub", "custom.enc"), h.path("in.txt")), ExitOK)
	h.assertEntries("", "in.txt", "sub")
	h.assertEntries("sub", "custom.enc")
	h.assertMode0600("sub/custom.enc")
	ct := h.readFile("sub/custom.enc")
	h.verifyEncrypted(ct, cipherAES, testKeyID, "")

	// Long flag forms, FILE to -o PATH on decrypt.
	expect(t, h.run("decrypt", "--output", h.path("sub", "plain.out"), h.path("sub", "custom.enc")), ExitOK)
	h.assertContent("sub/plain.out", pt)
	h.assertMode0600("sub/plain.out")

	// FILE to -o - (stdout).
	res := h.run("encrypt", "-o", "-", h.path("in.txt"))
	expect(t, res, ExitOK)
	h.verifyEncrypted(res.stdout, cipherAES, testKeyID, "")
	res = h.run("decrypt", "-o", "-", h.path("sub", "custom.enc"))
	expect(t, res, ExitOK)
	if !bytes.Equal(res.stdout, pt) {
		t.Error("decrypt -o - did not write the plaintext to stdout")
	}

	// stdin to -o PATH.
	expect(t, h.runIn(pt, "encrypt", "-o", h.path("sub", "from-stdin.rypt")), ExitOK)
	ct2 := h.readFile("sub/from-stdin.rypt")
	h.verifyEncrypted(ct2, cipherAES, testKeyID, "")
	h.assertMode0600("sub/from-stdin.rypt")
	expect(t, h.runIn(ct2, "decrypt", "-o", h.path("sub", "from-stdin.out")), ExitOK)
	h.assertContent("sub/from-stdin.out", pt)

	h.assertEntries("", "in.txt", "sub")
	h.assertEntries("sub", "custom.enc", "plain.out", "from-stdin.rypt", "from-stdin.out")
	h.wantCalls(3, 3)
}

// TestFlagSpellings checks the documented flags in their long and short
// spellings.
func TestFlagSpellings(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	pt := []byte("hello, flags")
	h.writeFile("a", pt)
	expect(t, h.run("encrypt", "--key-id", testKeyID, "--cipher", "xchacha20-poly1305", "--label", "L", "--output", h.path("a.enc"), h.path("a")), ExitOK)
	h.verifyEncrypted(h.readFile("a.enc"), cipherXChaCha, testKeyID, "L")
	expect(t, h.run("encrypt", "-k", testKeyID, "-o", h.path("a.enc"), "-f", h.path("a")), ExitOK)
	h.verifyEncrypted(h.readFile("a.enc"), cipherAES, testKeyID, "")
	expect(t, h.run("decrypt", "--force", "--output", h.path("a"), h.path("a.enc")), ExitOK)
	h.assertContent("a", pt)
}

// TestLabelRoundTrip covers labels at the size limit and with multi-byte
// characters, through the API's aad.
func TestLabelRoundTrip(t *testing.T) {
	t.Parallel()
	for _, label := range []string{
		"x",
		strings.Repeat("a", 1024),
		strings.Repeat("é", 512),        // 1024 bytes, 512 characters
		strings.Repeat("a", 1020) + "😀", // 1024 bytes
		"label with spaces, \"quotes\" and = signs",
	} {
		h := newHarness(t)
		pt := testData(1000, uint64(len(label)))
		h.writeFile("f", pt)
		expect(t, h.run("encrypt", "--label", label, h.path("f")), ExitOK)
		ct := h.readFile("f.rypt")
		h.verifyEncrypted(ct, cipherAES, testKeyID, label)
		if w := h.api.lastCall(t, "wrap"); !w.aadPresent || string(w.aad) != label {
			t.Errorf("wrap aad = %q (present %v), want the label", w.aad, w.aadPresent)
		}
		expect(t, h.run("decrypt", "-o", h.path("g"), h.path("f.rypt")), ExitOK)
		h.assertContent("g", pt)
		if u := h.api.lastCall(t, "unwrap"); !u.aadPresent || string(u.aad) != label {
			t.Errorf("unwrap aad = %q (present %v), want the label", u.aad, u.aadPresent)
		}
	}
}

// TestDecryptToTerminal: only encrypt refuses a terminal stdout.
func TestDecryptToTerminal(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	pt := []byte("plaintext for a terminal\n")
	ct := h.encryptFixture("x.rypt", pt)
	res := h.invoke(invocation{args: []string{"decrypt"}, stdin: bytes.NewReader(ct), terminal: true})
	expect(t, res, ExitOK)
	if !bytes.Equal(res.stdout, pt) {
		t.Errorf("stdout %q, want %q", res.stdout, pt)
	}
	res = h.invoke(invocation{args: []string{"decrypt", "-o", "-", h.path("x.rypt")}, terminal: true})
	expect(t, res, ExitOK)
	if !bytes.Equal(res.stdout, pt) {
		t.Errorf("stdout %q, want %q", res.stdout, pt)
	}
	h.wantCalls(1, 2)
}

// TestEncryptToFileWithTerminalStdout: a terminal stdout does not matter
// when the output is a file.
func TestEncryptToFileWithTerminalStdout(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("f", []byte("abc"))
	res := h.invoke(invocation{args: []string{"encrypt", h.path("f")}, terminal: true})
	expect(t, res, ExitOK)
	res = h.invoke(invocation{args: []string{"encrypt", "-o", h.path("g.rypt")}, stdin: strings.NewReader("abc"), terminal: true})
	expect(t, res, ExitOK)
	h.assertEntries("", "f", "f.rypt", "g.rypt")
	h.wantCalls(2, 0)
}

// TestKeyIDSources: RYPT_KEY_ID is the default, -k overrides it, and
// decrypt uses only the header's key ID.
func TestKeyIDSources(t *testing.T) {
	t.Parallel()

	t.Run("env default", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.env["RYPT_KEY_ID"] = otherKeyID
		ct := h.encryptFixture("a.rypt", []byte("x"))
		h.verifyEncrypted(ct, cipherAES, otherKeyID, "")
		if c := h.api.lastCall(t, "wrap"); c.keyID != otherKeyID {
			t.Errorf("wrap went to key %s, want RYPT_KEY_ID %s", c.keyID, otherKeyID)
		}
	})

	t.Run("flag overrides env", func(t *testing.T) {
		t.Parallel()
		for _, flag := range []string{"-k", "--key-id"} {
			for _, envVal := range []string{otherKeyID, "not-a-uuid"} {
				h := newHarness(t)
				h.env["RYPT_KEY_ID"] = envVal
				ct := h.encryptFixture("a.rypt", []byte("x"), flag, testKeyID)
				h.verifyEncrypted(ct, cipherAES, testKeyID, "")
				if c := h.api.lastCall(t, "wrap"); c.keyID != testKeyID {
					t.Errorf("%s with RYPT_KEY_ID=%s: wrap went to key %s, want %s", flag, envVal, c.keyID, testKeyID)
				}
			}
		}
	})

	t.Run("upper-case key ID", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		delete(h.env, "RYPT_KEY_ID")
		ct := h.encryptFixture("a.rypt", []byte("x"), "-k", strings.ToUpper(testKeyID))
		// The mock records a violation unless the path is lower-case.
		h.verifyEncrypted(ct, cipherAES, testKeyID, "")
		expect(t, h.runIn(ct, "decrypt"), ExitOK)
	})

	t.Run("decrypt ignores key ID flag and env", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		pt := testData(100, 1)
		ct := h.encryptFixture("a.rypt", pt)
		cases := []struct {
			env  string
			args []string
		}{
			{otherKeyID, nil},
			{"", nil},
			{"garbage", nil},
			{testKeyID, []string{"-k", otherKeyID}},
			{"garbage", []string{"--key-id", "also-garbage"}},
			{unknownKeyID, []string{"-k", unknownKeyID}},
		}
		for _, c := range cases {
			if c.env == "" {
				delete(h.env, "RYPT_KEY_ID")
			} else {
				h.env["RYPT_KEY_ID"] = c.env
			}
			res := h.runIn(ct, append([]string{"decrypt"}, c.args...)...)
			if res.code != ExitOK {
				t.Errorf("RYPT_KEY_ID=%q args %q: exit %d, want 0\n%s", c.env, c.args, res.code, res.stderr)
				continue
			}
			if !bytes.Equal(res.stdout, pt) {
				t.Errorf("RYPT_KEY_ID=%q args %q: wrong plaintext", c.env, c.args)
			}
			if u := h.api.lastCall(t, "unwrap"); u.keyID != testKeyID {
				t.Errorf("RYPT_KEY_ID=%q args %q: unwrap went to key %s, want the header's %s", c.env, c.args, u.keyID, testKeyID)
			}
		}
		h.wantCalls(1, len(cases))
	})
}

// TestAPIURL: RYPT_API_URL with a trailing slash, a path prefix, and each
// loopback name that may use plain http.
func TestAPIURL(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.env["RYPT_API_URL"] = h.api.URL() + "/"
	ct := h.encryptFixture("a.rypt", []byte("x"))
	h.env["RYPT_API_URL"] = strings.Replace(h.api.URL(), "127.0.0.1", "localhost", 1)
	expect(t, h.runIn(ct, "decrypt"), ExitOK)
	h.wantCalls(1, 1)

	// A base URL with a path: requests go under it.
	prefixed := httptest.NewServer(http.StripPrefix("/rypt/api", h.api))
	defer prefixed.Close()
	for _, base := range []string{prefixed.URL + "/rypt/api", prefixed.URL + "/rypt/api/"} {
		h.env["RYPT_API_URL"] = base
		ct = h.encryptFixture("b.rypt", []byte("y"), "-f")
		res := h.runIn(ct, "decrypt")
		expect(t, res, ExitOK)
	}
	h.wantCalls(3, 3)

	// IPv6 loopback, when the host has it.
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Logf("no IPv6 loopback: %v", err)
		return
	}
	v6 := httptest.NewUnstartedServer(h.api)
	v6.Listener.Close()
	v6.Listener = ln
	v6.Start()
	defer v6.Close()
	if !strings.HasPrefix(v6.URL, "http://[::1]:") {
		t.Fatalf("unexpected IPv6 server URL %s", v6.URL)
	}
	h.env["RYPT_API_URL"] = v6.URL
	expect(t, h.runIn(ct, "decrypt"), ExitOK)
	h.wantCalls(3, 4)
}

// TestUntrustedTLS: an https API whose certificate does not verify is
// unreachable: exit 1, nothing written.
func TestUntrustedTLS(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	srv := httptest.NewUnstartedServer(h.api)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the failed handshakes
	srv.StartTLS()
	defer srv.Close()
	h.env["RYPT_API_URL"] = srv.URL
	h.writeFile("in", []byte("x"))
	expect(t, h.run("encrypt", h.path("in")), ExitAPI)
	h.assertEntries("", "in")
	h.wantCalls(0, 0)
}
