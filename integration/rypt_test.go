//go:build integration

// Package integration runs the rypt binary against the live rypt API.
//
// The tests read RYPT_TOKEN and RYPT_KEY_ID from the environment and skip
// when either is unset. RYPT_API_URL, if set, selects another server. A run
// spends about fifteen operations on the key. Run them with:
//
//	go test -tags integration -count=1 ./integration/...
package integration

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// binary is the rypt binary built by TestMain.
var binary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "rypt-integration-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	binary = filepath.Join(dir, "rypt")
	if runtime.GOOS == "windows" {
		binary += ".exe"
	}
	build := exec.Command("go", "build", "-o", binary, "github.com/x6c-co/rypt-cli/cmd/rypt")
	build.Stdout, build.Stderr = os.Stderr, os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "building rypt:", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// credentials skips the test unless the live API credentials are set.
func credentials(t *testing.T) (token string) {
	t.Helper()
	token = os.Getenv("RYPT_TOKEN")
	if token == "" || os.Getenv("RYPT_KEY_ID") == "" {
		t.Skip("RYPT_TOKEN and RYPT_KEY_ID must be set to run integration tests")
	}
	return token
}

type result struct {
	stdout, stderr []byte
	code           int
}

// rypt runs the binary with the test process's environment plus extra, and
// fails the test if the token appears in its output.
func rypt(t *testing.T, stdin []byte, extra []string, args ...string) result {
	t.Helper()
	token := credentials(t)
	cmd := exec.Command(binary, args...)
	cmd.Env = append(os.Environ(), extra...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running rypt: %v", err)
	}
	for _, out := range [][]byte{stdout.Bytes(), stderr.Bytes()} {
		if bytes.Contains(out, []byte(token)) {
			t.Fatal("rypt wrote the API token to its output")
		}
	}
	return result{stdout.Bytes(), stderr.Bytes(), code}
}

func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRoundTripFiles(t *testing.T) {
	credentials(t)
	for _, cipher := range []string{"aes-256-gcm", "xchacha20-poly1305"} {
		for _, size := range []int{0, 65537} {
			t.Run(fmt.Sprintf("%s/%d", cipher, size), func(t *testing.T) {
				dir := t.TempDir()
				plain := filepath.Join(dir, "data.bin")
				want := randomBytes(t, size)
				if err := os.WriteFile(plain, want, 0o600); err != nil {
					t.Fatal(err)
				}

				r := rypt(t, nil, nil, "encrypt", "--cipher", cipher, plain)
				if r.code != 0 {
					t.Fatalf("encrypt: exit %d: %s", r.code, r.stderr)
				}
				sealed := plain + ".rypt"
				fi, err := os.Stat(sealed)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
					t.Errorf("encrypted file mode = %v, want 0600", fi.Mode().Perm())
				}
				ct, err := os.ReadFile(sealed)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.HasPrefix(ct, []byte("RYPT\x01")) {
					t.Fatalf("encrypted file does not start with the magic and version")
				}

				if err := os.Remove(plain); err != nil {
					t.Fatal(err)
				}
				r = rypt(t, nil, nil, "decrypt", sealed)
				if r.code != 0 {
					t.Fatalf("decrypt: exit %d: %s", r.code, r.stderr)
				}
				got, err := os.ReadFile(plain)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatal("decrypted data differs from the original")
				}
			})
		}
	}
}

func TestRoundTripPipe(t *testing.T) {
	credentials(t)
	want := randomBytes(t, 3*65536+7)
	r := rypt(t, want, nil, "encrypt", "--label", "integration pipe")
	if r.code != 0 {
		t.Fatalf("encrypt: exit %d: %s", r.code, r.stderr)
	}
	r = rypt(t, r.stdout, nil, "decrypt")
	if r.code != 0 {
		t.Fatalf("decrypt: exit %d: %s", r.code, r.stderr)
	}
	if !bytes.Equal(r.stdout, want) {
		t.Fatal("decrypted data differs from the original")
	}
}

// TestTamperedLabel changes one bit of the label in the header. The server
// refuses to unwrap the data key with the changed aad.
func TestTamperedLabel(t *testing.T) {
	credentials(t)
	r := rypt(t, []byte("secret"), nil, "encrypt", "--label", "label-A")
	if r.code != 0 {
		t.Fatalf("encrypt: exit %d: %s", r.code, r.stderr)
	}
	ct := bytes.Clone(r.stdout)
	i := bytes.Index(ct, []byte("label-A"))
	if i < 0 {
		t.Fatal("label not found in the header")
	}
	ct[i+len("label-")] ^= 0x02 // "A" becomes "C"

	r = rypt(t, ct, nil, "decrypt")
	if r.code != 1 {
		t.Fatalf("decrypt of a tampered label: exit %d, want 1: %s", r.code, r.stderr)
	}
	if len(r.stdout) != 0 {
		t.Error("decrypt of a tampered label wrote output")
	}
	for _, want := range []string{"invalid_ciphertext", "request_id"} {
		if !strings.Contains(string(r.stderr), want) {
			t.Errorf("stderr %q does not mention %s", r.stderr, want)
		}
	}
}

// TestUnknownKey uses a key ID the token cannot see. The API answers 404
// not_found, or 403 key_not_allowed when the token is restricted to other
// keys.
func TestUnknownKey(t *testing.T) {
	credentials(t)
	r := rypt(t, []byte("x"), nil, "encrypt", "-k", "00000000-0000-4000-8000-000000000000")
	if r.code != 1 {
		t.Fatalf("encrypt with an unknown key: exit %d, want 1: %s", r.code, r.stderr)
	}
	stderr := string(r.stderr)
	if !strings.Contains(stderr, "not_found") && !strings.Contains(stderr, "key_not_allowed") {
		t.Errorf("stderr %q mentions neither not_found nor key_not_allowed", r.stderr)
	}
	if !strings.Contains(stderr, "request_id") {
		t.Errorf("stderr %q does not mention request_id", r.stderr)
	}
}

// TestBadToken checks that a wrong token is reported without being echoed.
func TestBadToken(t *testing.T) {
	credentials(t)
	bad := "ry_ZZZZZZZZ_ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
	r := rypt(t, []byte("x"), []string{"RYPT_TOKEN=" + bad}, "encrypt")
	if r.code != 1 {
		t.Fatalf("encrypt with a wrong token: exit %d, want 1: %s", r.code, r.stderr)
	}
	if !strings.Contains(string(r.stderr), "unauthorized") {
		t.Errorf("stderr %q does not mention unauthorized", r.stderr)
	}
	if bytes.Contains(r.stderr, []byte(bad)) {
		t.Error("rypt wrote the token to stderr")
	}
}
