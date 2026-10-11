package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"
)

const testVersion = "v9.8.7-test"

func TestMain(m *testing.M) {
	// Retries must not sleep. Set once here, never per test: tests run in
	// parallel and the hook is a package variable.
	saved := clientBackoff
	clientBackoff = func(int) time.Duration { return 0 }
	code := m.Run()
	clientBackoff = saved
	os.Exit(code)
}

// harness runs the rypt command line in-process against a mock API, in a
// private directory.
type harness struct {
	t   *testing.T
	dir string
	api *mockAPI
	// env is the process environment Run sees. Tests change it freely.
	env map[string]string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	api := newMockAPI(t, testKeyID, otherKeyID)
	return &harness{
		t:   t,
		dir: t.TempDir(),
		api: api,
		env: map[string]string{
			"RYPT_TOKEN":   testToken,
			"RYPT_KEY_ID":  testKeyID,
			"RYPT_API_URL": api.URL(),
		},
	}
}

// invocation is one run of the command line.
type invocation struct {
	args     []string
	stdin    io.Reader // nil: empty
	stdout   io.Writer // nil: captured
	terminal bool      // StdoutIsTerminal's answer
	ctx      context.Context
}

type result struct {
	code   int
	stdout []byte
	stderr string
}

func (h *harness) run(args ...string) result {
	h.t.Helper()
	return h.invoke(invocation{args: args})
}

// runIn runs with stdin holding in.
func (h *harness) runIn(in []byte, args ...string) result {
	h.t.Helper()
	return h.invoke(invocation{args: args, stdin: bytes.NewReader(in)})
}

func (h *harness) invoke(inv invocation) result {
	h.t.Helper()
	env := maps.Clone(h.env)
	var stdout, stderr bytes.Buffer
	var out io.Writer = &stdout
	if inv.stdout != nil {
		out = inv.stdout
	}
	stdin := inv.stdin
	if stdin == nil {
		stdin = strings.NewReader("")
	}
	ctx := inv.ctx
	if ctx == nil {
		ctx = context.Background()
	}
	terminal := inv.terminal
	code := Run(ctx, Env{
		Args:             inv.args,
		Getenv:           func(k string) string { return env[k] },
		Stdin:            stdin,
		Stdout:           out,
		Stderr:           &stderr,
		StdoutIsTerminal: func() bool { return terminal },
		Version:          testVersion,
	})
	res := result{code: code, stdout: stdout.Bytes(), stderr: stderr.String()}
	h.checkInvariants(inv, env, res)
	return res
}

// checkInvariants asserts what must hold after every run.
func (h *harness) checkInvariants(inv invocation, env map[string]string, res result) {
	t := h.t
	t.Helper()
	switch res.code {
	case ExitOK, ExitAPI, ExitUsage, ExitIO, ExitIntegrity, ExitInterrupted:
	default:
		t.Errorf("rypt %q: exit code %d is not one rypt defines", inv.args, res.code)
	}

	// The token never reaches stdout or stderr, nor does a DEK.
	secrets := [][]byte{[]byte(testToken), []byte(testSecret), []byte(wrongToken)}
	if tok := env["RYPT_TOKEN"]; len(tok) >= 12 {
		secrets = append(secrets, []byte(tok))
	}
	for _, dek := range h.api.issuedDEKs() {
		secrets = append(secrets, dek,
			[]byte(base64.StdEncoding.EncodeToString(dek)),
			[]byte(base64.RawStdEncoding.EncodeToString(dek)),
			[]byte(hex.EncodeToString(dek)))
	}
	if bytesContainAny([]byte(res.stderr), secrets...) {
		t.Errorf("rypt %q: stderr contains the API token or a DEK:\n%s", inv.args, res.stderr)
	}
	if bytesContainAny(res.stdout, secrets...) {
		t.Errorf("rypt %q: stdout contains the API token or a DEK", inv.args)
	}

	// Server-supplied text is stripped of control characters before it is
	// printed; nothing else rypt prints contains them either.
	for _, r := range res.stderr {
		if (unicode.IsControl(r) && r != '\n' && r != '\t') || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			t.Errorf("rypt %q: stderr contains control or format character %U:\n%q", inv.args, r, res.stderr)
			break
		}
	}

	if res.code == ExitOK && res.stderr != "" {
		t.Errorf("rypt %q: exit 0 but stderr is not empty:\n%s", inv.args, res.stderr)
	}
	if res.code != ExitOK && strings.TrimSpace(res.stderr) == "" {
		t.Errorf("rypt %q: exit %d with no message on stderr", inv.args, res.code)
	}

	h.assertNoTempFiles()
}

// assertNoTempFiles fails if any rypt temporary file is left anywhere under
// the harness directory.
func (h *harness) assertNoTempFiles() {
	h.t.Helper()
	filepath.WalkDir(h.dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // for example a directory a test made unreadable
		}
		if name := d.Name(); strings.HasPrefix(name, ".rypt-") || strings.HasSuffix(name, ".tmp") {
			h.t.Errorf("temporary file left behind: %s", p)
		}
		return nil
	})
}

// expect fails the test unless res exited with code.
func expect(t testing.TB, res result, code int) {
	t.Helper()
	if res.code != code {
		t.Fatalf("exit code %d, want %d\nstderr:\n%s", res.code, code, res.stderr)
	}
}

// wantCalls checks the number of wrap and unwrap requests the mock has
// received, and that there were no others.
func (h *harness) wantCalls(wrap, unwrap int) {
	h.t.Helper()
	gw, gu, total := h.api.count("wrap"), h.api.count("unwrap"), h.api.total()
	if gw != wrap || gu != unwrap || total != wrap+unwrap {
		h.t.Errorf("API requests: wrap %d, unwrap %d, total %d; want wrap %d, unwrap %d, total %d",
			gw, gu, total, wrap, unwrap, wrap+unwrap)
	}
}

func (h *harness) path(elem ...string) string {
	return filepath.Join(append([]string{h.dir}, elem...)...)
}

// writeFile writes data to name (relative to the harness directory) with
// mode 0644 and returns the full path.
func (h *harness) writeFile(name string, data []byte) string {
	h.t.Helper()
	p := h.path(name)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		h.t.Fatal(err)
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		h.t.Fatal(err)
	}
	return p
}

func (h *harness) readFile(name string) []byte {
	h.t.Helper()
	b, err := os.ReadFile(h.path(name))
	if err != nil {
		h.t.Fatal(err)
	}
	return b
}

func (h *harness) assertMissing(name string) {
	h.t.Helper()
	if _, err := os.Lstat(h.path(name)); !errors.Is(err, fs.ErrNotExist) {
		h.t.Errorf("%s exists (err %v), want no such file", name, err)
	}
}

func (h *harness) assertContent(name string, want []byte) {
	h.t.Helper()
	got, err := os.ReadFile(h.path(name))
	if err != nil {
		h.t.Errorf("reading %s: %v", name, err)
		return
	}
	if !bytes.Equal(got, want) {
		h.t.Errorf("%s: content differs: got %d bytes, want %d bytes", name, len(got), len(want))
	}
}

// assertMode0600 checks the permission bits of a file rypt wrote.
func (h *harness) assertMode0600(name string) {
	h.t.Helper()
	assertMode0600(h.t, h.path(name))
}

func assertMode0600(t testing.TB, p string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		return // mode bits have no effect on Windows
	}
	fi, err := os.Lstat(p)
	if err != nil {
		t.Errorf("stat %s: %v", p, err)
		return
	}
	if !fi.Mode().IsRegular() {
		t.Errorf("%s is %v, want a regular file", p, fi.Mode())
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("%s has mode %#o, want 0600", p, perm)
	}
}

// assertEntries checks that directory sub of the harness directory holds
// exactly the names in want.
func (h *harness) assertEntries(sub string, want ...string) {
	h.t.Helper()
	ents, err := os.ReadDir(h.path(sub))
	if err != nil {
		h.t.Fatal(err)
	}
	var got []string
	for _, e := range ents {
		got = append(got, e.Name())
	}
	sort.Strings(got)
	want = append([]string(nil), want...)
	sort.Strings(want)
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		h.t.Errorf("directory %q holds %q, want %q", sub, got, want)
	}
}

// testData returns n reproducible pseudo-random bytes.
func testData(n int, seed uint64) []byte {
	var s [32]byte
	binary.LittleEndian.PutUint64(s[:], seed)
	b := make([]byte, n)
	rand.NewChaCha8(s).Read(b)
	return b
}

// encryptFixture encrypts plaintext through the command line into name and
// returns the ciphertext. The mock's counters include the wrap.
func (h *harness) encryptFixture(name string, plaintext []byte, extra ...string) []byte {
	h.t.Helper()
	args := append([]string{"encrypt", "-o", h.path(name)}, extra...)
	res := h.runIn(plaintext, args...)
	expect(h.t, res, ExitOK)
	return h.readFile(name)
}

// craft builds a file from spec §5 by hand, with a DEK the mock can unwrap,
// without any API request.
func (h *harness) craft(cipherID byte, chunkSize uint32, label string, plaintext []byte) ([]byte, specHeader) {
	h.t.Helper()
	var aad []byte
	if label != "" {
		aad = []byte(label)
	}
	dek, wrapped := h.api.issue(testKeyID, aad)
	hdr := specHeader{
		Magic:     []byte("RYPT"),
		Version:   1,
		Cipher:    cipherID,
		ChunkSize: chunkSize,
		KeyID:     keyIDBytes(testKeyID),
		Label:     []byte(label),
		Wrapped:   []byte(wrapped),
	}
	return specSeal(h.t, hdr, dek, plaintext), hdr
}

// verifyEncrypted checks a file rypt encrypted against spec §5, using the
// DEK the mock issued for the header's wrapped value, and returns the
// plaintext.
func (h *harness) verifyEncrypted(data []byte, wantCipher byte, wantKeyID, wantLabel string) []byte {
	h.t.Helper()
	t := h.t
	hdr, hdrLen := parseSpecHeader(t, data)
	if string(hdr.Magic) != "RYPT" || hdr.Version != 1 {
		t.Fatalf("header magic %q version %d, want RYPT 1", hdr.Magic, hdr.Version)
	}
	if hdr.Cipher != wantCipher {
		t.Errorf("header cipher %#x, want %#x", hdr.Cipher, wantCipher)
	}
	if hdr.ChunkSize != 65536 {
		t.Errorf("header chunk size %d, want 65536", hdr.ChunkSize)
	}
	if !bytes.Equal(hdr.KeyID, keyIDBytes(wantKeyID)) {
		t.Errorf("header key ID %x, want the raw bytes of %s", hdr.KeyID, wantKeyID)
	}
	if string(hdr.Label) != wantLabel {
		t.Errorf("header label %q, want %q", hdr.Label, wantLabel)
	}
	var dek []byte
	for _, c := range h.api.callsOf("wrap") {
		if c.dek != nil && c.wrapped == string(hdr.Wrapped) {
			dek = c.dek
		}
	}
	if dek == nil {
		t.Fatalf("the header's wrapped DEK (%d bytes) is not a value the API returned from wrap", len(hdr.Wrapped))
	}
	pt, chunks := specOpen(t, data, dek)
	want := (len(pt) + 65535) / 65536
	if want == 0 {
		want = 1
	}
	if chunks != want {
		t.Errorf("%d plaintext bytes in %d chunks, want %d", len(pt), chunks, want)
	}
	if got := len(data) - hdrLen; got != len(pt)+16*chunks {
		t.Errorf("body is %d bytes, want %d", got, len(pt)+16*chunks)
	}
	return pt
}

// errWriter fails every write.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, errors.New("write failed: broken pipe") }
