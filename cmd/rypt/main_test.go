//go:build unix

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// End-to-end tests of the rypt binary: it is built once, and each test runs
// it as a child process against an in-process mock of the API.

const (
	e2eVersion = "e2e-1.2.3"
	e2eToken   = "ry_E2eTestP_k3Jd8sLq0wPz5xVb7nMc2aRt9yHu4gFe"
	e2eKeyID   = "0f8fad5b-d9cb-469f-a165-70867728950e"
)

// raceEnabled is set by race_test.go when the tests run with -race.
var raceEnabled bool

var (
	buildOnce sync.Once
	buildDir  string
	binPath   string
	buildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	if buildDir != "" {
		os.RemoveAll(buildDir)
	}
	os.Exit(code)
}

// ryptBinary builds the command once, with the race detector when the tests
// themselves run with it.
func ryptBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		goTool, err := exec.LookPath("go")
		if err != nil {
			buildErr = err
			return
		}
		buildDir, buildErr = os.MkdirTemp("", "rypt-e2e-")
		if buildErr != nil {
			return
		}
		binPath = filepath.Join(buildDir, "rypt")
		args := []string{"build", "-o", binPath, "-ldflags", "-X main.version=" + e2eVersion}
		env := os.Environ()
		if raceEnabled {
			args = append(args, "-race")
			env = append(env, "CGO_ENABLED=1")
		}
		cmd := exec.Command(goTool, append(args, ".")...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = errors.New("go build: " + err.Error() + "\n" + string(out))
		}
	})
	if buildErr != nil {
		if errors.Is(buildErr, exec.ErrNotFound) {
			t.Skip("the go command is not available to build the binary")
		}
		t.Fatal(buildErr)
	}
	return binPath
}

// e2eAPI is a small mock of wrap and unwrap.
type e2eAPI struct {
	srv     *httptest.Server
	mu      sync.Mutex
	wraps   int
	unwraps int
	deks    map[string][]byte // wrapped -> DEK
	gate    chan struct{}     // when not nil, requests wait for it to close
	entered chan string       // receives the op of every request, if not nil
}

func newE2EAPI(t *testing.T) *e2eAPI {
	a := &e2eAPI{deks: map[string][]byte{}, entered: make(chan string, 16)}
	a.srv = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.srv.Close)
	return a
}

// blockRequests makes every request wait until the test ends or the
// client goes away.
func (a *e2eAPI) blockRequests(t *testing.T) {
	gate := make(chan struct{})
	a.mu.Lock()
	a.gate = gate
	a.mu.Unlock()
	t.Cleanup(func() { close(gate) }) // runs before the server closes
}

func (a *e2eAPI) counts() (wraps, unwraps int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.wraps, a.unwraps
}

func (a *e2eAPI) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Request-Id", "e2e-req")
	w.Header().Set("Content-Type", "application/json")
	if r.Header.Get("Authorization") != "Bearer "+e2eToken {
		w.WriteHeader(401)
		io.WriteString(w, `{"error":"unauthorized","message":"no","request_id":"e2e-req"}`)
		return
	}
	var body struct {
		Wrapped string `json:"wrapped"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	op := filepath.Base(r.URL.Path)

	a.mu.Lock()
	switch op {
	case "wrap":
		a.wraps++
	case "unwrap":
		a.unwraps++
	}
	gate := a.gate
	a.mu.Unlock()
	select {
	case a.entered <- op:
	default:
	}
	if gate != nil {
		select {
		case <-gate:
		case <-r.Context().Done():
		}
		return
	}

	switch op {
	case "wrap":
		dek := make([]byte, 32)
		rand.Read(dek)
		raw := make([]byte, 139)
		rand.Read(raw)
		wrapped := base64.StdEncoding.EncodeToString(raw)
		a.mu.Lock()
		a.deks[wrapped] = dek
		a.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"dek": base64.StdEncoding.EncodeToString(dek), "wrapped": wrapped})
	case "unwrap":
		a.mu.Lock()
		dek, ok := a.deks[body.Wrapped]
		a.mu.Unlock()
		if !ok {
			w.WriteHeader(400)
			io.WriteString(w, `{"error":"invalid_ciphertext","message":"ciphertext or aad invalid","request_id":"e2e-req"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"dek": base64.StdEncoding.EncodeToString(dek)})
	default:
		w.WriteHeader(404)
		io.WriteString(w, `{"error":"not_found","message":"no","request_id":"e2e-req"}`)
	}
}

// command returns the rypt child process, in dir, with an environment built
// from scratch: the parent's environment could hold a real RYPT_TOKEN.
func command(t *testing.T, dir string, api *e2eAPI, args ...string) (*exec.Cmd, *bytes.Buffer, *bytes.Buffer) {
	cmd := exec.Command(ryptBinary(t), args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"RYPT_TOKEN=" + e2eToken,
		"RYPT_KEY_ID=" + e2eKeyID,
		"HOME=" + dir,
		"GORACE=halt_on_error=1",
	}
	if api != nil {
		cmd.Env = append(cmd.Env, "RYPT_API_URL="+api.srv.URL)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	return cmd, &stdout, &stderr
}

func exitCode(t *testing.T, err error) int {
	t.Helper()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("running rypt: %v", err)
	}
	return ee.ExitCode() // -1 when killed by a signal
}

// leftovers returns any rypt temporary files in dir.
func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	m, err := filepath.Glob(filepath.Join(dir, ".rypt-*"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func checkStderr(t *testing.T, stderr string) {
	t.Helper()
	if strings.Contains(stderr, e2eToken) {
		t.Errorf("stderr contains the token:\n%s", stderr)
	}
	if strings.Contains(stderr, "DATA RACE") {
		t.Errorf("the race detector fired:\n%s", stderr)
	}
}

func TestVersionAndUsage(t *testing.T) {
	dir := t.TempDir()
	cmd, stdout, stderr := command(t, dir, nil, "version")
	if code := exitCode(t, cmd.Run()); code != 0 {
		t.Fatalf("rypt version: exit %d\n%s", code, stderr)
	}
	if !strings.Contains(stdout.String(), e2eVersion) {
		t.Errorf("rypt version printed %q, want the -ldflags version %q", stdout, e2eVersion)
	}

	cmd, _, stderr = command(t, dir, nil)
	if code := exitCode(t, cmd.Run()); code != 2 {
		t.Errorf("rypt with no arguments: exit %d, want 2", code)
	}
	if stderr.Len() == 0 {
		t.Error("rypt with no arguments printed nothing on stderr")
	}

	cmd, stdout, _ = command(t, dir, nil, "help")
	if code := exitCode(t, cmd.Run()); code != 0 || !strings.Contains(stdout.String(), "rypt encrypt") {
		t.Errorf("rypt help: exit %d, stdout %q", code, stdout)
	}
}

// TestRoundTripBinary checks exit codes pass through the process.
func TestRoundTripBinary(t *testing.T) {
	dir := t.TempDir()
	api := newE2EAPI(t)
	pt := []byte(strings.Repeat("end to end\n", 10000))
	if err := os.WriteFile(filepath.Join(dir, "f"), pt, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd, _, stderr := command(t, dir, api, "encrypt", "f")
	if code := exitCode(t, cmd.Run()); code != 0 {
		t.Fatalf("encrypt: exit %d\n%s", code, stderr)
	}
	fi, err := os.Stat(filepath.Join(dir, "f.rypt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("f.rypt has mode %#o, want 0600", fi.Mode().Perm())
	}

	cmd, _, stderr = command(t, dir, api, "encrypt", "f")
	if code := exitCode(t, cmd.Run()); code != 2 {
		t.Errorf("encrypt over an existing output: exit %d, want 2\n%s", code, stderr)
	}

	cmd, stdout, stderr := command(t, dir, api, "decrypt", "-o", "-", "f.rypt")
	if code := exitCode(t, cmd.Run()); code != 0 {
		t.Fatalf("decrypt: exit %d\n%s", code, stderr)
	}
	if !bytes.Equal(stdout.Bytes(), pt) {
		t.Error("decrypt did not reproduce the plaintext")
	}
	checkStderr(t, stderr.String())

	ct, _ := os.ReadFile(filepath.Join(dir, "f.rypt"))
	os.WriteFile(filepath.Join(dir, "bad.rypt"), ct[:len(ct)-1], 0o600)
	cmd, _, stderr = command(t, dir, api, "decrypt", "bad.rypt")
	if code := exitCode(t, cmd.Run()); code != 4 {
		t.Errorf("decrypt of a truncated file: exit %d, want 4\n%s", code, stderr)
	}
	if w, u := api.counts(); w != 1 || u != 2 {
		t.Errorf("API requests: wrap %d, unwrap %d; want 1, 2", w, u)
	}
	if l := leftovers(t, dir); len(l) != 0 {
		t.Errorf("temporary files left: %q", l)
	}
}

// interrupted runs rypt until ready reports it is busy, sends sig, and
// checks it exits 130 within 5 seconds, leaving no output and no
// temporary file.
func interrupted(t *testing.T, sig os.Signal, api *e2eAPI, stdinData []byte, ready func(dir string) bool, args ...string) {
	t.Helper()
	interruptWith(t, []os.Signal{sig}, 5*time.Second, api, stdinData, ready, args...)
}

// interruptWith is interrupted with a list of signals, sent 100ms apart,
// and a limit on how long rypt may take to exit after the first.
func interruptWith(t *testing.T, sigs []os.Signal, within time.Duration, api *e2eAPI, stdinData []byte, ready func(dir string) bool, args ...string) {
	t.Helper()
	dir := t.TempDir()
	cmd, _, stderr := command(t, dir, api, args...)
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// The write end stays open, so rypt blocks reading stdin.
	t.Cleanup(func() { pw.Close() })
	cmd.Stdin = pr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pr.Close()
	var waitErr error
	exited := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() {
		cmd.Process.Kill()
		<-exited
	})
	if len(stdinData) > 0 {
		go pw.Write(stdinData) // may block on a full pipe until rypt reads
	}

	deadline := time.Now().Add(10 * time.Second)
	for !ready(dir) {
		if time.Now().After(deadline) {
			t.Fatalf("rypt never became ready\nstderr:\n%s", stderr)
		}
		select {
		case <-exited:
			t.Fatalf("rypt exited early (%v)\nstderr:\n%s", waitErr, stderr)
		case <-time.After(10 * time.Millisecond):
		}
	}
	time.Sleep(200 * time.Millisecond) // let it settle into the blocking call

	start := time.Now()
	limit := time.After(within)
	if err := cmd.Process.Signal(sigs[0]); err != nil {
		t.Fatal(err)
	}
	for _, sig := range sigs[1:] {
		time.Sleep(100 * time.Millisecond)
		cmd.Process.Signal(sig) // fails if rypt has already exited
	}
	select {
	case <-exited:
		if code := exitCode(t, waitErr); code != 130 {
			t.Errorf("exit %d after %v, want 130\nstderr:\n%s", code, sigs, stderr)
		}
		t.Logf("exited %v after the first signal", time.Since(start))
	case <-limit:
		t.Fatalf("rypt did not exit within %v of %v\nstderr:\n%s", within, sigs, stderr)
	}
	if !strings.Contains(stderr.String(), "interrupted") {
		t.Errorf("stderr does not say it was interrupted:\n%s", stderr)
	}
	checkStderr(t, stderr.String())
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		t.Errorf("left behind in the destination directory: %s", e.Name())
	}
}

func tempExists(dir string) bool { return len(mustGlob(filepath.Join(dir, ".rypt-*"))) > 0 }

func mustGlob(pattern string) []string {
	m, _ := filepath.Glob(pattern)
	return m
}

// TestInterruptWhileReadingStdin: rypt has wrapped the DEK and is blocked
// reading a pipe that never closes.
func TestInterruptWhileReadingStdin(t *testing.T) {
	t.Parallel()
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			t.Parallel()
			api := newE2EAPI(t)
			ready := func(dir string) bool {
				w, _ := api.counts()
				return w == 1 && tempExists(dir)
			}
			interrupted(t, sig, api, bytes.Repeat([]byte("p"), 100000), ready, "encrypt", "-o", "out.rypt")
		})
	}
}

// TestInterruptDuringWrap: the signal arrives while the API request is in
// flight.
func TestInterruptDuringWrap(t *testing.T) {
	t.Parallel()
	api := newE2EAPI(t)
	api.blockRequests(t)
	ready := func(dir string) bool {
		select {
		case op := <-api.entered:
			return op == "wrap"
		default:
			return false
		}
	}
	interrupted(t, os.Interrupt, api, nil, ready, "encrypt", "-o", "out.rypt")
}

// TestInterruptWhileDecrypting: rypt has unwrapped the DEK and is blocked
// reading the rest of the body from a pipe. The temporary file holds
// decrypted data, so it must go. SIGHUP is what a closed terminal or a
// dropped SSH session sends.
func TestInterruptWhileDecrypting(t *testing.T) {
	t.Parallel()
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGHUP} {
		t.Run(sig.String(), func(t *testing.T) {
			t.Parallel()
			api := newE2EAPI(t)
			// Make a real file with the binary, then feed only part of it.
			src := t.TempDir()
			pt := bytes.Repeat([]byte("q"), 300000)
			os.WriteFile(filepath.Join(src, "f"), pt, 0o644)
			cmd, _, stderr := command(t, src, api, "encrypt", "f")
			if code := exitCode(t, cmd.Run()); code != 0 {
				t.Fatalf("encrypt: exit %d\n%s", code, stderr)
			}
			ct, err := os.ReadFile(filepath.Join(src, "f.rypt"))
			if err != nil {
				t.Fatal(err)
			}
			ready := func(dir string) bool {
				_, u := api.counts()
				return u == 1 && tempExists(dir)
			}
			interrupted(t, sig, api, ct[:len(ct)/2], ready, "decrypt", "-o", "out")
		})
	}
}
