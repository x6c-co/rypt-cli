//go:build unix

package main

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/x6c-co/rypt-cli/internal/cli"
)

// TestSecondSignal: a second Ctrl-C during the grace period ends the wait
// at once, and still removes the temporary file. rypt is blocked reading a
// pipe, so a single signal would take the whole 2s grace period.
func TestSecondSignal(t *testing.T) {
	t.Parallel()
	api := newE2EAPI(t)
	ready := func(dir string) bool {
		w, _ := api.counts()
		return w == 1 && tempExists(dir)
	}
	sigs := []os.Signal{os.Interrupt, os.Interrupt}
	interruptWith(t, sigs, 1500*time.Millisecond, api, bytes.Repeat([]byte("p"), 100000), ready, "encrypt", "-o", "out.rypt")
}

// TestHangupIgnored: under nohup, or a shell that ignores SIGHUP, a hangup
// does not stop rypt.
func TestHangupIgnored(t *testing.T) {
	t.Parallel()
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	api := newE2EAPI(t)
	dir := t.TempDir()
	cmd, _, stderr := command(t, dir, api)
	bin := cmd.Path
	cmd.Path = sh
	cmd.Args = []string{"sh", "-c", `trap '' HUP; exec "$0" encrypt -o out.rypt`, bin}
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
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
	pt := bytes.Repeat([]byte("h"), 100000)
	written := make(chan error, 1)
	go func() {
		_, err := pw.Write(pt)
		written <- err
	}()

	deadline := time.Now().Add(10 * time.Second)
	for w, _ := api.counts(); w != 1 || !tempExists(dir); w, _ = api.counts() {
		if time.Now().After(deadline) {
			t.Fatalf("rypt never became ready\nstderr:\n%s", stderr)
		}
		select {
		case <-exited:
			t.Fatalf("rypt exited early (%v)\nstderr:\n%s", waitErr, stderr)
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	// Had rypt handled the signal, it would give up once the grace period
	// ends, since it is blocked reading stdin.
	select {
	case <-exited:
		t.Fatalf("rypt exited after an ignored SIGHUP (%v)\nstderr:\n%s", waitErr, stderr)
	case <-time.After(interruptGrace + 500*time.Millisecond):
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	pw.Close()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("rypt did not finish after stdin closed")
	}
	if code := exitCode(t, waitErr); code != 0 {
		t.Fatalf("exit %d, want 0\nstderr:\n%s", code, stderr)
	}

	dec, out, stderr := command(t, dir, api, "decrypt", "-o", "-", "out.rypt")
	if code := exitCode(t, dec.Run()); code != 0 {
		t.Fatalf("decrypt: exit %d\n%s", code, stderr)
	}
	if !bytes.Equal(out.Bytes(), pt) {
		t.Error("decrypt did not reproduce the plaintext")
	}
}

// TestPlainHTTPNeverProxied: with HTTP_PROXY set, a plain-http API URL is
// reached directly. A proxy would see the token in clear text. Plain http
// is allowed only to the addresses 127.0.0.1 and ::1, never to a name such
// as localhost, which is looked up and could resolve to another machine, so
// http://localhost is a usage error and sends nothing. (net/http reads the
// proxy variables once per process, hence a child process per case.)
func TestPlainHTTPNeverProxied(t *testing.T) {
	t.Parallel()
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)

	// encrypt runs "rypt encrypt -o out.rypt" in a new directory, with
	// RYPT_API_URL set to apiURL and HTTP_PROXY set to the proxy.
	encrypt := func(t *testing.T, api *e2eAPI, apiURL string) (code int, dir, stderr string) {
		t.Helper()
		dir = t.TempDir()
		cmd, _, errBuf := command(t, dir, api, "encrypt", "-o", "out.rypt")
		cmd.Env = append(cmd.Env, "RYPT_API_URL="+apiURL, "HTTP_PROXY="+proxy.URL, "http_proxy="+proxy.URL)
		cmd.Stdin = bytes.NewReader([]byte("proxied?"))
		code = exitCode(t, cmd.Run())
		checkStderr(t, errBuf.String())
		return code, dir, errBuf.String()
	}
	// reached checks that encrypt with the API's own plain-http URL sends
	// one wrap request to the API and writes out.rypt.
	reached := func(t *testing.T, api *e2eAPI) {
		t.Helper()
		u := api.srv.URL
		code, dir, stderr := encrypt(t, api, u)
		if code != 0 {
			t.Errorf("RYPT_API_URL=%s with HTTP_PROXY set: exit %d\n%s", u, code, stderr)
		}
		if w, _ := api.counts(); w != 1 {
			t.Errorf("RYPT_API_URL=%s: the API got %d wrap requests, want 1", u, w)
		}
		if _, err := os.Stat(filepath.Join(dir, "out.rypt")); err != nil {
			t.Errorf("RYPT_API_URL=%s: %v", u, err)
		}
	}

	// The subtests run one after another, so the proxy check at the end
	// covers all of them.
	t.Run("127.0.0.1", func(t *testing.T) {
		api := newE2EAPI(t)
		if !strings.HasPrefix(api.srv.URL, "http://127.0.0.1:") {
			t.Fatalf("unexpected API server URL %s", api.srv.URL)
		}
		reached(t, api)
	})
	t.Run("[::1]", func(t *testing.T) {
		ln, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("no IPv6 loopback: %v", err)
		}
		api := newE2EAPIOn(t, ln)
		if !strings.HasPrefix(api.srv.URL, "http://[::1]:") {
			t.Fatalf("unexpected API server URL %s", api.srv.URL)
		}
		reached(t, api)
	})
	// The port is a live API's, so a request that rypt sent would show in
	// its counts. Where localhost resolves only to ::1, the request would
	// fail to connect instead, and the exit code check catches that.
	t.Run("localhost refused", func(t *testing.T) {
		api := newE2EAPI(t)
		u, err := url.Parse(api.srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{"localhost", "LOCALHOST"} {
			apiURL := "http://" + host + ":" + u.Port()
			code, dir, stderr := encrypt(t, api, apiURL)
			if code != cli.ExitUsage {
				t.Errorf("RYPT_API_URL=%s: exit %d, want %d\n%s", apiURL, code, cli.ExitUsage, stderr)
			}
			if !strings.Contains(stderr, "RYPT_API_URL") || !strings.Contains(stderr, "https") {
				t.Errorf("RYPT_API_URL=%s: stderr does not say that the URL needs https:\n%s", apiURL, stderr)
			}
			if _, err := os.Stat(filepath.Join(dir, "out.rypt")); err == nil {
				t.Errorf("RYPT_API_URL=%s: out.rypt was written", apiURL)
			}
			if l := leftovers(t, dir); len(l) != 0 {
				t.Errorf("RYPT_API_URL=%s: temporary files left: %q", apiURL, l)
			}
		}
		if w, _ := api.counts(); w != 0 {
			t.Errorf("the API got %d wrap requests, want 0", w)
		}
	})

	if n := proxied.Load(); n != 0 {
		t.Errorf("the proxy received %d requests, want 0", n)
	}
}
