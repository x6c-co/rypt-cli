//go:build unix

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestModeWithPermissiveUmask: outputs are 0600 even when the umask would
// allow more. Not parallel: the umask belongs to the whole process, and
// parallel tests only start after the sequential ones finish.
func TestModeWithPermissiveUmask(t *testing.T) {
	old := syscall.Umask(0)
	defer syscall.Umask(old)

	h := newHarness(t)
	pt := testData(100000, 21)
	h.writeFile("in", pt)
	expect(t, h.run("encrypt", h.path("in")), ExitOK)
	h.assertMode0600("in.rypt")

	expect(t, h.runIn(pt, "encrypt", "-o", h.path("stdin.rypt")), ExitOK)
	h.assertMode0600("stdin.rypt")

	if err := os.Remove(h.path("in")); err != nil {
		t.Fatal(err)
	}
	expect(t, h.run("decrypt", h.path("in.rypt")), ExitOK)
	h.assertMode0600("in")
	h.assertContent("in", pt)

	// --force over a world-writable file.
	if err := os.Chmod(h.path("in"), 0o666); err != nil {
		t.Fatal(err)
	}
	expect(t, h.run("decrypt", "--force", h.path("in.rypt")), ExitOK)
	h.assertMode0600("in")
	if err := os.Chmod(h.path("in.rypt"), 0o777); err != nil {
		t.Fatal(err)
	}
	expect(t, h.run("encrypt", "-f", h.path("in")), ExitOK)
	h.assertMode0600("in.rypt")
	h.wantCalls(3, 2)
}

// TestPermissionErrors: an unreadable input or an unwritable destination
// directory is a local I/O error, found before any API call.
func TestPermissionErrors(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission bits do not restrict root")
	}
	t.Parallel()
	h := newHarness(t)
	h.writeFile("secret", []byte("x"))
	ct, _ := h.craft(cipherAES, 65536, "", []byte("x"))
	h.writeFile("c.rypt", ct)
	h.writeFile("ro/keep", nil)
	if err := os.Chmod(h.path("secret"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(h.path("ro"), 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(h.path("ro"), 0o700) })

	for _, args := range [][]string{
		{"encrypt", h.path("secret")},
		{"encrypt", "-o", h.path("other.rypt"), h.path("secret")},
		{"encrypt", "-o", h.path("ro", "x.rypt"), h.path("c.rypt")},
		{"encrypt", "-o", h.path("ro", "x.rypt")},
		{"decrypt", "-o", h.path("ro", "x"), h.path("c.rypt")},
		{"decrypt", "-o", h.path("ro", "x")},
	} {
		res := h.runIn(ct, args...)
		if res.code != ExitIO {
			t.Errorf("rypt %q: exit %d, want 3\n%s", args, res.code, res.stderr)
		}
	}
	h.wantCalls(0, 0)
	h.assertEntries("ro", "keep")
	h.assertEntries("", "secret", "c.rypt", "ro")
}

// TestInterruptDuringFallbackCopy: on a file system without hard links the
// output is committed by copying into a new file at the destination. If
// the process is interrupted during that copy, the entry point removes the
// tracked temporary files and exits; the half-written destination must go
// too. A FIFO stands in for a slow copy source. Not parallel:
// RemoveTempFiles acts on the whole process.
func TestInterruptDuringFallbackCopy(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "src")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	dst := filepath.Join(dir, "dst")
	errc := make(chan error, 1)
	go func() { errc <- copyExclusive(fifo, dst) }()
	w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 5000)); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if fi, err := os.Stat(dst); err == nil && fi.Size() == 5000 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the copy did not start")
		}
		time.Sleep(5 * time.Millisecond)
	}

	RemoveTempFiles() // what the entry point does when the grace period ends
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("after RemoveTempFiles the partial destination remains (stat err %v)", err)
	}
	w.Close()
	if err := <-errc; err == nil {
		t.Error("the interrupted copy reported success")
	}
	if _, err := os.Lstat(dst); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the failed copy left its destination (stat err %v)", err)
	}

	// A completed copy is no longer tracked: a later RemoveTempFiles keeps it.
	src := filepath.Join(dir, "plain")
	if err := os.WriteFile(src, []byte("complete"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyExclusive(src, dst); err != nil {
		t.Fatal(err)
	}
	RemoveTempFiles()
	if got, err := os.ReadFile(dst); err != nil || string(got) != "complete" {
		t.Errorf("a completed copy was removed or changed: %q, %v", got, err)
	}
}

// TestOutputNotRegularFile: an existing FIFO or device, or a symlink to
// one, is refused as the output before any API call, even with --force, and
// is left as it was. --force would otherwise rename a regular file over it.
func TestOutputNotRegularFile(t *testing.T) {
	h := newHarness(t)
	pt := testData(1000, 32)
	h.writeFile("in", pt)
	h.encryptFixture("in.rypt", pt)
	fifo := h.path("fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	if err := os.Symlink(fifo, h.path("link")); err != nil {
		t.Fatal(err)
	}

	for _, out := range []string{fifo, h.path("link"), os.DevNull} {
		for _, args := range [][]string{
			{"encrypt", "-o", out, h.path("in")},
			{"encrypt", "-f", "-o", out, h.path("in")},
			{"encrypt", "--force", "-o", out},
			{"decrypt", "-o", out, h.path("in.rypt")},
			{"decrypt", "-f", "-o", out, h.path("in.rypt")},
		} {
			res := h.run(args...)
			if res.code != ExitUsage || !strings.Contains(res.stderr, "not a regular file") {
				t.Errorf("rypt %q: exit %d, want %d refusing a file that is not regular\n%s", args, res.code, ExitUsage, res.stderr)
			}
		}
	}
	h.wantCalls(1, 0)
	if fi, err := os.Lstat(fifo); err != nil || fi.Mode().Type() != fs.ModeNamedPipe {
		t.Errorf("the FIFO was replaced: %v, %v", fi.Mode(), err)
	}
	if fi, err := os.Lstat(h.path("link")); err != nil || fi.Mode().Type() != fs.ModeSymlink {
		t.Errorf("the symlink was replaced: %v, %v", fi.Mode(), err)
	}
	if fi, err := os.Stat(os.DevNull); err != nil || fi.Mode().IsRegular() {
		t.Errorf("%s was replaced: %v, %v", os.DevNull, fi.Mode(), err)
	}
}
