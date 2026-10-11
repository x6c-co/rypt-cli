//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// openPTY returns the two ends of a new pseudo-terminal. The ioctls go
// through SyscallConn so the master stays non-blocking and Close unblocks
// a pending Read.
func openPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals: %v", err)
	}
	rc, err := m.SyscallConn()
	if err != nil {
		m.Close()
		t.Skipf("pty: %v", err)
	}
	var unlock int32
	var n uint32
	var errno syscall.Errno
	rc.Control(func(fd uintptr) {
		if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); e != 0 {
			errno = e
			return
		}
		_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&n)))
	})
	if errno != 0 {
		m.Close()
		t.Skipf("pty ioctl: %v", errno)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		t.Skipf("opening the pty: %v", err)
	}
	t.Cleanup(func() { s.Close(); m.Close() })
	return m, s
}

// TestStdoutTerminal: the binary detects a terminal stdout. encrypt refuses
// it before any API call; decrypt writes to it.
func TestStdoutTerminal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	api := newE2EAPI(t)
	pt := []byte("to-the-terminal")
	if err := os.WriteFile(filepath.Join(dir, "f"), pt, 0o644); err != nil {
		t.Fatal(err)
	}

	master, slave := openPTY(t)
	screen := make(chan []byte, 256)
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				screen <- append([]byte(nil), buf[:n]...)
			}
			if err != nil {
				close(screen)
				return
			}
		}
	}()

	for _, args := range [][]string{{"encrypt"}, {"encrypt", "-"}, {"encrypt", "-o", "-", "f"}} {
		cmd, _, stderr := command(t, dir, api, args...)
		cmd.Stdin = bytes.NewReader(pt)
		cmd.Stdout = slave
		if code := exitCode(t, cmd.Run()); code != 2 {
			t.Errorf("rypt %q to a terminal: exit %d, want 2\n%s", args, code, stderr)
		}
	}
	if w, _ := api.counts(); w != 0 {
		t.Errorf("encrypt to a terminal made %d wrap requests, want 0", w)
	}

	cmd, _, stderr := command(t, dir, api, "encrypt", "f")
	cmd.Stdout = slave
	if code := exitCode(t, cmd.Run()); code != 0 {
		t.Fatalf("encrypt to a file with a terminal stdout: exit %d\n%s", code, stderr)
	}
	cmd, _, stderr = command(t, dir, api, "decrypt", "-o", "-", "f.rypt")
	cmd.Stdout = slave
	if code := exitCode(t, cmd.Run()); code != 0 {
		t.Fatalf("decrypt to a terminal: exit %d\n%s", code, stderr)
	}
	checkStderr(t, stderr.String())

	// The plaintext reached the terminal.
	var shown []byte
	timeout := time.After(5 * time.Second)
	for !bytes.Contains(shown, pt) {
		select {
		case b, ok := <-screen:
			if !ok {
				t.Fatalf("the terminal shows %q, want it to contain %q", shown, pt)
			}
			shown = append(shown, b...)
		case <-timeout:
			t.Fatalf("the terminal shows %q, want it to contain %q", shown, pt)
		}
	}
	if w, u := api.counts(); w != 1 || u != 1 {
		t.Errorf("API requests: wrap %d, unwrap %d; want 1, 1", w, u)
	}
}
