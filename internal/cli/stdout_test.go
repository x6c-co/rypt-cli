package cli

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// openFile opens name in the harness directory with flag and closes it when
// the test ends.
func (h *harness) openFile(name string, flag int) *os.File {
	h.t.Helper()
	f, err := os.OpenFile(name, flag, 0o600)
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { f.Close() })
	return f
}

// growthGuard returns a context that is cancelled once the file at p is
// larger than limit bytes. Without the refusal under test, encrypting a file
// onto itself grows it until the disk is full.
func growthGuard(t *testing.T, p string, limit int64) context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		for ctx.Err() == nil {
			if fi, err := os.Stat(p); err == nil && fi.Size() > limit {
				cancel()
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return ctx
}

// TestStdoutIsInput: rypt refuses, before calling the API, to write to
// stdout when stdout is the input file, as in "rypt decrypt -o - f.rypt >>
// f.rypt". The input would otherwise grow while it is being read.
func TestStdoutIsInput(t *testing.T) {
	h := newHarness(t)
	pt := testData(200000, 31)
	h.writeFile("g", pt)
	ct := h.encryptFixture("f.rypt", pt)

	cases := []struct {
		file      string
		viaStdin  bool
		args      []string
		mentioned string
	}{
		{"g", false, []string{"encrypt", "-o", "-", h.path("g")}, h.path("g")},
		{"g", true, []string{"encrypt"}, "stdin"},
		{"g", true, []string{"encrypt", "-o", "-", "-"}, "stdin"},
		{"f.rypt", false, []string{"decrypt", "-o", "-", h.path("f.rypt")}, h.path("f.rypt")},
		{"f.rypt", true, []string{"decrypt"}, "stdin"},
	}
	for _, c := range cases {
		inv := invocation{
			args:   c.args,
			stdout: h.openFile(h.path(c.file), os.O_WRONLY|os.O_APPEND),
			ctx:    growthGuard(t, h.path(c.file), 1<<20),
		}
		if c.viaStdin {
			inv.stdin = h.openFile(h.path(c.file), os.O_RDONLY)
		}
		res := h.invoke(inv)
		if res.code != ExitUsage || !strings.Contains(res.stderr, "over the input") || !strings.Contains(res.stderr, c.mentioned) {
			t.Errorf("rypt %q with stdout appending to %s: exit %d, want %d refusing to write over %s\n%s",
				c.args, c.file, res.code, ExitUsage, c.mentioned, res.stderr)
		}
	}
	h.wantCalls(1, 0)
	h.assertContent("g", pt)
	h.assertContent("f.rypt", ct)
}

// TestStdoutToOtherFiles: stdout that is a different regular file, or a
// device, is written as usual.
func TestStdoutToOtherFiles(t *testing.T) {
	h := newHarness(t)
	pt := testData(70000, 33)
	h.writeFile("g", pt)

	h.writeFile("g.rypt", nil)
	res := h.invoke(invocation{
		args:   []string{"encrypt"},
		stdin:  h.openFile(h.path("g"), os.O_RDONLY),
		stdout: h.openFile(h.path("g.rypt"), os.O_WRONLY|os.O_APPEND),
	})
	expect(t, res, ExitOK)

	h.writeFile("g.out", nil)
	res = h.invoke(invocation{
		args:   []string{"decrypt", "-o", "-", h.path("g.rypt")},
		stdout: h.openFile(h.path("g.out"), os.O_WRONLY|os.O_APPEND),
	})
	expect(t, res, ExitOK)
	h.assertContent("g.out", pt)

	// Checking a file's integrity by decrypting to the null device: stdin
	// and stdout are both devices, never the same regular file.
	res = h.invoke(invocation{
		args:   []string{"decrypt"},
		stdin:  h.openFile(h.path("g.rypt"), os.O_RDONLY),
		stdout: h.openFile(os.DevNull, os.O_WRONLY),
	})
	expect(t, res, ExitOK)
	res = h.invoke(invocation{
		args:   []string{"encrypt"},
		stdin:  h.openFile(os.DevNull, os.O_RDONLY),
		stdout: h.openFile(os.DevNull, os.O_WRONLY),
	})
	expect(t, res, ExitOK)
	h.wantCalls(2, 2)
}
