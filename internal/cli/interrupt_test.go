package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"
)

// cancelingReader passes reads through and cancels a context once more
// than after bytes have been read. It still returns those bytes; the
// command line must notice the cancellation by itself.
type cancelingReader struct {
	r      io.Reader
	after  int
	cancel context.CancelFunc
	n      int
}

func (c *cancelingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += n
	if c.n > c.after {
		c.cancel()
	}
	return n, err
}

// TestInterruptWhileEncrypting: a cancelled context stops encryption with
// exit 130, and nothing is left at the destination.
func TestInterruptWhileEncrypting(t *testing.T) {
	t.Parallel()
	for _, toStdout := range []bool{false, true} {
		h := newHarness(t)
		pt := testData(1<<20, 13)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		args := []string{"encrypt", "-o", h.path("out.rypt")}
		if toStdout {
			args = []string{"encrypt"}
		}
		res := h.invoke(invocation{
			args:  args,
			stdin: &cancelingReader{r: bytes.NewReader(pt), after: 0, cancel: cancel},
			ctx:   ctx,
		})
		expect(t, res, ExitInterrupted)
		h.wantCalls(1, 0)
		h.assertEntries("")
		if toStdout && len(res.stdout) >= len(pt) {
			t.Errorf("an interrupted encryption wrote %d bytes to stdout", len(res.stdout))
		}
	}
}

// TestInterruptWhileDecrypting: the same while decrypting, after the
// unwrap.
func TestInterruptWhileDecrypting(t *testing.T) {
	t.Parallel()
	for _, toStdout := range []bool{false, true} {
		h := newHarness(t)
		pt := testData(1<<20, 14)
		ct, hdr := h.craft(cipherXChaCha, 65536, "x", pt)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		args := []string{"decrypt", "-o", h.path("out")}
		if toStdout {
			args = []string{"decrypt"}
		}
		res := h.invoke(invocation{
			args: args,
			// Cancel on the first read past the header, which comes after
			// the unwrap.
			stdin: &cancelingReader{r: bytes.NewReader(ct), after: len(hdr.encode()), cancel: cancel},
			ctx:   ctx,
		})
		expect(t, res, ExitInterrupted)
		h.wantCalls(0, 1)
		h.assertEntries("")
		if toStdout && len(res.stdout) >= len(pt) {
			t.Errorf("an interrupted decryption wrote all %d bytes", len(res.stdout))
		}
	}
}

// TestInterruptDuringAPICall: cancelling while wrap or unwrap is in flight
// exits 130 promptly, without waiting for the server, and cleans up.
func TestInterruptDuringAPICall(t *testing.T) {
	t.Parallel()
	for _, op := range []string{"wrap", "unwrap"} {
		t.Run(op, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			pt := testData(5000, 15)
			ct, _ := h.craft(cipherAES, 65536, "", pt)
			h.writeFile("in", pt)
			h.writeFile("in2.rypt", ct)

			entered := make(chan struct{}, 1)
			release := make(chan struct{})
			var once sync.Once
			// Registered after the mock, so it runs before the server closes.
			t.Cleanup(func() { once.Do(func() { close(release) }) })
			h.api.setHook(func(_ string, r *http.Request) {
				entered <- struct{}{}
				select {
				case <-release:
				case <-r.Context().Done():
				}
			})

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go func() {
				<-entered
				cancel()
			}()
			args := []string{"encrypt", h.path("in")}
			if op == "unwrap" {
				args = []string{"decrypt", h.path("in2.rypt")}
			}
			start := time.Now()
			res := h.invoke(invocation{args: args, ctx: ctx})
			expect(t, res, ExitInterrupted)
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("took %v to stop after the interrupt", d)
			}
			if op == "wrap" {
				h.wantCalls(1, 0)
			} else {
				h.wantCalls(0, 1)
			}
			h.assertEntries("", "in", "in2.rypt")
		})
	}
}

// TestAlreadyCancelled: a context cancelled before Run starts never
// produces output.
func TestAlreadyCancelled(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("in", []byte("data"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res := h.invoke(invocation{args: []string{"encrypt", h.path("in")}, ctx: ctx})
	expect(t, res, ExitInterrupted)
	h.assertEntries("", "in")
}
