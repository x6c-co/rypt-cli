package cli

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
)

// The fixture for the body tests: three chunks, the last one short.
const threeChunkSize = 2*65536 + 100

// TestBodyTampering: any change to the body fails with exit 4 and, when
// decrypting to a file, writes nothing (spec §5, §6, §8).
func TestBodyTampering(t *testing.T) {
	t.Parallel()
	type mutation func(t *testing.T, ct []byte) []byte
	cases := []struct {
		name   string
		mutate mutation
		// stdoutPrefix is how many plaintext bytes authenticate before the
		// failure when decrypting to stdout.
		stdoutPrefix int
	}{
		{"bit flipped in chunk 0", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			ct[b[0][0]] ^= 0x01
			return ct
		}, 0},
		{"bit flipped in chunk 1", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			ct[b[1][0]+30000] ^= 0x80
			return ct
		}, 65536},
		{"bit flipped in the final chunk", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			ct[b[2][0]] ^= 0x10
			return ct
		}, 131072},
		{"bit flipped in the last tag", func(t *testing.T, ct []byte) []byte {
			ct[len(ct)-1] ^= 0x01
			return ct
		}, 131072},
		{"bit flipped in a non-final tag", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			ct[b[0][1]-1] ^= 0x04
			return ct
		}, 0},
		{"truncated at the last chunk boundary", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			return ct[:b[2][0]]
		}, 65536},
		{"truncated at the first chunk boundary", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			return ct[:b[1][0]]
		}, 0},
		{"truncated to the header", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			return ct[:b[0][0]]
		}, 0},
		{"truncated by one byte", func(t *testing.T, ct []byte) []byte {
			return ct[:len(ct)-1]
		}, 131072},
		{"truncated inside the tag of the final chunk", func(t *testing.T, ct []byte) []byte {
			return ct[:len(ct)-10]
		}, 131072},
		{"truncated inside chunk 1", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			return ct[:b[1][0]+1000]
		}, 65536},
		{"one byte appended", func(t *testing.T, ct []byte) []byte {
			return append(ct, 0)
		}, 131072},
		{"a tag's worth appended", func(t *testing.T, ct []byte) []byte {
			return append(ct, make([]byte, 16)...)
		}, 131072},
		{"final chunk repeated", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			return append(ct, ct[b[2][0]:b[2][1]]...)
		}, 131072},
		{"chunks 0 and 1 swapped", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			out := append([]byte{}, ct[:b[0][0]]...)
			out = append(out, ct[b[1][0]:b[1][1]]...)
			out = append(out, ct[b[0][0]:b[0][1]]...)
			return append(out, ct[b[2][0]:]...)
		}, 0},
		{"chunk 0 duplicated", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			out := append([]byte{}, ct[:b[0][1]]...)
			out = append(out, ct[b[0][0]:b[0][1]]...)
			return append(out, ct[b[1][0]:]...)
		}, 65536},
		{"chunk 1 removed", func(t *testing.T, ct []byte) []byte {
			b := chunkBounds(t, ct)
			out := append([]byte{}, ct[:b[1][0]]...)
			return append(out, ct[b[2][0]:]...)
		}, 65536},
	}
	for _, cipherID := range []byte{cipherAES, cipherXChaCha} {
		for _, c := range cases {
			t.Run(fmt.Sprintf("cipher=%d/%s", cipherID, c.name), func(t *testing.T) {
				t.Parallel()
				h := newHarness(t)
				pt := testData(threeChunkSize, uint64(cipherID))
				ct, _ := h.craft(cipherID, 65536, "body", pt)
				if n := len(chunkBounds(t, ct)); n != 3 {
					t.Fatalf("fixture has %d chunks, want 3", n)
				}
				bad := c.mutate(t, append([]byte{}, ct...))
				h.writeFile("f.rypt", bad)

				// To a file: exit 4, no output, no temporary file.
				res := h.run("decrypt", h.path("f.rypt"))
				expect(t, res, ExitIntegrity)
				h.assertEntries("", "f.rypt")
				h.wantCalls(0, 1)

				// To stdout: exactly the chunks that authenticated, then exit 4.
				res = h.runIn(bad, "decrypt")
				expect(t, res, ExitIntegrity)
				if !bytes.Equal(res.stdout, pt[:c.stdoutPrefix]) {
					t.Errorf("stdout has %d bytes, want the first %d plaintext bytes", len(res.stdout), c.stdoutPrefix)
				}
				h.wantCalls(0, 2)
			})
		}
	}
}

// TestHeaderRejected: each rejection rule of spec §5, and a header that
// ends early, exits 4 before any API call.
func TestHeaderRejected(t *testing.T) {
	t.Parallel()
	type mutation func(ct []byte, hdr specHeader) []byte
	setU32 := func(off int, v uint32) mutation {
		return func(ct []byte, _ specHeader) []byte { binary.BigEndian.PutUint32(ct[off:], v); return ct }
	}
	set := func(off int, v byte) mutation {
		return func(ct []byte, _ specHeader) []byte { ct[off] = v; return ct }
	}
	// rebuild re-encodes the header with a change and keeps the body.
	rebuild := func(change func(h *specHeader)) mutation {
		return func(ct []byte, hdr specHeader) []byte {
			body := ct[len(hdr.encode()):]
			h2 := hdr
			change(&h2)
			return append(h2.encode(), body...)
		}
	}
	cases := []struct {
		name   string
		mutate mutation
	}{
		{"magic RYPX", set(3, 'X')},
		{"magic lower case", func(ct []byte, _ specHeader) []byte { copy(ct, "rypt"); return ct }},
		{"magic zero", func(ct []byte, _ specHeader) []byte { copy(ct, "\x00\x00\x00\x00"); return ct }},
		{"magic bit flip", func(ct []byte, _ specHeader) []byte { ct[0] ^= 0x01; return ct }},
		{"version 0", set(offVersion, 0)},
		{"version 2", set(offVersion, 2)},
		{"version 0x81", set(offVersion, 0x81)},
		{"cipher 0", set(offCipher, 0)},
		{"cipher 3", set(offCipher, 3)},
		{"cipher 0xff", set(offCipher, 0xff)},
		{"chunk size 0", setU32(offChunkSize, 0)},
		{"chunk size 1", setU32(offChunkSize, 1)},
		{"chunk size 1023", setU32(offChunkSize, 1023)},
		{"chunk size 16 MiB + 1", setU32(offChunkSize, 16<<20+1)},
		{"chunk size 2^31", setU32(offChunkSize, 1<<31)},
		{"chunk size max", setU32(offChunkSize, 0xffffffff)},
		{"label length 1025", rebuild(func(h *specHeader) { h.Label = bytes.Repeat([]byte("l"), 1025) })},
		{"label length 65535", rebuild(func(h *specHeader) { h.Label = bytes.Repeat([]byte("l"), 65535) })},
		{"label invalid UTF-8", rebuild(func(h *specHeader) { h.Label = []byte("ab\xffcd") })},
		{"wrapped length 0", rebuild(func(h *specHeader) { h.Wrapped = nil })},
		{"wrapped length 65537", rebuild(func(h *specHeader) { h.Wrapped = bytes.Repeat([]byte("A"), 65537) })},
		{"wrapped length 2^32-1", func(ct []byte, hdr specHeader) []byte {
			binary.BigEndian.PutUint32(ct[hdr.offWrappedLen():], 0xffffffff)
			return ct
		}},
		{"wrapped invalid UTF-8", rebuild(func(h *specHeader) { h.Wrapped = append([]byte("CiQA"), 0xc3, 0x28) })},
		{"wrapped length past the end", func(ct []byte, hdr specHeader) []byte {
			n := hdr.offWrappedLen()
			binary.BigEndian.PutUint32(ct[n:], 60000)
			return ct[:n+4+1000]
		}},
		{"label length past the end", func(ct []byte, hdr specHeader) []byte {
			binary.BigEndian.PutUint16(ct[offLabelLen:], 1000)
			return ct[:offLabel+500]
		}},
	}
	// Truncated headers: every prefix boundary of the fields.
	for _, n := range []int{0, 1, 3, 4, 5, 6, 9, 10, 25, 26, 27, 28, 30, 31, 33, 34, 35, 100, -1} {
		n := n
		cases = append(cases, struct {
			name   string
			mutate mutation
		}{fmt.Sprintf("truncated header at %d", n), func(ct []byte, hdr specHeader) []byte {
			if n < 0 {
				n = len(hdr.encode()) - 1 // one byte short
			}
			return ct[:n]
		}})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			pt := testData(70000, 6)
			ct, hdr := h.craft(cipherAES, 65536, "lbl", pt) // header: 28 + 3 + 4 + 188 bytes
			if len(hdr.encode()) != 223 {
				t.Fatalf("fixture header is %d bytes, want 223", len(hdr.encode()))
			}
			bad := c.mutate(append([]byte{}, ct...), hdr)
			h.writeFile("f.rypt", bad)

			res := h.run("decrypt", h.path("f.rypt"))
			expect(t, res, ExitIntegrity)
			h.assertEntries("", "f.rypt")

			res = h.runIn(bad, "decrypt", "-o", "-")
			expect(t, res, ExitIntegrity)
			if len(res.stdout) != 0 {
				t.Errorf("wrote %d bytes to stdout for a rejected header", len(res.stdout))
			}
			h.wantCalls(0, 0)
		})
	}
}

// TestHeaderChangedToValidValue: a header field changed to another valid
// value is not caught by the API but fails every chunk, because the whole
// header is the associated data.
func TestHeaderChangedToValidValue(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(ct []byte)
	}{
		{"chunk size 65536 to 1024", func(ct []byte) { binary.BigEndian.PutUint32(ct[offChunkSize:], 1024) }},
		{"chunk size bit 10 flipped", func(ct []byte) { ct[offChunkSize+2] ^= 0x04 }},
		{"chunk size 65536 to 32768", func(ct []byte) { binary.BigEndian.PutUint32(ct[offChunkSize:], 32768) }},
		{"chunk size 65536 to 131072", func(ct []byte) { binary.BigEndian.PutUint32(ct[offChunkSize:], 131072) }},
		{"cipher AES to XChaCha", func(ct []byte) { ct[offCipher] = cipherXChaCha }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			pt := testData(threeChunkSize, 8)
			ct, _ := h.craft(cipherAES, 65536, "", pt)
			c.mutate(ct)
			h.writeFile("f.rypt", ct)
			expect(t, h.run("decrypt", h.path("f.rypt")), ExitIntegrity)
			h.assertEntries("", "f.rypt")
			res := h.runIn(ct, "decrypt")
			expect(t, res, ExitIntegrity)
			if len(res.stdout) != 0 {
				t.Errorf("wrote %d bytes to stdout", len(res.stdout))
			}
			h.wantCalls(0, 2)
		})
	}
}

// TestHeaderLimitsAccepted: files at the edges of what §5 allows, built by
// hand, decrypt.
func TestHeaderLimitsAccepted(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cipher    byte
		chunkSize uint32
		label     string
		size      int
	}{
		{cipherAES, 1024, "", 0},
		{cipherAES, 1024, "", 1024},
		{cipherAES, 1024, "", 5000},
		{cipherXChaCha, 1024, "small chunks", 4096},
		{cipherAES, 1025, "", 3000},
		{cipherXChaCha, 16 << 20, "", 70000},
		{cipherAES, 65536, strings.Repeat("L", 1024), 10},
		{cipherXChaCha, 4096, strings.Repeat("é", 512), 9000},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("cipher=%d/chunk=%d/label=%d/size=%d", c.cipher, c.chunkSize, len(c.label), c.size), func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			pt := testData(c.size, uint64(c.chunkSize))
			ct, _ := h.craft(c.cipher, c.chunkSize, c.label, pt)
			h.writeFile("f.rypt", ct)
			expect(t, h.run("decrypt", h.path("f.rypt")), ExitOK)
			h.assertContent("f", pt)
			h.assertMode0600("f")
			res := h.runIn(ct, "decrypt")
			expect(t, res, ExitOK)
			if !bytes.Equal(res.stdout, pt) {
				t.Error("stdout differs from the plaintext")
			}
			h.wantCalls(0, 2)
		})
	}
}

// TestEmptyInputToDecrypt: an empty file or stdin is a truncated header.
func TestEmptyInputToDecrypt(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("empty.rypt", nil)
	expect(t, h.run("decrypt", h.path("empty.rypt")), ExitIntegrity)
	expect(t, h.runIn(nil, "decrypt"), ExitIntegrity)
	expect(t, h.runIn(nil, "decrypt", "-o", h.path("out")), ExitIntegrity)
	h.wantCalls(0, 0)
	h.assertEntries("", "empty.rypt")
}

// TestPlaintextIsNotCiphertext: decrypting a file that was never encrypted
// is an integrity failure, not a usage or API error.
func TestPlaintextIsNotCiphertext(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.writeFile("notes.txt.rypt", []byte(strings.Repeat("just some text\n", 100)))
	expect(t, h.run("decrypt", h.path("notes.txt.rypt")), ExitIntegrity)
	h.wantCalls(0, 0)
	h.assertEntries("", "notes.txt.rypt")
}

// TestCLIEncryptedTampered runs a tamper case on a file the command line
// encrypted itself, for both ciphers.
func TestCLIEncryptedTampered(t *testing.T) {
	t.Parallel()
	for _, c := range ciphers[1:] {
		h := newHarness(t)
		pt := testData(threeChunkSize, 12)
		ct := h.encryptFixture("f.rypt", pt, "--cipher", c.name, "--label", "x")
		b := chunkBounds(t, ct)
		h.writeFile("trunc.rypt", ct[:b[2][0]])
		res := h.run("decrypt", "-o", "-", h.path("trunc.rypt"))
		expect(t, res, ExitIntegrity)
		if !bytes.Equal(res.stdout, pt[:65536]) {
			t.Errorf("%s: stdout has %d bytes, want 65536", c.name, len(res.stdout))
		}
		flipped := append([]byte{}, ct...)
		flipped[b[1][0]+5] ^= 1
		h.writeFile("flip.rypt", flipped)
		expect(t, h.run("decrypt", h.path("flip.rypt")), ExitIntegrity)
		h.assertMissing("flip")
		expect(t, h.run("decrypt", h.path("f.rypt")), ExitOK)
		h.assertContent("f", pt)
		h.wantCalls(1, 3)
	}
}
