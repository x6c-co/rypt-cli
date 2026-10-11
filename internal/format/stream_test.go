package format

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"testing"
	"testing/iotest"

	"golang.org/x/crypto/chacha20poly1305"
)

// smallChunk is the chunk size of the files that tamper tests take apart.
const smallChunk = MinChunkSize

// directAEAD builds the AEAD for c from the standard constructors, not
// NewAEAD, so that the tests check the package against an independent
// reading of the spec.
func directAEAD(t testing.TB, c Cipher, key []byte) cipher.AEAD {
	t.Helper()
	var aead cipher.AEAD
	var err error
	switch c {
	case AES256GCM:
		var block cipher.Block
		if block, err = aes.NewCipher(key); err == nil {
			aead, err = cipher.NewGCM(block)
		}
	case XChaCha20Poly1305:
		aead, err = chacha20poly1305.NewX(key)
	default:
		t.Fatalf("no AEAD for cipher %v", c)
	}
	if err != nil {
		t.Fatal(err)
	}
	return aead
}

// specNonce builds the nonce for chunk i by hand: the counter fills every
// byte but the last, big-endian, and the last byte is the final flag.
func specNonce(size, i int, final bool) []byte {
	if i >= 1<<24 {
		panic("specNonce: counter too large for this helper")
	}
	nonce := make([]byte, size)
	nonce[size-4] = byte(i >> 16)
	nonce[size-3] = byte(i >> 8)
	nonce[size-2] = byte(i)
	if final {
		nonce[size-1] = 0x01
	}
	return nonce
}

// openByHand decrypts file without using Decrypt: it splits the body into
// chunks of chunkSize+TagSize bytes and opens each with the spec's nonce. It
// checks the chunk structure and returns the plaintext.
func openByHand(t testing.TB, h *Header, key, file []byte) []byte {
	t.Helper()
	raw := mustMarshal(t, h)
	if !bytes.HasPrefix(file, raw) {
		t.Fatal("file does not start with the encoded header")
	}
	aead := directAEAD(t, h.Cipher, key)
	body := file[len(raw):]
	var out []byte
	for i := 0; ; i++ {
		chunk := body[:min(int(h.ChunkSize)+TagSize, len(body))]
		body = body[len(chunk):]
		final := len(body) == 0
		if len(chunk) < TagSize {
			t.Fatalf("chunk %d is %d bytes, shorter than a tag", i, len(chunk))
		}
		p, err := aead.Open(nil, specNonce(aead.NonceSize(), i, final), chunk, raw)
		if err != nil {
			t.Fatalf("chunk %d (final %v) does not open with the spec nonce: %v", i, final, err)
		}
		out = append(out, p...)
		if final {
			return out
		}
	}
}

// chunkCount returns how many chunks hold n plaintext bytes.
func chunkCount(n, chunkSize int) int {
	return max(1, (n+chunkSize-1)/chunkSize)
}

func TestRoundTrip(t *testing.T) {
	sizes := []struct{ n, chunks int }{
		{0, 1}, {1, 1}, {65535, 1}, {65536, 1}, {65537, 2}, {131072, 2},
	}
	for _, c := range ciphers {
		for _, label := range []string{"", "quarterly report ✓"} {
			for _, size := range sizes {
				t.Run(fmt.Sprintf("%v/label%d/%d", c, len(label), size.n), func(t *testing.T) {
					h := newHeader(c, DefaultChunkSize, label)
					plaintext := randomBytes(size.n)
					file := encryptBytes(t, h, testKey(), plaintext)

					raw := mustMarshal(t, h)
					if got, want := len(file)-len(raw), size.n+size.chunks*TagSize; got != want {
						t.Errorf("body is %d bytes, want %d (%d chunks)", got, want, size.chunks)
					}
					if got := openByHand(t, h, testKey(), file); !bytes.Equal(got, plaintext) {
						t.Error("hand-opened plaintext differs")
					}
					got, err := decryptBytes(file, testKey())
					if err != nil {
						t.Fatalf("decrypt: %v", err)
					}
					if !bytes.Equal(got, plaintext) {
						t.Error("decrypted plaintext differs")
					}
				})
			}
		}
	}
}

// TestRoundTripReaders encrypts and decrypts through readers that return
// short reads, and checks that the file does not depend on how the input
// was read.
func TestRoundTripReaders(t *testing.T) {
	wrappers := []struct {
		name string
		wrap func(io.Reader) io.Reader
	}{
		{"one byte", iotest.OneByteReader},
		{"half", iotest.HalfReader},
		{"data and EOF", iotest.DataErrReader},
		{"one byte, data and EOF", func(r io.Reader) io.Reader {
			return iotest.DataErrReader(iotest.OneByteReader(r))
		}},
	}
	for _, c := range ciphers {
		for _, n := range []int{0, 1, smallChunk - 1, smallChunk, smallChunk + 1, 2 * smallChunk, 3*smallChunk - 7} {
			h := newHeader(c, smallChunk, "label")
			plaintext := randomBytes(n)
			want := encryptBytes(t, h, testKey(), plaintext)
			if got := len(want) - len(mustMarshal(t, h)); got != n+chunkCount(n, smallChunk)*TagSize {
				t.Errorf("%v, %d bytes: body is %d bytes", c, n, got)
			}
			if got := openByHand(t, h, testKey(), want); !bytes.Equal(got, plaintext) {
				t.Errorf("%v, %d bytes: hand-opened plaintext differs", c, n)
			}
			for _, w := range wrappers {
				var file bytes.Buffer
				if err := Encrypt(&file, w.wrap(bytes.NewReader(plaintext)), h, testKey()); err != nil {
					t.Fatalf("%v, %d bytes, %s: Encrypt: %v", c, n, w.name, err)
				}
				if !bytes.Equal(file.Bytes(), want) {
					t.Errorf("%v, %d bytes, %s: Encrypt wrote a different file", c, n, w.name)
				}
				// ReadHeader and Decrypt share the wrapped reader, so this
				// also checks that ReadHeader leaves it at the body.
				got, err := decryptFrom(w.wrap(bytes.NewReader(want)), testKey())
				if err != nil {
					t.Fatalf("%v, %d bytes, %s: decrypt: %v", c, n, w.name, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Errorf("%v, %d bytes, %s: decrypted plaintext differs", c, n, w.name)
				}
			}
		}
	}
}

func TestChunkReader(t *testing.T) {
	const size, spare = 8, 4
	for _, n := range []int{0, 1, size - 1, size, size + 1, 2 * size, 2*size + 1} {
		data := randomBytes(n)
		c := newChunkReader(iotest.DataErrReader(iotest.HalfReader(bytes.NewReader(data))), size, spare)
		var got []byte
		chunks := 0
		for final := false; !final; {
			chunk, last, err := c.next()
			if err != nil {
				t.Fatalf("%d bytes: next: %v", n, err)
			}
			if !last && len(chunk) != size {
				t.Errorf("%d bytes: non-final chunk %d is %d bytes", n, chunks, len(chunk))
			}
			if cap(chunk) != size+spare {
				t.Errorf("%d bytes: chunk %d has capacity %d, want %d", n, chunks, cap(chunk), size+spare)
			}
			got = append(got, chunk...)
			chunks++
			final = last
		}
		if !bytes.Equal(got, data) || chunks != chunkCount(n, size) {
			t.Errorf("%d bytes: read %d bytes in %d chunks, want %d in %d", n, len(got), chunks, n, chunkCount(n, size))
		}

		// Mark the spare capacity as a sealed tag would, then wipe.
		for _, b := range c.bufs {
			for i := len(b); i < cap(b); i++ {
				b[:cap(b)][i] = 0xff
			}
		}
		c.wipe()
		for i, b := range c.bufs {
			if !bytes.Equal(b[:cap(b)], make([]byte, cap(b))) {
				t.Errorf("%d bytes: buffer %d not wiped: %x", n, i, b[:cap(b)])
			}
		}
	}
}

// retainingReader passes reads through to r and keeps every buffer it is
// handed. Retaining p breaks the io.Reader contract; TestBuffersWiped does
// it on purpose, to see what Encrypt and Decrypt leave in their buffers.
type retainingReader struct {
	r    io.Reader
	seen [][]byte
}

func (r *retainingReader) Read(p []byte) (int, error) {
	r.seen = append(r.seen, p)
	return r.r.Read(p)
}

// retainingWriter collects what is written to it and, against the
// io.Writer contract, keeps every slice it is given, for the same reason.
type retainingWriter struct {
	out  bytes.Buffer
	seen [][]byte
}

func (w *retainingWriter) Write(p []byte) (int, error) {
	w.seen = append(w.seen, p)
	return w.out.Write(p)
}

// wiped reports whether bufs is non-empty and every byte of every buffer,
// up to its capacity, is zero.
func wiped(bufs [][]byte) bool {
	for _, b := range bufs {
		if slices.ContainsFunc(b[:cap(b)], func(x byte) bool { return x != 0 }) {
			return false
		}
	}
	return len(bufs) > 0
}

// TestBuffersWiped checks that Encrypt and Decrypt hold the input and the
// decrypted plaintext only in buffers they zero before returning, both on
// success and on failure.
func TestBuffersWiped(t *testing.T) {
	for _, c := range ciphers {
		file, headerLen, plaintext := tamperFile(t, c)
		h := newHeader(c, smallChunk, "label")

		// A writer that fails after the header leaves the second chunk's
		// plaintext in the read-ahead buffer.
		for _, n := range []int{len(file), headerLen} {
			r := &retainingReader{r: bytes.NewReader(plaintext)}
			err := Encrypt(&failWriter{n: n, err: errors.New("disk full")}, r, h, testKey())
			if (err == nil) != (n == len(file)) {
				t.Fatalf("%v: Encrypt with a writer failing after %d bytes: %v", c, n, err)
			}
			if !wiped(r.seen) {
				t.Errorf("%v: Encrypt with a writer failing after %d bytes left its buffers unwiped", c, n)
			}
		}

		tampered := bytes.Clone(file)
		tampered[headerLen+smallChunk+TagSize+7] ^= 0x10
		for _, f := range [][]byte{file, tampered} {
			hdr, raw, err := ReadHeader(bytes.NewReader(f))
			if err != nil {
				t.Fatal(err)
			}
			r := &retainingReader{r: bytes.NewReader(f[headerLen:])}
			w := &retainingWriter{}
			err = Decrypt(w, r, hdr, raw, testKey())
			intact := bytes.Equal(f, file)
			want := plaintext
			if !intact {
				want = plaintext[:smallChunk]
				if !errors.Is(err, ErrIntegrity) {
					t.Fatalf("%v: tampered file: err = %v, want ErrIntegrity", c, err)
				}
			} else if err != nil {
				t.Fatalf("%v: Decrypt: %v", c, err)
			}
			if !bytes.Equal(w.out.Bytes(), want) {
				t.Fatalf("%v (intact %v): wrote %d bytes, want %d", c, intact, w.out.Len(), len(want))
			}
			// The slices written to w are the plaintext itself, so they
			// must be wiped along with the buffers r filled.
			if !wiped(r.seen) || !wiped(w.seen) {
				t.Errorf("%v (intact %v): Decrypt left plaintext in memory it did not wipe", c, intact)
			}
		}
	}
}

func TestSetNonce(t *testing.T) {
	const counter = 0x0102030405060708
	gcm := make([]byte, 12)
	setNonce(gcm, counter, false)
	if want := []byte{0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0}; !bytes.Equal(gcm, want) {
		t.Errorf("12-byte nonce = %x, want %x", gcm, want)
	}
	setNonce(gcm, 1, true)
	if want := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1}; !bytes.Equal(gcm, want) {
		t.Errorf("12-byte final nonce = %x, want %x", gcm, want)
	}

	x := make([]byte, 24)
	setNonce(x, counter, true)
	want := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 1}
	if !bytes.Equal(x, want) {
		t.Errorf("24-byte nonce = %x, want %x", x, want)
	}
}

// TestNonceKnownAnswer pins the nonce layout. It opens chunks of a file with
// literal nonces and the standard AEAD constructors, and checks that the
// classic layout mistakes do not open them.
func TestNonceKnownAnswer(t *testing.T) {
	// 258 chunks, so the counter of the last ones needs two bytes.
	const chunks = 258
	plaintext := randomBytes((chunks-1)*smallChunk + 100)

	// Literal AES-256-GCM nonces: counter in bytes 0 to 10, flag in byte 11.
	gcmNonces := map[int][]byte{
		0:   {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00},
		1:   {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00},
		2:   {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00},
		255: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0x00},
		256: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x00},
		257: {0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01, 0x01},
	}
	// Mistaken nonces for chunk 1, none of which may open it.
	wrongGCM := map[string][]byte{
		"uint64 at the start":  {0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0, 0, 0x00},
		"little-endian":        {0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x00},
		"no flag byte":         {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01},
		"final flag on chunk1": {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x01},
	}

	for _, c := range ciphers {
		h := newHeader(c, smallChunk, "kat")
		raw := mustMarshal(t, h)
		file := encryptBytes(t, h, testKey(), plaintext)
		body := file[len(raw):]
		if want := len(plaintext) + chunks*TagSize; len(body) != want {
			t.Fatalf("%v: body is %d bytes, want %d", c, len(body), want)
		}
		chunk := func(i int) []byte {
			start := i * (smallChunk + TagSize)
			return body[start:min(start+smallChunk+TagSize, len(body))]
		}
		aead := directAEAD(t, c, testKey())
		// An XChaCha20-Poly1305 nonce has the same layout as the GCM one
		// with 12 more leading counter bytes.
		nonceFor := func(gcmNonce []byte) []byte {
			return append(make([]byte, aead.NonceSize()-len(gcmNonce)), gcmNonce...)
		}

		for i, n := range gcmNonces {
			got, err := aead.Open(nil, nonceFor(n), chunk(i), raw)
			if err != nil {
				t.Errorf("%v: chunk %d does not open with nonce %x", c, i, nonceFor(n))
				continue
			}
			start := i * smallChunk
			if !bytes.Equal(got, plaintext[start:min(start+smallChunk, len(plaintext))]) {
				t.Errorf("%v: chunk %d has the wrong plaintext", c, i)
			}
		}
		for name, n := range wrongGCM {
			if _, err := aead.Open(nil, nonceFor(n), chunk(1), raw); err == nil {
				t.Errorf("%v: chunk 1 opens with the %s nonce %x", c, name, nonceFor(n))
			}
		}
		// The final chunk does not open without its flag.
		last := gcmNonces[chunks-1]
		unflagged := slices.Clone(last)
		unflagged[len(unflagged)-1] = 0
		if _, err := aead.Open(nil, nonceFor(unflagged), chunk(chunks-1), raw); err == nil {
			t.Errorf("%v: final chunk opens without the final flag", c)
		}
	}
}

// TestFinalChunkFlag checks that a full last chunk is flagged final and is
// not followed by an empty chunk.
func TestFinalChunkFlag(t *testing.T) {
	for _, c := range ciphers {
		for _, n := range []int{0, smallChunk, 2 * smallChunk} {
			h := newHeader(c, smallChunk, "")
			file := encryptBytes(t, h, testKey(), randomBytes(n))
			body := file[len(mustMarshal(t, h)):]
			if want := n + chunkCount(n, smallChunk)*TagSize; len(body) != want {
				t.Errorf("%v, %d bytes: body is %d bytes, want %d", c, n, len(body), want)
			}
			aead := directAEAD(t, c, testKey())
			last := len(body) - min(len(body), smallChunk+TagSize)
			i := last / (smallChunk + TagSize)
			nonce := specNonce(aead.NonceSize(), i, true)
			if _, err := aead.Open(nil, nonce, body[last:], mustMarshal(t, h)); err != nil {
				t.Errorf("%v, %d bytes: last chunk is not flagged final", c, n)
			}
		}
	}
}

// tamperFile returns a test file of three chunks, the last one partial,
// with its header length and plaintext.
func tamperFile(t testing.TB, c Cipher) (file []byte, headerLen int, plaintext []byte) {
	t.Helper()
	h := newHeader(c, smallChunk, "label")
	plaintext = randomBytes(2*smallChunk + 500)
	return encryptBytes(t, h, testKey(), plaintext), len(mustMarshal(t, h)), plaintext
}

// headerField names the header field at offset i of a header whose label
// is labelLen bytes.
func headerField(i, labelLen int) string {
	switch {
	case i < offVersion:
		return "magic"
	case i < offCipher:
		return "version"
	case i < offChunkSize:
		return "cipher"
	case i < offKeyID:
		return "chunk size"
	case i < offLabelLen:
		return "key ID"
	case i < FixedHeaderLen:
		return "label length"
	case i < FixedHeaderLen+labelLen:
		return "label"
	case i < FixedHeaderLen+labelLen+4:
		return "wrapped length"
	}
	return "wrapped DEK"
}

func TestTamperHeader(t *testing.T) {
	for _, c := range ciphers {
		file, headerLen, _ := tamperFile(t, c)
		fields := map[string]bool{}
		for i := range headerLen {
			field := headerField(i, len("label"))
			fields[field] = true
			for bit := range 8 {
				f := bytes.Clone(file)
				f[i] ^= 1 << bit
				out, err := decryptBytes(f, testKey())
				if !errors.Is(err, ErrIntegrity) {
					t.Errorf("%v: flipping bit %d of byte %d (%s): err = %v, want ErrIntegrity", c, bit, i, field, err)
				}
				// Every chunk is bound to the header, so not even the
				// first chunk may decrypt.
				if len(out) != 0 {
					t.Errorf("%v: flipping bit %d of byte %d (%s): %d plaintext bytes written", c, bit, i, field, len(out))
				}
			}
		}
		if len(fields) != 9 {
			t.Errorf("%v: tampered %d header fields, want 9", c, len(fields))
		}
	}
}

func TestTamperBody(t *testing.T) {
	for _, c := range ciphers {
		file, headerLen, plaintext := tamperFile(t, c)
		for i := headerLen; i < len(file); i++ {
			f := bytes.Clone(file)
			f[i] ^= 1 << (i % 8)
			out, err := decryptBytes(f, testKey())
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%v: flipping body byte %d: err = %v, want ErrIntegrity", c, i-headerLen, err)
			}
			// Only the chunks before the tampered one reach the writer.
			chunk := (i - headerLen) / (smallChunk + TagSize)
			if !bytes.Equal(out, plaintext[:chunk*smallChunk]) {
				t.Fatalf("%v: flipping body byte %d: wrote %d plaintext bytes, want %d",
					c, i-headerLen, len(out), chunk*smallChunk)
			}
		}
	}
}

func TestDecryptWritesOnlyAuthenticatedChunks(t *testing.T) {
	for _, c := range ciphers {
		file, headerLen, plaintext := tamperFile(t, c)
		for chunk := range 3 {
			f := bytes.Clone(file)
			f[headerLen+chunk*(smallChunk+TagSize)+7] ^= 0x10
			out, err := decryptBytes(f, testKey())
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%v: tampered chunk %d: err = %v, want ErrIntegrity", c, chunk, err)
			}
			if !bytes.Equal(out, plaintext[:chunk*smallChunk]) {
				t.Errorf("%v: tampered chunk %d: wrote %d bytes, want exactly the %d bytes before it",
					c, chunk, len(out), chunk*smallChunk)
			}
		}
	}
}

func TestTruncate(t *testing.T) {
	const stride = smallChunk + TagSize
	for _, c := range ciphers {
		file, headerLen, plaintext := tamperFile(t, c)
		for n := headerLen; n < len(file); n++ {
			out, err := decryptBytes(file[:n], testKey())
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("%v: truncated to %d body bytes: err = %v, want ErrIntegrity", c, n-headerLen, err)
			}
			// Complete chunks that are followed by more bytes authenticate
			// as non-final. At a chunk boundary, the last complete chunk is
			// taken as final and fails.
			whole, rest := (n-headerLen)/stride, (n-headerLen)%stride
			want := whole
			if rest == 0 {
				want = max(0, whole-1)
			}
			if !bytes.Equal(out, plaintext[:want*smallChunk]) {
				t.Fatalf("%v: truncated to %d body bytes: wrote %d bytes, want %d",
					c, n-headerLen, len(out), want*smallChunk)
			}
		}
	}
}

func TestEmptyBody(t *testing.T) {
	for _, c := range ciphers {
		file, headerLen, _ := tamperFile(t, c)
		header := file[:headerLen]
		bodies := map[string][]byte{
			"no body":         nil,
			"1 byte":          {0},
			"15 bytes":        make([]byte, 15),
			"16 zero bytes":   make([]byte, 16),
			"a stray tag":     file[len(file)-TagSize:],
			"the first chunk": file[headerLen : headerLen+smallChunk+TagSize],
		}
		for name, body := range bodies {
			f := append(bytes.Clone(header), body...)
			_, err := decryptBytes(f, testKey())
			if !errors.Is(err, ErrIntegrity) {
				t.Errorf("%v, %s: err = %v, want ErrIntegrity", c, name, err)
			}
			// A body too short to hold a tag is reported as truncated.
			if len(body) < TagSize && !strings.Contains(fmt.Sprint(err), "truncated") {
				t.Errorf("%v, %s: err = %v, want a truncation error", c, name, err)
			}
		}
	}
}

func TestAppend(t *testing.T) {
	for _, c := range ciphers {
		// Files whose final chunk is empty, partial and full.
		for _, n := range []int{0, 2*smallChunk + 500, 2 * smallChunk} {
			h := newHeader(c, smallChunk, "label")
			file := encryptBytes(t, h, testKey(), randomBytes(n))
			headerLen := len(mustMarshal(t, h))
			lastStart := headerLen + (chunkCount(n, smallChunk)-1)*(smallChunk+TagSize)
			extras := map[string][]byte{
				"1 byte":                   {0},
				"15 bytes":                 make([]byte, 15),
				"16 bytes":                 make([]byte, 16),
				"17 bytes":                 make([]byte, 17),
				"a full chunk":             randomBytes(smallChunk + TagSize),
				"a copy of the last":       file[lastStart:],
				"a copy of the first":      file[headerLen:min(len(file), headerLen+smallChunk+TagSize)],
				"a copy of the whole body": file[headerLen:],
			}
			for name, extra := range extras {
				f := append(bytes.Clone(file), extra...)
				if _, err := decryptBytes(f, testKey()); !errors.Is(err, ErrIntegrity) {
					t.Errorf("%v, %d bytes, appended %s: err = %v, want ErrIntegrity", c, n, name, err)
				}
			}
		}
	}
}

func TestRearrangeChunks(t *testing.T) {
	const stride = smallChunk + TagSize
	for _, c := range ciphers {
		// Four full chunks, so every rearrangement keeps chunk sizes valid.
		h := newHeader(c, smallChunk, "label")
		file := encryptBytes(t, h, testKey(), randomBytes(4*smallChunk))
		headerLen := len(mustMarshal(t, h))
		chunk := func(i int) []byte { return file[headerLen+i*stride : headerLen+(i+1)*stride] }
		orders := map[string][]int{
			"swap 0 and 1":         {1, 0, 2, 3},
			"swap 1 and 2":         {0, 2, 1, 3},
			"swap 2 and final":     {0, 1, 3, 2},
			"swap 0 and final":     {3, 1, 2, 0},
			"reverse":              {3, 2, 1, 0},
			"delete 0":             {1, 2, 3},
			"delete 1":             {0, 2, 3},
			"delete 2":             {0, 1, 3},
			"delete final":         {0, 1, 2},
			"duplicate 0":          {0, 0, 1, 2, 3},
			"duplicate 1":          {0, 1, 1, 2, 3},
			"duplicate final":      {0, 1, 2, 3, 3},
			"final only":           {3},
			"final first":          {3, 0, 1, 2, 3},
			"repeat whole body":    {0, 1, 2, 3, 0, 1, 2, 3},
			"replace 1 with 0":     {0, 0, 2, 3},
			"replace final with 2": {0, 1, 2, 2},
		}
		for name, order := range orders {
			f := bytes.Clone(file[:headerLen])
			for _, i := range order {
				f = append(f, chunk(i)...)
			}
			if _, err := decryptBytes(f, testKey()); !errors.Is(err, ErrIntegrity) {
				t.Errorf("%v, %s: err = %v, want ErrIntegrity", c, name, err)
			}
		}
	}
}

// TestSplice checks that a body only decrypts under its own header and key.
func TestSplice(t *testing.T) {
	for _, c := range ciphers {
		plaintext := randomBytes(2*smallChunk + 500)
		h := newHeader(c, smallChunk, "label")
		file := encryptBytes(t, h, testKey(), plaintext)
		headerLen := len(mustMarshal(t, h))

		other := newHeader(c, smallChunk, "lab3l")
		otherFile := encryptBytes(t, other, testKey(), plaintext)
		spliced := append(bytes.Clone(otherFile[:headerLen]), file[headerLen:]...)
		if _, err := decryptBytes(spliced, testKey()); !errors.Is(err, ErrIntegrity) {
			t.Errorf("%v: body under another header: err = %v, want ErrIntegrity", c, err)
		}

		wrongKey := testKey()
		wrongKey[0] ^= 1
		out, err := decryptBytes(file, wrongKey)
		if !errors.Is(err, ErrIntegrity) || len(out) != 0 {
			t.Errorf("%v: wrong key: wrote %d bytes, err = %v; want nothing and ErrIntegrity", c, len(out), err)
		}
	}
}

// failWriter accepts n bytes, then fails with err.
type failWriter struct {
	n   int
	err error
	buf bytes.Buffer
}

func (w *failWriter) Write(p []byte) (int, error) {
	if len(p) <= w.n {
		w.n -= len(p)
		return w.buf.Write(p)
	}
	n, _ := w.buf.Write(p[:w.n])
	w.n = 0
	return n, w.err
}

// shortWriter reports one byte fewer than it is given, without an error.
type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return max(0, len(p)-1), nil }

func TestEncryptReaderError(t *testing.T) {
	sentinel := errors.New("disk on fire")
	plaintext := randomBytes(3 * smallChunk)
	for _, c := range ciphers {
		h := newHeader(c, smallChunk, "")
		for _, n := range []int{0, 1, smallChunk - 1, smallChunk, smallChunk + 1, 2 * smallChunk, 3 * smallChunk} {
			for _, readErr := range []error{sentinel, io.ErrUnexpectedEOF} {
				r := io.MultiReader(bytes.NewReader(plaintext[:n]), iotest.ErrReader(readErr))
				err := Encrypt(io.Discard, r, h, testKey())
				// A source's own io.ErrUnexpectedEOF is a failed read, not
				// the end of the input.
				if !errors.Is(err, readErr) || errors.Is(err, ErrIntegrity) {
					t.Errorf("%v: reader failing with %q after %d bytes: err = %v, want the reader's error only",
						c, readErr, n, err)
				}
			}
		}
	}
}

func TestDecryptReaderError(t *testing.T) {
	sentinel := errors.New("disk on fire")
	for _, c := range ciphers {
		file, headerLen, _ := tamperFile(t, c)
		h, raw, err := ReadHeader(bytes.NewReader(file))
		if err != nil {
			t.Fatal(err)
		}
		body := file[headerLen:]
		// Every cut point, including chunk boundaries (where the error
		// arrives during the look-ahead) and the very end.
		for n := 0; n <= len(body); n++ {
			r := io.MultiReader(bytes.NewReader(body[:n]), iotest.ErrReader(sentinel))
			err := Decrypt(io.Discard, r, h, raw, testKey())
			if !errors.Is(err, sentinel) || errors.Is(err, ErrIntegrity) {
				t.Fatalf("%v: reader failing after %d body bytes: err = %v, want the reader's error only", c, n, err)
			}
		}
		// A source that reports io.ErrUnexpectedEOF is truncated.
		for _, n := range []int{0, 1, smallChunk + TagSize, len(body) - 1, len(body)} {
			r := io.MultiReader(bytes.NewReader(body[:n]), iotest.ErrReader(io.ErrUnexpectedEOF))
			if err := Decrypt(io.Discard, r, h, raw, testKey()); !errors.Is(err, ErrIntegrity) {
				t.Errorf("%v: io.ErrUnexpectedEOF after %d body bytes: err = %v, want ErrIntegrity", c, n, err)
			}
		}
	}
}

func TestEncryptWriterError(t *testing.T) {
	sentinel := errors.New("disk full")
	plaintext := randomBytes(2*smallChunk + 500)
	for _, c := range ciphers {
		h := newHeader(c, smallChunk, "label")
		headerLen := len(mustMarshal(t, h))
		for _, n := range []int{0, 10, headerLen, headerLen + 5, headerLen + smallChunk + TagSize, headerLen + 2*(smallChunk+TagSize) + 1} {
			w := &failWriter{n: n, err: sentinel}
			err := Encrypt(w, bytes.NewReader(plaintext), h, testKey())
			if !errors.Is(err, sentinel) || errors.Is(err, ErrIntegrity) {
				t.Errorf("%v: writer failing after %d bytes: err = %v, want the writer's error only", c, n, err)
			}
		}
		err := Encrypt(shortWriter{}, bytes.NewReader(plaintext), h, testKey())
		if !errors.Is(err, io.ErrShortWrite) || errors.Is(err, ErrIntegrity) {
			t.Errorf("%v: short writer: err = %v, want io.ErrShortWrite", c, err)
		}
	}
}

func TestDecryptWriterError(t *testing.T) {
	sentinel := errors.New("disk full")
	for _, c := range ciphers {
		file, headerLen, _ := tamperFile(t, c)
		for _, n := range []int{0, 5, smallChunk, smallChunk + 5, 2*smallChunk + 499} {
			r := bytes.NewReader(file)
			h, raw, err := ReadHeader(r)
			if err != nil {
				t.Fatal(err)
			}
			w := &failWriter{n: n, err: sentinel}
			err = Decrypt(w, r, h, raw, testKey())
			if !errors.Is(err, sentinel) || errors.Is(err, ErrIntegrity) {
				t.Errorf("%v: writer failing after %d bytes: err = %v, want the writer's error only", c, n, err)
			}
		}
		h, raw, _ := ReadHeader(bytes.NewReader(file))
		err := Decrypt(shortWriter{}, bytes.NewReader(file[headerLen:]), h, raw, testKey())
		if !errors.Is(err, io.ErrShortWrite) || errors.Is(err, ErrIntegrity) {
			t.Errorf("%v: short writer: err = %v, want io.ErrShortWrite", c, err)
		}
	}
}

// noRead is a reader that must not be read.
type noRead struct{ t *testing.T }

func (r noRead) Read([]byte) (int, error) {
	r.t.Error("input read before arguments were validated")
	return 0, io.EOF
}

func TestEncryptValidatesFirst(t *testing.T) {
	for _, key := range [][]byte{nil, make([]byte, 16), make([]byte, 31), make([]byte, 33)} {
		var w bytes.Buffer
		err := Encrypt(&w, noRead{t}, newHeader(AES256GCM, DefaultChunkSize, ""), key)
		if err == nil || errors.Is(err, ErrIntegrity) {
			t.Errorf("%d-byte key: err = %v, want a non-integrity error", len(key), err)
		}
		if w.Len() != 0 {
			t.Errorf("%d-byte key: wrote %d bytes", len(key), w.Len())
		}
	}

	bad := []*Header{
		nil,
		newHeader(0x03, DefaultChunkSize, ""),
		newHeader(AES256GCM, MinChunkSize-1, ""),
		newHeader(AES256GCM, DefaultChunkSize, string(make([]byte, MaxLabelLen+1))),
		{Cipher: AES256GCM, ChunkSize: DefaultChunkSize},
	}
	for i, h := range bad {
		var w bytes.Buffer
		err := Encrypt(&w, noRead{t}, h, testKey())
		if err == nil || errors.Is(err, ErrIntegrity) {
			t.Errorf("bad header %d: err = %v, want a non-integrity error", i, err)
		}
		if w.Len() != 0 {
			t.Errorf("bad header %d: wrote %d bytes", i, w.Len())
		}
	}
}

func TestDecryptValidatesArguments(t *testing.T) {
	file, headerLen, _ := tamperFile(t, AES256GCM)
	h, raw, err := ReadHeader(bytes.NewReader(file))
	if err != nil {
		t.Fatal(err)
	}
	body := file[headerLen:]
	check := func(name string, h *Header, raw, key []byte) {
		t.Helper()
		var w bytes.Buffer
		err := Decrypt(&w, bytes.NewReader(body), h, raw, key)
		if err == nil || errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: err = %v, want a non-integrity error", name, err)
		}
		if w.Len() != 0 {
			t.Errorf("%s: wrote %d bytes", name, w.Len())
		}
	}

	check("short key", h, raw, make([]byte, 16))
	check("long key", h, raw, make([]byte, 33))
	check("nil header", nil, raw, testKey())

	edits := map[string]func(h *Header){
		"other cipher":     func(h *Header) { h.Cipher = XChaCha20Poly1305 },
		"other chunk size": func(h *Header) { h.ChunkSize = 2 * smallChunk },
		"invalid chunk":    func(h *Header) { h.ChunkSize = 0 },
		"huge chunk":       func(h *Header) { h.ChunkSize = 1 << 31 },
		"other label":      func(h *Header) { h.Label = []byte("other") },
		"other key ID":     func(h *Header) { h.KeyID[0] ^= 1 },
	}
	for name, edit := range edits {
		h2 := *h
		edit(&h2)
		check(name, &h2, raw, testKey())
	}
	check("raw header with a trailing byte", h, append(bytes.Clone(raw), 'x'), testKey())
}
