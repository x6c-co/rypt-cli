package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
)

// errTooManyChunks is returned instead of reusing a nonce. A 64-bit chunk
// counter cannot overflow on real input.
var errTooManyChunks = errors.New("too many chunks")

// Encrypt writes the encoding of h to w, then encrypts everything read from
// r into chunks of h.ChunkSize plaintext bytes and writes them to w.
//
// It reads one chunk ahead so that the last chunk read is the one flagged
// final, including when it is exactly h.ChunkSize bytes. Empty input
// produces a single final chunk with no plaintext.
func Encrypt(w io.Writer, r io.Reader, h *Header, key []byte) error {
	// Validate everything before the first write.
	raw, err := h.Marshal()
	if err != nil {
		return err
	}
	aead, err := NewAEAD(h.Cipher, key)
	if err != nil {
		return err
	}
	if err := writeAll(w, raw); err != nil {
		return err
	}

	// Each chunk is sealed in place, in the spare capacity that chunkReader
	// leaves for the tag, so the plaintext is overwritten as it is encrypted.
	chunks := newChunkReader(r, int(h.ChunkSize), TagSize)
	defer chunks.wipe()
	nonce := make([]byte, aead.NonceSize())
	for counter := uint64(0); ; counter++ {
		chunk, final, err := chunks.next()
		if err != nil {
			return fmt.Errorf("reading input: %w", err)
		}
		setNonce(nonce, counter, final)
		if err := writeAll(w, aead.Seal(chunk[:0], nonce, chunk, raw)); err != nil {
			return err
		}
		if final {
			return nil
		}
		if counter == math.MaxUint64 {
			return errTooManyChunks
		}
	}
}

// Decrypt decrypts the body that follows a header. r must be positioned at
// the first byte after the header, and rawHeader must be the bytes that
// ReadHeader returned for h.
//
// Each chunk is written to w only after it authenticates. A chunk is final
// when no bytes follow it. Decrypt returns an error matching ErrIntegrity
// when a chunk fails authentication or the body is truncated, including a
// body with no chunks. Because chunks are written as they authenticate, w
// may have received plaintext before such an error.
func Decrypt(w io.Writer, r io.Reader, h *Header, rawHeader, key []byte) error {
	// Re-encoding h validates it before its chunk size sizes the buffer, and
	// comparing the encoding to rawHeader ensures that the cipher and chunk
	// size used below are the ones the associated data commits to.
	raw, err := h.Marshal()
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, rawHeader) {
		return errors.New("header does not match its raw bytes")
	}
	aead, err := NewAEAD(h.Cipher, key)
	if err != nil {
		return err
	}

	// Each chunk is opened in place, so the plaintext overwrites the
	// ciphertext and is overwritten in turn by later input.
	chunks := newChunkReader(r, int(h.ChunkSize)+TagSize, 0)
	defer chunks.wipe()
	nonce := make([]byte, aead.NonceSize())
	for counter := uint64(0); ; counter++ {
		chunk, final, err := chunks.next()
		if err != nil {
			if isTruncation(err) {
				return corrupt("truncated body")
			}
			return fmt.Errorf("reading input: %w", err)
		}
		// A final chunk holds at least its tag. This also rejects a body
		// with no chunks at all.
		if len(chunk) < TagSize {
			return corrupt("truncated body")
		}
		setNonce(nonce, counter, final)
		plaintext, err := aead.Open(chunk[:0], nonce, chunk, rawHeader)
		if err != nil {
			return corrupt(fmt.Sprintf("chunk %d failed authentication", counter))
		}
		if err := writeAll(w, plaintext); err != nil {
			return err
		}
		if final {
			return nil
		}
		if counter == math.MaxUint64 {
			return errTooManyChunks
		}
	}
}

// chunkReader reads its input one chunk ahead, so that it can tell which
// chunk is the last: a chunk is final when no bytes follow it. It holds the
// input only in its two buffers, which wipe zeroes.
type chunkReader struct {
	r       io.Reader
	bufs    [2][]byte
	ahead   int  // index of the buffer holding the chunk read ahead
	n       int  // bytes in that chunk
	eof     bool // r has returned io.EOF
	started bool
}

// newChunkReader returns a chunkReader for chunks of up to size bytes, in
// buffers with spare bytes of capacity beyond that.
func newChunkReader(r io.Reader, size, spare int) *chunkReader {
	return &chunkReader{r: r, bufs: [2][]byte{
		make([]byte, size, size+spare),
		make([]byte, size, size+spare),
	}}
}

// next returns the next chunk and whether it is the last. Only the last
// chunk may be short. The chunk and its spare capacity belong to the caller
// until the following call.
func (c *chunkReader) next() (chunk []byte, final bool, err error) {
	if !c.started {
		c.started = true
		if err := c.fill(); err != nil {
			return nil, false, err
		}
	}
	chunk = c.bufs[c.ahead][:c.n]
	c.ahead ^= 1
	c.n = 0
	if !c.eof {
		if err := c.fill(); err != nil {
			return nil, false, err
		}
	}
	return chunk, c.n == 0, nil
}

// fill reads a chunk into the read-ahead buffer. It stops short only at
// io.EOF itself: any other error, including a source's own
// io.ErrUnexpectedEOF, is returned, so that Encrypt never mistakes a failed
// read for the end of its input.
func (c *chunkReader) fill() error {
	buf := c.bufs[c.ahead]
	for c.n < len(buf) {
		m, err := c.r.Read(buf[c.n:])
		c.n += m
		if err == io.EOF {
			c.eof = true
			return nil
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// wipe zeroes both buffers, including their spare capacity.
func (c *chunkReader) wipe() {
	for _, b := range c.bufs {
		clear(b[:cap(b)])
	}
}

// setNonce writes the nonce for chunk number counter: the counter as a
// big-endian integer filling every byte but the last, then the final flag.
// That puts a 64-bit counter in bytes 3 to 10 of a 12-byte nonce and bytes
// 15 to 22 of a 24-byte nonce.
func setNonce(nonce []byte, counter uint64, final bool) {
	clear(nonce)
	n := len(nonce)
	binary.BigEndian.PutUint64(nonce[n-9:n-1], counter)
	if final {
		nonce[n-1] = 0x01
	}
}

// writeAll writes p to w, treating a short write as an error.
func writeAll(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	if err != nil {
		return fmt.Errorf("writing output: %w", err)
	}
	return nil
}
