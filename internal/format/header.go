package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"slices"
	"unicode/utf8"
)

// Offsets of the fixed header fields.
const (
	offVersion   = 4
	offCipher    = 5
	offChunkSize = 6
	offKeyID     = 10
	offLabelLen  = 26
)

// Marshal validates h and returns its encoding. It returns an error, not
// matching ErrIntegrity, if a field is out of range.
func (h *Header) Marshal() ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, err
	}
	b := make([]byte, 0, FixedHeaderLen+len(h.Label)+4+len(h.Wrapped))
	b = append(b, Magic...)
	b = append(b, Version, byte(h.Cipher))
	b = binary.BigEndian.AppendUint32(b, h.ChunkSize)
	b = append(b, h.KeyID[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.Label)))
	b = append(b, h.Label...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(h.Wrapped)))
	b = append(b, h.Wrapped...)
	return b, nil
}

// validate returns an error describing the first field of h that a header
// cannot hold. ReadHeader applies the same field checks, so every header
// that Marshal accepts reads back.
func (h *Header) validate() error {
	if h == nil {
		return errors.New("nil header")
	}
	if err := checkCipher(h.Cipher); err != nil {
		return err
	}
	if err := checkChunkSize(h.ChunkSize); err != nil {
		return err
	}
	if err := checkLabelLen(len(h.Label)); err != nil {
		return err
	}
	if err := checkUTF8("label", h.Label); err != nil {
		return err
	}
	if err := checkWrappedLen(int64(len(h.Wrapped))); err != nil {
		return err
	}
	return checkUTF8("wrapped DEK", h.Wrapped)
}

// ReadHeader reads one header from r, reading no byte past its end. It
// returns the parsed header and the exact bytes read, which are the
// associated data for every chunk.
//
// The header is rejected, with an error matching ErrIntegrity, when the
// magic, version or cipher is unknown, the chunk size is outside
// MinChunkSize to MaxChunkSize, the label is longer than MaxLabelLen or is
// not valid UTF-8, the wrapped DEK is empty, longer than MaxWrappedLen or not
// valid UTF-8, or r ends before the header does.
func ReadHeader(r io.Reader) (*Header, []byte, error) {
	// Every read is an io.ReadFull of a length the header has declared and
	// validated, so nothing past the header is consumed and a hostile length
	// cannot cause a large allocation.
	raw, err := readHeaderBytes(r, nil, FixedHeaderLen)
	if err != nil {
		return nil, nil, err
	}
	if string(raw[:offVersion]) != Magic {
		return nil, nil, invalidHeader(errors.New("unknown magic"))
	}
	if v := raw[offVersion]; v != Version {
		return nil, nil, invalidHeader(fmt.Errorf("unsupported version %d", v))
	}
	h := &Header{
		Cipher:    Cipher(raw[offCipher]),
		ChunkSize: binary.BigEndian.Uint32(raw[offChunkSize:offKeyID]),
	}
	copy(h.KeyID[:], raw[offKeyID:offLabelLen])
	if err := checkCipher(h.Cipher); err != nil {
		return nil, nil, invalidHeader(err)
	}
	if err := checkChunkSize(h.ChunkSize); err != nil {
		return nil, nil, invalidHeader(err)
	}

	labelLen := int(binary.BigEndian.Uint16(raw[offLabelLen:FixedHeaderLen]))
	if err := checkLabelLen(labelLen); err != nil {
		return nil, nil, invalidHeader(err)
	}
	// Read the label together with the wrapped length that follows it.
	if raw, err = readHeaderBytes(r, raw, labelLen+4); err != nil {
		return nil, nil, err
	}
	label := raw[FixedHeaderLen : FixedHeaderLen+labelLen]
	if err := checkUTF8("label", label); err != nil {
		return nil, nil, invalidHeader(err)
	}
	if labelLen > 0 {
		h.Label = bytes.Clone(label)
	}

	wrappedLen := binary.BigEndian.Uint32(raw[len(raw)-4:])
	if err := checkWrappedLen(int64(wrappedLen)); err != nil {
		return nil, nil, invalidHeader(err)
	}
	start := len(raw)
	if raw, err = readHeaderBytes(r, raw, int(wrappedLen)); err != nil {
		return nil, nil, err
	}
	wrapped := raw[start:]
	if err := checkUTF8("wrapped DEK", wrapped); err != nil {
		return nil, nil, invalidHeader(err)
	}
	h.Wrapped = bytes.Clone(wrapped)
	return h, raw, nil
}

// readHeaderBytes appends exactly n bytes read from r to raw. Input that ends
// first is a truncated header.
func readHeaderBytes(r io.Reader, raw []byte, n int) ([]byte, error) {
	raw = slices.Grow(raw, n)
	tail := raw[len(raw) : len(raw)+n]
	if _, err := io.ReadFull(r, tail); err != nil {
		if isTruncation(err) {
			return nil, corrupt("truncated header")
		}
		return nil, fmt.Errorf("reading header: %w", err)
	}
	return raw[:len(raw)+n], nil
}

func checkCipher(c Cipher) error {
	if c != AES256GCM && c != XChaCha20Poly1305 {
		return fmt.Errorf("unknown cipher 0x%02x", byte(c))
	}
	return nil
}

func checkChunkSize(n uint32) error {
	if n < MinChunkSize || n > MaxChunkSize {
		return fmt.Errorf("chunk size %d is outside %d to %d", n, MinChunkSize, MaxChunkSize)
	}
	return nil
}

func checkLabelLen(n int) error {
	if n > MaxLabelLen {
		return fmt.Errorf("label is %d bytes, longer than %d", n, MaxLabelLen)
	}
	return nil
}

// checkWrappedLen takes an int64 so that a 32-bit length from the header
// cannot wrap negative on a 32-bit platform.
func checkWrappedLen(n int64) error {
	switch {
	case n == 0:
		return errors.New("wrapped DEK is empty")
	case n > MaxWrappedLen:
		return fmt.Errorf("wrapped DEK is %d bytes, longer than %d", n, MaxWrappedLen)
	}
	return nil
}

func checkUTF8(field string, b []byte) error {
	if !utf8.Valid(b) {
		return fmt.Errorf("%s is not valid UTF-8", field)
	}
	return nil
}

// corrupt returns an error matching ErrIntegrity with the given detail.
func corrupt(detail string) error {
	return fmt.Errorf("%w: %s", ErrIntegrity, detail)
}

// invalidHeader returns an error matching ErrIntegrity for a header field
// that failed validation.
func invalidHeader(err error) error {
	return fmt.Errorf("%w: invalid header: %v", ErrIntegrity, err)
}

// isTruncation reports whether a read error means the input ended early.
func isTruncation(err error) bool {
	return errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
}
