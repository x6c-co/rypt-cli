package format

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"testing/iotest"
)

// encodeRaw encodes h like Marshal but without validating it, so tests can
// build headers that ReadHeader must reject.
func encodeRaw(h *Header) []byte {
	var b []byte
	b = append(b, Magic...)
	b = append(b, Version, byte(h.Cipher))
	b = binary.BigEndian.AppendUint32(b, h.ChunkSize)
	b = append(b, h.KeyID[:]...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.Label)))
	b = append(b, h.Label...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(h.Wrapped)))
	b = append(b, h.Wrapped...)
	return b
}

// endless is a reader that never ends. Following a header with it shows
// that a rejection is not caused by running out of input.
type endless struct{}

func (endless) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}

func TestMarshalLayout(t *testing.T) {
	h := &Header{
		Cipher:    XChaCha20Poly1305,
		ChunkSize: 0x00010203,
		KeyID:     testKeyID,
		Label:     []byte("ab"),
		Wrapped:   []byte("xyz"),
	}
	want := []byte{
		'R', 'Y', 'P', 'T', // magic
		0x01,                   // version
		0x02,                   // cipher
		0x00, 0x01, 0x02, 0x03, // chunk size
		0x6f, 0x1d, 0x2c, 0x3b, 0x4a, 0x59, 0x48, 0x37, // key ID
		0x86, 0x95, 0xa4, 0xb3, 0xc2, 0xd1, 0xe0, 0xff,
		0x00, 0x02, // label length
		'a', 'b', // label
		0x00, 0x00, 0x00, 0x03, // wrapped length
		'x', 'y', 'z', // wrapped DEK
	}
	got := mustMarshal(t, h)
	if !bytes.Equal(got, want) {
		t.Fatalf("Marshal = %x\nwant      %x", got, want)
	}
	if !bytes.Equal(got, encodeRaw(h)) {
		t.Fatal("encodeRaw disagrees with Marshal")
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	headers := []*Header{
		newHeader(AES256GCM, DefaultChunkSize, ""),
		newHeader(XChaCha20Poly1305, DefaultChunkSize, "backups/2026 ✓"),
		newHeader(AES256GCM, MinChunkSize, strings.Repeat("é", MaxLabelLen/2)),
		newHeader(XChaCha20Poly1305, MaxChunkSize, strings.Repeat("x", MaxLabelLen)),
		{Cipher: AES256GCM, ChunkSize: MinChunkSize, Wrapped: []byte("w")},
		{Cipher: AES256GCM, ChunkSize: MaxChunkSize, Wrapped: bytes.Repeat([]byte("A"), MaxWrappedLen)},
		{Cipher: XChaCha20Poly1305, ChunkSize: 1 << 20, Label: []byte{}, Wrapped: []byte("日本")},
	}
	body := []byte("body bytes that follow the header")
	for i, h := range headers {
		raw := mustMarshal(t, h)
		if len(raw) > MaxHeaderLen {
			t.Errorf("header %d: %d bytes, more than MaxHeaderLen", i, len(raw))
		}
		r := bytes.NewReader(append(bytes.Clone(raw), body...))
		got, gotRaw, err := ReadHeader(r)
		if err != nil {
			t.Fatalf("header %d: ReadHeader: %v", i, err)
		}
		if !bytes.Equal(gotRaw, raw) {
			t.Errorf("header %d: ReadHeader returned raw %x, want %x", i, gotRaw, raw)
		}
		if r.Len() != len(body) {
			t.Errorf("header %d: ReadHeader left %d bytes, want %d", i, r.Len(), len(body))
		}
		if got.Cipher != h.Cipher || got.ChunkSize != h.ChunkSize || got.KeyID != h.KeyID ||
			!bytes.Equal(got.Label, h.Label) || !bytes.Equal(got.Wrapped, h.Wrapped) {
			t.Errorf("header %d: ReadHeader = %+v, want %+v", i, got, h)
		}
		if len(h.Label) == 0 && got.Label != nil {
			t.Errorf("header %d: empty label read back as %q, want nil", i, got.Label)
		}
		if again := mustMarshal(t, got); !bytes.Equal(again, raw) {
			t.Errorf("header %d: Marshal(ReadHeader(raw)) differs from raw", i)
		}

		// The parsed fields do not alias the returned raw bytes.
		for _, field := range [][]byte{got.Label, got.Wrapped} {
			if len(field) > 0 {
				field[0] ^= 0xff
			}
		}
		if !bytes.Equal(gotRaw, raw) {
			t.Errorf("header %d: a parsed field aliases the raw header", i)
		}
	}
}

func TestReadHeaderReadsNoFurther(t *testing.T) {
	sentinel := errors.New("read past the header")
	for _, label := range []string{"", "label"} {
		raw := mustMarshal(t, newHeader(AES256GCM, DefaultChunkSize, label))
		readers := map[string]io.Reader{
			"plain":    io.MultiReader(bytes.NewReader(raw), iotest.ErrReader(sentinel)),
			"one byte": iotest.OneByteReader(io.MultiReader(bytes.NewReader(raw), iotest.ErrReader(sentinel))),
			"half":     iotest.HalfReader(io.MultiReader(bytes.NewReader(raw), iotest.ErrReader(sentinel))),
		}
		for name, r := range readers {
			if _, got, err := ReadHeader(r); err != nil || !bytes.Equal(got, raw) {
				t.Errorf("%s reader, label %q: ReadHeader = %x, %v", name, label, got, err)
			}
		}
	}
}

func TestReadHeaderTruncated(t *testing.T) {
	raw := mustMarshal(t, newHeader(XChaCha20Poly1305, DefaultChunkSize, "label"))
	for n := range len(raw) {
		_, _, err := ReadHeader(bytes.NewReader(raw[:n]))
		if !errors.Is(err, ErrIntegrity) {
			t.Errorf("header truncated to %d of %d bytes: err = %v, want ErrIntegrity", n, len(raw), err)
		}
		// A reader that ends with io.ErrUnexpectedEOF is truncated too.
		r := io.MultiReader(bytes.NewReader(raw[:n]), iotest.ErrReader(io.ErrUnexpectedEOF))
		if _, _, err := ReadHeader(r); !errors.Is(err, ErrIntegrity) {
			t.Errorf("header cut by io.ErrUnexpectedEOF at %d bytes: err = %v, want ErrIntegrity", n, err)
		}
	}
}

func TestReadHeaderReaderError(t *testing.T) {
	sentinel := errors.New("disk on fire")
	raw := mustMarshal(t, newHeader(AES256GCM, DefaultChunkSize, "label"))
	for n := range len(raw) {
		r := io.MultiReader(bytes.NewReader(raw[:n]), iotest.ErrReader(sentinel))
		_, _, err := ReadHeader(r)
		if !errors.Is(err, sentinel) || errors.Is(err, ErrIntegrity) {
			t.Errorf("reader failing after %d bytes: err = %v, want the reader's error only", n, err)
		}
	}
}

// headerCase is a header encoding and whether ReadHeader must accept it.
type headerCase struct {
	name   string
	raw    []byte
	accept bool
}

func headerCases() []headerCase {
	base := newHeader(AES256GCM, DefaultChunkSize, "label")
	enc := func(f func(h *Header)) []byte {
		h := *base
		f(&h)
		return encodeRaw(&h)
	}
	patch := func(f func(b []byte)) []byte {
		b := encodeRaw(base)
		f(b)
		return b
	}
	wrappedLenAt := FixedHeaderLen + len(base.Label)

	return []headerCase{
		{"valid", encodeRaw(base), true},

		{"magic rypt", patch(func(b []byte) { copy(b, "rypt") }), false},
		{"magic zero", patch(func(b []byte) { copy(b, "\x00\x00\x00\x00") }), false},
		{"magic RYPX", patch(func(b []byte) { b[3] = 'X' }), false},

		{"version 0x00", patch(func(b []byte) { b[offVersion] = 0x00 }), false},
		{"version 0x02", patch(func(b []byte) { b[offVersion] = 0x02 }), false},
		{"version 0xff", patch(func(b []byte) { b[offVersion] = 0xff }), false},

		{"cipher 0x00", enc(func(h *Header) { h.Cipher = 0x00 }), false},
		{"cipher 0x01", enc(func(h *Header) { h.Cipher = 0x01 }), true},
		{"cipher 0x02", enc(func(h *Header) { h.Cipher = 0x02 }), true},
		{"cipher 0x03", enc(func(h *Header) { h.Cipher = 0x03 }), false},
		{"cipher 0xff", enc(func(h *Header) { h.Cipher = 0xff }), false},

		{"chunk size 0", enc(func(h *Header) { h.ChunkSize = 0 }), false},
		{"chunk size 1023", enc(func(h *Header) { h.ChunkSize = 1023 }), false},
		{"chunk size 1024", enc(func(h *Header) { h.ChunkSize = 1024 }), true},
		{"chunk size 65536", enc(func(h *Header) { h.ChunkSize = 65536 }), true},
		{"chunk size 16 MiB", enc(func(h *Header) { h.ChunkSize = 16 << 20 }), true},
		{"chunk size 16 MiB + 1", enc(func(h *Header) { h.ChunkSize = 16<<20 + 1 }), false},
		{"chunk size 0xffffffff", enc(func(h *Header) { h.ChunkSize = math.MaxUint32 }), false},

		{"label length 0", enc(func(h *Header) { h.Label = nil }), true},
		{"label length 1024", enc(func(h *Header) { h.Label = bytes.Repeat([]byte("l"), 1024) }), true},
		{"label length 1025", enc(func(h *Header) { h.Label = bytes.Repeat([]byte("l"), 1025) }), false},
		{"label length 0xffff", enc(func(h *Header) { h.Label = bytes.Repeat([]byte("l"), 0xffff) }), false},
		{"label invalid UTF-8", enc(func(h *Header) { h.Label = []byte("lab\xffel") }), false},
		{"label truncated rune", enc(func(h *Header) { h.Label = []byte("caf\xc3") }), false},
		{"label surrogate", enc(func(h *Header) { h.Label = []byte("\xed\xa0\x80") }), false},
		{"label NUL", enc(func(h *Header) { h.Label = []byte("a\x00b") }), true},

		{"wrapped length 0", enc(func(h *Header) { h.Wrapped = nil }), false},
		{"wrapped length 1", enc(func(h *Header) { h.Wrapped = []byte("w") }), true},
		{"wrapped length 65536", enc(func(h *Header) { h.Wrapped = bytes.Repeat([]byte("w"), 65536) }), true},
		{"wrapped length 65537", enc(func(h *Header) { h.Wrapped = bytes.Repeat([]byte("w"), 65537) }), false},
		{"wrapped length 0xffffffff", patch(func(b []byte) {
			binary.BigEndian.PutUint32(b[wrappedLenAt:], math.MaxUint32)
		}), false},
		{"wrapped length 0x80000000", patch(func(b []byte) {
			binary.BigEndian.PutUint32(b[wrappedLenAt:], 0x80000000)
		}), false},
		{"wrapped invalid UTF-8", enc(func(h *Header) { h.Wrapped = []byte("d3Jh\x80cHBlZA==") }), false},
		{"wrapped overlong encoding", enc(func(h *Header) { h.Wrapped = []byte("\xc0\xaf") }), false},
	}
}

func TestReadHeaderValidation(t *testing.T) {
	for _, tc := range headerCases() {
		t.Run(tc.name, func(t *testing.T) {
			// The header is followed by endless input, so a rejection is
			// never just the input running out.
			r := io.MultiReader(bytes.NewReader(tc.raw), endless{})
			h, raw, err := ReadHeader(r)
			if !tc.accept {
				if !errors.Is(err, ErrIntegrity) {
					t.Fatalf("ReadHeader err = %v, want ErrIntegrity", err)
				}
				if h != nil || raw != nil {
					t.Errorf("ReadHeader returned a header with an error")
				}
				return
			}
			if err != nil {
				t.Fatalf("ReadHeader: %v", err)
			}
			if !bytes.Equal(raw, tc.raw) {
				t.Errorf("ReadHeader returned %d raw bytes, want %d", len(raw), len(tc.raw))
			}
		})
	}
}

// TestMarshalAgreesWithReadHeader checks that Marshal accepts exactly the
// headers ReadHeader accepts, so Encrypt never writes an unreadable file.
func TestMarshalAgreesWithReadHeader(t *testing.T) {
	for _, tc := range headerCases() {
		h, _, err := ReadHeader(bytes.NewReader(tc.raw))
		if err != nil {
			// Rebuild the header fields that a rejecting ReadHeader does
			// not return, then check that Marshal rejects them too.
			if tc.raw[offVersion] != Version || string(tc.raw[:4]) != Magic {
				continue // Marshal cannot express these.
			}
			if strings.HasPrefix(tc.name, "wrapped length 0x") {
				continue // The wrapped DEK is not present in tc.raw.
			}
			h = parseRaw(t, tc.raw)
			if _, err := h.Marshal(); err == nil {
				t.Errorf("%s: ReadHeader rejects but Marshal accepts", tc.name)
			}
			continue
		}
		raw, err := h.Marshal()
		if err != nil {
			t.Errorf("%s: ReadHeader accepts but Marshal rejects: %v", tc.name, err)
		} else if !bytes.Equal(raw, tc.raw) {
			t.Errorf("%s: Marshal(ReadHeader(raw)) differs from raw", tc.name)
		}
	}
}

// parseRaw decodes a complete header encoding without validating it.
func parseRaw(t *testing.T, b []byte) *Header {
	t.Helper()
	h := &Header{Cipher: Cipher(b[offCipher]), ChunkSize: binary.BigEndian.Uint32(b[offChunkSize:])}
	copy(h.KeyID[:], b[offKeyID:])
	n := int(binary.BigEndian.Uint16(b[offLabelLen:]))
	h.Label = b[FixedHeaderLen : FixedHeaderLen+n]
	rest := b[FixedHeaderLen+n:]
	m := int(binary.BigEndian.Uint32(rest))
	h.Wrapped = rest[4 : 4+m]
	if len(rest) != 4+m {
		t.Fatalf("parseRaw: %d trailing bytes", len(rest)-4-m)
	}
	return h
}

func TestMarshalRejects(t *testing.T) {
	tests := []struct {
		name string
		edit func(h *Header)
	}{
		{"cipher 0x00", func(h *Header) { h.Cipher = 0x00 }},
		{"cipher 0x03", func(h *Header) { h.Cipher = 0x03 }},
		{"cipher 0xff", func(h *Header) { h.Cipher = 0xff }},
		{"chunk size 0", func(h *Header) { h.ChunkSize = 0 }},
		{"chunk size 1023", func(h *Header) { h.ChunkSize = 1023 }},
		{"chunk size 16 MiB + 1", func(h *Header) { h.ChunkSize = MaxChunkSize + 1 }},
		{"chunk size 0xffffffff", func(h *Header) { h.ChunkSize = math.MaxUint32 }},
		{"label 1025 bytes", func(h *Header) { h.Label = make([]byte, MaxLabelLen+1) }},
		{"label 65536 bytes", func(h *Header) { h.Label = make([]byte, 1<<16) }},
		{"label invalid UTF-8", func(h *Header) { h.Label = []byte{'a', 0xff} }},
		{"wrapped nil", func(h *Header) { h.Wrapped = nil }},
		{"wrapped empty", func(h *Header) { h.Wrapped = []byte{} }},
		{"wrapped 65537 bytes", func(h *Header) { h.Wrapped = bytes.Repeat([]byte("w"), MaxWrappedLen+1) }},
		{"wrapped invalid UTF-8", func(h *Header) { h.Wrapped = []byte{0xfe} }},
	}
	for _, tt := range tests {
		h := newHeader(AES256GCM, DefaultChunkSize, "label")
		tt.edit(h)
		raw, err := h.Marshal()
		if err == nil {
			t.Errorf("%s: Marshal = %x, want error", tt.name, raw)
			continue
		}
		if errors.Is(err, ErrIntegrity) {
			t.Errorf("%s: Marshal error %q matches ErrIntegrity", tt.name, err)
		}
	}

	var nilHeader *Header
	if _, err := nilHeader.Marshal(); err == nil || errors.Is(err, ErrIntegrity) {
		t.Errorf("nil Header: Marshal err = %v, want a non-integrity error", err)
	}
}
