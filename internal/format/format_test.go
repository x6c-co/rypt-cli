package format

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"strings"
	"testing"
)

// ciphers lists every supported cipher, for tests that cover each.
var ciphers = []Cipher{AES256GCM, XChaCha20Poly1305}

// testKeyID is an arbitrary key ID whose bytes are all distinct.
var testKeyID = [16]byte{
	0x6f, 0x1d, 0x2c, 0x3b, 0x4a, 0x59, 0x48, 0x37,
	0x86, 0x95, 0xa4, 0xb3, 0xc2, 0xd1, 0xe0, 0xff,
}

// testWrapped stands in for the API's base64 "wrapped" string.
const testWrapped = "dGhpcyBpcyBhIHdyYXBwZWQgZGF0YSBrZXk="

// testKey returns a fixed KeySize-byte key.
func testKey() []byte {
	key := make([]byte, KeySize)
	for i := range key {
		key[i] = byte(i*7 + 3)
	}
	return key
}

// newHeader returns a valid header with the given cipher, chunk size and label.
func newHeader(c Cipher, chunkSize uint32, label string) *Header {
	h := &Header{
		Cipher:    c,
		ChunkSize: chunkSize,
		KeyID:     testKeyID,
		Wrapped:   []byte(testWrapped),
	}
	if label != "" {
		h.Label = []byte(label)
	}
	return h
}

// randomBytes returns n pseudo-random bytes, the same for the same n.
func randomBytes(n int) []byte {
	rng := rand.New(rand.NewChaCha8([32]byte{byte(n), byte(n >> 8), byte(n >> 16)}))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	return b
}

// encryptBytes encrypts plaintext under h and key and returns the file.
func encryptBytes(t testing.TB, h *Header, key, plaintext []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := Encrypt(&buf, bytes.NewReader(plaintext), h, key); err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	return buf.Bytes()
}

// decryptBytes reads the header of file and decrypts its body. It returns
// the plaintext written before any error.
func decryptBytes(file, key []byte) ([]byte, error) {
	return decryptFrom(bytes.NewReader(file), key)
}

// decryptFrom reads a header from r and decrypts the rest of r.
func decryptFrom(r io.Reader, key []byte) ([]byte, error) {
	h, raw, err := ReadHeader(r)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	err = Decrypt(&out, r, h, raw, key)
	return out.Bytes(), err
}

// mustMarshal returns the encoding of h.
func mustMarshal(t testing.TB, h *Header) []byte {
	t.Helper()
	raw, err := h.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return raw
}

func TestParseCipher(t *testing.T) {
	for _, c := range ciphers {
		got, err := ParseCipher(c.String())
		if err != nil || got != c {
			t.Errorf("ParseCipher(%q) = %v, %v; want %v", c.String(), got, err, c)
		}
	}
	if got := AES256GCM.String(); got != "aes-256-gcm" {
		t.Errorf("AES256GCM.String() = %q", got)
	}
	if got := XChaCha20Poly1305.String(); got != "xchacha20-poly1305" {
		t.Errorf("XChaCha20Poly1305.String() = %q", got)
	}
	for _, name := range []string{
		"", "AES-256-GCM", "aes256gcm", "aes-128-gcm", "chacha20-poly1305",
		"XChaCha20-Poly1305", " aes-256-gcm", "aes-256-gcm\n", "0x01", "1",
	} {
		if c, err := ParseCipher(name); err == nil {
			t.Errorf("ParseCipher(%q) = %v, want error", name, c)
		}
	}
}

func TestCipherStringUnknown(t *testing.T) {
	for c, want := range map[Cipher]string{0x00: "Cipher(0x00)", 0x03: "Cipher(0x03)", 0xff: "Cipher(0xff)"} {
		if got := c.String(); got != want {
			t.Errorf("Cipher(%d).String() = %q, want %q", byte(c), got, want)
		}
		if _, err := ParseCipher(c.String()); err == nil {
			t.Errorf("ParseCipher(%q) succeeded", c.String())
		}
	}
}

func TestParseKeyID(t *testing.T) {
	const canonical = "6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff"
	for _, s := range []string{
		canonical,
		strings.ToUpper(canonical),
		"6F1d2C3b-4A59-4837-8695-A4b3C2d1E0fF",
	} {
		id, err := ParseKeyID(s)
		if err != nil {
			t.Errorf("ParseKeyID(%q): %v", s, err)
			continue
		}
		if id != testKeyID {
			t.Errorf("ParseKeyID(%q) = %x, want %x", s, id, testKeyID)
		}
		if got := FormatKeyID(id); got != canonical {
			t.Errorf("FormatKeyID(ParseKeyID(%q)) = %q, want %q", s, got, canonical)
		}
	}

	for _, s := range []string{
		"",
		"{6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff}",
		"urn:uuid:6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff",
		"6f1d2c3b4a5948378695a4b3c2d1e0ff",
		"6f1d2c3b-4a59-4837-8695a4b3c2d1e0ff",
		"6f1d2c3b-4a594837-8695-a4b3c2d1e0ff-",
		"6f1d2c3-b4a59-4837-8695-a4b3c2d1e0ff",
		"6f1d2c3b4-a59-4837-8695-a4b3c2d1e0ff",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e0f",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e0fff",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e0fg",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e0f ",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e0+f",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e-0f",
		"x6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff",
		" 6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff ",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff\n",
		"\t6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff",
		"6f1d2c3b_4a59_4837_8695_a4b3c2d1e0ff",
		"6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ﬀ",
	} {
		if id, err := ParseKeyID(s); err == nil {
			t.Errorf("ParseKeyID(%q) = %x, want error", s, id)
		}
	}

	// A hyphen replaced by a hex digit keeps the length and leaves every
	// group hex, so only the check of that one position rejects it.
	for _, p := range []int{8, 13, 18, 23} {
		s := canonical[:p] + "a" + canonical[p+1:]
		if id, err := ParseKeyID(s); err == nil {
			t.Errorf("ParseKeyID(%q) = %x, want error", s, id)
		}
	}
}

func TestFormatKeyID(t *testing.T) {
	tests := []struct {
		id   [16]byte
		want string
	}{
		{[16]byte{}, "00000000-0000-0000-0000-000000000000"},
		{testKeyID, "6f1d2c3b-4a59-4837-8695-a4b3c2d1e0ff"},
		{
			[16]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			"ffffffff-ffff-ffff-ffff-ffffffffffff",
		},
		{
			[16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
			"00010203-0405-0607-0809-0a0b0c0d0e0f",
		},
	}
	for _, tt := range tests {
		got := FormatKeyID(tt.id)
		if got != tt.want {
			t.Errorf("FormatKeyID(%x) = %q, want %q", tt.id, got, tt.want)
		}
		if id, err := ParseKeyID(got); err != nil || id != tt.id {
			t.Errorf("ParseKeyID(%q) = %x, %v; want %x", got, id, err, tt.id)
		}
	}
}

func TestNewAEAD(t *testing.T) {
	for c, nonceSize := range map[Cipher]int{AES256GCM: 12, XChaCha20Poly1305: 24} {
		aead, err := NewAEAD(c, testKey())
		if err != nil {
			t.Fatalf("NewAEAD(%v): %v", c, err)
		}
		if aead.NonceSize() != nonceSize || aead.Overhead() != TagSize {
			t.Errorf("NewAEAD(%v): nonce size %d, overhead %d; want %d, %d",
				c, aead.NonceSize(), aead.Overhead(), nonceSize, TagSize)
		}
		for _, n := range []int{0, 16, 24, 31, 33, 64} {
			if _, err := NewAEAD(c, make([]byte, n)); err == nil {
				t.Errorf("NewAEAD(%v) with a %d-byte key succeeded", c, n)
			}
		}
	}
	for _, c := range []Cipher{0x00, 0x03, 0xff} {
		_, err := NewAEAD(c, testKey())
		if err == nil {
			t.Errorf("NewAEAD(%v) succeeded", c)
		}
		if errors.Is(err, ErrIntegrity) {
			t.Errorf("NewAEAD(%v) error matches ErrIntegrity", c)
		}
	}
}
