package cli

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

// An independent implementation of the version 1 file format, written from
// spec §5 rather than from internal/format, so the tests can check what the
// command line writes and build files it must accept or reject.

const (
	cipherAES     = 0x01
	cipherXChaCha = 0x02

	offVersion   = 4
	offCipher    = 5
	offChunkSize = 6
	offKeyID     = 10
	offLabelLen  = 26
	offLabel     = 28
	tagLen       = 16
)

type specHeader struct {
	Magic     []byte
	Version   byte
	Cipher    byte
	ChunkSize uint32
	KeyID     []byte
	Label     []byte
	Wrapped   []byte
}

func keyIDBytes(id string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(id, "-", ""))
	if err != nil || len(b) != 16 {
		panic("bad test key ID " + id)
	}
	return b
}

// encode returns the header bytes, with the length fields taken from the
// label and wrapped DEK.
func (h specHeader) encode() []byte {
	b := append([]byte{}, h.Magic...)
	b = append(b, h.Version, h.Cipher)
	b = binary.BigEndian.AppendUint32(b, h.ChunkSize)
	b = append(b, h.KeyID...)
	b = binary.BigEndian.AppendUint16(b, uint16(len(h.Label)))
	b = append(b, h.Label...)
	b = binary.BigEndian.AppendUint32(b, uint32(len(h.Wrapped)))
	return append(b, h.Wrapped...)
}

// offWrappedLen is the offset of the wrapped length field.
func (h specHeader) offWrappedLen() int { return offLabel + len(h.Label) }

// parseSpecHeader parses a header strictly and returns it with its length.
func parseSpecHeader(t testing.TB, data []byte) (specHeader, int) {
	t.Helper()
	if len(data) < offLabel {
		t.Fatalf("file is %d bytes, shorter than the fixed header", len(data))
	}
	h := specHeader{
		Magic:     data[0:4],
		Version:   data[offVersion],
		Cipher:    data[offCipher],
		ChunkSize: binary.BigEndian.Uint32(data[offChunkSize:]),
		KeyID:     data[offKeyID : offKeyID+16],
	}
	labelLen := int(binary.BigEndian.Uint16(data[offLabelLen:]))
	if labelLen > 1024 || len(data) < offLabel+labelLen+4 {
		t.Fatalf("bad label length %d", labelLen)
	}
	h.Label = data[offLabel : offLabel+labelLen]
	p := offLabel + labelLen
	wrappedLen := int(binary.BigEndian.Uint32(data[p:]))
	p += 4
	if wrappedLen > 65536 || len(data) < p+wrappedLen {
		t.Fatalf("bad wrapped length %d", wrappedLen)
	}
	h.Wrapped = data[p : p+wrappedLen]
	return h, p + wrappedLen
}

func specAEAD(t testing.TB, cipherID byte, dek []byte) cipher.AEAD {
	t.Helper()
	switch cipherID {
	case cipherAES:
		block, err := aes.NewCipher(dek)
		if err != nil {
			t.Fatal(err)
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	case cipherXChaCha:
		aead, err := chacha20poly1305.NewX(dek)
		if err != nil {
			t.Fatal(err)
		}
		return aead
	}
	t.Fatalf("unknown cipher %#x", cipherID)
	return nil
}

// specNonce is the chunk counter, big-endian, followed by the final flag.
func specNonce(size int, counter uint64, final bool) []byte {
	n := make([]byte, size)
	binary.BigEndian.PutUint64(n[size-9:size-1], counter)
	if final {
		n[size-1] = 1
	}
	return n
}

// specSeal encrypts plaintext into a complete file under h.
func specSeal(t testing.TB, h specHeader, dek, plaintext []byte) []byte {
	t.Helper()
	header := h.encode()
	aead := specAEAD(t, h.Cipher, dek)
	out := append([]byte{}, header...)
	cs := int(h.ChunkSize)
	for i := uint64(0); ; i++ {
		n := min(cs, len(plaintext))
		final := n == len(plaintext)
		out = aead.Seal(out, specNonce(aead.NonceSize(), i, final), plaintext[:n], header)
		plaintext = plaintext[n:]
		if final {
			return out
		}
	}
}

// specOpen decrypts a whole file, failing the test on any deviation from
// the format, and returns the plaintext and the number of chunks.
func specOpen(t testing.TB, data, dek []byte) ([]byte, int) {
	t.Helper()
	h, hdrLen := parseSpecHeader(t, data)
	header := data[:hdrLen]
	aead := specAEAD(t, h.Cipher, dek)
	body := data[hdrLen:]
	if len(body) == 0 {
		t.Fatalf("file has no chunks")
	}
	full := int(h.ChunkSize) + tagLen
	var pt []byte
	chunks := 0
	for i := uint64(0); len(body) > 0; i++ {
		n := min(full, len(body))
		final := n == len(body)
		if !final && n < full {
			t.Fatalf("chunk %d is short", i)
		}
		out, err := aead.Open(nil, specNonce(aead.NonceSize(), i, final), body[:n], header)
		if err != nil {
			t.Fatalf("chunk %d (final=%v) does not authenticate under the spec nonce and header: %v", i, final, err)
		}
		if final && len(out) == 0 && i > 0 {
			t.Fatalf("an empty final chunk follows a full chunk")
		}
		pt = append(pt, out...)
		body = body[n:]
		chunks++
	}
	return pt, chunks
}

// chunkBounds returns the [start, end) offsets of each chunk of a file.
func chunkBounds(t testing.TB, data []byte) [][2]int {
	t.Helper()
	h, p := parseSpecHeader(t, data)
	full := int(h.ChunkSize) + tagLen
	var out [][2]int
	for p < len(data) {
		e := min(p+full, len(data))
		out = append(out, [2]int{p, e})
		p = e
	}
	return out
}
