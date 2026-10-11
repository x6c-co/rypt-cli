package format

import (
	"bytes"
	"errors"
	"testing"
)

// fuzzMaxChunk bounds the chunk size FuzzDecrypt decrypts with, so that a
// header declaring 16 MiB chunks does not make every execution slow.
const fuzzMaxChunk = 1 << 16

func addHeaderSeeds(f *testing.F) {
	for _, h := range []*Header{
		newHeader(AES256GCM, DefaultChunkSize, ""),
		newHeader(XChaCha20Poly1305, MinChunkSize, "label ✓"),
		newHeader(AES256GCM, MaxChunkSize, string(bytes.Repeat([]byte("l"), MaxLabelLen))),
		{Cipher: XChaCha20Poly1305, ChunkSize: 4096, Wrapped: []byte("w")},
	} {
		raw := mustMarshal(f, h)
		f.Add(raw)
		f.Add(raw[:len(raw)-1])
		f.Add(append(bytes.Clone(raw), "trailing body"...))
	}
	f.Add([]byte{})
	f.Add([]byte(Magic))
}

// FuzzReadHeader checks that ReadHeader never panics, rejects malformed
// input only with ErrIntegrity, and on success returns exactly the bytes it
// consumed, which Marshal reproduces.
func FuzzReadHeader(f *testing.F) {
	addHeaderSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		h, raw, err := ReadHeader(r)
		if err != nil {
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("ReadHeader error does not match ErrIntegrity: %v", err)
			}
			return
		}
		if len(raw) > MaxHeaderLen || !bytes.Equal(raw, data[:len(raw)]) {
			t.Fatalf("ReadHeader returned %d raw bytes that are not the input prefix", len(raw))
		}
		if r.Len() != len(data)-len(raw) {
			t.Fatalf("ReadHeader consumed %d bytes but returned %d", len(data)-r.Len(), len(raw))
		}
		again, err := h.Marshal()
		if err != nil {
			t.Fatalf("Marshal rejects a header ReadHeader accepted: %v", err)
		}
		if !bytes.Equal(again, raw) {
			t.Fatal("Marshal(ReadHeader(data)) differs from the bytes read")
		}
	})
}

// FuzzDecrypt checks that decryption never panics and fails only with
// ErrIntegrity. Encryption is deterministic for a given header, key and
// plaintext, so any input that decrypts must be exactly what Encrypt
// produces for the recovered plaintext.
func FuzzDecrypt(f *testing.F) {
	addHeaderSeeds(f)
	for _, c := range ciphers {
		for _, n := range []int{0, 1, smallChunk, 2*smallChunk + 3} {
			f.Add(encryptBytes(f, newHeader(c, smallChunk, "label"), testKey(), randomBytes(n)))
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		h, raw, err := ReadHeader(r)
		if err != nil {
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("ReadHeader error does not match ErrIntegrity: %v", err)
			}
			return
		}
		if h.ChunkSize > fuzzMaxChunk {
			return
		}
		var out bytes.Buffer
		if err := Decrypt(&out, r, h, raw, testKey()); err != nil {
			if !errors.Is(err, ErrIntegrity) {
				t.Fatalf("Decrypt error does not match ErrIntegrity: %v", err)
			}
			return
		}
		if again := encryptBytes(t, h, testKey(), out.Bytes()); !bytes.Equal(again, data) {
			t.Fatal("input decrypted but is not what Encrypt produces for its plaintext")
		}
	})
}
