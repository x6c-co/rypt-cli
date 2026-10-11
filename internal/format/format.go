// Package format implements version 1 of the rypt file format: a cleartext
// header followed by a body of AEAD-encrypted chunks.
//
// All integers are big-endian. The header is:
//
//	magic          4 bytes  ASCII "RYPT"
//	version        1 byte   0x01
//	cipher         1 byte   0x01 AES-256-GCM, 0x02 XChaCha20-Poly1305
//	chunk size     4 bytes  plaintext bytes per chunk
//	key ID        16 bytes  rypt key UUID, raw bytes
//	label length   2 bytes  0 to 1024
//	label          variable UTF-8
//	wrapped length 4 bytes  length of the next field
//	wrapped DEK    variable the API's "wrapped" string, as UTF-8 bytes
//
// The body is a sequence of chunks, each the AEAD ciphertext of one
// plaintext chunk followed by its 16-byte tag. Every chunk uses the complete
// header bytes as associated data. The nonce is the chunk counter (big-endian,
// starting at 0) followed by one byte that is 0x01 for the final chunk and
// 0x00 otherwise.
package format

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// Format constants.
const (
	Magic   = "RYPT"
	Version = 0x01

	// DefaultChunkSize is the plaintext chunk size the encryptor writes.
	DefaultChunkSize = 65536
	// MinChunkSize and MaxChunkSize bound the chunk size a header may declare.
	MinChunkSize = 1 << 10
	MaxChunkSize = 16 << 20

	// MaxLabelLen is the largest label, in bytes.
	MaxLabelLen = 1024
	// MaxWrappedLen is the largest wrapped DEK, in bytes.
	MaxWrappedLen = 65536

	// KeySize is the DEK size for both ciphers.
	KeySize = 32
	// TagSize is the AEAD tag size for both ciphers.
	TagSize = 16

	// FixedHeaderLen is the length of the header fields before the label.
	FixedHeaderLen = 4 + 1 + 1 + 4 + 16 + 2
	// MaxHeaderLen is the length of the largest valid header.
	MaxHeaderLen = FixedHeaderLen + MaxLabelLen + 4 + MaxWrappedLen
)

// Cipher identifies the AEAD that encrypts the body.
type Cipher byte

// The supported ciphers, by their header byte.
const (
	AES256GCM         Cipher = 0x01
	XChaCha20Poly1305 Cipher = 0x02
)

// Command-line names of the ciphers.
const (
	aes256GCMName         = "aes-256-gcm"
	xchacha20Poly1305Name = "xchacha20-poly1305"
)

// ErrIntegrity is matched, with errors.Is, by every error that reports an
// integrity failure: a header that fails validation, a chunk that fails
// authentication, or input that ends early (a truncated header or body).
// Errors from the underlying reader or writer do not match it.
var ErrIntegrity = errors.New("integrity check failed")

// Header is a parsed version 1 header.
type Header struct {
	Cipher    Cipher
	ChunkSize uint32
	KeyID     [16]byte
	Label     []byte
	Wrapped   []byte
}

// ParseCipher returns the cipher with the given command-line name,
// "aes-256-gcm" or "xchacha20-poly1305".
func ParseCipher(name string) (Cipher, error) {
	switch name {
	case aes256GCMName:
		return AES256GCM, nil
	case xchacha20Poly1305Name:
		return XChaCha20Poly1305, nil
	}
	return 0, fmt.Errorf("unknown cipher %q: want %s or %s", name, aes256GCMName, xchacha20Poly1305Name)
}

// String returns the command-line name of c.
func (c Cipher) String() string {
	switch c {
	case AES256GCM:
		return aes256GCMName
	case XChaCha20Poly1305:
		return xchacha20Poly1305Name
	}
	return fmt.Sprintf("Cipher(0x%02x)", byte(c))
}

// NewAEAD returns the AEAD for c keyed with key, which must be KeySize bytes.
func NewAEAD(c Cipher, key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key is %d bytes, want %d", len(key), KeySize)
	}
	switch c {
	case AES256GCM:
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	case XChaCha20Poly1305:
		return chacha20poly1305.NewX(key)
	}
	return nil, fmt.Errorf("unknown cipher 0x%02x", byte(c))
}
