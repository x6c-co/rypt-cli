package cli

import (
	"context"
	"fmt"
	"io"
	"unicode/utf8"

	"github.com/x6c-co/rypt-cli/internal/format"
)

func runEncrypt(ctx context.Context, env Env, opts *options) (err error) {
	api, err := newClient(env)
	if err != nil {
		return err
	}

	keyIDText := env.Getenv("RYPT_KEY_ID")
	if opts.keyIDSet {
		keyIDText = opts.keyID
	}
	if keyIDText == "" {
		return usageErrorf("no key ID: use --key-id or set RYPT_KEY_ID")
	}
	keyID, err := format.ParseKeyID(keyIDText)
	if err != nil {
		return usageErrorf("the key ID is not a UUID of the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")
	}

	if len(opts.label) > format.MaxLabelLen {
		return usageErrorf("the label is %d bytes; the limit is %d", len(opts.label), format.MaxLabelLen)
	}
	if !utf8.ValidString(opts.label) {
		return usageErrorf("the label is not valid UTF-8")
	}

	cipher := format.AES256GCM
	if opts.cipherSet {
		if cipher, err = format.ParseCipher(opts.cipher); err != nil {
			return usageErrorf("unknown cipher %q: use aes-256-gcm or xchacha20-poly1305", opts.cipher)
		}
	}

	in, inFile, err := openInput(env, opts.input)
	if err != nil {
		return err
	}
	if inFile != nil {
		defer inFile.Close()
	}

	// Resolve the output and refuse a bad one before calling the API, so a
	// refused write costs no operation.
	toStdout := false
	out := ""
	switch {
	case opts.outputSet:
		toStdout, out = opts.output == "-", opts.output
	case inFile != nil:
		out = opts.input + ".rypt"
	default:
		toStdout = true
	}

	var dst io.Writer
	var tmp *tempFile
	if toStdout {
		if env.StdoutIsTerminal != nil && env.StdoutIsTerminal() {
			return refusef("refusing to write ciphertext to a terminal; use -o or redirect stdout")
		}
		if err := checkStdout(env, opts.input, inFile); err != nil {
			return err
		}
		dst = env.Stdout
	} else {
		if err := checkOutput(opts.input, inFile, out, opts.force); err != nil {
			return err
		}
		if tmp, err = createTemp(out, opts.force); err != nil {
			return err
		}
		defer tmp.discard()
		dst = tmp
	}

	var label []byte
	if opts.label != "" {
		label = []byte(opts.label)
	}
	wrapped, err := api.Wrap(ctx, format.FormatKeyID(keyID), label)
	if err != nil {
		return fmt.Errorf("wrap: %w", err)
	}
	dek := wrapped.DEK
	defer clear(dek)
	if len(dek) != format.KeySize {
		return &exitError{code: ExitAPI, err: fmt.Errorf("wrap: the API returned a %d-byte data key, not %d", len(dek), format.KeySize)}
	}

	h := &format.Header{
		Cipher:    cipher,
		ChunkSize: format.DefaultChunkSize,
		KeyID:     keyID,
		Label:     label,
		Wrapped:   []byte(wrapped.Wrapped),
	}
	if _, err := h.Marshal(); err != nil {
		// The client bounds the wrapped DEK, so this means the API returned a
		// value the header cannot hold.
		return &exitError{code: ExitAPI, err: fmt.Errorf("wrap: the API returned an unusable wrapped data key: %w", err)}
	}

	if err := format.Encrypt(dst, ctxReader{ctx, in}, h, dek); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return ioError(err)
	}
	if tmp != nil {
		return tmp.commit()
	}
	return nil
}
