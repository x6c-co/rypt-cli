package cli

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/x6c-co/rypt-cli/internal/format"
)

const suffix = ".rypt"

func runDecrypt(ctx context.Context, env Env, opts *options) error {
	// decrypt ignores --key-id and RYPT_KEY_ID: the key ID is in the header.
	api, err := newClient(env)
	if err != nil {
		return err
	}

	fromStdin := opts.input == "" || opts.input == "-"
	toStdout := false
	out := ""
	switch {
	case opts.outputSet:
		toStdout, out = opts.output == "-", opts.output
	case fromStdin:
		toStdout = true
	default:
		out = strings.TrimSuffix(opts.input, suffix)
		if out == opts.input || filepath.Base(opts.input) == suffix {
			return usageErrorf("%s does not end in %s; use -o to name the output", opts.input, suffix)
		}
	}

	in, inFile, err := openInput(env, opts.input)
	if err != nil {
		return err
	}
	if inFile != nil {
		defer inFile.Close()
	}
	in = ctxReader{ctx, in}

	h, rawHeader, err := format.ReadHeader(in)
	if err != nil {
		return classify(ctx, fmt.Errorf("%s: %w", describe(opts.input), err))
	}

	var dst io.Writer
	var tmp *tempFile
	if toStdout {
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

	var aad []byte
	if len(h.Label) > 0 {
		aad = h.Label
	}
	// A wrapped DEK that is not base64 cannot have come from the API: the
	// header is damaged, and no operation is spent finding that out.
	// The decoder skips line breaks, so a field of only line breaks decodes
	// to nothing.
	wrapped, err := base64.StdEncoding.AppendDecode(nil, h.Wrapped)
	if err != nil || len(wrapped) == 0 {
		return fmt.Errorf("%s: the wrapped data key in the header is not base64: %w", describe(opts.input), format.ErrIntegrity)
	}
	dek, err := api.Unwrap(ctx, format.FormatKeyID(h.KeyID), wrapped, aad)
	if err != nil {
		return fmt.Errorf("unwrap: %w", err)
	}
	defer clear(dek)
	if len(dek) != format.KeySize {
		return &exitError{code: ExitAPI, err: fmt.Errorf("unwrap: the API returned a %d-byte data key, not %d", len(dek), format.KeySize)}
	}

	if err := format.Decrypt(dst, in, h, rawHeader, dek); err != nil {
		return classify(ctx, fmt.Errorf("%s: %w", describe(opts.input), err))
	}
	if tmp != nil {
		return tmp.commit()
	}
	return nil
}

// classify returns err with its exit code: an integrity failure keeps the
// integrity code, an interrupt returns the context error, and anything else
// is a local I/O error.
func classify(ctx context.Context, err error) error {
	switch {
	case errors.Is(err, format.ErrIntegrity):
		return err
	case ctx.Err() != nil:
		return ctx.Err()
	default:
		return ioError(err)
	}
}
