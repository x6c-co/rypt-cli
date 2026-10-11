// Package cli implements the rypt command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/x6c-co/rypt-cli/internal/client"
	"github.com/x6c-co/rypt-cli/internal/format"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitAPI         = 1 // the rypt API refused the request or was unreachable
	ExitUsage       = 2 // a usage error, including a refused overwrite
	ExitIO          = 3 // a local I/O error
	ExitIntegrity   = 4 // a bad header, a chunk that fails authentication, or truncated input
	ExitInterrupted = 130
)

// Env is everything Run needs from the process.
type Env struct {
	Args             []string // command-line arguments, without the program name
	Getenv           func(string) string
	Stdin            io.Reader
	Stdout           io.Writer
	Stderr           io.Writer
	StdoutIsTerminal func() bool
	Version          string
}

const usage = `rypt encrypts and decrypts files. Each file gets a new data key from the
rypt API; the file is encrypted locally, and the data key is stored in the
file header wrapped by a rypt key, so it can be recovered only through the
API.

Usage:
  rypt encrypt [flags] [FILE]
  rypt decrypt [flags] [FILE]
  rypt version
  rypt help

encrypt FILE writes FILE.rypt. decrypt FILE.rypt writes FILE; a FILE without
the .rypt suffix needs -o. With no FILE, or with FILE "-", rypt reads stdin
and writes stdout. encrypt does not write to stdout when it is a terminal.

Flags:
  -k, --key-id UUID   the rypt key that wraps the data key (encrypt only;
                      default $RYPT_KEY_ID). decrypt takes the key ID from
                      the file header and ignores this flag.
  -o, --output PATH   the output path; "-" means stdout
  -f, --force         replace an existing output file
      --cipher NAME   aes-256-gcm (default) or xchacha20-poly1305 (encrypt)
      --label TEXT    a label of at most 1024 bytes of UTF-8 (encrypt). It is
                      stored in the clear in the header and binds the wrapped
                      data key: decryption needs the same label.
  -h, --help          show this help

Environment:
  RYPT_TOKEN    the rypt API token (required)
  RYPT_KEY_ID   the default key ID for encrypt
  RYPT_API_URL  the API base URL (default https://api.rypt.dev)

Exit codes:
  0  success
  1  the rypt API refused the request or was unreachable
  2  usage error, including a refused overwrite
  3  local I/O error
  4  integrity failure: a bad header, a chunk that fails authentication,
     or a truncated file
  130  interrupted by SIGINT, SIGTERM or SIGHUP; temporary files are removed

When decrypting to a file, rypt moves the output into place only after the
whole input authenticates. When decrypting to stdout, rypt writes each chunk
as soon as it authenticates. It cannot detect truncation until it reaches the
end of the input, so a truncated input writes partial output to stdout and
then exits with code 4. Discard the output of any run that does not exit 0.

Each encrypt and each decrypt makes one call to the rypt API, which counts
as one operation against the key's monthly allowance. After a connection
error or an HTTP 502, 503 or 504 the call is retried at most twice, and a
retry may count too. Deleting a rypt key makes every file wrapped under it
permanently unrecoverable.
`

// exitError carries the exit code for an error.
type exitError struct {
	code int
	err  error
	hint bool // print a pointer to the help text
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// usageErrorf returns an error for a mistake on the command line or in the
// environment.
func usageErrorf(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...), hint: true}
}

// refusef returns an error for a request rypt declines to carry out, such as
// replacing an existing file. It exits with the usage code.
func refusef(format string, args ...any) error {
	return &exitError{code: ExitUsage, err: fmt.Errorf(format, args...)}
}

func ioError(err error) error {
	return &exitError{code: ExitIO, err: err}
}

// exitCode maps an error to its exit code.
func exitCode(err error) int {
	var ee *exitError
	var ce *client.Error
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &ee):
		return ee.code
	case errors.Is(err, context.Canceled):
		return ExitInterrupted
	case errors.Is(err, format.ErrIntegrity):
		return ExitIntegrity
	case errors.As(err, &ce):
		return ExitAPI
	default:
		return ExitIO
	}
}

// Run runs the rypt command line and returns the process exit code.
func Run(ctx context.Context, env Env) int {
	if len(env.Args) == 0 {
		fmt.Fprint(env.Stderr, usage)
		return ExitUsage
	}
	cmd, args := env.Args[0], env.Args[1:]
	var err error
	switch cmd {
	case "encrypt", "decrypt":
		var opts *options
		opts, err = parseArgs(cmd, args)
		if err == nil && opts.help {
			fmt.Fprint(env.Stdout, usage)
			return ExitOK
		}
		if err == nil {
			if cmd == "encrypt" {
				err = runEncrypt(ctx, env, opts)
			} else {
				err = runDecrypt(ctx, env, opts)
			}
		}
	case "version", "--version":
		if len(args) > 0 {
			err = usageErrorf("version takes no arguments")
			break
		}
		fmt.Fprintf(env.Stdout, "rypt %s\n", env.Version)
	case "help", "-h", "--help":
		fmt.Fprint(env.Stdout, usage)
	default:
		err = usageErrorf("unknown command %q", cmd)
	}
	code := exitCode(err)
	if err != nil {
		if code == ExitInterrupted {
			fmt.Fprintln(env.Stderr, "rypt: interrupted")
		} else {
			fmt.Fprintf(env.Stderr, "rypt: %v\n", err)
		}
		var ee *exitError
		if errors.As(err, &ee) && ee.hint {
			fmt.Fprintln(env.Stderr, "Run 'rypt help' for usage.")
		}
	}
	return code
}

// clientBackoff, when not nil, replaces the client's delay between retries.
// Tests set it to avoid sleeping.
var clientBackoff func(retry int) time.Duration

// newClient returns an API client configured from the environment.
func newClient(env Env) (*client.Client, error) {
	token := env.Getenv("RYPT_TOKEN")
	if token == "" {
		return nil, usageErrorf("RYPT_TOKEN is not set")
	}
	for i := 0; i < len(token); i++ {
		if token[i] <= ' ' || token[i] > '~' {
			return nil, usageErrorf("RYPT_TOKEN contains a character that is not printable ASCII")
		}
	}
	c, err := client.New(client.Options{
		BaseURL:   env.Getenv("RYPT_API_URL"),
		Token:     token,
		UserAgent: "rypt-cli/" + env.Version,
		Backoff:   clientBackoff,
	})
	if err != nil {
		return nil, usageErrorf("RYPT_API_URL: %v", err)
	}
	return c, nil
}
