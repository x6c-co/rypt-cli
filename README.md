# rypt

`rypt` encrypts and decrypts files with envelope encryption. For each file it
asks the [rypt](https://rypt.dev) API for a new 256-bit data key (DEK),
encrypts the file locally with that key, and stores the DEK, wrapped by a
rypt key, in the file header. Decryption sends the wrapped DEK back to the API
to unwrap it and decrypts locally.

The file contents never leave your machine. The rypt service holds the
key-encryption keys; `rypt` never sees them.

## Install

With [Homebrew](https://brew.sh), on macOS or Linux:

```sh
brew install --cask x6c-co/tap/rypt
```

Or download it: each [release](https://github.com/x6c-co/rypt-cli/releases)
has a binary for Linux, macOS, and Windows on amd64 and arm64, named like
`rypt-linux-amd64`, and a `SHA256SUMS` file. The macOS binaries are signed with
a Developer ID certificate and notarized by Apple. Rename the binary to `rypt`
(`rypt.exe` on Windows) and, on Linux and macOS, make it executable with
`chmod +x rypt`.

Or install with Go:

```sh
go install github.com/x6c-co/rypt-cli/cmd/rypt@latest
```

Or build from a checkout with GNU make (`gmake` on the BSDs):

```sh
make build        # ./rypt for this machine
make dist         # dist/rypt-{linux,darwin}-{amd64,arm64}, dist/rypt-windows-{amd64,arm64}.exe
                  # and dist/SHA256SUMS
make dist VERSION=v1.0.0
```

`rypt version` prints the version given to `make`, or else the module version
that `go install` records. To check a release or `make dist` output, run
`sha256sum -c --ignore-missing SHA256SUMS`
(`shasum -a 256 -c --ignore-missing SHA256SUMS` on macOS) in the directory
that holds it.

## Usage

```
rypt encrypt [flags] [FILE]
rypt decrypt [flags] [FILE]
rypt version
rypt help
```

```sh
export RYPT_TOKEN=ry_...                       # from the rypt dashboard
export RYPT_KEY_ID=0f1e2d3c-4b5a-6978-8796-a5b4c3d2e1f0

rypt encrypt report.pdf                        # writes report.pdf.rypt
rypt decrypt report.pdf.rypt                   # writes report.pdf
rypt decrypt -o copy.pdf report.pdf.rypt
tar -czf - photos/ | rypt encrypt --label photos-2026 > photos.tgz.rypt
rypt decrypt < photos.tgz.rypt | tar -xzf -
```

| Flag | Applies to | Meaning |
| --- | --- | --- |
| `-k`, `--key-id UUID` | encrypt | The rypt key that wraps the DEK. Overrides `RYPT_KEY_ID`. `decrypt` reads the key ID from the file header and ignores this flag. |
| `-o`, `--output PATH` | both | The output path. `-o -` means stdout. |
| `-f`, `--force` | both | Allows replacing an existing output file. |
| `--cipher NAME` | encrypt | `aes-256-gcm` (default) or `xchacha20-poly1305`. |
| `--label TEXT` | encrypt | A label of at most 1024 bytes of UTF-8, stored in the header and bound to the wrapped DEK. |

| Variable | Meaning |
| --- | --- |
| `RYPT_TOKEN` | Required. The rypt API token. There is no flag for it, so it never appears in a process list. |
| `RYPT_KEY_ID` | The default key for `encrypt`. |
| `RYPT_API_URL` | The API base URL, default `https://api.rypt.dev`. Plain `http` is accepted only for `localhost`, `127.0.0.1`, and `::1`, and is never sent through a proxy. This variable exists for tests. |

Input and output:

- `encrypt FILE` writes `FILE.rypt`. `decrypt FILE.rypt` writes `FILE`. A file
  to decrypt without the `.rypt` suffix needs `-o`.
- With no `FILE`, or with `FILE` set to `-`, `rypt` reads stdin and writes
  stdout. `encrypt` refuses to write ciphertext to a terminal.
- `rypt` never replaces an existing file unless you pass `--force`, and it
  refuses to write over its input, including when stdout is the input file
  (`rypt decrypt -o - f.rypt >> f.rypt`). These checks run before any API
  call, so a refused run costs no operation.
- The output must be a regular file. To write to a device or a named pipe,
  use `-o -` and redirect stdout, for example
  `rypt decrypt -o - f.rypt > /dev/null` to check a file's integrity.
- Output files are created with mode 0600 (on Windows, mode bits have no
  effect). Output goes to a temporary file in the destination directory,
  which is moved into place only when it is complete. Without `--force` the
  move is a hard link, which cannot replace a file that appeared in the
  meantime.
- Directories are not accepted. Archive one first, for example with `tar`.

### Decrypting to stdout

When decrypting to a file, `rypt` writes nothing at the destination unless the
whole input authenticates. When decrypting to stdout, `rypt` writes each 64 KiB
chunk as soon as that chunk authenticates. It cannot detect truncation until
it reaches the end of the input, so a truncated input produces partial output
followed by exit code 4. Treat the output of any run that does not exit 0 as
untrusted. In a shell pipeline, use `set -o pipefail` to see the failure.

### Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. |
| 1 | The rypt API refused the request or was unreachable. The message includes the API error code and request ID. |
| 2 | Usage error: a missing token, a missing or malformed key ID, a bad flag, or a refused overwrite. |
| 3 | Local I/O error. |
| 4 | Integrity failure: header validation failed, a chunk failed authentication, or the file is truncated. |
| 130 | Interrupted by SIGINT, SIGTERM, or SIGHUP (a closed terminal or a dropped SSH session). Temporary files are removed. If `rypt` is blocked, for example reading a terminal, it gives up after 2 seconds; a second signal ends the wait at once. |

`rypt` cannot check a header field that is bound to the wrapped DEK until the
API unwraps it. A header whose key ID, label, wrapped DEK, or wrapped length
was changed but still parses is usually refused by the API (`not_found`,
`key_not_allowed`, or `invalid_ciphertext`), which gives exit code 1. A change
that makes the header invalid, such as a label or wrapped DEK that is no
longer UTF-8 or a length out of range, gives exit code 4, as does any change
to the body.

## Operational notes

- **Deleting a rypt key makes every file wrapped under it permanently
  unrecoverable.** A deleted key can be restored for seven days, during which
  it refuses every operation.
- **Rotating the free-tier key makes files wrapped under the previous version
  undecryptable.** Free keys keep one version.
- The rypt service receives the plaintext DEK during `wrap` and `unwrap`. It
  never receives the file contents.
- The file header, including the label, is stored in clear and is not secret.
  Do not put secrets in labels.
- Decryption needs a successful call to the rypt API. There is no offline
  mode.
- Each `encrypt` and each `decrypt` makes one API call, which counts as one
  operation against the key's monthly allowance. After a connection error or
  an HTTP 502, 503, or 504 the call is retried at most twice, and a retry may
  count too. A free key that reaches its cap is refused until the date `rypt`
  prints (`resets_at`).
- `rypt` zeroes the DEK in memory when the file is done. Go does not guarantee
  that no other copies exist, so this is best effort.
- `rypt` never prints the token or a DEK, but Go's verbose HTTP/2 debug
  logging does: do not run `rypt` with `GODEBUG=http2debug=2` where its
  stderr is kept. (`GODEBUG=http2client=0` makes it use HTTP/1.1, which has
  no such logging.)

## File format (version 1)

All integers are big-endian.

| Field | Size | Contents |
| --- | --- | --- |
| magic | 4 bytes | ASCII `RYPT` |
| version | 1 byte | `0x01` |
| cipher | 1 byte | `0x01` AES-256-GCM, `0x02` XChaCha20-Poly1305 |
| chunk size | 4 bytes | Plaintext bytes per chunk; `rypt` writes 65536 |
| key ID | 16 bytes | The rypt key UUID, raw bytes |
| label length | 2 bytes | 0 to 1024 |
| label | variable | UTF-8 |
| wrapped length | 4 bytes | Length of the next field, 1 to 65536 |
| wrapped DEK | variable | The API's `wrapped` string, byte for byte |

The body is a sequence of chunks, each the AEAD ciphertext of one plaintext
chunk followed by its 16-byte tag. Every chunk but the last holds exactly
`chunk size` plaintext bytes; an empty input produces one empty final chunk.
The nonce is the chunk counter, big-endian from 0, in all but the last byte
(12-byte nonce for AES-256-GCM, 24-byte for XChaCha20-Poly1305); the last
byte is `0x01` for the final chunk and `0x00` otherwise. The associated data
of every chunk is the complete header, so any change to the header, and any
truncation, reordering, or extension of the body, fails authentication.

## Development

```sh
make vet test                 # go vet, gofmt check, unit and mock-server tests
make race                     # tests with the race detector (needs cgo)
RYPT_TOKEN=... RYPT_KEY_ID=... make integration   # live API, about 15 operations
go run scripts/probe.go       # record live wrap/unwrap shapes, see docs/api-notes.md
```

The unit tests cover the file format, including tamper and header-validation
cases. The client and command tests run against an in-memory mock of the API
built with `net/http/httptest`, selected with `RYPT_API_URL`. The integration
tests build the binary, run full round trips against the live API, and skip
when `RYPT_TOKEN` or `RYPT_KEY_ID` is unset. They never print the token.

[docs/api-notes.md](docs/api-notes.md) records the observed behaviour of the
`wrap` and `unwrap` endpoints.

[docs/releasing.md](docs/releasing.md) explains how a release is built,
signed, and published.

## License

MIT. See [LICENSE](LICENSE).
