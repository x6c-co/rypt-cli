package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"
)

// response is one complete HTTP response.
type response struct {
	status    int
	requestID string // x-request-id header, passed through serverText
	body      []byte
	tooLarge  bool // the body exceeded maxResponseBytes and was cut
}

// reply is the body of a 200 response, for the caller to decode and clear.
type reply struct {
	body      []byte
	requestID string
	attempts  int
}

// malformed returns a KindResponse error. msg must be fixed text: it must
// never quote the body, which may hold a DEK.
func (r *reply) malformed(msg string) *Error {
	return &Error{
		Kind:       KindResponse,
		StatusCode: http.StatusOK,
		Message:    msg,
		RequestID:  r.requestID,
		Attempts:   r.attempts,
	}
}

// decode decodes the body into res with decodeDEK and then clears the body.
// It returns the "wrapped" value when wantWrapped, or a KindResponse error.
func (r *reply) decode(wantWrapped bool, res *dekFields) (string, error) {
	wrapped, problem := decodeDEK(r.body, wantWrapped, res)
	clear(r.body)
	if problem != "" {
		return "", r.malformed(problem)
	}
	return wrapped, nil
}

// call posts payload as JSON to the op endpoint of keyID and returns the
// body of a 200 response. It retries on transport errors and on HTTP 502,
// 503 and 504, up to MaxAttempts requests in total. When ctx is done it
// stops and returns ctx.Err().
func (c *Client) call(ctx context.Context, keyID, op string, payload any) (*reply, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		// Not reachable with the request types in this package.
		return nil, &Error{Kind: KindTransport, Message: "cannot encode the API request"}
	}
	endpoint := c.base.String() + "/v1/keys/" + url.PathEscape(keyID) + "/" + op

	var last *Error
	for attempt := 1; attempt <= MaxAttempts; attempt++ {
		if attempt > 1 {
			if err := sleep(ctx, c.backoff(attempt-1)); err != nil {
				return nil, err
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		resp, err := c.exchange(ctx, endpoint, body)
		if err != nil {
			// The caller's ctx decides cancellation. A Client.Timeout error
			// can also look like a deadline, but it is a transport failure
			// and is retried.
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			last = &Error{
				Kind:     KindTransport,
				Message:  "cannot reach the rypt API",
				Attempts: attempt,
				Err:      &transportError{err: err, text: c.serverText(err.Error())},
			}
			if !retryableErr(err) {
				return nil, last
			}
			continue
		}

		if resp.status != http.StatusOK {
			last = c.apiError(resp.status, resp.body, resp.requestID)
			clear(resp.body)
			last.Attempts = attempt
			if !retryableStatus(resp.status) {
				return nil, last
			}
			continue
		}
		if resp.tooLarge {
			clear(resp.body)
			return nil, (&reply{requestID: resp.requestID, attempts: attempt}).malformed("response too large")
		}
		return &reply{body: resp.body, requestID: resp.requestID, attempts: attempt}, nil
	}
	return nil, last
}

// transportError is the Err of a KindTransport Error. The text of a
// net/http error can quote bytes the server sent, such as a malformed status
// or header line, so it is passed through serverText; errors.Is and
// errors.As still reach err.
type transportError struct {
	err  error
	text string
}

func (e *transportError) Error() string { return e.text }
func (e *transportError) Unwrap() error { return e.err }

// exchange sends one request and reads the whole response. A failure to
// read the body is returned as an error, like a failure to connect.
func (c *Client) exchange(ctx context.Context, endpoint string, body []byte) (*response, error) {
	// A fresh body reader for every attempt.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	buf, tooLarge, err := readBody(resp.Body, resp.ContentLength)
	if err != nil {
		clear(buf)
		return nil, fmt.Errorf("reading the response: %w", err)
	}
	return &response{
		status:    resp.StatusCode,
		requestID: c.serverText(resp.Header.Get("X-Request-Id")),
		body:      buf,
		tooLarge:  tooLarge,
	}, nil
}

// readBody reads r to EOF, keeping at most maxResponseBytes+1 bytes. If r
// has more than maxResponseBytes bytes, it stops and reports tooLarge.
// sizeHint is the Content-Length, or -1. The buffer is grown by hand so
// that each outgrown buffer is cleared: the body may hold a DEK.
func readBody(r io.Reader, sizeHint int64) (buf []byte, tooLarge bool, err error) {
	size := 4096
	if sizeHint >= 0 && sizeHint < maxResponseBytes {
		size = int(sizeHint) + 1 // one spare byte to reach EOF without growing
	}
	buf = make([]byte, 0, size)
	for {
		if len(buf) == cap(buf) {
			grown := make([]byte, len(buf), min(2*cap(buf), maxResponseBytes+1))
			copy(grown, buf)
			clear(buf)
			buf = grown
		}
		n, err := r.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if len(buf) > maxResponseBytes {
			return buf, true, nil
		}
		if err == io.EOF {
			return buf, false, nil
		}
		if err != nil {
			return buf, false, err
		}
	}
}

// sleep waits for d or until ctx is done, whichever comes first.
func sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return ctx.Err()
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retryableStatus reports whether a response status is worth retrying.
// HTTP 429 is not: neither the monthly cap nor the rate limit clears in the
// time a retry waits.
func retryableStatus(status int) bool {
	switch status {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryableErr reports whether a failed exchange might succeed if repeated.
// A certificate the client does not trust, or a server that does not speak
// TLS, will fail the same way every time.
func retryableErr(err error) bool {
	var (
		verifyErr  *tls.CertificateVerificationError
		recordErr  tls.RecordHeaderError
		unknownCA  x509.UnknownAuthorityError
		hostErr    x509.HostnameError
		invalidErr x509.CertificateInvalidError
	)
	switch {
	case errors.As(err, &verifyErr),
		errors.As(err, &recordErr),
		errors.As(err, &unknownCA),
		errors.As(err, &hostErr),
		errors.As(err, &invalidErr),
		errors.Is(err, http.ErrSchemeMismatch):
		return false
	}
	return true
}

// dekFields is the 200 body of wrap and unwrap. encoding/json decodes the
// standard base64 "dek" into a []byte, so the key never lives in an
// immutable string. "wrapped" is kept raw so that unwrap can ignore it.
type dekFields struct {
	DEK     []byte          `json:"dek"`
	Wrapped json.RawMessage `json:"wrapped"`
}

// decodeDEK decodes a 200 body into res and checks that it holds a 32-byte
// "dek" and, if wantWrapped, a valid "wrapped" string, which it returns. On
// a problem it zeroes res.DEK and returns a fixed description that never
// quotes the body.
func decodeDEK(body []byte, wantWrapped bool, res *dekFields) (wrapped, problem string) {
	err := json.Unmarshal(body, res)
	switch {
	case err != nil:
		problem = jsonProblem(err)
	case res.DEK == nil:
		problem = "dek is missing"
	case len(res.DEK) != dekLen:
		problem = "dek is not 32 bytes"
	case wantWrapped:
		wrapped, problem = decodeWrapped(res.Wrapped)
	}
	if problem != "" {
		// A decode error can come after the DEK was decoded.
		clear(res.DEK[:cap(res.DEK)])
		return "", problem
	}
	return wrapped, ""
}

// decodeWrapped decodes the "wrapped" value of a wrap response. The value is
// opaque; only its type and length are checked.
func decodeWrapped(raw json.RawMessage) (string, string) {
	if len(raw) == 0 {
		return "", "wrapped is missing or empty"
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", "wrapped is not a string"
	}
	switch {
	case s == "":
		return "", "wrapped is missing or empty"
	case strings.ContainsRune(s, utf8.RuneError):
		// encoding/json turns invalid UTF-8 and lone surrogates into
		// U+FFFD, so s would not be the value the server sent, and the file
		// could never be decrypted.
		return "", "wrapped is not valid UTF-8"
	case len(s) > maxWrappedLen:
		return "", "wrapped is longer than 65536 bytes"
	}
	return s, ""
}

// jsonProblem describes a decoding error without its text, which can quote
// bytes of the body.
func jsonProblem(err error) string {
	var (
		typeErr *json.UnmarshalTypeError
		b64Err  base64.CorruptInputError
	)
	switch {
	case errors.As(err, &b64Err):
		return "dek is not valid base64"
	case errors.As(err, &typeErr) && typeErr.Field == "dek":
		return "dek is not a valid base64 string"
	case errors.As(err, &typeErr):
		return "response is not a JSON object"
	}
	return "response is not valid JSON"
}

// apiError builds the KindAPI error for a non-200 response. It decodes the
// API error envelope when the body is one; otherwise, as for an HTML page
// from a proxy, Code stays empty and Message is fixed text. headerID is the
// sanitized x-request-id header.
func (c *Client) apiError(status int, body []byte, headerID string) *Error {
	e := &Error{Kind: KindAPI, StatusCode: status, RequestID: headerID}

	// Each field is decoded on its own, so one of an unexpected type does
	// not lose the others.
	var env map[string]json.RawMessage
	if json.Unmarshal(body, &env) == nil {
		e.Code = c.jsonText(env["error"])
	}
	if e.Code == "" {
		e.Message = fmt.Sprintf("unexpected HTTP %d response", status)
		return e
	}
	e.Message = c.jsonText(env["message"])
	if id := c.jsonText(env["request_id"]); id != "" {
		e.RequestID = id
	}
	e.ResetsAt = c.jsonText(env["resets_at"])
	var limit int64
	if json.Unmarshal(env["cap"], &limit) == nil && limit > 0 {
		e.Cap = limit
	}
	return e
}

// jsonText returns the value of a JSON string passed through serverText,
// or "" if raw is not a string.
func (c *Client) jsonText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return c.serverText(s)
}

// serverText makes server-supplied text safe to keep in an Error. Besides
// sanitizing it, it redacts the token, in case a server echoes it back; that
// happens before truncation so that no part of the token can survive.
func (c *Client) serverText(s string) string {
	return truncate(strings.ReplaceAll(clean(s), c.token, "[redacted]"))
}
