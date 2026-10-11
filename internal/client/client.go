// Package client is a minimal client for the rypt API's wrap and unwrap
// operations. See docs/api-notes.md for the observed request and response
// shapes.
package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// DefaultBaseURL is the production API.
const DefaultBaseURL = "https://api.rypt.dev"

// RequestTimeout bounds each HTTP request, including reading the response.
const RequestTimeout = 30 * time.Second

// MaxAttempts is the number of times a request is sent: one try and up to
// two retries.
const MaxAttempts = 3

const (
	// dekLen is the only DEK length the program accepts.
	dekLen = 32
	// maxWrappedLen is the largest "wrapped" value a file header can hold
	// (the header's wrapped length limit).
	maxWrappedLen = 65536
	// maxResponseBytes caps how much of a response body is read.
	maxResponseBytes = 1 << 20
	// defaultUserAgent is sent when Options.UserAgent is empty.
	defaultUserAgent = "rypt"
)

// Options configures a Client.
type Options struct {
	// BaseURL is the API base URL. Empty means DefaultBaseURL. It is
	// validated with ParseBaseURL.
	BaseURL string
	// Token is the API token. It is sent only in the Authorization header.
	Token string
	// UserAgent is sent in the User-Agent header.
	UserAgent string
	// HTTPClient, if not nil, replaces the default client, which has a
	// RequestTimeout timeout and does not follow redirects. Tests use it.
	HTTPClient *http.Client
	// Backoff, if not nil, returns the delay before retry n (1 or 2). Tests
	// use it to avoid sleeping.
	Backoff func(retry int) time.Duration
}

// Client calls the rypt API.
type Client struct {
	base      *url.URL
	token     string
	userAgent string
	http      *http.Client
	backoff   func(retry int) time.Duration
}

// WrapResult is the result of a successful wrap.
type WrapResult struct {
	// DEK is the 32-byte data key the server generated. The caller zeroes
	// it when done.
	DEK []byte
	// Wrapped is the API's "wrapped" string, exactly as received.
	Wrapped string
}

// Kind classifies an Error.
type Kind int

const (
	// KindAPI means the API answered with an error status.
	KindAPI Kind = iota + 1
	// KindTransport means the API could not be reached, or the connection
	// failed before a complete response arrived.
	KindTransport
	// KindResponse means the API answered 200 with a body that does not
	// have the expected shape.
	KindResponse
)

// Error is the only error type Wrap and Unwrap return, apart from ctx.Err()
// (context.Canceled or context.DeadlineExceeded) when ctx is done. All text
// that came from the server has had control characters removed.
type Error struct {
	Kind       Kind
	StatusCode int    // HTTP status; 0 for KindTransport
	Code       string // API "error" code; may be empty
	Message    string // API "message", or a description of the failure
	RequestID  string // API "request_id", else the x-request-id header
	Cap        int64  // "cap" of ops_cap_reached
	ResetsAt   string // "resets_at" of ops_cap_reached
	Attempts   int    // requests sent
	Err        error  // the underlying transport error, for KindTransport
}

func (e *Error) Error() string {
	var b strings.Builder
	switch e.Kind {
	case KindTransport:
		msg := e.Message
		if msg == "" {
			msg = "cannot reach the rypt API"
		}
		b.WriteString(msg)
		switch {
		case e.Attempts == 1:
			b.WriteString(" after 1 attempt")
		case e.Attempts > 1:
			fmt.Fprintf(&b, " after %d attempts", e.Attempts)
		}
		if e.Err != nil {
			// Transport errors can quote bytes the server sent, such as a
			// malformed status line.
			b.WriteString(": ")
			b.WriteString(sanitize(e.Err.Error()))
		}
		return b.String()
	case KindResponse:
		fmt.Fprintf(&b, "malformed API response (HTTP %d)", e.StatusCode)
		if e.Message != "" {
			b.WriteString(": ")
			b.WriteString(e.Message)
		}
	default:
		b.WriteString("API error")
		if e.Code != "" {
			b.WriteString(" ")
			b.WriteString(e.Code)
		}
		fmt.Fprintf(&b, " (HTTP %d)", e.StatusCode)
		if e.Message != "" {
			b.WriteString(": ")
			b.WriteString(e.Message)
		}
		var limits []string
		if e.Cap > 0 {
			limits = append(limits, "cap "+strconv.FormatInt(e.Cap, 10))
		}
		if e.ResetsAt != "" {
			limits = append(limits, "resets at "+e.ResetsAt)
		}
		if len(limits) > 0 {
			b.WriteString("; ")
			b.WriteString(strings.Join(limits, ", "))
		}
	}
	if e.RequestID != "" {
		fmt.Fprintf(&b, " (request_id %s)", e.RequestID)
	}
	return b.String()
}

func (e *Error) Unwrap() error { return e.Err }

// ParseBaseURL validates an API base URL. The scheme must be https, or http
// when the host is localhost, 127.0.0.1 or ::1. The URL must have a host and
// no user info, query or fragment. A trailing slash is removed from the
// path.
func ParseBaseURL(raw string) (*url.URL, error) {
	if raw == "" {
		raw = DefaultBaseURL
	}
	// The URL is not echoed in errors: it could carry a password.
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("invalid API base URL")
	}
	switch {
	case u.Opaque != "":
		return nil, errors.New("invalid API base URL")
	case u.User != nil:
		return nil, errors.New("API base URL must not contain user info")
	case strings.Contains(raw, "?"):
		// Checked on the raw string so that a bare "?" is refused too.
		return nil, errors.New("API base URL must not contain a query")
	case strings.Contains(raw, "#"):
		return nil, errors.New("API base URL must not contain a fragment")
	case u.Hostname() == "":
		return nil, errors.New("API base URL must have a host")
	}
	host := u.Host
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackName(u.Hostname()) {
			return nil, errors.New("API base URL must use https unless the host is localhost, 127.0.0.1 or ::1")
		}
		// net/http bypasses a proxy only for the exact name "localhost", so
		// "LOCALHOST" would send the token through HTTP_PROXY in clear text.
		host = strings.ToLower(host)
	default:
		return nil, errors.New("API base URL must use https")
	}
	return &url.URL{
		Scheme:  u.Scheme,
		Host:    host,
		Path:    strings.TrimRight(u.Path, "/"),
		RawPath: strings.TrimRight(u.RawPath, "/"),
	}, nil
}

// isLoopbackName reports whether host is one of the names for which plain
// http is allowed. It deliberately matches names, not address ranges. The
// comparison ignores ASCII case only: strings.EqualFold would also accept
// non-ASCII look-alikes such as "localhoſt".
func isLoopbackName(host string) bool {
	return strings.ToLower(host) == "localhost" || host == "127.0.0.1" || host == "::1"
}

// New returns a Client. It returns an error if the base URL is invalid, or
// if the token is empty or contains a control character, which cannot be
// sent in an HTTP header.
func New(opts Options) (*Client, error) {
	base, err := ParseBaseURL(opts.BaseURL)
	if err != nil {
		return nil, err
	}
	if opts.Token == "" {
		return nil, errors.New("API token is empty")
	}
	// Not a format check: a control character cannot go in an HTTP header,
	// and net/http would refuse every attempt.
	if strings.ContainsFunc(opts.Token, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return nil, errors.New("API token contains control characters")
	}
	c := &Client{
		base:      base,
		token:     opts.Token,
		userAgent: opts.UserAgent,
		http:      opts.HTTPClient,
		backoff:   opts.Backoff,
	}
	if c.userAgent == "" {
		c.userAgent = defaultUserAgent
	}
	if c.http == nil {
		c.http = defaultHTTPClient()
	}
	if c.backoff == nil {
		c.backoff = defaultBackoff
	}
	return c, nil
}

// defaultHTTPClient returns a client with a RequestTimeout timeout that never
// follows redirects, so the token and body are never re-sent to another URL.
func defaultHTTPClient() *http.Client {
	var transport *http.Transport
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = t.Clone()
	} else {
		transport = &http.Transport{Proxy: http.ProxyFromEnvironment}
	}
	transport.Proxy = httpsOnlyProxy(transport.Proxy)
	return &http.Client{
		Transport: transport,
		Timeout:   RequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// httpsOnlyProxy returns a proxy function that uses next for https requests
// only. Plain http is only ever allowed to a loopback host, and through a
// proxy the token would travel in clear text. https requests still use
// HTTPS_PROXY, through a CONNECT tunnel that carries the TLS session.
func httpsOnlyProxy(next func(*http.Request) (*url.URL, error)) func(*http.Request) (*url.URL, error) {
	return func(r *http.Request) (*url.URL, error) {
		if r.URL.Scheme != "https" || next == nil {
			return nil, nil
		}
		return next(r)
	}
}

// defaultBackoff returns the delay before retry n.
func defaultBackoff(retry int) time.Duration {
	if retry <= 1 {
		return 250 * time.Millisecond
	}
	return 750 * time.Millisecond
}

// wrapRequest is the wrap body. It never has a "dek" field: the server
// generates the DEK. An empty aad is omitted, so the body is {}.
type wrapRequest struct {
	AAD []byte `json:"aad,omitempty"`
}

// unwrapRequest is the unwrap body. An empty aad is omitted.
type unwrapRequest struct {
	Wrapped string `json:"wrapped"`
	AAD     []byte `json:"aad,omitempty"`
}

// Wrap asks the server to generate a DEK and wrap it under keyID. aad is
// sent only when it is not empty.
func (c *Client) Wrap(ctx context.Context, keyID string, aad []byte) (*WrapResult, error) {
	rep, err := c.call(ctx, keyID, "wrap", wrapRequest{AAD: aad})
	if err != nil {
		return nil, err
	}
	var res dekFields
	wrapped, err := rep.decode(true, &res)
	if err != nil {
		return nil, err
	}
	return &WrapResult{DEK: res.DEK, Wrapped: wrapped}, nil
}

// Unwrap asks the server to unwrap wrapped under keyID and returns the
// 32-byte DEK. aad is sent only when it is not empty. The caller zeroes the
// returned slice when done.
func (c *Client) Unwrap(ctx context.Context, keyID, wrapped string, aad []byte) ([]byte, error) {
	rep, err := c.call(ctx, keyID, "unwrap", unwrapRequest{Wrapped: wrapped, AAD: aad})
	if err != nil {
		return nil, err
	}
	var res dekFields
	if _, err := rep.decode(false, &res); err != nil {
		return nil, err
	}
	return res.DEK, nil
}
