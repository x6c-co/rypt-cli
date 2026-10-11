# rypt API notes: wrap and unwrap

These notes record what the rypt API does for the two operations this program
uses. Each item is marked with its source:

- **live**: observed on 2026-10-11 against `https://api.rypt.dev` with a real
  API key on an `hsm`-tier key, using `scripts/probe.go`.
- **openapi**: stated in the OpenAPI description (`openapi.yaml`, info version
  0.5.0) from https://bin.x6c.co/file/axzrrd.

To repeat the observations, export `RYPT_TOKEN` and `RYPT_KEY_ID` in your own
shell and run `go run scripts/probe.go` (about 10 operations) or
`go run scripts/probe.go -limits` (about 20 requests, instead of the default
run). The probe never prints the token or a data key. `-limits` measures the
largest `aad` that `wrap` accepts and checks that `unwrap` accepts the same
`aad`; it does not measure `unwrap`'s own limit.

## Paths

| Operation | Method and path | Source |
| --- | --- | --- |
| wrap | `POST {base}/v1/keys/{key_id}/wrap` | live, openapi |
| unwrap | `POST {base}/v1/keys/{key_id}/unwrap` | live, openapi |

- `{key_id}` is a UUID. The OpenAPI pattern accepts upper- and lower-case hex.
  The program sends lower-case. (openapi)
- An unknown path under `/v1/keys/{id}/` returns `404 not_found`. `GET` on the
  wrap path returns `405 method_not_allowed` with `allow: POST`. (live)
- The base URL is `https://api.rypt.dev`. The OpenAPI also lists
  `http://127.0.0.1:8080` for local development. (openapi)

## Request requirements

- Header `Authorization: Bearer <token>`. The token is 44 characters:
  `ry_`, an 8-character prefix, `_`, and a 32-character secret, all base62.
  (openapi; the live token has this shape)
- Header `Content-Type: application/json` is required. Without it the server
  returns `415 unsupported_media_type`. (live)
- A request body over 128 KiB returns `413 payload_too_large`. (live, openapi)
- Invalid JSON returns `400 invalid_request`. (live)

## wrap

Request body. All fields are optional. `{}` asks the server to generate a DEK.

```json
{ "aad": "<standard base64, padded>" }
```

| Field | Type | Notes |
| --- | --- | --- |
| `dek` | base64 string or null | 16, 24, or 32 bytes decoded. Absent or null means "generate one". The program never sends it. (openapi) |
| `aad` | base64 string or null | Absent, `null`, and `""` all mean "no aad". (openapi; `""` confirmed live on unwrap) |

Response `200`, when no `dek` was sent:

```json
{ "dek": "<44 chars: 32 bytes, standard base64, padded>",
  "wrapped": "<188 chars observed>" }
```

- The response has exactly the fields `dek` and `wrapped`. (live)
- `dek` is 44 characters of standard padded base64 and decodes to 32 bytes.
  (live)
- When the request carries a `dek`, the response omits `dek` entirely.
  (openapi)

### The `wrapped` value

- `wrapped` is standard padded base64. (live, openapi)
- Observed: 188 characters, which decode to 139 or 140 bytes. The decoded
  bytes begin `0a 24 00 …`, consistent with a Cloud KMS ciphertext (a
  protobuf whose first field is a 36-byte length-prefixed value). The
  observed prefix of the string is `CiQA`. (live, `hsm` tier)
- The OpenAPI states no maximum length for `wrapped`, and the service does
  not document its internal structure. The length can differ on other tiers
  (`free` and `wrapped` keys use a rypt-held data key under a shared Cloud
  KMS root), so the program treats `wrapped` as an opaque string. (openapi)
- Program decision: store `wrapped` byte for byte as UTF-8, never decode it,
  and refuse a `wrap` response whose `wrapped` is empty or longer than 65,536
  bytes, the header's limit. The observed 188 characters are far below that.

## unwrap

Request body:

```json
{ "wrapped": "<the wrap response's wrapped value>",
  "aad": "<the same aad that was given to wrap>" }
```

- `wrapped` is required. `aad` follows the same rules as for `wrap`.
  (openapi)
- Unwrapping without `aad` a value wrapped with an `aad` returns
  `400 invalid_ciphertext`, message `ciphertext or aad invalid`. (live)
- A `wrapped` value with one character changed returns
  `400 invalid_ciphertext`. (live)
- An unknown key ID returns `404 not_found`. The API never confirms whether a
  key ID exists. (live, openapi)

Response `200`:

```json
{ "dek": "<44 chars: 32 bytes, standard base64, padded>" }
```

- The response has exactly the field `dek`, and the DEK equals the one that
  `wrap` returned. Confirmed for an omitted aad, an `aad` of `""`, an aad of
  11 bytes, of 1,024 bytes, and of 8,144 bytes. (live)

## aad size limits

| Tier | Largest `aad` | Source |
| --- | --- | --- |
| `free`, `wrapped` | 65,536 bytes decoded | openapi |
| `software` | 65,520 bytes decoded | openapi |
| `hsm` | 65,520 bytes, and `dek` + `aad` at most 8,176 bytes | openapi, live |

Live, on an `hsm` key with a server-generated DEK:

- `wrap` accepts an `aad` of 8,144 bytes and refuses 8,145 bytes with
  `413 payload_too_large`, message
  `dek and aad together must be at most 8176 bytes for an hsm key`. The
  generated 32-byte DEK counts toward the 8,176 bytes. (live)
- `wrap` with an `aad` of 65,537 bytes returns `413 payload_too_large`, message
  `aad must be at most 65520 bytes`. (live)
- `unwrap` accepts the 8,144-byte `aad` that was used at wrap. (live)

Program decision: the label, which is the only `aad` the program sends, is at
most 1,024 bytes. That is within every tier's limit, including `hsm`. A
1,024-byte aad was confirmed live on `hsm` for both `wrap` and `unwrap`.

## Errors

Every error body has this shape (live, openapi):

```json
{ "error": "<code>", "message": "<text>", "request_id": "<uuid>" }
```

- `request_id` equals the `x-request-id` response header, which every
  response carries, including successful ones. (live)
- `ops_cap_reached` adds `cap` (an integer, the monthly cap) and `resets_at`
  (an RFC 3339 time, midnight UTC on the first of the next month). (openapi;
  not triggered live)
- The `content-type` of error responses is `application/json`. (live)

Status codes for `wrap` and `unwrap`:

| Status | Codes | Meaning | Source |
| --- | --- | --- | --- |
| 400 | `invalid_request`, `invalid_base64`, `invalid_dek_length`, `invalid_ciphertext` | A bad request, or an `aad` or `wrapped` that does not authenticate | live (`invalid_request`, `invalid_ciphertext`), openapi |
| 401 | `unauthorized` | A missing, malformed, revoked, or wrong token. All cases are indistinguishable. | live, openapi |
| 402 | `billing_required` | A paid key whose tenant billing is not in good standing. `wrap` only. `unwrap` is never refused for billing. | openapi |
| 403 | `ip_not_allowed`, `key_not_allowed`, `api_key_required` | A restricted API key. An API key restricted to particular keys gets `key_not_allowed` ("this api key is restricted to other keys") for any other key ID, including one that does not exist, where an unrestricted API key gets `404 not_found`. | live (`key_not_allowed`), openapi |
| 404 | `not_found` | An unknown, destroyed, or inaccessible key ID | live, openapi |
| 405 | `method_not_allowed` | The wrong method | live |
| 409 | `key_pending_deletion` | The key is pending deletion. Both operations are refused. | openapi |
| 413 | `payload_too_large` | A body over 128 KiB, or an `aad` over the tier limit | live, openapi |
| 415 | `unsupported_media_type` | No `Content-Type: application/json` | live, openapi |
| 429 | `ops_cap_reached`, `rate_limited` | A `free` key at its monthly cap, or over 100 requests per second for the API key | openapi |
| 500 | `internal_error` | A server-side failure | openapi |
| 503 | `unavailable` | A bounded internal queue was full. "Nothing is wrong with the request; retry it." | openapi |

- No `retry-after` header was observed on any response. (live)
- Responses from Cloudflare in front of the service (for example a 502 or
  504) may not carry the JSON envelope. The client falls back to the
  `x-request-id` header and the HTTP status. (inference; not observed)

## Consequences for the program

- A tampered label or `wrapped` DEK in a file header is refused by `unwrap`
  with `400 invalid_ciphertext`, and a tampered key ID with `404 not_found`
  (or `403 key_not_allowed` for an API key restricted to particular keys).
  (The OpenAPI description also lists `400 invalid_base64`, which a `wrapped`
  value that is no longer base64 would presumably get.) A changed
  `wrapped` length that still parses is usually refused the same way. These reach the
  program as API refusals, exit code 1, before any chunk is decrypted. A
  change that makes the header fail local validation (a label or `wrapped`
  value that is no longer UTF-8, or a length out of range) is exit code 4
  with no API call. With the correct DEK, every one of these changes also
  fails chunk authentication, because the whole header is the chunk
  associated data; the format tests check every header bit that way.
- The client retries a connection error and HTTP 502, 503, and 504, at most
  twice. It does not retry a TLS certificate or protocol error, which would
  fail the same way again, or any other status.
- Rotating a key so that the version a `wrapped` value names is no longer
  enabled makes `unwrap` return `400 invalid_ciphertext`. (openapi)
