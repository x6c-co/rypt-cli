package format

import (
	"encoding/hex"
	"errors"
)

// errKeyID is returned by ParseKeyID for any malformed key ID. It does not
// echo the input, which may be long or contain control characters.
var errKeyID = errors.New("key ID must be a UUID in the form xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx")

// ParseKeyID parses a UUID in the canonical 8-4-4-4-12 hexadecimal form.
// Upper- and lower-case hex digits are accepted. Any other form is an error.
func ParseKeyID(s string) ([16]byte, error) {
	var id [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, errKeyID
	}
	// hex.Decode rejects anything that is not a hex digit, so a hyphen or
	// space inside a group fails here.
	digits := s[0:8] + s[9:13] + s[14:18] + s[19:23] + s[24:36]
	if _, err := hex.Decode(id[:], []byte(digits)); err != nil {
		return [16]byte{}, errKeyID
	}
	return id, nil
}

// FormatKeyID returns id in the canonical lower-case 8-4-4-4-12 form.
func FormatKeyID(id [16]byte) string {
	var buf [36]byte
	hex.Encode(buf[0:8], id[0:4])
	buf[8] = '-'
	hex.Encode(buf[9:13], id[4:6])
	buf[13] = '-'
	hex.Encode(buf[14:18], id[6:8])
	buf[18] = '-'
	hex.Encode(buf[19:23], id[8:10])
	buf[23] = '-'
	hex.Encode(buf[24:36], id[10:16])
	return string(buf[:])
}
