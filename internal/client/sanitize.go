package client

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// maxServerText caps the length in bytes of each piece of server-supplied
// text kept in an Error.
const maxServerText = 512

// sanitize makes server-supplied text safe to print on a terminal: it
// applies clean and then truncate.
func sanitize(s string) string {
	return truncate(clean(s))
}

// clean drops control characters (C0, DEL and C1, so no escape sequences),
// format characters such as U+202E RIGHT-TO-LEFT OVERRIDE and U+200B ZERO
// WIDTH SPACE, and the Unicode line and paragraph separators. Invalid UTF-8
// becomes U+FFFD.
func clean(s string) string {
	var b strings.Builder
	for _, r := range s { // invalid UTF-8 arrives as utf8.RuneError (U+FFFD)
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncate trims s and cuts it on a rune boundary to at most maxServerText
// bytes, ending in "..." when cut.
func truncate(s string) string {
	const ellipsis = "..."
	s = strings.TrimSpace(s)
	if len(s) <= maxServerText {
		return s
	}
	cut := maxServerText - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return strings.TrimSpace(s[:cut]) + ellipsis
}
