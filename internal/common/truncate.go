package common

import (
	"unicode/utf8"
)

// TruncateString truncates s to at most maxLen bytes without splitting a
// multi-byte UTF-8 sequence. It returns s unchanged when it already fits.
//
// The truncation is rune-aware: runes are accumulated until adding the next
// rune would exceed maxLen, so the result is always valid UTF-8. For example,
// s="a\xC3\xA9" ("aé", 3 bytes) with maxLen=2 returns "a" rather than the
// invalid 2-byte prefix [0x61,0xC3].
//
// A non-positive maxLen yields an empty string when truncation is required.
func TruncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 0 {
		return ""
	}
	runes := []rune(s)
	n := 0
	end := 0
	for i, r := range runes {
		sz := utf8.RuneLen(r)
		if sz < 0 {
			sz = len(string(r))
		}
		if n+sz > maxLen {
			break
		}
		n += sz
		end = i + 1
	}
	return string(runes[:end])
}
