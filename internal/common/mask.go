package common

// MaskToken masks a full secret token for display (show first 8 and last 4
// chars). Tokens of 12 or fewer characters carry too little entropy to
// partially reveal, so they mask to "****". This is the single source for
// full-token masking; callers in store and api layers must delegate here
// instead of reimplementing the slicing.
func MaskToken(token string) string {
	if len(token) <= 12 {
		return "****"
	}
	return token[:8] + "..." + token[len(token)-4:]
}

// MaskTokenPrefix masks a stored token prefix for display. The full token is
// unrecoverable after creation, so list views show the stored prefix plus an
// ellipsis (mirroring the MaskToken convention). An empty prefix masks to
// "****" so callers never emit a bare ellipsis.
func MaskTokenPrefix(prefix string) string {
	if prefix == "" {
		return "****"
	}
	return prefix + "..."
}
