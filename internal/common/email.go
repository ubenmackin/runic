package common

import (
	"errors"
	"regexp"
	"strings"
)

// ErrInvalidEmail is returned by store-layer user mutations when the
// normalized email address fails canonical validation. API handlers map it
// to a 400 response; it is defined here so both layers share one sentinel
// instead of matching on error strings.
var ErrInvalidEmail = errors.New("invalid email format")

var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// NormalizeEmail trims surrounding whitespace and lower-cases the address so
// "  User@Example.COM " and "user@example.com" map to the same stored value.
// This is the single source for email normalization; callers in the store and
// API layers must delegate here instead of reimplementing TrimSpace/ToLower.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ValidateEmail reports whether email matches the canonical address shape:
// local part, "@", domain, dot, and a TLD of at least 2 letters. The input
// is expected to be already normalized (see NormalizeEmail); an empty string
// returns false, so callers that treat email as optional must guard on empty
// before calling. The frontend isValidEmail helper mirrors this pattern.
func ValidateEmail(email string) bool {
	return emailRegex.MatchString(email)
}
