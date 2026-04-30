package common

// EnsureSlice returns an empty slice if the input is nil, otherwise returns the input.
// This is useful after SQL row iteration to ensure JSON responses return [] instead of null.
func EnsureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
