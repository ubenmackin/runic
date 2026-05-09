package common

// EnsureSlice returns a non-nil slice. This is useful after SQL row iteration to ensure JSON responses return [] instead of null.
func EnsureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
