package common

// EnsureSlice returns a non-nil slice. It is intended for the boundary
// between Go and JSON: encoding a nil slice to JSON produces `null`, which
// most frontends and API consumers dislike, whereas encoding an empty slice
// produces `[]`. Call it on values that come from SQL row iteration or any
// other source that can legitimately return a nil slice.
//
// Example:
//
//	peers := scanPeers(rows) // may return nil
//	return common.EnsureSlice(peers) // → "[]" in JSON, not "null"
func EnsureSlice[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
