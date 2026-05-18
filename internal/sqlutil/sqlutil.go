// Package sqlutil provides shared SQL utilities used across the codebase.
package sqlutil

// BuildPlaceholders builds a string of n question marks separated by commas,
// e.g. "?,?,?". Returns empty string for n <= 0.
func BuildPlaceholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, n*2-1)
	for i := 0; i < n; i++ {
		b[i*2] = '?'
		if i < n-1 {
			b[i*2+1] = ','
		}
	}
	return string(b)
}
