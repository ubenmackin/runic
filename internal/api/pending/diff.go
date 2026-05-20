// Package pending provides diff utilities for pending bundle previews.
package pending

import "fmt"

// generateDiff computes a line-by-line LCS diff between oldContent and newContent,
// returning a human-readable string with "+", "-", and " " prefixes per line.
// Uses a space-optimized 2-row DP table (O(n) space instead of O(m×n)).
func generateDiff(oldContent, newContent string) string {
	if oldContent == newContent {
		return "No changes detected."
	}

	oldLines := splitLines(oldContent)
	newLines := splitLines(newContent)

	// Compute LCS using 2-row DP table (O(n) space instead of O(m×n))
	m, n := len(oldLines), len(newLines)
	dp := make([][]int, 2)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}
	for i := 1; i <= m; i++ {
		prev, cur := dp[(i-1)%2], dp[i%2]
		for j := 1; j <= n; j++ {
			switch {
			case oldLines[i-1] == newLines[j-1]:
				cur[j] = prev[j-1] + 1
			case prev[j] > cur[j-1]:
				cur[j] = prev[j]
			default:
				cur[j] = cur[j-1]
			}
		}
	}

	// Backtrack to produce diff output
	type diffEntry struct {
		prefix string
		line   string
	}
	var entries []diffEntry
	i, j := m, n
	for i > 0 || j > 0 {
		switch {
		case i > 0 && j > 0 && oldLines[i-1] == newLines[j-1]:
			entries = append(entries, diffEntry{"  ", oldLines[i-1]})
			i--
			j--
		case j > 0 && (i == 0 || dp[i%2][j-1] >= dp[(i-1)%2][j]):
			entries = append(entries, diffEntry{"+ ", newLines[j-1]})
			j--
		default:
			entries = append(entries, diffEntry{"- ", oldLines[i-1]})
			i--
		}
	}

	// Reverse entries (backtrack produced them in reverse order)
	for l, r := 0, len(entries)-1; l < r; l, r = l+1, r-1 {
		entries[l], entries[r] = entries[r], entries[l]
	}

	var diff string
	for _, e := range entries {
		diff += fmt.Sprintf("%s%s\n", e.prefix, e.line)
	}

	return diff
}

// splitLines splits s into lines without allocating a separate regex or
// importing additional packages. Trailing content after the last newline
// is included as the final element.
func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
