package common

import "slices"

// MergePeerIDs merges multiple slices of peer IDs into a single deduplicated
// slice in sorted ascending order.
//
// Contract (pinned by TestMergePeerIDs_SortedDedup): inputs may be unsorted
// and may contain duplicates within and across slices; the output always
// contains each ID exactly once, sorted ascending. An empty or all-empty
// input yields an empty (non-nil) slice. Callers rely on the sorted order
// for deterministic fan-out and test assertions.
//
// This is the single shared implementation for peer fan-out dedup. It lives in
// internal/common (a leaf package with no engine or API dependencies) so both
// the engine compiler and the API change worker can reuse it without creating
// an import cycle. Do not reimplement map-dedup+sort elsewhere; call this.
func MergePeerIDs(idSlices ...[]int) []int {
	seen := make(map[int]struct{})
	var total int
	for _, s := range idSlices {
		total += len(s)
	}
	result := make([]int, 0, total)
	for _, s := range idSlices {
		for _, id := range s {
			if _, ok := seen[id]; !ok {
				seen[id] = struct{}{}
				result = append(result, id)
			}
		}
	}
	slices.Sort(result)
	return result
}
