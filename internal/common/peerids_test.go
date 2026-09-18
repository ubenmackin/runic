package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMergePeerIDs_SortedDedup pins the shared fan-out contract: unsorted
// inputs with duplicates collapse to a single sorted slice. This guards
// against divergence with the removed api/common shim (which used an
// unsorted map[bool] dedup) and any future reimplementation.
func TestMergePeerIDs_SortedDedup(t *testing.T) {
	got := MergePeerIDs([]int{3, 1, 2, 1}, []int{2, 5, 3}, nil, []int{})
	assert.Equal(t, []int{1, 2, 3, 5}, got, "output must be deduplicated and sorted ascending")

	got = MergePeerIDs()
	assert.NotNil(t, got, "empty input must yield non-nil slice")
	assert.Empty(t, got, "empty input must yield empty slice")

	got = MergePeerIDs([]int{9}, []int{9}, []int{9})
	assert.Equal(t, []int{9}, got, "repeated single ID must collapse to one element")
}
