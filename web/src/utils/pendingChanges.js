/**
 * Aggregates the total count of pending changes from the API response.
 * Handles null/undefined inputs, null array items, string number inputs,
 * and non-array inputs gracefully.
 * @param {Array} pendingChangesData - The response from /api/v1/pending-changes
 * @returns {number} Total count of pending changes across all peers
 */
export function aggregatePendingChangesCount(pendingChangesData) {
  if (!pendingChangesData) return 0
  if (!Array.isArray(pendingChangesData)) return 0
  return pendingChangesData.reduce((sum, item) => {
    if (!item) return sum
    // Support both `changes_count` (existing API) and `count`/`sub_count` (new format)
    const rawChangesCount = item.changes_count
    const changesCount = typeof rawChangesCount === 'string' ? parseInt(rawChangesCount, 10) || 0 : (rawChangesCount || 0)
    const rawCount = item.count
    const count = typeof rawCount === 'string' ? parseInt(rawCount, 10) || 0 : (rawCount || 0)
    const rawSubCount = item.sub_count
    const subCount = typeof rawSubCount === 'string' ? parseInt(rawSubCount, 10) || 0 : (rawSubCount || 0)
    return sum + changesCount + count + subCount
  }, 0)
}
