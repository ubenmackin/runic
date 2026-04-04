/**
 * Aggregates the total count of pending changes from the API response.
 * @param {Array} pendingChangesData - The response from /api/v1/pending-changes
 * @returns {number} Total count of pending changes across all peers
 */
export function aggregatePendingChangesCount(pendingChangesData) {
  return pendingChangesData?.reduce((sum, item) => sum + (item.changes_count || 0), 0) || 0
}
