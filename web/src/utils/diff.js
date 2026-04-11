/**
 * Compute a simple line-by-line diff between old and new rules
 * @param {string} oldRules - The old rules content
 * @param {string} newRules - The new rules content
 * @returns {string} The diff output with +/- prefixes
 */
export function computeDiff(oldRules, newRules) {
  // Handle empty inputs - return empty string if both are empty
  if (!oldRules && !newRules) {
    return ''
  }
  const oldLines = (oldRules || '').split('\n')
  const newLines = (newRules || '').split('\n')
  const result = []
  const maxLen = Math.max(oldLines.length, newLines.length)
  for (let i = 0; i < maxLen; i++) {
    const oldLine = oldLines[i] || ''
    const newLine = newLines[i] || ''
    if (oldLine === newLine) {
      result.push(` ${newLine}`) // Unchanged line
    } else if (!oldLine) {
      result.push(`+ ${newLine}`) // New line added
    } else if (!newLine) {
      result.push(`- ${oldLine}`) // Line removed
    } else {
      result.push(`- ${oldLine}`) // Line changed (old)
      result.push(`+ ${newLine}`) // Line changed (new)
    }
  }
  return result.join('\n')
}
