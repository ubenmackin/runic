// Compute a simple line-by-line diff between old and new rules with +/- prefixes
export function computeDiff(oldRules, newRules) {
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
      result.push(` ${newLine}`)
    } else if (!oldLine) {
      result.push(`+ ${newLine}`)
    } else if (!newLine) {
      result.push(`- ${oldLine}`)
    } else {
      result.push(`- ${oldLine}`)
      result.push(`+ ${newLine}`)
    }
  }
  return result.join('\n')
}
