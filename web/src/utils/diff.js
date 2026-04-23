// Compute an LCS-based line-by-line diff between old and new rules with +/- prefixes
export function computeDiff(oldRules, newRules) {
  if (!oldRules && !newRules) {
    return ''
  }
  const oldLines = (oldRules || '').split('\n').filter((l, i, arr) => i < arr.length - 1 || l !== '')
  const newLines = (newRules || '').split('\n').filter((l, i, arr) => i < arr.length - 1 || l !== '')

  // Build LCS DP table of lengths
  const m = oldLines.length
  const n = newLines.length
  const dp = Array.from({ length: m + 1 }, () => new Int32Array(n + 1))

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (oldLines[i - 1] === newLines[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1])
      }
    }
  }

  // Backtrack through the DP table to produce diff lines
  const result = []
  let i = m
  let j = n
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && oldLines[i - 1] === newLines[j - 1]) {
      result.push(` ${oldLines[i - 1]}`)
      i--
      j--
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      result.push(`+ ${newLines[j - 1]}`)
      j--
    } else {
      result.push(`- ${oldLines[i - 1]}`)
      i--
    }
  }

  result.reverse()
  return result.join('\n')
}
