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

// A "smart" diff that groups changes by section headers (lines starting with "# ---")
// and classifies changes as adds, removes, or modifications (paired old→new).
export function computeSmartDiff(oldRules, newRules) {
  const rawDiff = computeDiff(oldRules, newRules)
  if (!rawDiff) {
    return []
  }

  // Parse each diff line into {prefix, content}
  // computeDiff formats lines as: " {content}", "+ {content}", "- {content}"
  // The marker is line[0] (' ', '+', or '-'), followed by a space separator for +/-,
  // but for unchanged lines the space IS the marker, so content always starts at index 2
  // (for unchanged lines, the separator space is the same as the marker — both are ' ')
  const diffLines = rawDiff.split('\n').map((line) => {
    const prefix = line[0] // ' ', '+', or '-'
    const content = prefix === ' ' ? line.substring(1) : line.substring(2)
    return { prefix, content }
  })

  // Filter out entries with empty content — these are artifacts of how
  // computeDiff represents empty lines (e.g., "+ " or "- ") and would
  // otherwise fall through all branch checks in the loop, causing an
  // infinite loop since `i` would never advance.
  const filteredLines = diffLines.filter((dl) => dl.content !== '')

  const isSectionHeader = (content) => content.startsWith('# ---')

  // --- First pass: identify which section headers have changes ---
  let currentSectionHeader = null
  const sectionsWithChanges = new Set()

  for (const { prefix, content } of filteredLines) {
    if (isSectionHeader(content)) {
      if (prefix === ' ') {
        // Unchanged section header — just update the tracker
        currentSectionHeader = content
      } else {
        // Added/removed section header — it IS a changed line.
        // It belongs to the current section (or none if no section yet).
        if (currentSectionHeader) {
          sectionsWithChanges.add(currentSectionHeader)
        }
      }
    } else {
      // Non-header line
      if (prefix === '+' || prefix === '-') {
        if (currentSectionHeader) {
          sectionsWithChanges.add(currentSectionHeader)
        }
      }
    }
  }

  // --- Second pass: emit entries ---
  const entries = []
  currentSectionHeader = null
  let emittedSectionHeaders = new Set()

  const emitSectionHeaderIfNeeded = (header) => {
    if (header && sectionsWithChanges.has(header) && !emittedSectionHeaders.has(header)) {
      emittedSectionHeaders.add(header)
      entries.push({
        type: 'section-header',
        line: header,
        sectionHeader: header,
      })
    }
  }

  let i = 0
  while (i < filteredLines.length) {
    const { prefix, content } = filteredLines[i]

    // Unchanged line — skip, but update section header tracker
    if (prefix === ' ') {
      if (isSectionHeader(content)) {
        currentSectionHeader = content
      }
      i++
      continue
    }

    // Added/removed section header — treat as a changed line, NOT a section header
    if (isSectionHeader(content)) {
      emitSectionHeaderIfNeeded(currentSectionHeader)
      if (prefix === '+') {
        entries.push({ type: 'add', line: content, sectionHeader: currentSectionHeader })
      } else if (prefix === '-') {
        entries.push({ type: 'remove', line: content, sectionHeader: currentSectionHeader })
      }
      i++
      continue
    }

    // Changed non-header line
    emitSectionHeaderIfNeeded(currentSectionHeader)

    // Collect consecutive '-' lines (not section headers)
    const removes = []
    let j = i
    while (j < filteredLines.length && filteredLines[j].prefix === '-' && !isSectionHeader(filteredLines[j].content)) {
      removes.push(filteredLines[j].content)
      j++
    }

    // Collect consecutive '+' lines immediately following (not section headers)
    const adds = []
    while (j < filteredLines.length && filteredLines[j].prefix === '+' && !isSectionHeader(filteredLines[j].content)) {
      adds.push(filteredLines[j].content)
      j++
    }

    // Pair removes and adds 1:1 as changes; extras are standalone
    const pairCount = Math.min(removes.length, adds.length)
    for (let k = 0; k < pairCount; k++) {
      entries.push({
        type: 'change',
        oldLine: removes[k],
        newLine: adds[k],
        sectionHeader: currentSectionHeader,
      })
    }
    // Remaining removes
    for (let k = pairCount; k < removes.length; k++) {
      entries.push({
        type: 'remove',
        line: removes[k],
        sectionHeader: currentSectionHeader,
      })
    }
    // Remaining adds
    for (let k = pairCount; k < adds.length; k++) {
      entries.push({
        type: 'add',
        line: adds[k],
        sectionHeader: currentSectionHeader,
      })
    }

    i = j
  }

  return entries
}
