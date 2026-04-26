/**
 * Parse a composite peer value like "peer:5:10.20.10.20" into { id, ip }.
 * Returns null if the value is not a composite (i.e., it's a plain numeric ID).
 * @param {string|number} value - The value to parse
 * @returns {{ id: number, ip: string | null } | null} Parsed result or null
 */
export function parseCompositePeerValue(value) {
  if (typeof value === 'string' && value.startsWith('peer:')) {
    const parts = value.split(':')
    return { id: parseInt(parts[1], 10), ip: parts.slice(2).join(':') || null }
  }
  return null
}
