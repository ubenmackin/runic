import { isValidIP } from './validation.js'

/**
 * Parse a composite peer value like "peer:5:10.20.10.20" into { id, ip }.
 * Returns null if the value is not a composite (i.e., it's a plain numeric ID)
 * or if the composite is malformed. The id must be a positive integer and
 * any attached IP must be a valid IPv4 or IPv6 address.
 * @param {string|number} value - The value to parse
 * @returns {{ id: number, ip: string | null } | null} Parsed result or null
 */
export function parseCompositePeerValue(value) {
  if (typeof value !== 'string') return null
  if (!value.startsWith('peer:')) return null
  const parts = value.split(':')
  if (parts.length < 2) return null
  const idStr = (parts[1] ?? '').trim()
  if (!/^\d+$/.test(idStr)) return null
  const id = Number(idStr)
  if (!Number.isInteger(id) || id <= 0) return null
  const rawIp = parts.slice(2).join(':').trim()
  if (!rawIp) return { id, ip: null }
  if (!isValidIP(rawIp)) return null
  return { id, ip: rawIp }
}
