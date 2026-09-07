/**
 * Validates if a port number is in the valid range (1-65535).
 * Requires a full-string digit match so values like "22abc", "22.5",
 * "0x16" or " 22 " are rejected instead of being parsed leniently.
 * @param {string|number} port - The port value to validate
 * @returns {boolean} True if the port is valid, false otherwise
 */
export const isValidPort = (port) => {
  if (port === null || port === undefined) return false
  const str = String(port).trim()
  if (!/^\d+$/.test(str)) return false
  const num = Number(str)
  return Number.isInteger(num) && num >= 1 && num <= 65535
}

/** Validate an IPv6 address with strict group and compression rules */
function isValidIPv6(value) {
  if (typeof value !== 'string' || !value) return false
  if (/\s/.test(value)) return false
  if (!value.includes(':')) return false
  if (/[^0-9a-fA-F:.]/.test(value)) return false
  // A triple colon (or longer run) is never valid
  if (value.includes(':::')) return false
  const HEX_PART = /^[0-9a-fA-F]{1,4}$/

  // An embedded IPv4 tail (e.g. ::ffff:192.0.2.1) occupies two 16-bit groups.
  // Replace it with a placeholder so the remaining hex structure checks below apply.
  let addr = value
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':')
    if (lastColon === -1) return false
    const ipv4Part = value.slice(lastColon + 1)
    if (!ipv4Part.includes('.')) return false
    const octets = ipv4Part.split('.')
    if (octets.length !== 4) return false
    for (const octet of octets) {
      if (!/^\d{1,3}$/.test(octet)) return false
      const num = Number(octet)
      if (!Number.isInteger(num) || num < 0 || num > 255) return false
    }
    addr = `${value.slice(0, lastColon)}:0:0`
  }

  const parts = addr.split('::')
  if (parts.length > 2) return false
  if (parts.length === 2) {
    const [left, right] = parts
    const leftGroups = left === '' ? [] : left.split(':')
    const rightGroups = right === '' ? [] : right.split(':')
    for (const group of [...leftGroups, ...rightGroups]) {
      if (!HEX_PART.test(group)) return false
    }
    // '::' compresses at least one group, so at most 7 groups are explicit
    return leftGroups.length + rightGroups.length <= 7
  }
  const groups = addr.split(':')
  if (groups.length !== 8) return false
  return groups.every((group) => HEX_PART.test(group))
}

/** Validate an IP address (IPv4 or IPv6) */
export function isValidIP(value) {
  if (typeof value !== 'string') return false
  if (!value) return false
  if (/\s/.test(value)) return false
  // IPv4
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const match = value.match(ipv4Regex)
  if (match) {
    return match.slice(1).every((octet) => {
      if (!/^\d{1,3}$/.test(octet)) return false
      const num = Number(octet)
      return Number.isInteger(num) && num >= 0 && num <= 255
    })
  }
  // IPv6 (strict validation)
  if (value.includes(':')) return isValidIPv6(value)
  return false
}

/** Validate a CIDR notation (IP/prefix) */
export function isValidCIDR(value) {
  if (typeof value !== 'string') return false
  if (!value) return false
  const parts = value.split('/')
  if (parts.length !== 2) return false
  const [ip, prefix] = parts
  if (!isValidIP(ip)) return false
  const prefixStr = (prefix || '').trim()
  if (!/^\d+$/.test(prefixStr)) return false
  const prefixNum = Number(prefixStr)
  if (!Number.isInteger(prefixNum)) return false
  // IPv4 prefix: 0-32, IPv6 prefix: 0-128
  if (ip.includes(':')) return prefixNum >= 0 && prefixNum <= 128
  return prefixNum >= 0 && prefixNum <= 32
}

/** Validate an email address */
export function isValidEmail(value) {
  if (typeof value !== 'string') return false
  if (!value) return false
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(value)
}

/** Validate a hostname */
export function isValidHostname(value) {
  if (typeof value !== 'string') return false
  if (!value) return false
  if (value.length > 253) return false
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
  return hostnameRegex.test(value)
}
