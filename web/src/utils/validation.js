/**
 * Validates if a port number is in the valid range (1-65535)
 * @param {string|number} port - The port value to validate
 * @returns {boolean} True if the port is valid, false otherwise
 */
export const isValidPort = (port) => {
  const num = parseInt(port, 10)
  return !isNaN(num) && num >= 1 && num <= 65535
}

/** Validate an IP address (IPv4 or IPv6) */
export function isValidIP(value) {
  if (!value) return false
  // IPv4
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
  const match = value.match(ipv4Regex)
  if (match) {
    return match.slice(1).every(octet => parseInt(octet, 10) >= 0 && parseInt(octet, 10) <= 255)
  }
  // IPv6 (basic validation)
  const ipv6Regex = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/
  return ipv6Regex.test(value)
}

/** Validate a CIDR notation (IP/prefix) */
export function isValidCIDR(value) {
  if (!value) return false
  const parts = value.split('/')
  if (parts.length !== 2) return false
  const [ip, prefix] = parts
  if (!isValidIP(ip)) return false
  const prefixNum = parseInt(prefix, 10)
  if (isNaN(prefixNum)) return false
  // IPv4 prefix: 0-32, IPv6 prefix: 0-128
  if (ip.includes(':')) return prefixNum >= 0 && prefixNum <= 128
  return prefixNum >= 0 && prefixNum <= 32
}

/** Validate an email address */
export function isValidEmail(value) {
  if (!value) return false
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  return emailRegex.test(value)
}

/** Validate a hostname */
export function isValidHostname(value) {
  if (!value) return false
  if (value.length > 253) return false
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
  return hostnameRegex.test(value)
}
