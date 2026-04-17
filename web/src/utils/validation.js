/**
 * Validates if a port number is in the valid range (1-65535)
 * @param {string|number} port - The port value to validate
 * @returns {boolean} True if the port is valid, false otherwise
 */
export const isValidPort = (port) => {
  const num = parseInt(port, 10)
  return !isNaN(num) && num >= 1 && num <= 65535
}
