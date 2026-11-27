import {
  isValidPort,
  isValidIP,
  isValidCIDR,
  isValidEmail,
  isValidHostname,
} from './validation'
import { describe, test, expect } from 'vitest'

describe('isValidPort', () => {
  describe('accepts valid ports', () => {
    test('accepts boundary numeric values', () => {
      expect(isValidPort(1)).toBe(true)
      expect(isValidPort(65535)).toBe(true)
    })

    test('accepts numeric strings', () => {
      expect(isValidPort('22')).toBe(true)
      expect(isValidPort('65535')).toBe(true)
    })

    test('accepts strings with surrounding whitespace', () => {
      expect(isValidPort(' 443 ')).toBe(true)
    })
  })

  describe('rejects invalid ports', () => {
    test('rejects null and undefined', () => {
      expect(isValidPort(null)).toBe(false)
      expect(isValidPort(undefined)).toBe(false)
    })

    test('rejects empty and whitespace-only values', () => {
      expect(isValidPort('')).toBe(false)
      expect(isValidPort('   ')).toBe(false)
    })

    test('rejects out-of-range values', () => {
      expect(isValidPort(0)).toBe(false)
      expect(isValidPort(65536)).toBe(false)
      expect(isValidPort('0')).toBe(false)
      expect(isValidPort('99999')).toBe(false)
    })

    test('rejects non-numeric values', () => {
      expect(isValidPort('abc')).toBe(false)
      expect(isValidPort('22abc')).toBe(false)
      expect(isValidPort('22.5')).toBe(false)
      expect(isValidPort('0x16')).toBe(false)
      expect(isValidPort('-1')).toBe(false)
    })
  })
})

describe('isValidIP', () => {
  describe('rejects non-string and empty values', () => {
    test('rejects non-strings', () => {
      expect(isValidIP(null)).toBe(false)
      expect(isValidIP(undefined)).toBe(false)
      expect(isValidIP(42)).toBe(false)
      expect(isValidIP({})).toBe(false)
    })

    test('rejects empty strings', () => {
      expect(isValidIP('')).toBe(false)
    })

    test('rejects strings containing whitespace', () => {
      expect(isValidIP(' 192.168.1.1')).toBe(false)
      expect(isValidIP('192.168.1.1 ')).toBe(false)
    })
  })

  describe('IPv4', () => {
    test('accepts valid addresses', () => {
      expect(isValidIP('192.168.1.1')).toBe(true)
      expect(isValidIP('0.0.0.0')).toBe(true)
      expect(isValidIP('255.255.255.255')).toBe(true)
    })

    test('rejects out-of-range octets', () => {
      expect(isValidIP('256.1.1.1')).toBe(false)
      expect(isValidIP('1.1.1.256')).toBe(false)
      expect(isValidIP('999.999.999.999')).toBe(false)
    })

    test('rejects malformed addresses', () => {
      expect(isValidIP('1.2.3')).toBe(false)
      expect(isValidIP('1.2.3.4.5')).toBe(false)
      expect(isValidIP('1.2.3.a')).toBe(false)
      expect(isValidIP('1..3.4')).toBe(false)
    })
  })

  describe('IPv6', () => {
    test('accepts compressed addresses', () => {
      expect(isValidIP('::')).toBe(true)
      expect(isValidIP('::1')).toBe(true)
      expect(isValidIP('2001:db8::1')).toBe(true)
      expect(isValidIP('fe80::1')).toBe(true)
    })

    test('accepts full eight-group addresses', () => {
      expect(isValidIP('2001:0db8:85a3:0000:0000:8a2e:0370:7334')).toBe(true)
      expect(isValidIP('0:0:0:0:0:0:0:0')).toBe(true)
    })

    test('accepts embedded IPv4 tails', () => {
      expect(isValidIP('::ffff:192.0.2.1')).toBe(true)
      expect(isValidIP('2001:db8::192.0.2.1')).toBe(true)
    })

    test('rejects triple-colon sequences', () => {
      expect(isValidIP('2001:db8:::1')).toBe(false)
    })

    test('rejects multiple compressions', () => {
      expect(isValidIP('2001:db8::1::2')).toBe(false)
    })

    test('rejects compression that still leaves too many groups', () => {
      expect(isValidIP('1:2:3:4:5:6:7:8::')).toBe(false)
    })

    test('rejects wrong group counts', () => {
      expect(isValidIP('2001:db8:1:2:3:4:5')).toBe(false)
      expect(isValidIP('1:2:3:4:5:6:7:8:9')).toBe(false)
    })

    test('rejects oversized groups', () => {
      expect(isValidIP('12345::1')).toBe(false)
      expect(isValidIP('1:2:3:4:5:6:7:12345')).toBe(false)
    })

    test('rejects invalid hex characters', () => {
      expect(isValidIP('gggg::1')).toBe(false)
      expect(isValidIP('2001:db8::zzzz')).toBe(false)
    })

    test('rejects malformed embedded IPv4 tails', () => {
      expect(isValidIP('::ffff:999.0.0.1')).toBe(false)
      expect(isValidIP('::ffff:1.2.3')).toBe(false)
      expect(isValidIP('::ffff:1.2.3.4.5')).toBe(false)
      expect(isValidIP('::ffff:1.2.3.x')).toBe(false)
      expect(isValidIP('::ffff:1.2.3.a')).toBe(false)
    })

    test('rejects colon-terminated dotted values', () => {
      expect(isValidIP('192.168.1.1:')).toBe(false)
      expect(isValidIP('1.2.3.4:5')).toBe(false)
    })
  })
})

describe('isValidCIDR', () => {
  test('rejects non-string and empty values', () => {
    expect(isValidCIDR(null)).toBe(false)
    expect(isValidCIDR(123)).toBe(false)
    expect(isValidCIDR('')).toBe(false)
  })

  test('accepts valid IPv4 CIDR', () => {
    expect(isValidCIDR('192.168.1.0/24')).toBe(true)
    expect(isValidCIDR('0.0.0.0/0')).toBe(true)
    expect(isValidCIDR('255.255.255.255/32')).toBe(true)
  })

  test('accepts valid IPv6 CIDR', () => {
    expect(isValidCIDR('2001:db8::/32')).toBe(true)
    expect(isValidCIDR('::/0')).toBe(true)
    expect(isValidCIDR('::1/128')).toBe(true)
  })

  test('accepts a trimmed prefix', () => {
    expect(isValidCIDR('192.168.1.0/ 24')).toBe(true)
  })

  test('rejects malformed shapes', () => {
    expect(isValidCIDR('192.168.1.0')).toBe(false)
    expect(isValidCIDR('192.168.1.0/24/1')).toBe(false)
    expect(isValidCIDR('/24')).toBe(false)
    expect(isValidCIDR('not-an-ip/24')).toBe(false)
    expect(isValidCIDR('192.168.1.0/')).toBe(false)
  })

  test('rejects invalid prefixes', () => {
    expect(isValidCIDR('192.168.1.0/abc')).toBe(false)
    expect(isValidCIDR('192.168.1.0/-1')).toBe(false)
    expect(isValidCIDR('192.168.1.0/33')).toBe(false)
    expect(isValidCIDR('2001:db8::/129')).toBe(false)
    expect(isValidCIDR(`192.168.1.0/${'9'.repeat(400)}`)).toBe(false)
  })
})

describe('isValidEmail', () => {
  test('rejects non-string and empty values', () => {
    expect(isValidEmail(null)).toBe(false)
    expect(isValidEmail(42)).toBe(false)
    expect(isValidEmail('')).toBe(false)
  })

  test('accepts valid addresses', () => {
    expect(isValidEmail('user@example.com')).toBe(true)
    expect(isValidEmail('first.last+tag@sub.example.co')).toBe(true)
  })

  test('rejects malformed addresses', () => {
    expect(isValidEmail('user@example')).toBe(false)
    expect(isValidEmail('user@example.c')).toBe(false)
    expect(isValidEmail('user name@example.com')).toBe(false)
    expect(isValidEmail('@example.com')).toBe(false)
    expect(isValidEmail('user@')).toBe(false)
    expect(isValidEmail('user@.com')).toBe(false)
  })
})

describe('isValidHostname', () => {
  test('rejects non-string and empty values', () => {
    expect(isValidHostname(null)).toBe(false)
    expect(isValidHostname(42)).toBe(false)
    expect(isValidHostname('')).toBe(false)
  })

  test('accepts valid hostnames', () => {
    expect(isValidHostname('localhost')).toBe(true)
    expect(isValidHostname('example.com')).toBe(true)
    expect(isValidHostname('sub-domain.example.co.uk')).toBe(true)
    expect(isValidHostname('a1-b2.example')).toBe(true)
  })

  test('rejects hostnames longer than 253 characters', () => {
    expect(isValidHostname('a'.repeat(254))).toBe(false)
  })

  test('rejects labels longer than 63 characters', () => {
    expect(isValidHostname(`${'a'.repeat(64)}.com`)).toBe(false)
  })

  test('rejects malformed hostnames', () => {
    expect(isValidHostname('-example.com')).toBe(false)
    expect(isValidHostname('example-.com')).toBe(false)
    expect(isValidHostname('example..com')).toBe(false)
    expect(isValidHostname('example_host.com')).toBe(false)
    expect(isValidHostname('example.com.')).toBe(false)
  })
})
