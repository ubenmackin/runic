import { aggregatePendingChangesCount } from './pendingChanges'
import { describe, test, expect } from 'vitest'

describe('aggregatePendingChangesCount', () => {
  describe('change type detection and counting', () => {
    test('sums changes_count from all peers', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 5 },
        { peer_id: 'peer-2', changes_count: 3 },
        { peer_id: 'peer-3', changes_count: 2 },
      ]
      expect(aggregatePendingChangesCount(pendingChanges)).toBe(10)
    })

    test('handles single peer with changes', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 7 },
      ]
      expect(aggregatePendingChangesCount(pendingChanges)).toBe(7)
    })

    test('handles peers with zero changes', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 5 },
        { peer_id: 'peer-2', changes_count: 0 },
        { peer_id: 'peer-3', changes_count: 3 },
      ]
      expect(aggregatePendingChangesCount(pendingChanges)).toBe(8)
    })

    test('handles all peers with zero changes', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 0 },
        { peer_id: 'peer-2', changes_count: 0 },
      ]
      expect(aggregatePendingChangesCount(pendingChanges)).toBe(0)
    })
  })

  describe('summary generation', () => {
    test('correctly aggregates large numbers', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 1000 },
        { peer_id: 'peer-2', changes_count: 2000 },
        { peer_id: 'peer-3', changes_count: 3000 },
      ]
      expect(aggregatePendingChangesCount(pendingChanges)).toBe(6000)
    })

    test('handles mixed positive and zero values', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 10 },
        { peer_id: 'peer-2', changes_count: 0 },
        { peer_id: 'peer-3', changes_count: 5 },
        { peer_id: 'peer-4', changes_count: 0 },
        { peer_id: 'peer-5', changes_count: 15 },
      ]
      expect(aggregatePendingChangesCount(pendingChanges)).toBe(30)
    })
  })

  describe('edge cases', () => {
    test('returns 0 for empty array', () => {
      expect(aggregatePendingChangesCount([])).toBe(0)
    })

    test('returns 0 for null', () => {
      expect(aggregatePendingChangesCount(null)).toBe(0)
    })

    test('returns 0 for undefined', () => {
      expect(aggregatePendingChangesCount(undefined)).toBe(0)
    })

    test('handles missing changes_count property', () => {
      const pendingChanges = [
        { peer_id: 'peer-1' },
        { peer_id: 'peer-2', changes_count: 5 },
        { peer_id: 'peer-3' },
      ]
      expect(aggregatePendingChangesCount(pendingChanges)).toBe(5)
    })

    test('handles null items in array', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 3 },
        null,
        { peer_id: 'peer-2', changes_count: 2 },
      ]
      // The current implementation doesn't handle null items in array
      // This test documents the actual behavior (throws error)
      expect(() => aggregatePendingChangesCount(pendingChanges)).toThrow()
    })

    test('handles undefined items in array', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 4 },
        undefined,
        { peer_id: 'peer-2', changes_count: 1 },
      ]
      // The current implementation doesn't handle undefined items in array
      // This test documents the actual behavior (throws error)
      expect(() => aggregatePendingChangesCount(pendingChanges)).toThrow()
    })
  })

  describe('data structure variations', () => {
    test('handles additional properties on peer objects', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: 5, peer_name: 'Peer One', status: 'online' },
        { peer_id: 'peer-2', changes_count: 3, peer_name: 'Peer Two', status: 'offline' },
      ]
      expect(aggregatePendingChangesCount(pendingChanges)).toBe(8)
    })

    test('handles objects with changes_count as string number', () => {
      const pendingChanges = [
        { peer_id: 'peer-1', changes_count: '5' },
        { peer_id: 'peer-2', changes_count: '3' },
      ]
      // String numbers result in string concatenation: 0 + '5' = '05', '05' + '3' = '053'
      const result = aggregatePendingChangesCount(pendingChanges)
      expect(result).toBe('053') // string concatenation occurs with leading 0
    })
  })
})
