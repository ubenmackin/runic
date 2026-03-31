import { useState, useEffect, useMemo, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RotateCw, CheckCircle, Clock, AlertTriangle, Search, ChevronLeft, ChevronRight } from 'lucide-react'
import { QUERY_KEYS, api } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import { usePagination } from '../hooks/usePagination'
import TableSkeleton from '../components/TableSkeleton'

export default function SetupKeys() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const [showRotateModal, setShowRotateModal] = useState(null) // peer ID or 'bulk'
  const [rotationResult, setRotationResult] = useState(null) // { peerId, newKey, token }
  const [searchTerm, setSearchTerm] = useState('')
  const rotateConfirmModalRef = useRef(null)
  const rotateResultModalRef = useRef(null)

  // Fetch peers with rotation info
  const { data: peers, isLoading: peersLoading } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
  })

  // Rotate single peer key
  const rotateMutation = useMutation({
    mutationFn: (peerId) => api.post(`/peers/${peerId}/rotate-key`),
    onSuccess: (data, peerId) => {
      setRotationResult({ peerId, ...data })
      setShowRotateModal(null)
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
      showToast('Key rotated successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  // Bulk rotation
  const bulkRotateMutation = useMutation({
    mutationFn: async () => {
      if (!peers) return
      const agentPeers = peers.filter(p => !p.is_manual)
      const results = await Promise.allSettled(
        agentPeers.map(peer => api.post(`/peers/${peer.id}/rotate-key`))
      )
      return results
    },
    onSuccess: (results) => {
      if (!results) return;
      const succeeded = results.filter(r => r.status === 'fulfilled').length
      const failed = results.filter(r => r.status === 'rejected').length
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
      showToast(`Bulk rotation: ${succeeded} succeeded, ${failed} failed`, succeeded > 0 ? 'success' : 'error')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const handleRotate = (peerId) => {
    rotateMutation.mutate(peerId)
  }

  const handleBulkRotate = () => {
    bulkRotateMutation.mutate()
    setShowRotateModal(null)
  }

  const getRotationStatus = (peer) => {
    // Determine rotation status based on peer data
    if (!peer.hmac_key_last_rotated_at) return { status: 'never', icon: Clock, color: 'text-gray-400' }
    
    const lastRotated = new Date(peer.hmac_key_last_rotated_at)
    const now = new Date()
    const hoursSince = (now - lastRotated) / (1000 * 60 * 60)
    
    if (hoursSince < 1) return { status: 'recent', icon: CheckCircle, color: 'text-green-500' }
    if (hoursSince < 24) return { status: 'today', icon: CheckCircle, color: 'text-green-500' }
    if (hoursSince < 72) return { status: 'aging', icon: Clock, color: 'text-yellow-500' }
    return { status: 'old', icon: AlertTriangle, color: 'text-red-500' }
  }

  const formatLastRotation = (timestamp) => {
    if (!timestamp) return 'Never'
    const date = new Date(timestamp)
    const now = new Date()
    const diffMs = now - date
    const diffHours = Math.floor(diffMs / (1000 * 60 * 60))
    const diffDays = Math.floor(diffHours / 24)
    
    if (diffHours < 1) return `${Math.floor(diffMs / (1000 * 60))} minutes ago`
    if (diffHours < 24) return `${diffHours} hours ago`
    if (diffDays < 7) return `${diffDays} days ago`
    return date.toLocaleDateString()
  }

  // Filter out manual peers (they have no HMAC keys) and apply search
  const agentPeers = useMemo(() => (peers || []).filter(p => !p.is_manual), [peers])
  const filteredPeers = useMemo(() => {
    if (!searchTerm) return agentPeers
    const term = searchTerm.toLowerCase()
    return agentPeers.filter(p =>
      (p.hostname || '').toLowerCase().includes(term) ||
      (p.ip_address || '').toLowerCase().includes(term)
    )
  }, [agentPeers, searchTerm])

  const {
    paginatedData: paginatedPeers,
    totalPages,
    showingRange: peersShowingRange,
    page: peersPage,
    rowsPerPage: peersRowsPerPage,
    onPageChange: setPeersPage,
    onRowsPerPageChange: setPeersRowsPerPage,
    totalItems: peersTotal
  } = usePagination(filteredPeers, 'setupKeys')

  // Reset page to 1 when search term changes
  useEffect(() => {
    setPeersPage(1)
  }, [searchTerm])

  // Focus trap for rotation confirmation modal
  useEffect(() => {
    if (!showRotateModal) return
    const modal = rotateConfirmModalRef.current
    if (!modal) return
    const focusable = modal.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    if (focusable.length === 0) return
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    first.focus()
    const handleTab = (e) => {
      if (e.key !== 'Tab') return
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last.focus() }
      } else {
        if (document.activeElement === last) { e.preventDefault(); first.focus() }
      }
    }
    modal.addEventListener('keydown', handleTab)
    return () => modal.removeEventListener('keydown', handleTab)
  }, [showRotateModal])

  // Focus trap for rotation result modal
  useEffect(() => {
    if (!rotationResult) return
    const modal = rotateResultModalRef.current
    if (!modal) return
    const focusable = modal.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    )
    if (focusable.length === 0) return
    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    first.focus()
    const handleTab = (e) => {
      if (e.key !== 'Tab') return
      if (e.shiftKey) {
        if (document.activeElement === first) { e.preventDefault(); last.focus() }
      } else {
        if (document.activeElement === last) { e.preventDefault(); first.focus() }
      }
    }
    modal.addEventListener('keydown', handleTab)
    return () => modal.removeEventListener('keydown', handleTab)
  }, [rotationResult])

  if (peersLoading) return <TableSkeleton rows={5} columns={6} />

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">Setup Keys</h1>
          <p className="text-gray-600 dark:text-amber-muted">Manage per-peer HMAC key rotation</p>
        </div>
        <button
          onClick={() => setShowRotateModal('bulk')}
          disabled={bulkRotateMutation.isPending || !agentPeers || agentPeers.length === 0}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-purple-active hover:bg-purple-active/80 text-white rounded-lg disabled:opacity-50"
        >
          <RotateCw className="w-4 h-4" />
          Rotate All Keys
        </button>
      </div>

      {/* Search Bar and Rows per page */}
      <div className="flex items-center justify-between gap-4">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400 pointer-events-none" />
          <input
            type="text"
            placeholder="Search by hostname or IP..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-9 pr-10 py-2 border border-gray-300 dark:border-gray-border rounded-lg bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral placeholder-gray-400 focus:ring-2 focus:ring-purple-active focus:border-purple-active"
          />
          {searchTerm && (
            <button
              onClick={() => setSearchTerm('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600 dark:hover:text-light-neutral"
            >
              ×
            </button>
          )}
        </div>
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-500 dark:text-amber-muted">Rows:</span>
          <select
            value={peersRowsPerPage}
            onChange={(e) => setPeersRowsPerPage(Number(e.target.value))}
            className="text-sm border border-gray-300 dark:border-gray-border rounded px-2 py-2 bg-white dark:bg-charcoal-dark text-gray-900 dark:text-light-neutral focus:ring-2 focus:ring-purple-active focus:border-purple-active"
          >
            <option value={10}>10</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
            <option value={100}>100</option>
            <option value={-1}>All</option>
          </select>
        </div>
      </div>

      {/* Peers Rotation Table */}
      <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm">
        <div className="p-6">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral mb-4">Peer Keys</h2>
          
          {filteredPeers.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-border">
                <thead className="bg-gray-50 dark:bg-charcoal-darkest">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Peer</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Status</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Last Rotation</th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">Actions</th>
                  </tr>
                </thead>
                <tbody className="bg-white dark:bg-charcoal-dark divide-y divide-gray-200 dark:divide-gray-border">
                  {paginatedPeers.map((peer) => {
                    const rotationStatus = getRotationStatus(peer)
                    const StatusIcon = rotationStatus.icon
                    
                    return (
                      <tr key={peer.id} className="hover:bg-gray-50 dark:hover:bg-charcoal-darkest">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <div className="text-sm font-medium text-gray-900 dark:text-light-neutral">{peer.hostname}</div>
                            <div className="ml-2 text-xs text-gray-500 dark:text-amber-muted">{peer.ip_address}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <StatusIcon className={`w-4 h-4 mr-2 ${rotationStatus.color}`} />
                            <span className="text-sm text-gray-900 dark:text-light-neutral capitalize">{rotationStatus.status}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="text-sm text-gray-900 dark:text-light-neutral">
                            {formatLastRotation(peer.hmac_key_last_rotated_at)}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm">
                          <button
                            onClick={() => setShowRotateModal(peer.id)}
                            disabled={rotateMutation.isPending}
                            className="inline-flex items-center gap-2 px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-lg disabled:opacity-50"
                          >
                            <RotateCw className="w-3 h-3" />
                            Rotate
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="text-center py-8 text-gray-500 dark:text-amber-muted">
              No peers found. Add peers to manage their keys.
            </div>
          )}

          {/* Pagination Controls */}
          {peersTotal > 0 && (
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-gray-border bg-gray-50 dark:bg-charcoal-darkest">
              <span className="text-sm text-gray-500 dark:text-amber-muted">
                {peersShowingRange}
              </span>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setPeersPage(peersPage - 1)}
                  disabled={peersPage <= 1}
                  className="p-1.5 rounded hover:bg-gray-200 dark:hover:bg-charcoal-dark disabled:opacity-40 disabled:cursor-not-allowed"
                  title="Previous page"
                >
                  <ChevronLeft className="w-5 h-5 text-gray-600 dark:text-amber-primary" />
                </button>
                <span className="px-3 text-sm text-gray-600 dark:text-amber-primary">
                  Page {peersPage} of {totalPages}
                </span>
                <button
                  onClick={() => setPeersPage(peersPage + 1)}
                  disabled={peersPage >= totalPages}
                  className="p-1.5 rounded hover:bg-gray-200 dark:hover:bg-charcoal-dark disabled:opacity-40 disabled:cursor-not-allowed"
                  title="Next page"
                >
                  <ChevronRight className="w-5 h-5 text-gray-600 dark:text-amber-primary" />
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Rotation Confirmation Modal */}
      {showRotateModal && (
        <div ref={rotateConfirmModalRef} className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') setShowRotateModal(null) }}>
          <div className="bg-white dark:bg-charcoal-dark rounded-lg p-6 max-w-md w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-2">
              {showRotateModal === 'bulk' 
                ? 'Rotate All Peer Keys?'
                : `Rotate Key for ${peers?.find(p => p.id === showRotateModal)?.hostname || 'Peer'}?`
              }
            </h3>
            <p className="text-gray-600 dark:text-amber-muted mb-6">
              {showRotateModal === 'bulk'
                ? 'This will rotate HMAC keys for all peers. Each peer will need to retrieve their new key using the rotation token.'
                : 'This will generate a new HMAC key for this peer. The peer will need to retrieve the new key using the rotation token.'
              }
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setShowRotateModal(null)}
                className="flex-1 px-4 py-2 border border-gray-300 dark:border-gray-border rounded-lg text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
              >
                Cancel
              </button>
              <button
                onClick={() => showRotateModal === 'bulk' ? handleBulkRotate() : handleRotate(showRotateModal)}
                disabled={rotateMutation.isPending || bulkRotateMutation.isPending}
                className="flex-1 px-4 py-2 bg-purple-active hover:bg-purple-active/80 text-white rounded-lg disabled:opacity-50"
              >
                {(showRotateModal === 'bulk' ? bulkRotateMutation : rotateMutation).isPending ? 'Rotating...' : 'Rotate'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Rotation Result Modal */}
      {rotationResult && (
        <div ref={rotateResultModalRef} className="fixed inset-0 bg-black/50 flex items-center justify-center z-50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') setRotationResult(null) }}>
          <div className="bg-white dark:bg-charcoal-dark rounded-lg p-6 max-w-lg w-full mx-4">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Key Rotation Successful
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-muted mb-1">
                  New HMAC Key
                </label>
                <div className="p-3 bg-gray-100 dark:bg-charcoal-darkest rounded font-mono text-sm text-gray-700 dark:text-amber-primary break-all">
                  {rotationResult.new_hmac_key}
                </div>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-amber-muted mb-1">
                  Rotation Token (provide to agent)
                </label>
                <div className="p-3 bg-gray-100 dark:bg-charcoal-darkest rounded font-mono text-sm text-gray-700 dark:text-amber-primary break-all">
                  {rotationResult.rotation_token}
                </div>
              </div>
              <p className="text-sm text-gray-600 dark:text-amber-muted">
                The agent will use this token to retrieve the new key. The token expires in 5 minutes.
              </p>
            </div>
            <div className="mt-6">
              <button
                onClick={() => setRotationResult(null)}
                className="w-full px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
