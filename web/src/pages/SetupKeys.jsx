import { useState, useEffect, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RotateCw, CheckCircle, Clock, AlertTriangle } from 'lucide-react'
import { QUERY_KEYS, api } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import { usePagination } from '../hooks/usePagination'
import { useFocusTrap } from '../hooks/useFocusTrap'
import TableSkeleton from '../components/TableSkeleton'
import { useTableSort } from '../hooks/useTableSort'
import SortIndicator from '../components/SortIndicator'
import { formatRelativeTime } from '../utils/formatTime.js'
import TableToolbar from '../components/TableToolbar'
import PageHeader from '../components/PageHeader'
import Pagination from '../components/Pagination'
import { useTableFilter } from '../hooks/useTableFilter'

export default function SetupKeys() {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const [showRotateModal, setShowRotateModal] = useState(null) // peer ID or 'bulk'
  const [rotationResult, setRotationResult] = useState(null) // { peerId, newKey, token }
  const [searchTerm, setSearchTerm] = useState('')
  const { sortConfig, handleSort } = useTableSort('setupKeys', { key: 'hostname', direction: 'asc' })
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

  const getRotationStatusString = (peer) => {
    if (!peer.hmac_key_last_rotated_at) return 'never'

    const lastRotated = new Date(peer.hmac_key_last_rotated_at)
    const now = new Date()
    const hoursSince = (now - lastRotated) / (1000 * 60 * 60)

    if (hoursSince < 1) return 'recent'
    if (hoursSince < 24) return 'today'
    if (hoursSince < 72) return 'aging'
    return 'old'
  }

  const getRotationStatus = (peer) => {
    const status = getRotationStatusString(peer)
    switch (status) {
      case 'never': return { status, icon: Clock, color: 'text-gray-400' }
      case 'recent':
      case 'today': return { status, icon: CheckCircle, color: 'text-green-500' }
      case 'aging': return { status, icon: Clock, color: 'text-yellow-500' }
      default: return { status, icon: AlertTriangle, color: 'text-red-500' }
    }
  }

  // Filter out manual peers (they have no HMAC keys) and apply search
  const agentPeers = (peers || []).filter(p => !p.is_manual)
  const filteredPeers = useTableFilter(agentPeers, searchTerm, sortConfig, {
    filterFn: (p, term) => {
      return (p.hostname || '').toLowerCase().includes(term) || (p.ip_address || '').toLowerCase().includes(term)
    },
    fieldMap: {
      status: (p) => {
        const statusOrder = { never: 0, old: 1, aging: 2, recent: 3, today: 4 }
        return statusOrder[getRotationStatusString(p)] ?? 0
      },
      lastRotation: (p) => p.hmac_key_last_rotated_at ? new Date(p.hmac_key_last_rotated_at).getTime() : 0
    }
  })

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

  // Focus traps for modals
  useFocusTrap(rotateConfirmModalRef, !!showRotateModal)
  useFocusTrap(rotateResultModalRef, !!rotationResult)

  if (peersLoading) return <TableSkeleton rows={5} columns={6} />

  return (
    <div className="space-y-4">
      <PageHeader
        title="Setup Keys"
        description="Manage per-peer HMAC key rotation"
        actions={
          <button
            onClick={() => setShowRotateModal('bulk')}
            disabled={bulkRotateMutation.isPending || !peers || peers.filter(p => !p.is_manual).length === 0}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm bg-purple-active hover:bg-purple-active/80 text-white rounded-lg disabled:opacity-50"
          >
            <RotateCw className="w-4 h-4" />
            Rotate All Keys
          </button>
        }
      />

      {/* Search Bar and Rows per page */}
      <TableToolbar
        searchTerm={searchTerm}
        onSearchChange={(v) => setSearchTerm(v)}
        onClearSearch={() => setSearchTerm('')}
        placeholder="Search by hostname or IP..."
        rowsPerPage={peersRowsPerPage}
        onRowsPerPageChange={setPeersRowsPerPage}
      />

      {/* Peers Rotation Table */}
      {filteredPeers.length === 0 ? (
        <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-8 text-center">
          <p className="text-gray-500 dark:text-amber-muted">
            {searchTerm ? 'No peers match your search.' : 'No peers found. Add peers to manage their keys.'}
          </p>
        </div>
      ) : (
        <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 dark:bg-charcoal-darkest">
                <tr>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                    <button type="button" onClick={() => handleSort('hostname')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                      Peer <SortIndicator columnKey="hostname" sortConfig={sortConfig} />
                    </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                    <button type="button" onClick={() => handleSort('status')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                      Status <SortIndicator columnKey="status" sortConfig={sortConfig} />
                    </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-dark select-none">
                    <button type="button" onClick={() => handleSort('lastRotation')} className="flex items-center hover:text-runic-600 dark:hover:text-purple-active">
                      Last Rotation <SortIndicator columnKey="lastRotation" sortConfig={sortConfig} />
                    </button>
                  </th>
                  <th className="text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
                {paginatedPeers.map((peer) => {
                  const rotationStatus = getRotationStatus(peer)
                  const StatusIcon = rotationStatus.icon
                  
                  return (
                    <tr key={peer.id} className="">
                      <td className="px-4 py-3">
                        <div className="flex items-center">
                          <span className="font-medium text-gray-900 dark:text-light-neutral">{peer.hostname}</span>
                          <span className="ml-2 text-xs text-gray-500 dark:text-amber-muted">{peer.ip_address}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center">
                          <StatusIcon className={`w-4 h-4 mr-2 ${rotationStatus.color}`} />
                          <span className="text-sm text-gray-900 dark:text-light-neutral capitalize">{rotationStatus.status}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-600 dark:text-amber-primary">
                        {formatRelativeTime(peer.hmac_key_last_rotated_at)}
                      </td>
                      <td className="px-4 py-3">
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

          {/* Pagination Controls */}
          <Pagination
            showingRange={peersShowingRange}
            page={peersPage}
            totalPages={totalPages}
            onPageChange={setPeersPage}
            totalItems={peersTotal}
          />
        </div>
      )}

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
          <div className="flex items-center gap-3 text-green-600 dark:text-green-400">
            <CheckCircle className="w-6 h-6" />
            <span className="font-medium">Key rotation initiated successfully</span>
          </div>
          <p className="text-sm text-gray-600 dark:text-amber-muted">
            The agent will automatically detect and apply the new key within 5 minutes. No manual action is required.
          </p>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-muted mb-1">
              Rotation Reference ID
            </label>
            <div className="p-3 bg-gray-100 dark:bg-charcoal-darkest rounded font-mono text-sm text-gray-700 dark:text-amber-primary break-all">
              {rotationResult.rotation_token}
            </div>
          </div>
          <p className="text-xs text-gray-500 dark:text-amber-muted">
            The rotation will expire in 5 minutes if not picked up by the agent.
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
