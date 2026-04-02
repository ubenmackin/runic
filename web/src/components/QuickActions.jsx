import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, UserPlus, Shield, Loader2 } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from './ConfirmModal'

export default function QuickActions() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const showToast = useToastContext()
  const [showConfirmModal, setShowConfirmModal] = useState(false)

  // Fetch peers list
  const { data: peers, isLoading } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
    staleTime: 30000,
  })

  // Mutation for pushing rules to a single peer
  const pushRulesMutation = useMutation({
    mutationFn: (peerId) => api.post(`/peers/${peerId}/compile`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
    },
  })

  // Handle push rules to all peers
  const handlePushRulesToAll = async () => {
    if (!peers || peers.length === 0) {
      showToast('No peers available to push rules to', 'error')
      return
    }

  const results = await Promise.allSettled(
    peers.map(peer => pushRulesMutation.mutateAsync(peer.id))
  )

  const success = results.filter(r => r.status === 'fulfilled').length
  const failed = results.filter(r => r.status === 'rejected').length

  // Show result notification
  if (failed === 0) {
    showToast(`Successfully pushed rules to all ${success} peer(s)`, 'success')
  } else if (success === 0) {
    showToast(`Failed to push rules to all ${failed} peer(s)`, 'error')
  } else {
    showToast(`Pushed rules to ${success} peer(s), ${failed} failed`, 'error')
  }

    setShowConfirmModal(false)
  }

  return (
    <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm p-4">
      <div className="flex items-center gap-2 mb-4">
        <Shield className="w-5 h-5 text-purple-active" />
        <h3 className="text-sm font-semibold text-gray-900 dark:text-light-neutral">Quick Actions</h3>
      </div>

      <div className="space-y-2">
      {/* Push Rules to All */}
      <button
        onClick={() => setShowConfirmModal(true)}
        disabled={pushRulesMutation.isPending || isLoading}
        aria-label="Push Rules to All"
        className="w-full flex items-center gap-3 px-3 py-2.5 text-sm font-medium text-gray-700 dark:text-amber-primary bg-gray-50 dark:bg-charcoal-darkest hover:bg-gray-100 dark:hover:bg-charcoal-dark rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        {pushRulesMutation.isPending || isLoading ? (
          <Loader2 className="w-4 h-4 animate-spin text-purple-active" />
        ) : (
          <Upload className="w-4 h-4 text-purple-active" />
        )}
        <span>{pushRulesMutation.isPending ? 'Pushing Rules...' : isLoading ? 'Loading...' : 'Push Rules to All'}</span>
      </button>

      {/* Add Peer */}
      <button
        onClick={() => navigate('/peers')}
        aria-label="Add Peer"
        className="w-full flex items-center gap-3 px-3 py-2.5 text-sm font-medium text-gray-700 dark:text-amber-primary bg-gray-50 dark:bg-charcoal-darkest hover:bg-gray-100 dark:hover:bg-charcoal-dark rounded-lg transition-colors"
      >
        <UserPlus className="w-4 h-4 text-purple-active" />
        <span>Add Peer</span>
      </button>

      {/* Create Policy */}
      <button
        onClick={() => navigate('/policies')}
        aria-label="Create Policy"
        className="w-full flex items-center gap-3 px-3 py-2.5 text-sm font-medium text-gray-700 dark:text-amber-primary bg-gray-50 dark:bg-charcoal-darkest hover:bg-gray-100 dark:hover:bg-charcoal-dark rounded-lg transition-colors"
      >
        <Shield className="w-4 h-4 text-purple-active" />
        <span>Create Policy</span>
      </button>
      </div>

      {/* Confirmation Modal for Push Rules */}
      {showConfirmModal && (
        <ConfirmModal
          title="Push Rules to All Peers"
          message={`This will compile and push the current policy rules to all ${peers?.length || 0} peer(s). Continue?`}
          onConfirm={handlePushRulesToAll}
          onCancel={() => setShowConfirmModal(false)}
        />
      )}
    </div>
  )
}
