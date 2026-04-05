import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Upload, UserPlus, Shield } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import ConfirmModal from './ConfirmModal'
import PushJobModal from './PushJobModal'

export default function QuickActions() {
  const navigate = useNavigate()
  const qc = useQueryClient()
  const showToast = useToastContext()
  const [showConfirmModal, setShowConfirmModal] = useState(false)
  const [pushJobId, setPushJobId] = useState(null)

  // Fetch peers list for confirmation modal
  const { data: peers, isLoading } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
    staleTime: 30000,
  })

  // Handle push rules to all peers
  const handlePushRulesToAll = async () => {
    setShowConfirmModal(false)
    try {
      const response = await api.post('/pending-changes/push-all')
      if (response.job_id) {
        setPushJobId(response.job_id)
      } else {
        showToast('No peers to push to', 'info')
      }
    } catch (err) {
      showToast(`Failed to start push: ${err.message}`, 'error')
    }
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
        disabled={isLoading}
        aria-label="Push Rules to All"
        className="w-full flex items-center gap-3 px-3 py-2.5 text-sm font-medium text-gray-700 dark:text-amber-primary bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border hover:bg-gray-200 dark:hover:bg-charcoal-light rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
      >
        <Upload className="w-4 h-4 text-purple-active" />
        <span>{isLoading ? 'Loading...' : 'Push Rules to All'}</span>
      </button>

      {/* Add Peer */}
      <button
        onClick={() => navigate('/peers', { state: { openAddModal: true } })}
        aria-label="Add Peer"
        className="w-full flex items-center gap-3 px-3 py-2.5 text-sm font-medium text-gray-700 dark:text-amber-primary bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border hover:bg-gray-200 dark:hover:bg-charcoal-light rounded-lg transition-colors"
      >
        <UserPlus className="w-4 h-4 text-purple-active" />
        <span>Add Peer</span>
      </button>

      {/* Create Policy */}
      <button
        onClick={() => navigate('/policies', { state: { openAddModal: true } })}
        aria-label="Create Policy"
        className="w-full flex items-center gap-3 px-3 py-2.5 text-sm font-medium text-gray-700 dark:text-amber-primary bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border hover:bg-gray-200 dark:hover:bg-charcoal-light rounded-lg transition-colors"
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

      {/* Push Job Progress Modal */}
      {pushJobId && (
        <PushJobModal
          jobId={pushJobId}
          onClose={() => {
            setPushJobId(null)
            qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
          }}
        />
      )}
    </div>
  )
}
