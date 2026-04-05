import { useState, useEffect, useRef } from 'react'
import { X, RefreshCw, Copy, Check, AlertCircle, FileCode } from 'lucide-react'
import { api } from '../api/client'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useToastContext } from '../hooks/ToastContext'

export default function PendingChangesModal({ peerId, peerHostname, onClose, onApplied }) {
  const showToast = useToastContext()
  const modalRef = useRef(null)
  const [loading, setLoading] = useState(true)
  const [changes, setChanges] = useState([])
  const [error, setError] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [preview, setPreview] = useState(null)
  const [applyLoading, setApplyLoading] = useState(false)

  useFocusTrap(modalRef, true)

  // Load pending changes on mount
  useEffect(() => {
    const fetchChanges = async () => {
      setLoading(true)
      setError(null)
      try {
        const data = await api.get(`/pending-changes/${peerId}`)
        setChanges(data.changes || [])
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    fetchChanges()
  }, [peerId])

  const handleGeneratePreview = async () => {
    setPreviewLoading(true)
    setPreview(null)
    try {
      const data = await api.post(`/pending-changes/${peerId}/preview`)
      setPreview(data)
    } catch (err) {
      showToast(`Failed to generate preview: ${err.message}`, 'error')
    } finally {
      setPreviewLoading(false)
    }
  }

  const handleApply = async () => {
    setApplyLoading(true)
    try {
      await api.post(`/pending-changes/${peerId}/apply`)
      showToast('Changes applied successfully', 'success')
      onApplied()
      onClose()
    } catch (err) {
      showToast(`Failed to apply changes: ${err.message}`, 'error')
    } finally {
      setApplyLoading(false)
    }
  }

  const handleChangeTypeLabel = (type) => {
    switch (type) {
      case 'policy': return 'Policy'
      case 'group': return 'Group'
      case 'service': return 'Service'
      default: return type
    }
  }

  const handleActionLabel = (action) => {
    switch (action) {
      case 'create': return 'Created'
      case 'update': return 'Updated'
      case 'delete': return 'Deleted'
      default: return action
    }
  }

  const handleActionColor = (action) => {
    switch (action) {
      case 'create': return 'bg-green-100 dark:bg-green-900/30 text-green-800 dark:text-green-300'
      case 'update': return 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300'
      case 'delete': return 'bg-red-100 dark:bg-red-900/30 text-red-800 dark:text-red-300'
      default: return 'bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-300'
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') onClose() }}>
      <div ref={modalRef} className="bg-white dark:bg-charcoal-dark rounded-xl shadow-xl w-full max-w-4xl mx-4 max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-purple-active" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Pending Changes: {peerHostname}</h3>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 overflow-y-auto flex-1">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <RefreshCw className="w-8 h-8 text-purple-active animate-spin" />
              <p className="text-sm text-gray-500 dark:text-amber-muted">Loading pending changes...</p>
            </div>
          ) : error ? (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
              <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
            </div>
          ) : changes.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-gray-500 dark:text-amber-muted">No pending changes for this peer.</p>
            </div>
          ) : (
            <>
              {/* Pending Changes List */}
              <div className="mb-6">
                <h4 className="text-sm font-medium text-gray-700 dark:text-amber-primary mb-3">Queued Changes ({changes.length})</h4>
                <div className="space-y-2">
                  {changes.map((change, idx) => (
                    <div key={change.id || idx} className="flex items-center gap-3 p-3 bg-gray-50 dark:bg-charcoal-darkest rounded-lg">
                      <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${handleActionColor(change.change_action)}`}>
                        {handleActionLabel(change.change_action)}
                      </span>
                      <span className="px-2 py-0.5 text-xs font-medium rounded-full bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                        {handleChangeTypeLabel(change.change_type)}
                      </span>
                      <span className="text-sm text-gray-900 dark:text-light-neutral flex-1">
                        {change.change_summary}
                      </span>
                      <span className="text-xs text-gray-500 dark:text-amber-muted">
                        {new Date(change.created_at).toLocaleString()}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Preview Section */}
              {preview ? (
                <div className="space-y-4">
                  <h4 className="text-sm font-medium text-gray-700 dark:text-amber-primary">Bundle Preview</h4>
                  
                  {/* Version Info */}
                  <div className="flex items-center gap-4 text-sm">
                    <div>
                      <span className="text-gray-500 dark:text-amber-muted">Current Version: </span>
                      <span className="font-mono font-medium text-gray-900 dark:text-light-neutral">{preview.current_version_number ?? '—'}</span>
                    </div>
                    <div>
                      <span className="text-gray-500 dark:text-amber-muted">New Version: </span>
                      <span className="font-mono font-medium text-gray-900 dark:text-light-neutral">{preview.new_version_number ?? '—'}</span>
                    </div>
                  </div>

                  {/* Diff Section */}
                  {preview.diff_content && (
                    <div>
                      <h5 className="text-xs font-medium text-gray-600 dark:text-amber-muted mb-2 uppercase tracking-wide">Changes (Diff)</h5>
                      <pre className="bg-gray-900 dark:bg-black text-gray-100 p-4 rounded-lg text-sm font-mono overflow-auto whitespace-pre max-h-[200px] border border-gray-800">
                        <code>{preview.diff_content}</code>
                      </pre>
                    </div>
                  )}

                  {/* Full Bundle Preview */}
                  <div className="relative group">
                    <h5 className="text-xs font-medium text-gray-600 dark:text-amber-muted mb-2 uppercase tracking-wide">Full Bundle</h5>
                    <pre className="bg-gray-900 dark:bg-black text-gray-100 p-4 rounded-lg text-sm font-mono overflow-auto whitespace-pre max-h-[300px] border border-gray-800">
                      <code className="text-green-400">{preview.rules_content}</code>
                    </pre>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(preview.rules_content)
                        showToast('Copied to clipboard', 'success')
                      }}
                      className="absolute top-8 right-3 p-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-gray-300 transition-colors"
                      title="Copy Rules"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              ) : (
                <button
                  onClick={handleGeneratePreview}
                  disabled={previewLoading}
                  className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-purple-active hover:bg-purple-active/80 rounded-lg disabled:opacity-50"
                >
                  {previewLoading ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      Generating Preview...
                    </>
                  ) : (
                    <>
                      <FileCode className="w-4 h-4" />
                      Generate Preview
                    </>
                  )}
                </button>
              )}
            </>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-between shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-light-neutral bg-gray-100 dark:bg-charcoal-darkest rounded-lg hover:bg-gray-200 dark:hover:bg-charcoal-dark transition-colors"
          >
            Close
          </button>
          {changes.length > 0 && (
            <button
              onClick={handleApply}
              disabled={applyLoading || !preview}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-green-600 hover:bg-green-700 rounded-lg disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {applyLoading ? (
                <>
                  <RefreshCw className="w-4 h-4 animate-spin" />
                  Applying...
                </>
              ) : (
                <>
                  <Check className="w-4 h-4" />
                  Apply Changes
                </>
              )}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
