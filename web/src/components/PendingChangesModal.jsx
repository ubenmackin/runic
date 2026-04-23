import { useState, useEffect, useRef, useMemo } from 'react'
import { X, RefreshCw, Copy, Check, AlertCircle, Trash2 } from 'lucide-react'
import { api } from '../api/client'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useToastContext } from '../hooks/ToastContext'
import { computeSmartDiff } from '../utils/diff.js'

export default function PendingChangesModal({ peerId, peerHostname, onClose, onApplied }) {
  const showToast = useToastContext()
  const modalRef = useRef(null)
  const [loading, setLoading] = useState(true)
  const [changes, setChanges] = useState([])
  const [error, setError] = useState(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [preview, setPreview] = useState(null)
  const [applyLoading, setApplyLoading] = useState(false)
  const [rollbackLoading, setRollbackLoading] = useState(false)
  const [applyEntityLoading, setApplyEntityLoading] = useState(false)
  const [activeTab, setActiveTab] = useState('queued')
  const [deployedRules, setDeployedRules] = useState('')
  const [deployedRulesLoading, setDeployedRulesLoading] = useState(true)

  useFocusTrap(modalRef, true)

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

  useEffect(() => {
    const fetchDeployedRules = async () => {
      setDeployedRulesLoading(true)
      try {
        const data = await api.get(`/peers/${peerId}/bundle`)
        setDeployedRules(data.rules || '')
      } catch (err) {
        showToast(`Failed to fetch deployed rules: ${err.message}`, 'error')
      } finally {
        setDeployedRulesLoading(false)
      }
    }
    fetchDeployedRules()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [peerId])

  // Track the last changes reference we triggered preview for
  const lastChangesRef = useRef(null)

  // Auto-generate preview when changes are loaded
  useEffect(() => {
    if (changes.length > 0 && !preview && !previewLoading && lastChangesRef.current !== changes) {
      lastChangesRef.current = changes
      setPreviewLoading(true)
      setPreview(null)
      api.post(`/pending-changes/${peerId}/preview`)
        .then(data => setPreview(data))
        .catch(err => showToast(`Failed to generate preview: ${err.message}`, 'error'))
        .finally(() => setPreviewLoading(false))
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
}, [changes, preview, previewLoading, peerId])

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

  const handleBulkRollback = async () => {
    if (!window.confirm('Are you sure you want to discard ALL pending changes across all peers? This action cannot be undone.')) return
    setRollbackLoading(true)
    try {
      await api.post('/pending-changes/rollback')
      showToast('All pending changes discarded successfully', 'success')
      onApplied() // Triggers a refetch in the parent component
      onClose()
    } catch (err) {
      showToast(`Failed to rollback changes: ${err.message}`, 'error')
    } finally {
      setRollbackLoading(false)
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

  const groupedChanges = useMemo(() => {
    const groups = {}
    changes.forEach(change => {
      const key = `${change.change_type}-${change.change_id}`
      if (!groups[key]) {
        groups[key] = {
          entityType: change.change_type,
          entityId: change.change_id,
          entityName: change.entity_name || `Unknown ${change.change_type}`,
          changes: []
        }
      }
      groups[key].changes.push(change)
    })
    return Object.values(groups)
  }, [changes])

  const smartDiffEntries = useMemo(() => {
    if (preview && preview.rules_content) {
      return computeSmartDiff(deployedRules || '', preview.rules_content)
    }
    return []
  }, [deployedRules, preview])

  const diffText = useMemo(() => {
    if (smartDiffEntries.length === 0) return ''
    return smartDiffEntries.map(entry => {
      if (entry.type === 'section-header') return entry.line
      if (entry.type === 'add') return `+ ${entry.line}`
      if (entry.type === 'remove') return `- ${entry.line}`
      if (entry.type === 'change') return `- ${entry.oldLine}\n+ ${entry.newLine}`
      return ''
    }).join('\n')
  }, [smartDiffEntries])

  const handleEntityRollback = async (entityType, entityId) => {
    const confirmed = window.confirm(`Are you sure you want to rollback ${entityType}?`)
    if (!confirmed) return

    setRollbackLoading(true)
    try {
      await api.post('/pending-changes/rollback', { entity_type: entityType, entity_id: entityId })
      showToast('Rolled back successfully', 'success')
      onApplied() // Call parent's callback to refresh peers list
      const data = await api.get(`/pending-changes/${peerId}`)
      setChanges(data.changes || [])
      setPreview(null)
    } catch (err) {
      if (err.status === 409) {
        showToast(err.message || 'Cannot rollback: referenced by policies', 'error')
      } else {
        showToast(err.message || 'Failed to rollback', 'error')
      }
    } finally {
      setRollbackLoading(false)
    }
  }

  const handleEntityApply = async (entityType, entityId) => {
    const confirmed = window.confirm(`Apply changes for ${entityType}?`)
    if (!confirmed) return

    setApplyEntityLoading(true)
    try {
      await api.post(`/pending-changes/${peerId}/apply-entity`, { entity_type: entityType, entity_id: entityId })
      showToast('Changes applied successfully', 'success')
      onApplied()
      const data = await api.get(`/pending-changes/${peerId}`)
      setChanges(data.changes || [])
      setPreview(null)
    } catch (err) {
      showToast(`Failed to apply: ${err.message}`, 'error')
    } finally {
      setApplyEntityLoading(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') onClose() }}>
      <div ref={modalRef} className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-4xl mx-4 max-h-[90vh] flex flex-col">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-5 h-5 text-purple-active" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Changes for Review: {peerHostname}</h3>
          </div>
          <button onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {!loading && !error && changes.length > 0 && (
          <div className="flex border-b border-gray-200 dark:border-gray-border shrink-0">
        <button
          type="button"
          onClick={() => setActiveTab('queued')}
          className={`flex-1 px-4 py-3 text-sm font-medium text-center transition-colors ${
            activeTab === 'queued'
              ? 'text-purple-active border-b-2 border-purple-active dark:text-purple-active'
              : 'text-gray-500 hover:text-gray-700 dark:text-amber-muted dark:hover:text-amber-primary'
          }`}
        >
          Queued Changes
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('bundle')}
          className={`flex-1 px-4 py-3 text-sm font-medium text-center transition-colors ${
            activeTab === 'bundle'
              ? 'text-purple-active border-b-2 border-purple-active dark:text-purple-active'
              : 'text-gray-500 hover:text-gray-700 dark:text-amber-muted dark:hover:text-amber-primary'
          }`}
        >
          Bundle Preview
        </button>
          </div>
        )}

        <div className="p-6 overflow-y-auto flex-1">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <RefreshCw className="w-8 h-8 text-purple-active animate-spin" />
              <p className="text-sm text-gray-500 dark:text-amber-muted">Loading pending changes...</p>
            </div>
          ) : error ? (
            <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-none p-4">
              <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
            </div>
          ) : changes.length === 0 ? (
            <div className="text-center py-12">
              <p className="text-gray-500 dark:text-amber-muted">No pending changes for this peer.</p>
            </div>
          ) : activeTab === 'queued' ? (
            <>
              <div className="mb-6">
                <h4 className="text-sm font-medium text-gray-700 dark:text-amber-primary mb-3">Queued Changes ({changes.length})</h4>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-gray-200 dark:border-gray-border">
                        <th className="text-left py-2 px-3 font-medium text-gray-600 dark:text-amber-muted">Entity</th>
                        <th className="text-left py-2 px-3 font-medium text-gray-600 dark:text-amber-muted">Changes</th>
                        <th className="text-right py-2 px-3 font-medium text-gray-600 dark:text-amber-muted">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {groupedChanges.map(group => (
                        <tr key={`${group.entityType}-${group.entityId}`} className="border-b border-gray-100 dark:border-gray-800 hover:bg-gray-50 dark:hover:bg-charcoal-darkest">
                          <td className="py-3 px-3">
                            <div className="flex items-center gap-2">
                              <span className="px-2 py-0.5 text-xs font-medium bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                                {handleChangeTypeLabel(group.entityType)}
                              </span>
                              <span className="text-gray-900 dark:text-light-neutral font-medium">
                                {group.entityName}
                              </span>
                            </div>
                          </td>
                          <td className="py-3 px-3 text-gray-600 dark:text-amber-muted">
                            {group.changes.length} change(s)
                            <div className="mt-1 space-y-1">
                              {group.changes.map((change, idx) => (
                                <div key={change.id || idx} className="flex items-center gap-2 text-xs">
                                  <span className={`px-2 py-0.5 text-xs font-medium ${handleActionColor(change.change_action)}`}>
                                    {handleActionLabel(change.change_action)}
                                  </span>
                                  <span className="text-gray-500 dark:text-amber-muted">
                                    {change.change_summary}
                                  </span>
                                </div>
                              ))}
                            </div>
                          </td>
                          <td className="py-3 px-3 text-right">
                            <button
                              onClick={() => handleEntityApply(group.entityType, group.entityId)}
                              disabled={applyEntityLoading}
                              className="text-green-600 hover:text-green-800 dark:text-green-400 font-medium text-sm px-3 py-1 rounded-none hover:bg-green-50 dark:hover:bg-green-900/20 disabled:opacity-50"
                            >
                              {applyEntityLoading ? 'Applying...' : '✓ Apply'}
                            </button>
                            <button
                              onClick={() => handleEntityRollback(group.entityType, group.entityId)}
                              disabled={rollbackLoading}
                              className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 font-medium text-sm px-3 py-1 rounded-none hover:bg-blue-50 dark:hover:bg-blue-900/20 disabled:opacity-50 transition-colors"
                            >
                              {rollbackLoading ? 'Rolling back...' : '↩ Rollback'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              <div className="border-t border-gray-200 dark:border-gray-border my-4" />

              <div>
                <h5 className="text-xs font-medium text-gray-600 dark:text-amber-muted mb-2 uppercase tracking-wide">Smart Diff</h5>
                {previewLoading || deployedRulesLoading ? (
                  <div className="flex flex-col items-center justify-center py-8 space-y-4">
                    <RefreshCw className="w-6 h-6 text-purple-active animate-spin" />
                    <p className="text-sm text-gray-500 dark:text-amber-muted">Generating diff...</p>
                  </div>
                ) : smartDiffEntries.length === 0 ? (
                  <pre className="bg-gray-900 dark:bg-black p-4 rounded-none text-sm font-mono overflow-auto whitespace-pre max-h-[300px] border border-gray-800">
                    <div className="text-gray-400 italic">No differences from deployed rules</div>
                  </pre>
                ) : (
                  <div className="relative">
                    <pre className="bg-gray-900 dark:bg-black p-4 rounded-none text-sm font-mono overflow-auto whitespace-pre max-h-[300px] border border-gray-800">
                      {smartDiffEntries.map((entry, idx) => {
                        if (entry.type === 'section-header') {
                          return <div key={idx} className="text-gray-300 font-bold">{entry.line}</div>
                        }
                        if (entry.type === 'add') {
                          return <div key={idx} className="text-green-400">+ {entry.line}</div>
                        }
                        if (entry.type === 'remove') {
                          return <div key={idx} className="text-red-400">- {entry.line}</div>
                        }
                        if (entry.type === 'change') {
                          return (
                            <div key={idx}>
                              <div className="text-red-400">- {entry.oldLine}</div>
                              <div className="text-green-400">+ {entry.newLine}</div>
                            </div>
                          )
                        }
                        return null
                      })}
                    </pre>
                    <button
                      onClick={() => {
                        navigator.clipboard.writeText(diffText)
                        showToast('Copied to clipboard', 'success')
                      }}
                      className="absolute top-2 right-2 p-2 bg-gray-800 hover:bg-gray-700 rounded-none text-gray-300 transition-colors"
                      title="Copy Diff"
                    >
                      <Copy className="w-4 h-4" />
                    </button>
                  </div>
                )}
              </div>
            </>
          ) : activeTab === 'bundle' ? (
            <div className="space-y-4">
              <h4 className="text-sm font-medium text-gray-700 dark:text-amber-primary">Bundle Preview</h4>

              <div className="flex items-center gap-4 text-sm">
                <div>
                  <span className="text-gray-500 dark:text-amber-muted">Current Version: </span>
                  <span className="font-mono font-medium text-gray-900 dark:text-light-neutral">{preview?.current_version_number ?? '—'}</span>
                </div>
                <div>
                  <span className="text-gray-500 dark:text-amber-muted">New Version: </span>
                  <span className="font-mono font-medium text-gray-900 dark:text-light-neutral">{preview?.new_version_number ?? '—'}</span>
                </div>
              </div>

              <div className="relative group">
                <h5 className="text-xs font-medium text-gray-600 dark:text-amber-muted mb-2 uppercase tracking-wide">Full Bundle</h5>
                <pre className="bg-gray-900 dark:bg-black text-gray-100 p-4 rounded-none text-sm font-mono overflow-auto whitespace-pre max-h-[300px] border border-gray-800">
                  <code className="text-green-400">{preview?.rules_content ?? ''}</code>
                </pre>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(preview?.rules_content ?? '')
                    showToast('Copied to clipboard', 'success')
                  }}
                  className="absolute top-8 right-3 p-2 bg-gray-800 hover:bg-gray-700 rounded-none text-gray-300 transition-colors"
                  title="Copy Rules"
                >
                  <Copy className="w-4 h-4" />
                </button>
              </div>
            </div>
          ) : null}
        </div>

        <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-between shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-light-neutral bg-gray-100 dark:bg-charcoal-darkest rounded-none hover:bg-gray-200 dark:hover:bg-charcoal-dark transition-colors"
          >
            Close
          </button>
          {changes.length > 0 && (
            <div className="flex gap-2">
              <button
                onClick={handleBulkRollback}
                disabled={applyLoading || rollbackLoading}
                className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/40 rounded-none disabled:opacity-50 transition-colors"
                title="Discard all pending changes across all peers"
              >
                {rollbackLoading ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Discarding...
                  </>
                ) : (
                  <>
                    <Trash2 className="w-4 h-4" />
                    Discard All
                  </>
                )}
              </button>
              <button
                onClick={handleApply}
                disabled={applyLoading || rollbackLoading || !preview}
                className="flex items-center gap-2 px-4 py-2 text-sm font-bold uppercase text-white bg-green-600 hover:bg-green-700 rounded-none disabled:opacity-50 disabled:cursor-not-allowed border border-green-600/20 shadow-[0_0_15px_rgba(34,197,94,0.2)] transition-all"
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
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
