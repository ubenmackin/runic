import { useState, useEffect, useRef } from 'react'
import { FileCode, X, Copy, RefreshCw } from 'lucide-react'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { computeDiff } from '../utils/diff'
import { api } from '../api/client'

export default function BundleViewerModal({
  isOpen,
  onClose,
  peerId,
  peerHostname,
  viewingPendingRules = false,
}) {
  const showToast = useToastContext()
  const modalRef = useRef(null)
  const [bundleContent, setBundleContent] = useState('')
  const [bundleData, setBundleData] = useState(null)
  const [bundleLoading, setBundleLoading] = useState(false)
  const [showDiffView, setShowDiffView] = useState(true)

  useFocusTrap(modalRef, isOpen)

  // Fetch bundle data when modal opens
  useEffect(() => {
    if (!isOpen || !peerId) return
    setBundleLoading(true)
    setBundleContent('')
    setBundleData(null)
    setShowDiffView(true)
    const endpoint = viewingPendingRules ? `/peers/${peerId}/bundle?include_pending=true` : `/peers/${peerId}/bundle`
    api.get(endpoint)
      .then(data => {
        setBundleContent(data.rules)
        setBundleData(data)
      })
      .catch(err => {
        setBundleContent(`# Error: ${err.message}`)
        setBundleData(null)
      })
      .finally(() => setBundleLoading(false))
  }, [isOpen, peerId, viewingPendingRules])

  const handleCopy = async () => {
    const contentToCopy =
      viewingPendingRules && showDiffView && 'deployed_rules' in (bundleData || {})
        ? computeDiff(bundleData.deployed_rules || '', bundleData.rules || '')
        : bundleContent
    try {
      await navigator.clipboard.writeText(contentToCopy)
      showToast('Copied to clipboard', 'success')
    } catch {
      showToast('Failed to copy to clipboard', 'error')
    }
  }

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { onClose() } }}>
      <div ref={modalRef} className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-4xl mx-4 max-h-[90vh] flex flex-col">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
          <div className="flex items-center gap-2">
            <FileCode className="w-5 h-5 text-purple-active" />
            <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">
              {viewingPendingRules ? `Pending Rules: ${peerHostname}` : `Deployed Rules: ${peerHostname}`}
            </h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>
        <div className="p-6 overflow-y-auto flex-1">
          {bundleLoading ? (
            <div className="flex flex-col items-center justify-center py-12 space-y-4">
              <RefreshCw className="w-8 h-8 text-purple-active animate-spin" />
              <p className="text-sm text-gray-500 dark:text-amber-muted">Fetching latest bundle...</p>
            </div>
          ) : (
            <>
              <div className="mb-3">
                <div className="mt-2 text-sm">
                  <span className="text-gray-500 dark:text-amber-muted">Bundle Version: </span>
                  <span className="font-mono font-medium text-gray-900 dark:text-light-neutral" title={bundleData?.version || ''}>
                    v{bundleData?.version_number || '—'}
                  </span>
                  {viewingPendingRules && bundleData?.deployed_version && (
                    <span className="ml-2 text-gray-500 dark:text-amber-muted">
                      (was v{bundleData?.deployed_version?.split('-')[0] || '—'})
                    </span>
                  )}
                </div>
              </div>
              {viewingPendingRules && 'deployed_rules' in (bundleData || {}) && (
                <div className="flex gap-2 mb-3">
                  <button
                    onClick={() => setShowDiffView(true)}
                    className={`px-3 py-1 rounded-none text-sm font-medium transition-colors ${
                      showDiffView
                        ? 'bg-purple-active text-white'
                        : 'bg-gray-100 dark:bg-charcoal-darkest text-gray-700 dark:text-amber-primary hover:bg-gray-200 dark:hover:bg-charcoal-dark'
                    }`}
                  >
                    Show Diff
                  </button>
                  <button
                    onClick={() => setShowDiffView(false)}
                    className={`px-3 py-1 rounded-none text-sm font-medium transition-colors ${
                      !showDiffView
                        ? 'bg-purple-active text-white'
                        : 'bg-gray-100 dark:bg-charcoal-darkest text-gray-700 dark:text-amber-primary hover:bg-gray-200 dark:hover:bg-charcoal-dark'
                    }`}
                  >
                    Show Full Rules
                  </button>
                </div>
              )}
              <div className="relative group">
                <pre className="bg-gray-900 dark:bg-black text-gray-100 p-6 rounded-none text-sm font-mono overflow-auto whitespace-pre min-h-[200px] border border-gray-800">
                  <code>
                    {viewingPendingRules && showDiffView && 'deployed_rules' in (bundleData || {})
                      ? computeDiff(bundleData.deployed_rules || '', bundleData.rules || '')
                      : bundleContent}
                  </code>
                </pre>
                {bundleContent && (
                  <button
                    onClick={handleCopy}
                    className="absolute top-4 right-4 p-2 bg-gray-800 hover:bg-gray-700 rounded-none text-gray-300 transition-colors"
                    title="Copy Rules"
                  >
                    <Copy className="w-4 h-4" />
                  </button>
                )}
              </div>
            </>
          )}
        </div>
        <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-end shrink-0">
          <button
            onClick={onClose}
            className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-light-neutral bg-gray-100 dark:bg-charcoal-darkest rounded-none hover:bg-gray-200 dark:hover:bg-charcoal-dark transition-colors"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  )
}
