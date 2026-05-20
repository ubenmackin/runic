import { useRef, useMemo } from 'react'
import { X, RefreshCw, Eye } from 'lucide-react'
import { useFocusTrap } from '../hooks/useFocusTrap'
import SearchableSelect from './SearchableSelect'
import ToggleSwitch from './ToggleSwitch'
import InlineError from './InlineError'

const SPECIAL_TARGETS = {
  ALL_HOSTS: { id: 3, name: '__all_hosts__', label: 'All Hosts (IGMP)' },
}

export default function PolicyFormModal({
  isOpen,
  onClose,
  editItem,
  peerList,
  serviceList,
  groupList,
  specialTargetList,
  formData,
  setFormData,
  formErrors,
  activeTab,
  setActiveTab,
  showDescription,
  setShowDescription,
  preview,
  previewLoading,
  onSubmit,
  onPreview,
}) {
  const modalRef = useRef(null)
  useFocusTrap(modalRef, isOpen)

  const isIGMPService = formData.service_id && serviceList?.find(s => s.id === formData.service_id)?.name?.toUpperCase() === 'IGMP'
  const isVRRPService = formData.service_id && serviceList?.find(s => s.id === formData.service_id)?.name?.toUpperCase() === 'VRRP'
  const isSpecialService = isIGMPService || isVRRPService

  // Helper to extract peer ID from composite value (e.g., "peer:5:10.20.10.20" -> "5")
  const extractPeerId = (value) => {
    if (typeof value === 'string' && value.startsWith('peer:')) {
      const parts = value.split(':')
      return parts[1] || null
    }
    return value
  }

  // Helper to get peer object from selection value
  const getPeerFromSelection = (value) => {
    if (!value) return null
    const peerId = extractPeerId(value)
    return peerList?.find(p => p.id === peerId) || null
  }

  // Compute whether the forward button should be enabled
  const sourceType = formData.source_type
  const sourcePeer = sourceType === 'peer' ? getPeerFromSelection(formData.source_id) : null
  const canEnableForward = (sourceType === 'peer' && sourcePeer && !sourcePeer.is_manual) || (sourceType === 'group')

  // Compute whether the backward button should be enabled
  const targetType = formData.target_type
  const targetPeer = targetType === 'peer' ? getPeerFromSelection(formData.target_id) : null
  const canEnableBackward = (targetType === 'peer' && targetPeer && !targetPeer.is_manual) || (targetType === 'group')

  const polymorphicOptions = useMemo(() => [
    ...(groupList || []).map(g => ({ value: g.id, label: g.name, category: 'group' })),
    ...(peerList || []).flatMap(p => {
      const hasMultipleIPs = p.ips && p.ips.length > 1
      if (hasMultipleIPs) {
        return p.ips.map(peerIp => ({
          value: `peer:${p.id}:${peerIp.ip_address}`,
          label: `${p.hostname || p.ip_address} - ${peerIp.ip_address}`,
          category: 'peer',
        }))
      }
      return [{
        value: p.id,
        label: p.hostname || p.ip_address,
        category: 'peer',
      }]
    }),
    ...(specialTargetList || []).map(s => ({ value: s.id, label: s.display_name, category: 'special' })),
  ], [groupList, peerList, specialTargetList])

  const serviceOptions = useMemo(() => (serviceList || []).map(s => ({
    value: s.id,
    label: s.name,
    category: s.is_system ? 'System Services' : 'User Services',
  })), [serviceList])

  if (!isOpen) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" tabIndex="-1" onKeyDown={(e) => { if (e.key === 'Escape') { onClose() } }}>
      <div ref={modalRef} className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-2xl mx-4 flex flex-col max-h-[90vh]">
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">{editItem ? 'Edit Policy' : 'New Policy'}</h3>
          <button type="button" onClick={onClose} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none">
            <X className="w-5 h-5 text-gray-400" />
          </button>
        </div>
        <div className="flex border-b border-gray-200 dark:border-gray-border shrink-0">
          <button type="button" onClick={() => setActiveTab('setup')} className={`flex-1 px-4 py-3 text-sm font-medium transition-colors ${activeTab === 'setup' ? 'text-purple-active border-b-2 border-purple-active' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}>Setup</button>
          <button type="button" onClick={() => setActiveTab('preview')} className={`flex-1 px-4 py-3 text-sm font-medium transition-colors ${activeTab === 'preview' ? 'text-purple-active border-b-2 border-purple-active' : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'}`}>Preview</button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {activeTab === 'setup' && (
            <form id="policy-form" onSubmit={onSubmit} className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="col-span-2 sm:col-span-1">
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Name</label>
                  <input autoFocus type="text" value={formData.name} onChange={e => setFormData(d => ({ ...d, name: e.target.value }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-active" />
                </div>
                <div className="col-span-2 sm:col-span-1">
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Priority</label>
                  <input type="number" value={formData.priority} onChange={e => setFormData(d => ({ ...d, priority: e.target.value === '' ? '' : parseInt(e.target.value, 10) }))} required className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-purple-active" />
                </div>
              </div>
              <div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
                <button
                  type="button"
                  onClick={() => setShowDescription(!showDescription)}
                  className="w-full px-4 py-3 flex items-center justify-between bg-gray-50 dark:bg-charcoal-darkest hover:bg-gray-100 dark:hover:bg-charcoal-dark transition-colors"
                >
                  <span className="text-sm font-medium text-gray-700 dark:text-amber-primary">Description (Optional)</span>
                  <svg className={`w-4 h-4 text-gray-500 transition-transform duration-150 ${showDescription ? 'rotate-180' : ''}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                <div className={`transition-all duration-150 ease-in-out ${showDescription ? 'max-h-32 opacity-100' : 'max-h-0 opacity-0'} overflow-hidden`}>
                  <div className="p-4">
                    <textarea
                      value={formData.description}
                      onChange={e => setFormData(d => ({ ...d, description: e.target.value }))}
                      rows={2}
                      className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-white"
                      placeholder="Add a description for this policy..."
                    />
                  </div>
                </div>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-[1fr_auto_1fr] gap-x-4 gap-y-4 items-end">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Source</label>
                  <div title={isSpecialService ? "IGMP/VRRP are host-level protocols — source is not used" : undefined} className={isSpecialService ? 'opacity-50' : ''}>
                    <SearchableSelect options={polymorphicOptions} value={formData.source_id} category={formData.source_type} onChange={(v, type) => {
                      const isComposite = typeof v === 'string' && v.startsWith('peer:')
                      const compositeType = isComposite ? 'peer' : type
                      const newSourceIp = isComposite ? '' : (compositeType === 'peer' ? '' : '')
                      setFormData(d => ({ ...d, source_id: v, source_type: compositeType || 'group', source_ip: newSourceIp }))
                    }} placeholder="Select group or peer" disabled={isSpecialService} />
                  </div>
                </div>
                <div className="flex flex-col items-center justify-end gap-1.5 pb-0.5">
                  <div className="flex flex-col gap-1.5">
                    <button
                      type="button"
                      onClick={() => {
                        if (formData.direction === 'forward' || isSpecialService) return
                        setFormData(d => ({
                          ...d,
                          direction: d.direction === 'both' ? 'backward' : (d.direction === 'backward' ? 'both' : 'forward'),
                        }))
                      }}
                      disabled={isSpecialService || !canEnableForward}
                      className={`flex items-center justify-center w-28 h-8 rounded-none border-2 transition-all duration-200 ${
                        formData.direction === 'both' || formData.direction === 'forward'
                          ? 'bg-emerald-900/80 border-emerald-500 text-emerald-400 hover:bg-emerald-800/80'
                          : 'bg-gray-200 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-400 dark:text-gray-500 hover:bg-gray-300 dark:hover:bg-gray-700'
                      } ${isSpecialService || !canEnableForward ? 'opacity-50 cursor-not-allowed' : ''}`}
                      title={isSpecialService ? "IGMP/VRRP generate OUTPUT rules automatically — direction is fixed" : (!canEnableForward ? (formData.source_id ? "Cannot push rules from manual peer" : "Select a source peer first") : "Forward: Source → Target")}
                    >
                      <svg viewBox="0 0 80 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-16 h-4">
                        <line x1="8" y1="12" x2="66" y2="12" />
                        <polyline points="58,6 66,12 58,18" />
                      </svg>
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (formData.direction === 'backward' || isSpecialService) return
                        setFormData(d => ({
                          ...d,
                          direction: d.direction === 'both' ? 'forward' : (d.direction === 'forward' ? 'both' : 'backward'),
                        }))
                      }}
                      disabled={isSpecialService || !canEnableBackward}
                      className={`flex items-center justify-center w-28 h-8 rounded-none border-2 transition-all duration-200 ${
                        formData.direction === 'both' || formData.direction === 'backward'
                          ? 'bg-blue-900/80 border-blue-500 text-blue-400 hover:bg-blue-800/80'
                          : 'bg-gray-200 dark:bg-gray-800 border-gray-300 dark:border-gray-600 text-gray-400 dark:text-gray-500 hover:bg-gray-300 dark:hover:bg-gray-700'
                      } ${isSpecialService || !canEnableBackward ? 'opacity-50 cursor-not-allowed' : ''}`}
                      title={isSpecialService ? "IGMP/VRRP generate OUTPUT rules automatically — direction is fixed" : (!canEnableBackward ? (formData.target_id ? "Cannot push rules to manual peer" : "Select a target peer first") : "Backward: Target → Source")}
                    >
                      <svg viewBox="0 0 80 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="w-16 h-4">
                        <line x1="72" y1="12" x2="14" y2="12" />
                        <polyline points="22,6 14,12 22,18" />
                      </svg>
                    </button>
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Target</label>
                  <SearchableSelect options={polymorphicOptions} value={formData.target_id} category={formData.target_type} onChange={(v, type) => {
                    const isComposite = typeof v === 'string' && v.startsWith('peer:')
                    const compositeType = isComposite ? 'peer' : type
                    const newTargetIp = isComposite ? '' : (compositeType === 'peer' ? '' : '')
                    setFormData(d => ({ ...d, target_id: v, target_type: compositeType || 'peer', target_ip: newTargetIp }))
                  }} placeholder="Select group or peer" />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Service</label>
                  <SearchableSelect options={serviceOptions} value={formData.service_id} onChange={v => {
                    const serviceName = serviceList?.find(s => s.id === v)?.name?.toUpperCase()
                    const isSpecialSvc = serviceName === 'IGMP' || serviceName === 'VRRP'
                    setFormData(d => ({
                      ...d,
                      service_id: v,
                      source_id: isSpecialSvc ? SPECIAL_TARGETS.ALL_HOSTS.id : '',
                      source_type: isSpecialSvc ? 'special' : 'group',
                      source_ip: isSpecialSvc ? '' : '',
                    }))
                  }} placeholder="Select service" />
                </div>
                <div>{/* spacer */}</div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Action</label>
                  <div className="flex gap-4 pt-2">
                    <label className="flex items-center gap-2 cursor-pointer group">
                      <input type="radio" name="action" value="ACCEPT" checked={formData.action === 'ACCEPT'} onChange={e => setFormData(d => ({ ...d, action: e.target.value }))} className="text-purple-active focus:ring-purple-active bg-white dark:bg-charcoal-dark border-gray-300 dark:border-gray-border" />
                      <span className="text-sm text-green-700 dark:text-green-400 font-medium group-hover:opacity-80">ACCEPT</span>
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer group">
                      <input type="radio" name="action" value="LOG_DROP" checked={formData.action === 'LOG_DROP'} onChange={e => setFormData(d => ({ ...d, action: e.target.value }))} className="text-purple-active focus:ring-purple-active bg-white dark:bg-charcoal-dark border-gray-300 dark:border-gray-border" />
                      <span className="text-sm text-red-700 dark:text-red-400 font-medium group-hover:opacity-80">LOG+DROP</span>
                    </label>
                  </div>
                </div>
              </div>
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary">Applies To</label>
                  <span className="text-xs text-gray-500 dark:text-amber-muted">(Docker Integration)</span>
                  {isIGMPService && <span className="text-xs text-blue-600 dark:text-blue-400 ml-1">— &quot;Host Only&quot; is typical for IGMP</span>}
                  {isVRRPService && <span className="text-xs text-blue-600 dark:text-blue-400 ml-1">— &quot;Host Only&quot; is typical for VRRP</span>}
                </div>
                <div className="flex bg-gray-100 dark:bg-charcoal-darkest p-1 rounded-none border border-gray-200 dark:border-gray-border">
                  <button
                    type="button"
                    onClick={() => setFormData(d => ({ ...d, target_scope: 'both' }))}
                    className={`flex-1 py-1.5 text-xs font-medium rounded-none transition-all duration-200 ${
                      formData.target_scope === 'both' || !formData.target_scope
                        ? 'bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white ring-1 ring-black/5 dark:ring-white/10'
                        : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50'
                    }`}
                  >
                    Host + Docker
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormData(d => ({ ...d, target_scope: 'host' }))}
                    className={`flex-1 py-1.5 text-xs font-medium rounded-none transition-all duration-200 ${
                      formData.target_scope === 'host'
                        ? 'bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white ring-1 ring-black/5 dark:ring-white/10'
                        : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50'
                    }`}
                  >
                    Host Only
                  </button>
                  <button
                    type="button"
                    onClick={() => setFormData(d => ({ ...d, target_scope: 'docker' }))}
                    className={`flex-1 py-1.5 text-xs font-medium rounded-none transition-all duration-200 ${
                      formData.target_scope === 'docker'
                        ? 'bg-white dark:bg-charcoal-dark text-gray-900 dark:text-white ring-1 ring-black/5 dark:ring-white/10'
                        : 'text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300 hover:bg-white/50 dark:hover:bg-charcoal-dark/50'
                    }`}
                  >
                    Docker Only
                  </button>
                </div>
              </div>

              <div className="p-4 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border rounded-none">
                <div className="flex items-center justify-between">
                  <div>
                    <label id="policy-enabled-label" className="text-sm font-medium text-gray-900 dark:text-light-neutral">Policy enabled</label>
                    <p className="text-xs text-gray-500 dark:text-amber-muted mt-0.5">When disabled, this policy will not generate any firewall rules until re-enabled.</p>
                  </div>
                  <ToggleSwitch checked={formData.enabled} onChange={v => setFormData(d => ({ ...d, enabled: v }))} aria-labelledby="policy-enabled-label" />
                </div>
              </div>

              <InlineError message={formErrors._general} />
            </form>
          )}
          {activeTab === 'preview' && (
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <h4 className="text-sm font-medium text-gray-700 dark:text-amber-primary">Generated Rules</h4>
                <button type="button" onClick={onPreview} disabled={previewLoading} className="flex items-center gap-2 text-sm text-purple-active hover:opacity-80">
                  <RefreshCw className={`w-4 h-4 ${previewLoading ? 'animate-spin' : ''}`} />
                  Refresh
                </button>
              </div>
              {previewLoading && !preview && (
                <div className="flex items-center justify-center py-8">
                  <RefreshCw className="w-6 h-6 animate-spin text-purple-active" />
                  <span className="ml-2 text-sm text-gray-500">Generating preview...</span>
                </div>
              )}
              {preview && (
                <div className="p-3 bg-gray-900 dark:bg-charcoal-darkest rounded-none text-xs font-mono border border-gray-800 max-h-96 overflow-y-auto">
                  {preview.rules?.map((rule, i) => (
                    <p key={i} className="text-green-400 whitespace-pre-wrap">{rule}</p>
                  ))}
                  {!preview.rules?.length && <p className="text-gray-500 italic">No rules generated for this orientation.</p>}
                </div>
              )}
              {!previewLoading && !preview && (
                <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                  <Eye className="w-8 h-8 mx-auto mb-2 opacity-50" />
                  <p className="text-sm">Select source, service, and target to preview rules</p>
                </div>
              )}
            </div>
          )}
        </div>
        <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-end gap-3 shrink-0 bg-white dark:bg-charcoal-dark rounded-none">
          <button type="button" onClick={onClose} className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-none hover:bg-gray-50 dark:hover:bg-charcoal-darkest">Cancel</button>
          <button type="submit" form="policy-form" disabled={activeTab !== 'setup'} className="px-4 py-2 text-sm font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none transition-colors disabled:opacity-50 disabled:cursor-not-allowed border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all">{editItem ? 'Save Changes' : 'Create Policy'}</button>
        </div>
      </div>
    </div>
  )
}
