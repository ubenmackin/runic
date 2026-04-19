import { useState, useEffect, useCallback, useRef } from 'react'
import ReactDOM from 'react-dom'
import { X, ChevronLeft, ChevronRight, Check, Loader2, Server, Package, Shield, AlertCircle } from 'lucide-react'
import { api, QUERY_KEYS } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useQueryClient } from '@tanstack/react-query'
import InlineError from '../components/InlineError'
import ToggleSwitch from '../components/ToggleSwitch'
import SearchableSelect from '../components/SearchableSelect'

const OS_OPTIONS = [
  { value: 'debian', label: 'Debian' },
  { value: 'ubuntu', label: 'Ubuntu' },
  { value: 'rhel', label: 'RHEL' },
  { value: 'arch', label: 'Arch' },
  { value: 'opensuse', label: 'openSUSE' },
  { value: 'raspbian', label: 'Raspbian' },
  { value: 'linux', label: 'Generic Linux' },
]

const ARCH_OPTIONS = [
  { value: 'amd64', label: 'amd64' },
  { value: 'arm64', label: 'arm64' },
  { value: 'arm', label: 'arm' },
  { value: 'armv6', label: 'armv6' },
]

const PROTOCOL_OPTIONS = [
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'both', label: 'TCP+UDP' },
]

// Step indicators component
function StepIndicators({ currentStep }) {
  const steps = [
    { key: 'peer', label: 'Peer', icon: Server },
    { key: 'service', label: 'Service', icon: Package },
    { key: 'policy', label: 'Policy', icon: Shield },
    { key: 'review', label: 'Review', icon: Check },
  ]

  const currentIndex = steps.findIndex(s => s.key === currentStep)

  return (
    <div className="flex items-center justify-center gap-2 mb-6">
      {steps.map((step, idx) => {
        const Icon = step.icon
        const isActive = step.key === currentStep
        const isCompleted = idx < currentIndex

        return (
          <div key={step.key} className="flex items-center">
            <div
              className={`
                flex items-center justify-center w-8 h-8 rounded-none text-sm font-medium
                ${isActive
                  ? 'bg-purple-active text-white'
                  : isCompleted
                    ? 'bg-green-500 text-white'
                    : 'bg-gray-200 dark:bg-charcoal-darkest text-gray-500 dark:text-amber-muted'
                }
              `}
            >
              {isCompleted ? <Check className="w-4 h-4" /> : <Icon className="w-4 h-4" />}
            </div>
            <span
              className={`
                ml-1.5 text-xs font-medium
                ${isActive ? 'text-purple-active' : 'text-gray-500 dark:text-amber-muted'}
              `}
            >
              {step.label}
            </span>
            {idx < steps.length - 1 && (
              <div
                className={`
                  w-8 h-0.5 mx-2
                  ${idx < currentIndex ? 'bg-green-500' : 'bg-gray-200 dark:bg-charcoal-darkest'}
                `}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}

// Peer Step Component
function PeerStep({
  externalIP,
  existingPeer,
  setExistingPeer: _setExistingPeer,
  newPeer,
  setNewPeer,
  peerLoading,
  peerError,
  createNewPeerMode,
  setCreateNewPeerMode,
  formErrors,
}) {
  const handleNewPeerChange = (field, value) => {
    setNewPeer(prev => ({ ...prev, [field]: value }))
  }

  if (peerLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-8 space-y-3">
        <Loader2 className="w-6 h-6 text-purple-active animate-spin" />
        <p className="text-sm text-gray-500 dark:text-amber-muted">Looking up peer by IP...</p>
      </div>
    )
  }

  if (peerError && !createNewPeerMode) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-none">
          <AlertCircle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          <p className="text-sm text-amber-700 dark:text-amber-300">
            No existing peer found for IP <span className="font-mono font-medium">{externalIP}</span>
          </p>
        </div>
        <p className="text-sm text-gray-600 dark:text-amber-muted">
          Create a new manual peer entry for this IP address.
        </p>

        {/* New Peer Form */}
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Hostname <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newPeer.hostname}
              onChange={e => handleNewPeerChange('hostname', e.target.value)}
              placeholder="Enter hostname"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
            />
            {formErrors.hostname && <InlineError message={formErrors.hostname} />}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              IP Address <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newPeer.ip_address}
              disabled
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-gray-100 dark:bg-charcoal-darkest text-gray-500 dark:text-amber-muted cursor-not-allowed"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                OS Type
              </label>
              <SearchableSelect
                options={OS_OPTIONS}
                value={newPeer.os_type}
                onChange={v => handleNewPeerChange('os_type', v)}
                placeholder="Select OS..."
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
                Architecture
              </label>
              <SearchableSelect
                options={ARCH_OPTIONS}
                value={newPeer.arch}
                onChange={v => handleNewPeerChange('arch', v)}
                placeholder="Select arch..."
              />
            </div>
          </div>
        </div>

        <InlineError message={formErrors._general} />
      </div>
    )
  }

  if (existingPeer && !createNewPeerMode) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-none">
          <Check className="w-4 h-4 text-green-600 dark:text-green-400" />
          <p className="text-sm text-green-700 dark:text-green-300">
            Found existing peer: <span className="font-medium">{existingPeer.hostname}</span> ({existingPeer.ip_address})
          </p>
        </div>

        <div className="p-3 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border rounded-none">
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Hostname:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">{existingPeer.hostname}</span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">IP Address:</span>
              <span className="ml-2 font-mono text-gray-900 dark:text-light-neutral">{existingPeer.ip_address}</span>
            </div>
            {existingPeer.os_type && (
              <div>
                <span className="text-gray-500 dark:text-amber-muted">OS:</span>
                <span className="ml-2 text-gray-900 dark:text-light-neutral">{existingPeer.os_type}</span>
              </div>
            )}
          </div>
        </div>

        <button
          type="button"
          onClick={() => setCreateNewPeerMode(true)}
          className="text-sm text-purple-active hover:underline"
        >
          Create a new peer instead
        </button>
      </div>
    )
  }

  // Create new peer mode
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-600 dark:text-amber-muted">
          Creating a new manual peer for IP <span className="font-mono font-medium">{externalIP}</span>
        </p>
        {existingPeer && (
          <button
            type="button"
            onClick={() => setCreateNewPeerMode(false)}
            className="text-sm text-purple-active hover:underline"
          >
            Use existing peer instead
          </button>
        )}
      </div>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Hostname <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={newPeer.hostname}
            onChange={e => handleNewPeerChange('hostname', e.target.value)}
            placeholder="Enter hostname"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
          />
          {formErrors.hostname && <InlineError message={formErrors.hostname} />}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            IP Address <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={newPeer.ip_address}
            disabled
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-gray-100 dark:bg-charcoal-darkest text-gray-500 dark:text-amber-muted cursor-not-allowed"
          />
        </div>

        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              OS Type
            </label>
            <SearchableSelect
              options={OS_OPTIONS}
              value={newPeer.os_type}
              onChange={v => handleNewPeerChange('os_type', v)}
              placeholder="Select OS..."
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Architecture
            </label>
            <SearchableSelect
              options={ARCH_OPTIONS}
              value={newPeer.arch}
              onChange={v => handleNewPeerChange('arch', v)}
              placeholder="Select arch..."
            />
          </div>
        </div>
      </div>

      <InlineError message={formErrors._general} />
    </div>
  )
}

// Service Step Component
function ServiceStep({
  port,
  protocol,
  existingService,
  setExistingService: _setExistingService,
  newService,
  setNewService,
  serviceLoading,
  serviceError,
  formErrors,
}) {
  const handleNewServiceChange = (field, value) => {
    setNewService(prev => ({ ...prev, [field]: value }))
  }

  if (serviceLoading) {
    return (
      <div className="flex flex-col items-center justify-center py-8 space-y-3">
        <Loader2 className="w-6 h-6 text-purple-active animate-spin" />
        <p className="text-sm text-gray-500 dark:text-amber-muted">Looking up service by port...</p>
      </div>
    )
  }

  if (serviceError && !existingService) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 p-3 bg-amber-50 dark:bg-amber-900/20 border border-amber-200 dark:border-amber-800 rounded-none">
          <AlertCircle className="w-4 h-4 text-amber-600 dark:text-amber-400" />
          <p className="text-sm text-amber-700 dark:text-amber-300">
            No existing service found for port <span className="font-mono font-medium">{port}/{protocol}</span>
          </p>
        </div>
        <p className="text-sm text-gray-600 dark:text-amber-muted">
          Create a new service for this port.
        </p>

        {/* New Service Form */}
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Name <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newService.name}
              onChange={e => handleNewServiceChange('name', e.target.value)}
              placeholder="e.g., Web Server, Database"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
            />
            {formErrors.name && <InlineError message={formErrors.name} />}
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Protocol
            </label>
            <SearchableSelect
              options={PROTOCOL_OPTIONS}
              value={newService.protocol}
              onChange={v => handleNewServiceChange('protocol', v)}
              placeholder="Select protocol..."
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
              Destination Ports <span className="text-red-500">*</span>
            </label>
            <input
              type="text"
              value={newService.ports}
              onChange={e => handleNewServiceChange('ports', e.target.value)}
              placeholder="e.g., 443 or 80,443 or 8000:9000"
              className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
            />
            <p className="text-xs text-gray-500 dark:text-amber-muted mt-1">
              Single port, comma-separated, or range (e.g., 443, 80,443, or 8000:9000)
            </p>
            {formErrors.ports && <InlineError message={formErrors.ports} />}
          </div>
        </div>

        <InlineError message={formErrors._general} />
      </div>
    )
  }

  if (existingService) {
    return (
      <div className="space-y-4">
        <div className="flex items-center gap-2 p-3 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 rounded-none">
          <Check className="w-4 h-4 text-green-600 dark:text-green-400" />
          <p className="text-sm text-green-700 dark:text-green-300">
            Found existing service: <span className="font-medium">{existingService.name}</span> ({existingService.protocol}:{existingService.ports})
          </p>
        </div>

        <div className="p-3 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border rounded-none">
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Name:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">{existingService.name}</span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Protocol:</span>
              <span className="ml-2 text-gray-900 dark:text-light-neutral uppercase">{existingService.protocol}</span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Ports:</span>
              <span className="ml-2 font-mono text-gray-900 dark:text-light-neutral">:{existingService.ports}</span>
            </div>
          </div>
        </div>

        <p className="text-xs text-gray-500 dark:text-amber-muted">
          This service is already defined and will be used for the policy.
        </p>
      </div>
    )
  }

  return null
}

// Editable Field Component for Source/Target/Service/Direction
function EditableField({
  label,
  displayValue,
  autoDetectedValue,
  isEditing,
  onEditClick,
  onRevert,
  children,
  hasOverride
}) {
  return (
    <div className="flex items-center justify-between py-2">
      <div className="flex items-center gap-2">
        <span className="text-gray-500 dark:text-amber-muted text-sm">{label}:</span>
        {hasOverride && (
          <span className="text-xs px-1.5 py-0.5 bg-purple-100 dark:bg-purple-900 text-purple-700 dark:text-purple-300 rounded-none">
            Custom
          </span>
        )}
      </div>
      <div className="flex items-center gap-2">
        {isEditing ? (
          <div className="flex items-center gap-2">
            <div className="w-48">{children}</div>
            <button
              type="button"
              onClick={onRevert}
              className="text-xs text-gray-500 hover:text-gray-700 dark:text-amber-muted dark:hover:text-amber-primary"
            >
              Revert
            </button>
          </div>
        ) : (
          <>
            <span className="font-medium text-gray-900 dark:text-light-neutral text-sm">
              {displayValue}
            </span>
            <button
              type="button"
              onClick={onEditClick}
              className="text-xs text-purple-active hover:underline"
            >
              Edit
            </button>
          </>
        )}
      </div>
      {!isEditing && autoDetectedValue && displayValue !== autoDetectedValue && (
        <span className="text-xs text-gray-400 dark:text-gray-500 ml-2">
          (Auto: {autoDetectedValue})
        </span>
      )}
    </div>
  )
}

// Policy Configuration Step Component
function PolicyStep({
  policyConfig,
  setPolicyConfig,
  sourcePeer,
  service,
  targetPeer,
  direction,
  formErrors,
  // Editable field props
  peerOptions = [],
  serviceOptions = [],
  directionOptions = [],
  selectedSourcePeerId,
  selectedTargetPeerId,
  selectedServiceId,
  selectedDirection,
  setSelectedSourcePeerId,
  setSelectedTargetPeerId,
  setSelectedServiceId,
  setSelectedDirection,
  editMode = { source: false, target: false, service: false, direction: false },
  toggleEditMode,
  revertToAutoDetected,
  _allPeers = [],
  _allServices = [],
  peersLoading = false,
  getSourceDisplay,
  getTargetDisplay,
  getServiceDisplay,
  getDirectionDisplay,
}) {
  // Get the original auto-detected values for comparison
  const autoDetectedSource = sourcePeer?.hostname || sourcePeer?.ip_address || 'Unknown'
  const autoDetectedTarget = targetPeer?.hostname || targetPeer?.ip_address || 'Unknown'
  const autoDetectedService = service ? `${service.name} (${service.protocol}:${service.ports})` : 'Unknown'
  const autoDetectedDirection = direction === 'OUT' ? 'Forward' : 'Backward'

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Policy Name <span className="text-red-500">*</span>
          </label>
          <input
            type="text"
            value={policyConfig.name}
            onChange={e => setPolicyConfig(prev => ({ ...prev, name: e.target.value }))}
            placeholder="Enter policy name"
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
          />
          {formErrors.name && <InlineError message={formErrors.name} />}
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
            Priority
          </label>
          <input
            type="number"
            value={policyConfig.priority}
            onChange={e => setPolicyConfig(prev => ({ ...prev, priority: parseInt(e.target.value) || 100 }))}
            className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
          />
        </div>
      </div>

      <div>
        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">
          Description
        </label>
        <textarea
          value={policyConfig.description}
          onChange={e => setPolicyConfig(prev => ({ ...prev, description: e.target.value }))}
          rows={2}
          placeholder="Optional description for this policy"
          className="w-full px-3 py-2 border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral"
        />
      </div>

      <div className="p-4 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border rounded-none">
        <h4 className="text-sm font-medium text-gray-700 dark:text-amber-primary mb-3">Policy Summary</h4>
        <div className="space-y-1">
          {/* Source Field */}
          <EditableField
            label="Source"
            displayValue={getSourceDisplay ? getSourceDisplay() : (autoDetectedSource)}
            autoDetectedValue={autoDetectedSource}
            isEditing={editMode.source}
            onEditClick={() => toggleEditMode('source')}
            onRevert={() => revertToAutoDetected('source')}
            hasOverride={!!selectedSourcePeerId}
          >
            {editMode.source && (
              <SearchableSelect
                options={peerOptions}
                value={selectedSourcePeerId}
                onChange={(val) => { setSelectedSourcePeerId(val); toggleEditMode('source') }}
                placeholder="Select source peer..."
                disabled={peersLoading}
              />
            )}
          </EditableField>

          {/* Target Field */}
          <EditableField
            label="Target"
            displayValue={getTargetDisplay ? getTargetDisplay() : (autoDetectedTarget)}
            autoDetectedValue={autoDetectedTarget}
            isEditing={editMode.target}
            onEditClick={() => toggleEditMode('target')}
            onRevert={() => revertToAutoDetected('target')}
            hasOverride={!!selectedTargetPeerId}
          >
            {editMode.target && (
              <SearchableSelect
                options={peerOptions}
                value={selectedTargetPeerId}
                onChange={(val) => { setSelectedTargetPeerId(val); toggleEditMode('target') }}
                placeholder="Select target peer..."
                disabled={peersLoading}
              />
            )}
          </EditableField>

          {/* Service Field */}
          <EditableField
            label="Service"
            displayValue={getServiceDisplay ? getServiceDisplay() : (autoDetectedService)}
            autoDetectedValue={autoDetectedService}
            isEditing={editMode.service}
            onEditClick={() => toggleEditMode('service')}
            onRevert={() => revertToAutoDetected('service')}
            hasOverride={!!selectedServiceId}
          >
            {editMode.service && (
              <SearchableSelect
                options={serviceOptions}
                value={selectedServiceId}
                onChange={(val) => { setSelectedServiceId(val); toggleEditMode('service') }}
                placeholder="Select service..."
                disabled={peersLoading}
              />
            )}
          </EditableField>

          {/* Direction Field */}
          <EditableField
            label="Direction"
            displayValue={getDirectionDisplay ? getDirectionDisplay() : (autoDetectedDirection)}
            autoDetectedValue={autoDetectedDirection}
            isEditing={editMode.direction}
            onEditClick={() => toggleEditMode('direction')}
            onRevert={() => revertToAutoDetected('direction')}
            hasOverride={!!selectedDirection}
          >
            {editMode.direction && (
              <SearchableSelect
                options={directionOptions}
                value={selectedDirection}
                onChange={(val) => { setSelectedDirection(val); toggleEditMode('direction') }}
                placeholder="Select direction..."
              />
            )}
          </EditableField>

{/* Action - Read Only */}
<div className="flex justify-between py-2">
  <span className="text-gray-500 dark:text-amber-muted text-sm">Action:</span>
  <span className="px-2 py-0.5 text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300 rounded-none">
    ACCEPT
  </span>
</div>

{/* Target Scope - Read Only */}
<div className="flex justify-between py-2">
  <span className="text-gray-500 dark:text-amber-muted text-sm">Target Scope:</span>
  <span className="font-medium text-gray-900 dark:text-light-neutral text-sm">Host + Docker</span>
</div>
</div>
</div>

      <div className="flex items-center justify-between p-4 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border rounded-none">
        <div>
          <label className="text-sm font-medium text-gray-900 dark:text-light-neutral">Policy Enabled</label>
          <p className="text-xs text-gray-500 dark:text-amber-muted">
            When enabled, this policy will generate firewall rules.
          </p>
        </div>
        <ToggleSwitch
          checked={policyConfig.enabled}
          onChange={v => setPolicyConfig(prev => ({ ...prev, enabled: v }))}
        />
      </div>

      <InlineError message={formErrors._general} />
    </div>
  )
}

// Review Step Component
function ReviewStep({
  existingPeer,
  newPeer,
  createNewPeerMode,
  existingService,
  newService,
  policyConfig,
  sourcePeer,
  targetPeer,
  direction,
  // Override values
  selectedSourcePeerId,
  selectedTargetPeerId,
  selectedServiceId,
  selectedDirection,
  allPeers = [],
  allServices = [],
}) {
  const peerToShow = createNewPeerMode ? newPeer : (existingPeer || newPeer)
  const serviceToShow = existingService || newService

  // Get display values considering user overrides
  const getSourceDisplay = () => {
    if (selectedSourcePeerId) {
      const peer = allPeers.find(p => p.id === selectedSourcePeerId)
      return peer?.hostname || peer?.ip_address || '—'
    }
    return sourcePeer?.hostname || sourcePeer?.ip_address || '—'
  }

  const getTargetDisplay = () => {
    if (selectedTargetPeerId) {
      const peer = allPeers.find(p => p.id === selectedTargetPeerId)
      return peer?.hostname || peer?.ip_address || '—'
    }
    return targetPeer?.hostname || targetPeer?.ip_address || '—'
  }

  const getServiceDisplay = () => {
    if (selectedServiceId) {
      const svc = allServices.find(s => s.id === selectedServiceId)
      return svc ? `${svc.name} (${svc.protocol}:${svc.ports})` : '—'
    }
    return serviceToShow ? `${serviceToShow.name} (${serviceToShow.protocol}:${serviceToShow.ports})` : '—'
  }

  const getDirectionDisplay = () => {
    const effectiveDirection = selectedDirection || direction
    return effectiveDirection === 'OUT' ? 'Forward' : 'Backward'
  }

  return (
    <div className="space-y-4">
      {/* PEER Section */}
      <div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
        <div className="px-4 py-2 bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
          <h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral flex items-center gap-2">
            <Server className="w-4 h-4" />
            PEER {createNewPeerMode || !existingPeer ? '(New)' : '(Existing)'}
          </h4>
        </div>
        <div className="p-4 space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Hostname:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">
                {peerToShow?.hostname || '—'}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">IP Address:</span>
              <span className="ml-2 font-mono text-gray-900 dark:text-light-neutral">
                {peerToShow?.ip_address || '—'}
              </span>
            </div>
            {peerToShow?.os_type && (
              <div>
                <span className="text-gray-500 dark:text-amber-muted">OS:</span>
                <span className="ml-2 text-gray-900 dark:text-light-neutral">{peerToShow.os_type}</span>
              </div>
            )}
            {peerToShow?.arch && (
              <div>
                <span className="text-gray-500 dark:text-amber-muted">Architecture:</span>
                <span className="ml-2 text-gray-900 dark:text-light-neutral">{peerToShow.arch}</span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* SERVICE Section */}
      <div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
        <div className="px-4 py-2 bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
          <h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral flex items-center gap-2">
            <Package className="w-4 h-4" />
            SERVICE {existingService ? '(Existing)' : '(New)'}
          </h4>
        </div>
        <div className="p-4 space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Name:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">
                {serviceToShow?.name || '—'}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Protocol:</span>
              <span className="ml-2 text-gray-900 dark:text-light-neutral uppercase">
                {serviceToShow?.protocol || '—'}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Ports:</span>
              <span className="ml-2 font-mono text-gray-900 dark:text-light-neutral">
                :{serviceToShow?.ports || '—'}
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* POLICY Section */}
      <div className="border border-gray-200 dark:border-gray-border rounded-none overflow-hidden">
        <div className="px-4 py-2 bg-gray-50 dark:bg-charcoal-darkest border-b border-gray-200 dark:border-gray-border">
          <h4 className="text-sm font-medium text-gray-900 dark:text-light-neutral flex items-center gap-2">
            <Shield className="w-4 h-4" />
            POLICY
          </h4>
        </div>
        <div className="p-4 space-y-2 text-sm">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Name:</span>
              <span className="ml-2 font-medium text-gray-900 dark:text-light-neutral">
                {policyConfig?.name || '—'}
              </span>
            </div>
            <div>
              <span className="text-gray-500 dark:text-amber-muted">Priority:</span>
              <span className="ml-2 font-mono text-gray-900 dark:text-light-neutral">
                {policyConfig?.priority}
              </span>
            </div>
<div>
          <span className="text-gray-500 dark:text-amber-muted">Source:</span>
          <span className="ml-2 text-gray-900 dark:text-light-neutral">
            {getSourceDisplay()}
          </span>
        </div>
        <div>
          <span className="text-gray-500 dark:text-amber-muted">Target:</span>
          <span className="ml-2 text-gray-900 dark:text-light-neutral">
            {getTargetDisplay()}
          </span>
        </div>
        <div>
          <span className="text-gray-500 dark:text-amber-muted">Service:</span>
          <span className="ml-2 text-gray-900 dark:text-light-neutral">
            {getServiceDisplay()}
          </span>
        </div>
<div>
  <span className="text-gray-500 dark:text-amber-muted">Action:</span>
  <span className="ml-2 px-2 py-0.5 text-xs font-medium bg-green-100 text-green-700 dark:bg-green-900 dark:text-green-300 rounded-none">
    ACCEPT
  </span>
</div>
<div>
  <span className="text-gray-500 dark:text-amber-muted">Target Scope:</span>
  <span className="ml-2 text-gray-900 dark:text-light-neutral">Host + Docker</span>
</div>
<div>
  <span className="text-gray-500 dark:text-amber-muted">Direction:</span>
  <span className="ml-2 text-gray-900 dark:text-light-neutral">{getDirectionDisplay()}</span>
</div>
        <div>
          <span className="text-gray-500 dark:text-amber-muted">Enabled:</span>
              <span className={`ml-2 ${policyConfig?.enabled ? 'text-green-600 dark:text-green-400' : 'text-red-600 dark:text-red-400'}`}>
                {policyConfig?.enabled ? 'Yes' : 'No'}
              </span>
            </div>
          </div>
          {policyConfig?.description && (
            <div className="mt-2 pt-2 border-t border-gray-200 dark:border-gray-border">
              <span className="text-gray-500 dark:text-amber-muted">Description:</span>
              <p className="mt-1 text-gray-900 dark:text-light-neutral">{policyConfig.description}</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

export default function CraftPolicyWizard({ log, onClose, onSuccess }) {
  const qc = useQueryClient()
  const showToast = useToastContext()
  const modalRef = useRef(null)

  useFocusTrap(modalRef, true)

  // Parse log to extract direction, external IP, port, protocol
  const parseLog = useCallback((logEvent) => {
    if (!logEvent) return { direction: null, externalIP: '', port: 0, protocol: 'tcp' }

// Check for direction prefix in raw_line (e.g., "[RUNIC-DROP-I] " or "[RUNIC-DROP-O] ")
  const rawLine = logEvent.raw_line || ''
  let direction = logEvent.direction || null

  if (rawLine.includes('[RUNIC-DROP-I]')) {
    direction = 'IN'
  } else if (rawLine.includes('[RUNIC-DROP-O]')) {
    direction = 'OUT'
  }

    // Determine external IP and port based on direction
    let externalIP = ''
    let port = 0
    const protocol = logEvent.protocol?.toLowerCase() || 'tcp'

    if (direction === 'IN') {
      // Incoming traffic: source is external, destination is local
      externalIP = logEvent.src_ip || ''
      port = logEvent.dst_port || 0
} else if (direction === 'OUT') {
    // Outgoing traffic: destination is external, source is local
    externalIP = logEvent.dst_ip || ''
    port = logEvent.dst_port || 0
  } else {
      // Fallback: use src_ip as external
      externalIP = logEvent.src_ip || ''
      port = logEvent.dst_port || 0
    }

    return { direction, externalIP, port, protocol }
  }, [])

  const parsedLog = parseLog(log)

  // State machine: 'peer' | 'service' | 'policy' | 'review'
  const [step, setStep] = useState('peer')
  const direction = parsedLog.direction
  const externalIP = parsedLog.externalIP
  const port = parsedLog.port
  const protocol = parsedLog.protocol

  // User selections
  const [existingTargetPeer, setExistingTargetPeer] = useState(null) // External peer (target)
  const [newTargetPeer, setNewTargetPeer] = useState({ hostname: '', ip_address: parsedLog.externalIP, os_type: 'linux', arch: 'amd64' })
  const [existingSourcePeer, setExistingSourcePeer] = useState(null) // Local peer (source from log)
  const [existingService, setExistingService] = useState(null)
  const [newService, setNewService] = useState({ name: '', protocol: parsedLog.protocol, ports: String(parsedLog.port) })
  const [policyConfig, setPolicyConfig] = useState({
    name: '',
    priority: 100,
    enabled: true,
    description: ''
  })

  // UI state
  const [createTargetPeerMode, setCreateTargetPeerMode] = useState(false)
  const [targetPeerLoading, setTargetPeerLoading] = useState(true)
  const [targetPeerError, setTargetPeerError] = useState(null)
  const [_sourcePeerLoading, setSourcePeerLoading] = useState(true)
  const [_sourcePeerError, setSourcePeerError] = useState(null)
  const [serviceLoading, setServiceLoading] = useState(true)
  const [serviceError, setServiceError] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const [formErrors, setFormErrors] = useState({})

  // Editable selections for Source/Target/Service/Direction overrides
  const [selectedSourcePeerId, setSelectedSourcePeerId] = useState(null)
  const [selectedTargetPeerId, setSelectedTargetPeerId] = useState(null)
  const [selectedServiceId, setSelectedServiceId] = useState(null)
  const [selectedDirection, setSelectedDirection] = useState(null)
  const [editMode, setEditMode] = useState({
    source: false,
    target: false,
    service: false,
    direction: false
  })

  // All available peers and services for dropdown options
  const [allPeers, setAllPeers] = useState([])
  const [allServices, setAllServices] = useState([])
  const [peersLoading, setPeersLoading] = useState(true)

  // Fetch target peer by external IP on mount (Peer Step)
  useEffect(() => {
    if (!externalIP) {
      setTargetPeerLoading(false)
      setTargetPeerError({ message: 'No external IP found in log' })
      return
    }

    let isMounted = true

    const fetchTargetPeerByIP = async () => {
      setTargetPeerLoading(true)
      setTargetPeerError(null)
      try {
        const peer = await api.get(`/peers/by-ip?ip=${encodeURIComponent(externalIP)}`)
        if (isMounted) {
          setExistingTargetPeer(peer)
          setCreateTargetPeerMode(false)
        }
      } catch (err) {
        if (isMounted) {
          if (err.status === 404) {
            setTargetPeerError({ message: 'No peer found', status: 404 })
            setCreateTargetPeerMode(true)
            // Pre-fill hostname with a suggestion
            setNewTargetPeer(prev => ({
              ...prev,
              hostname: `peer-${externalIP.replace(/\./g, '-')}`,
              ip_address: externalIP
            }))
          } else {
            setTargetPeerError({ message: err.message })
          }
          setExistingTargetPeer(null)
        }
      } finally {
        if (isMounted) {
          setTargetPeerLoading(false)
        }
      }
    }

    fetchTargetPeerByIP()
    return () => {
      isMounted = false
    }
  }, [externalIP])

  // Fetch source peer by hostname or src_ip from log (local machine)
  useEffect(() => {
    const sourceIP = log?.src_ip
    const sourceHostname = log?.hostname

    if (!sourceIP && !sourceHostname) {
      setSourcePeerLoading(false)
      setSourcePeerError({ message: 'No source info found in log' })
      return
    }

    let isMounted = true

    const fetchSourcePeer = async () => {
      setSourcePeerLoading(true)
      setSourcePeerError(null)
try {
      // Try to find peer by hostname first, then by src_ip
      let peer = null
      if (sourceHostname) {
        try {
          // Use dedicated /by-hostname endpoint for exact match lookup
          peer = await api.get(`/peers/by-hostname?hostname=${encodeURIComponent(sourceHostname)}`)
        } catch {
          // Try by IP if hostname lookup fails
        }
      }
      if (!peer && sourceIP) {
        try {
          peer = await api.get(`/peers/by-ip?ip=${encodeURIComponent(sourceIP)}`)
        } catch {
          // Peer not found
        }
      }
        if (isMounted) {
          if (peer) {
            setExistingSourcePeer(peer)
          } else {
            // Create a placeholder for the local source peer (it might not exist in DB yet)
            setExistingSourcePeer({
              id: null,
              hostname: sourceHostname || `local-${sourceIP}`,
              ip_address: sourceIP
            })
          }
        }
      } catch (err) {
        if (isMounted) {
          setSourcePeerError({ message: err.message })
          // Still set a placeholder for the source peer
          setExistingSourcePeer({
            id: null,
            hostname: sourceHostname || `local-${sourceIP}`,
            ip_address: sourceIP
          })
        }
      } finally {
        if (isMounted) {
          setSourcePeerLoading(false)
        }
      }
    }

    fetchSourcePeer()
    return () => {
      isMounted = false
    }
  }, [log?.hostname, log?.src_ip])

  // Fetch service by port/protocol when entering service step
  useEffect(() => {
    if (step !== 'service') return
    if (!port) {
      setServiceLoading(false)
      setServiceError({ message: 'No port found in log' })
      return
    }

    let isMounted = true

    const fetchServiceByPort = async () => {
      setServiceLoading(true)
      setServiceError(null)
      try {
        const service = await api.get(`/services/by-port?port=${port}&protocol=${protocol}`)
        if (isMounted) {
          setExistingService(service)
        }
      } catch (err) {
        if (isMounted) {
          if (err.status === 404) {
            setServiceError({ message: 'No service found', status: 404 })
            setExistingService(null)
          } else {
            setServiceError({ message: err.message })
            setExistingService(null)
          }
        }
      } finally {
        if (isMounted) {
          setServiceLoading(false)
        }
      }
    }

    fetchServiceByPort()
    return () => {
      isMounted = false
    }
  }, [step, port, protocol])

  // Generate policy name when moving to policy step
  useEffect(() => {
    if (step === 'policy' && !policyConfig.name) {
      const targetPeerName = existingTargetPeer?.hostname || newTargetPeer.hostname || 'peer'
      const serviceName = existingService?.name || newService.name || 'service'
      const generatedName = `${targetPeerName}-${serviceName}`.toLowerCase().replace(/[^a-z0-9-]/g, '-').substring(0, 50)
      setPolicyConfig(prev => ({ ...prev, name: generatedName }))
    }
  }, [step, existingTargetPeer, newTargetPeer, existingService, newService, policyConfig.name])

  // Fetch all peers and services for dropdown options when entering policy step
  useEffect(() => {
    if (step !== 'policy') return

    let isMounted = true
    setPeersLoading(true)

    const fetchAllData = async () => {
      try {
        const [peersData, servicesData] = await Promise.all([
          api.get('/peers'),
          api.get('/services')
        ])
        if (isMounted) {
          setAllPeers(peersData || [])
          setAllServices(servicesData || [])
        }
      } catch (err) {
        if (isMounted) {
          console.error('Failed to fetch peers/services:', err)
        }
      } finally {
        if (isMounted) {
          setPeersLoading(false)
        }
      }
    }

    fetchAllData()
    return () => { isMounted = false }
  }, [step])

  // Convert peers to options format for SearchableSelect
  const peerOptions = allPeers.map(peer => ({
    value: peer.id,
    label: peer.hostname || peer.ip_address || 'Unknown',
    sublabel: peer.ip_address
  }))

  // Convert services to options format for SearchableSelect
  const serviceOptions = allServices.map(service => ({
    value: service.id,
    label: service.name,
    sublabel: `${service.protocol}:${service.ports}`
  }))

  // Direction options
  const directionOptions = [
    { value: 'OUT', label: 'Forward (OUT)' },
    { value: 'IN', label: 'Backward (IN)' }
  ]

  // Get display values for editable fields
  const getSourceDisplay = () => {
    if (selectedSourcePeerId) {
      const peer = allPeers.find(p => p.id === selectedSourcePeerId)
      return peer?.hostname || peer?.ip_address || 'Unknown'
    }
    return existingSourcePeer?.hostname || existingSourcePeer?.ip_address || 'Unknown'
  }

  const getTargetDisplay = () => {
    if (selectedTargetPeerId) {
      const peer = allPeers.find(p => p.id === selectedTargetPeerId)
      return peer?.hostname || peer?.ip_address || 'Unknown'
    }
    const target = createTargetPeerMode ? newTargetPeer : existingTargetPeer
    return target?.hostname || target?.ip_address || 'Unknown'
  }

  const getServiceDisplay = () => {
    if (selectedServiceId) {
      const svc = allServices.find(s => s.id === selectedServiceId)
      return svc ? `${svc.name} (${svc.protocol}:${svc.ports})` : 'Unknown'
    }
    const svc = existingService || newService
    return svc ? `${svc.name} (${svc.protocol}:${svc.ports})` : 'Unknown'
  }

  const getDirectionDisplay = () => {
    if (selectedDirection) {
      return selectedDirection === 'OUT' ? 'Forward' : 'Backward'
    }
    return direction === 'OUT' ? 'Forward' : 'Backward'
  }

  // Helper to toggle edit mode for a field
  const toggleEditMode = (field) => {
    setEditMode(prev => ({ ...prev, [field]: !prev[field] }))
  }

  // Helper to revert to auto-detected value
  const revertToAutoDetected = (field) => {
    switch (field) {
      case 'source':
        setSelectedSourcePeerId(null)
        break
      case 'target':
        setSelectedTargetPeerId(null)
        break
      case 'service':
        setSelectedServiceId(null)
        break
      case 'direction':
        setSelectedDirection(null)
        break
    }
    setEditMode(prev => ({ ...prev, [field]: false }))
  }

  // Validation functions
  const validatePeerStep = useCallback(() => {
    const errors = {}
    if (createTargetPeerMode || !existingTargetPeer) {
      if (!newTargetPeer.hostname?.trim()) {
        errors.hostname = 'Hostname is required'
      }
      if (!newTargetPeer.ip_address?.trim()) {
        errors.ip_address = 'IP Address is required'
      }
    }
    setFormErrors(errors)
    return Object.keys(errors).length === 0
  }, [createTargetPeerMode, existingTargetPeer, newTargetPeer])

  const validateServiceStep = useCallback(() => {
    const errors = {}
    if (!existingService) {
      if (!newService.name?.trim()) {
        errors.name = 'Service name is required'
      }
      if (!newService.ports?.trim()) {
        errors.ports = 'Ports are required'
      }
    }
    setFormErrors(errors)
    return Object.keys(errors).length === 0
  }, [existingService, newService])

  const validatePolicyStep = useCallback(() => {
    const errors = {}
    if (!policyConfig.name?.trim()) {
      errors.name = 'Policy name is required'
    }
    setFormErrors(errors)
    return Object.keys(errors).length === 0
  }, [policyConfig])

  // Navigation handlers
  const handleBack = () => {
    setFormErrors({})
    switch (step) {
      case 'service':
        setStep('peer')
        break
      case 'policy':
        setStep('service')
        break
      case 'review':
        setStep('policy')
        break
    }
  }

  const handleNext = () => {
    switch (step) {
      case 'peer':
        if (validatePeerStep()) {
          setStep('service')
        }
        break
      case 'service':
        if (validateServiceStep()) {
          setStep('policy')
        }
        break
      case 'policy':
        if (validatePolicyStep()) {
          setStep('review')
        }
        break
    }
  }

// Submit handler
  const handleSubmit = async () => {
    setSubmitting(true)
    setFormErrors({})

// Track newly created resources for cleanup on failure
  let createdSourcePeerId = null
  let createdTargetPeerId = null
  let createdServiceId = null

try {
    // Source is the local peer from the log, Target is the external peer
    // Use user-selected overrides if provided, otherwise use auto-detected values
    let sourcePeerId = selectedSourcePeerId || existingSourcePeer?.id
    let targetPeerId = selectedTargetPeerId || existingTargetPeer?.id
    let serviceId = selectedServiceId || existingService?.id
    const policyDirection = selectedDirection || direction

    // Step 0: Create source peer (local machine) if needed
    // Only create if no existing peer and user hasn't selected an override
    if (!selectedSourcePeerId && !existingSourcePeer?.id) {
      const createdSourcePeer = await api.post('/peers', {
        hostname: existingSourcePeer.hostname,
        ip_address: existingSourcePeer.ip_address,
        os_type: null,
        arch: null,
        is_manual: true
      })
      sourcePeerId = createdSourcePeer.id
      createdSourcePeerId = createdSourcePeer.id // Track for potential cleanup
      showToast('Source peer created successfully', 'success')
    }

    // Step 1: Create target peer (external IP) if needed
    // Only create if no existing peer and user hasn't selected an override
    if (!selectedTargetPeerId && (!existingTargetPeer || createTargetPeerMode)) {
      const createdTargetPeer = await api.post('/peers', {
        hostname: newTargetPeer.hostname,
        ip_address: newTargetPeer.ip_address,
        os_type: newTargetPeer.os_type || null,
        arch: newTargetPeer.arch || null,
        is_manual: true
      })
      targetPeerId = createdTargetPeer.id
      createdTargetPeerId = createdTargetPeer.id // Track for potential cleanup
      showToast('Target peer created successfully', 'success')
    }

    // Step 2: Create service if needed
    // Only create if no existing service and user hasn't selected an override
    if (!selectedServiceId && !existingService) {
      const createdService = await api.post('/services', {
        name: newService.name,
        protocol: newService.protocol,
        ports: newService.ports
      })
      serviceId = createdService.id
      createdServiceId = createdService.id // Track for potential cleanup
      showToast('Service created successfully', 'success')
    }

    // Step 3: Create policy
    // Source = local peer (from log), Target = external peer
    await api.post('/policies', {
      name: policyConfig.name,
      description: policyConfig.description || null,
      source_id: sourcePeerId,
      source_type: 'peer',
      service_id: serviceId,
      target_id: targetPeerId,
      target_type: 'peer',
      action: 'ACCEPT',
      priority: policyConfig.priority,
      enabled: policyConfig.enabled,
      direction: policyDirection === 'OUT' ? 'forward' : 'backward',
      target_scope: 'both'
    })

showToast('Policy created successfully', 'success')

// Invalidate relevant queries
qc.invalidateQueries({ queryKey: QUERY_KEYS.peers() })
qc.invalidateQueries({ queryKey: QUERY_KEYS.services() })
qc.invalidateQueries({ queryKey: QUERY_KEYS.policies() })
qc.invalidateQueries({ queryKey: ['pending-changes'] })
qc.invalidateQueries({ queryKey: QUERY_KEYS.logs() })

onSuccess?.()
onClose?.()
} catch (err) {
    // Cleanup orphaned resources on failure
    const cleanupErrors = []
    if (createdServiceId) {
      try {
        await api.delete(`/services/${createdServiceId}`)
      } catch (cleanupErr) {
        cleanupErrors.push(`service: ${cleanupErr.message}`)
      }
    }
    if (createdTargetPeerId) {
      try {
        await api.delete(`/peers/${createdTargetPeerId}`)
      } catch (cleanupErr) {
        cleanupErrors.push(`target peer: ${cleanupErr.message}`)
      }
    }
    if (createdSourcePeerId) {
      try {
        await api.delete(`/peers/${createdSourcePeerId}`)
      } catch (cleanupErr) {
        cleanupErrors.push(`source peer: ${cleanupErr.message}`)
      }
    }

const cleanupMsg = cleanupErrors.length > 0
? ` Additionally, cleanup failed for: ${cleanupErrors.join(', ')}`
: ''
setFormErrors({ _general: err.message })
showToast(`Failed to create policy: ${err.message}${cleanupMsg}`, 'error')
} finally {
setSubmitting(false)
}
}

// Check if can proceed
  const canProceed = useCallback(() => {
    switch (step) {
    case 'peer':
      return !targetPeerLoading && (existingTargetPeer || newTargetPeer.hostname)
    case 'service':
      return !serviceLoading && (existingService || (newService.name && newService.ports))
    case 'policy':
      return !!policyConfig.name
    case 'review':
      return true
    default:
      return false
    }
  }, [step, targetPeerLoading, existingTargetPeer, newTargetPeer, serviceLoading, existingService, newService, policyConfig])

  const modalContent = (
    <div className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50">
      <div
        ref={modalRef}
        className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-2xl mx-4 max-h-[90vh] flex flex-col"
      >
        {/* Header */}
        <div className="px-6 py-4 border-b border-gray-200 dark:border-gray-border flex items-center justify-between shrink-0">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">
            Craft Policy from Log
          </h3>
          <button
            onClick={onClose}
            className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none"
          >
            <X className="w-5 h-5 text-gray-500" />
          </button>
        </div>

        {/* Step Indicators */}
        <div className="px-6 pt-4 shrink-0">
          <StepIndicators currentStep={step} />
        </div>

{/* Content */}
      <div className="flex-1 overflow-y-auto p-6">
      {step === 'peer' && (
        <PeerStep
          externalIP={externalIP}
          existingPeer={existingTargetPeer}
          setExistingPeer={setExistingTargetPeer}
          newPeer={newTargetPeer}
          setNewPeer={setNewTargetPeer}
          peerLoading={targetPeerLoading}
          peerError={targetPeerError}
          createNewPeerMode={createTargetPeerMode}
          setCreateNewPeerMode={setCreateTargetPeerMode}
          formErrors={formErrors}
        />
      )}

      {step === 'service' && (
        <ServiceStep
          port={port}
          protocol={protocol}
          existingService={existingService}
          setExistingService={setExistingService}
          newService={newService}
          setNewService={setNewService}
          serviceLoading={serviceLoading}
          serviceError={serviceError}
          formErrors={formErrors}
        />
      )}

      {step === 'policy' && (
        <PolicyStep
          policyConfig={policyConfig}
          setPolicyConfig={setPolicyConfig}
          sourcePeer={existingSourcePeer}
          service={existingService || newService}
          targetPeer={createTargetPeerMode ? newTargetPeer : existingTargetPeer}
          direction={direction}
          formErrors={formErrors}
          // Editable field props
          peerOptions={peerOptions}
          serviceOptions={serviceOptions}
          directionOptions={directionOptions}
          selectedSourcePeerId={selectedSourcePeerId}
          selectedTargetPeerId={selectedTargetPeerId}
          selectedServiceId={selectedServiceId}
          selectedDirection={selectedDirection}
          setSelectedSourcePeerId={setSelectedSourcePeerId}
          setSelectedTargetPeerId={setSelectedTargetPeerId}
          setSelectedServiceId={setSelectedServiceId}
          setSelectedDirection={setSelectedDirection}
          editMode={editMode}
          toggleEditMode={toggleEditMode}
          revertToAutoDetected={revertToAutoDetected}
          allPeers={allPeers}
          allServices={allServices}
          peersLoading={peersLoading}
          getSourceDisplay={getSourceDisplay}
          getTargetDisplay={getTargetDisplay}
          getServiceDisplay={getServiceDisplay}
          getDirectionDisplay={getDirectionDisplay}
        />
      )}

      {step === 'review' && (
        <ReviewStep
          existingPeer={existingTargetPeer}
          newPeer={newTargetPeer}
          createNewPeerMode={createTargetPeerMode}
          existingService={existingService}
          newService={newService}
          policyConfig={policyConfig}
          sourcePeer={existingSourcePeer}
          targetPeer={createTargetPeerMode ? newTargetPeer : existingTargetPeer}
          direction={direction}
          // Pass override values
          selectedSourcePeerId={selectedSourcePeerId}
          selectedTargetPeerId={selectedTargetPeerId}
          selectedServiceId={selectedServiceId}
          selectedDirection={selectedDirection}
          allPeers={allPeers}
          allServices={allServices}
        />
      )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-200 dark:border-gray-border flex justify-between shrink-0">
          <button
            type="button"
            onClick={handleBack}
            disabled={step === 'peer'}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-none ${
              step === 'peer'
                ? 'text-gray-300 dark:text-gray-600 cursor-not-allowed'
                : 'text-gray-700 dark:text-amber-primary hover:bg-gray-50 dark:hover:bg-charcoal-darkest'
            }`}
          >
            <ChevronLeft className="w-4 h-4" />
            Back
          </button>

          <div className="flex items-center gap-3">
            {step !== 'review' ? (
              <button
                type="button"
                onClick={handleNext}
                disabled={!canProceed()}
                className="flex items-center gap-2 px-4 py-2 text-sm font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                Next
                <ChevronRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                type="button"
                onClick={handleSubmit}
                disabled={submitting}
                className="flex items-center gap-2 px-4 py-2 text-sm font-bold uppercase text-white bg-green-600 hover:bg-green-700 rounded-none disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {submitting ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Creating...
                  </>
                ) : (
                  <>
                    <Check className="w-4 h-4" />
                    Create Policy
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  )

  return ReactDOM.createPortal(modalContent, document.body)
}
