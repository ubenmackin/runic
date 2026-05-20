import { useState } from 'react'
import { Plus, X, RefreshCw } from 'lucide-react'

// Filter to IPv4 only — Runic is IPv4-only for firewall management
const isIPv4 = (ip) => !ip.includes(':')

export default function IPManager({
  peerId,
  isManual,
  ips,
  loading,
  onAddIP,
  onDeleteIP,
  agentVersion,
  latestAgentVersion,
  isAgentOutdated,
}) {
  const [newIpAddress, setNewIpAddress] = useState('')
  const [ipAdding, setIpAdding] = useState(false)
  const [ipDeleting, setIpDeleting] = useState(null)

  const handleAddIP = async () => {
    if (!peerId || !newIpAddress.trim()) return
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/
    if (!ipRegex.test(newIpAddress.trim())) return
    setIpAdding(true)
    try {
      await onAddIP(peerId, newIpAddress.trim())
      setNewIpAddress('')
    } catch {
      // Error handled by parent
    } finally {
      setIpAdding(false)
    }
  }

  const handleDeleteIP = async (ipId) => {
    setIpDeleting(ipId)
    try {
      await onDeleteIP(peerId, ipId)
    } catch {
      // Error handled by parent
    } finally {
      setIpDeleting(null)
    }
  }

  // Agent peer IPs (read-only)
  if (!isManual) {
    return (
      <div>
        {agentVersion !== undefined && (
          <div className="mb-3">
            <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-1">Agent Version</label>
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm text-gray-700 dark:text-amber-primary">v{agentVersion}</span>
              {isAgentOutdated && (
                <span className="px-1.5 py-0.5 text-[10px] font-mono font-medium border border-amber-400 dark:border-amber-500 text-amber-600 dark:text-amber-400">
                  v{latestAgentVersion} available
                </span>
              )}
            </div>
          </div>
        )}
        <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-2">IP Addresses</label>
        {loading ? (
          <div className="flex items-center gap-2 py-2">
            <RefreshCw className="w-3 h-3 animate-spin text-gray-400" />
            <span className="text-sm text-gray-500 dark:text-amber-muted">Loading IPs...</span>
          </div>
        ) : ips && ips.length > 0 ? (
          <div className="space-y-1">
            {ips.filter(ip => isIPv4(ip.ip_address)).map(ip => (
              <div key={ip.id} className="flex items-center gap-2 px-2 py-1.5 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border">
                <span className="font-mono text-sm text-gray-700 dark:text-amber-primary flex-1">{ip.ip_address}</span>
                {ip.is_primary && (
                  <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 border border-purple-400 dark:border-purple-500 text-purple-600 dark:text-purple-400">PRIMARY</span>
                )}
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-gray-400 dark:text-amber-muted py-1">No IP addresses detected</p>
        )}
        <p className="text-xs text-gray-500 dark:text-amber-muted mt-1 italic">
          Agent IPs are auto-detected and cannot be manually managed.
        </p>
      </div>
    )
  }

  // Manual peer IP management
  return (
    <div>
      <label className="block text-sm font-medium text-gray-700 dark:text-amber-primary mb-2">Secondary IP Addresses</label>
      {loading ? (
        <div className="flex items-center gap-2 py-2">
          <RefreshCw className="w-3 h-3 animate-spin text-gray-400" />
          <span className="text-sm text-gray-500 dark:text-amber-muted">Loading IPs...</span>
        </div>
      ) : (
        <div className="space-y-2">
          {ips && ips.length > 0 ? (
            <div className="space-y-1">
              {ips.filter(ip => isIPv4(ip.ip_address)).map(ip => (
                <div key={ip.id} className="flex items-center gap-2 px-2 py-1.5 bg-gray-50 dark:bg-charcoal-darkest border border-gray-200 dark:border-gray-border">
                  <span className="font-mono text-sm text-gray-700 dark:text-amber-primary flex-1">{ip.ip_address}</span>
                  {ip.is_primary ? (
                    <span className="text-[10px] font-mono font-medium px-1.5 py-0.5 border border-purple-400 dark:border-purple-500 text-purple-600 dark:text-purple-400">PRIMARY</span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => handleDeleteIP(ip.id)}
                      disabled={ipDeleting === ip.id}
                      className="p-1 hover:bg-red-100 dark:hover:bg-red-900/20 rounded-none disabled:opacity-50"
                      title="Remove IP address"
                    >
                      {ipDeleting === ip.id ? (
                        <RefreshCw className="w-3.5 h-3.5 text-red-500 animate-spin" />
                      ) : (
                        <X className="w-3.5 h-3.5 text-red-500" />
                      )}
                    </button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-sm text-gray-400 dark:text-amber-muted py-1">No additional IP addresses</p>
          )}
          <div className="flex gap-2">
            <input
              type="text"
              value={newIpAddress}
              onChange={e => setNewIpAddress(e.target.value)}
              placeholder="e.g., 10.20.10.20"
              className="flex-1 px-3 py-1.5 text-sm border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral placeholder-gray-400 dark:placeholder-amber-muted focus:ring-2 focus:ring-purple-active focus:border-transparent"
              onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); handleAddIP() } }}
            />
            <button
              type="button"
              onClick={handleAddIP}
              disabled={ipAdding || !newIpAddress.trim()}
              className="px-3 py-1.5 text-xs font-bold uppercase text-white bg-purple-active hover:bg-purple-600 rounded-none disabled:opacity-50 flex items-center gap-1 border border-purple-active/20 transition-all shrink-0"
            >
              {ipAdding ? (
                <RefreshCw className="w-3 h-3 animate-spin" />
              ) : (
                <Plus className="w-3 h-3" />
              )}
              Add IP
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
