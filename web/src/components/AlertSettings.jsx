import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Bell, Settings, AlertTriangle, Loader2 } from 'lucide-react'
import { api, QUERY_KEYS, getAlertRules, updateAlertRule } from '../api/client'
import { useToastContext } from '../hooks/ToastContext'
import ToggleSwitch from './ToggleSwitch'

// Human-readable alert type labels
const ALERT_TYPE_LABELS = {
  bundle_deployed: 'Bundle Deployed',
  bundle_failed: 'Bundle Failed',
  peer_offline: 'Peer Offline',
  peer_online: 'Peer Online',
  blocked_spike: 'Blocked Traffic Spike',
  new_peer: 'New Peer Registered',
}

// Throttle options in minutes
const THROTTLE_OPTIONS = [1, 5, 15, 30, 60]

// Window options in minutes (for blocked_spike)
const WINDOW_OPTIONS = [1, 5, 15, 30, 60]

export default function AlertSettings() {
  const qc = useQueryClient()
  const showToast = useToastContext()

  // Fetch alert rules
  const { data: alertRules, isLoading: rulesLoading, error: rulesError } = useQuery({
    queryKey: QUERY_KEYS.alertRules(),
    queryFn: getAlertRules,
  })

  // Fetch peers for override dropdown
  const { data: peers } = useQuery({
    queryKey: QUERY_KEYS.peers(),
    queryFn: () => api.get('/peers'),
  })

  // Update alert rule mutation
  const mutation = useMutation({
    mutationFn: ({ id, data }) => updateAlertRule(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: QUERY_KEYS.alertRules() })
      showToast('Alert rule updated successfully', 'success')
    },
    onError: (err) => showToast(err.message, 'error'),
  })

  const handleUpdateRule = (ruleId, field, value) => {
    const rule = alertRules.find(r => r.id === ruleId)
    if (!rule) return

    const updatedData = {
      ...rule,
      [field]: value,
    }

    mutation.mutate({ id: ruleId, data: updatedData })
  }

  if (rulesLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-purple-active" />
        <span className="ml-2 text-gray-600 dark:text-amber-muted">Loading alert rules...</span>
      </div>
    )
  }

  if (rulesError) {
    return (
      <div className="flex items-center gap-2 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-none">
        <AlertTriangle className="w-5 h-5 text-red-500" />
        <span className="text-red-700 dark:text-red-400">Failed to load alert rules: {rulesError.message}</span>
      </div>
    )
  }

  const alertTypes = Object.keys(ALERT_TYPE_LABELS)

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Bell className="w-5 h-5 text-purple-500" />
        <h2 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">Alert Rules</h2>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-gray-200 dark:divide-gray-border">
          <thead className="bg-gray-50 dark:bg-charcoal-darkest">
            <tr>
<th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
Alert Type
</th>
<th className="px-4 py-1.5 text-center text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
Enabled
</th>
<th className="px-4 py-1.5 text-center text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
Threshold
</th>
<th className="px-4 py-1.5 text-center text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
Window (min)
</th>
<th className="px-4 py-1.5 text-center text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
Throttle (min)
</th>
<th className="px-4 py-1.5 text-left text-xs font-medium text-gray-500 dark:text-amber-muted uppercase tracking-wider">
                Peer Override
              </th>
            </tr>
          </thead>
          <tbody className="bg-white dark:bg-charcoal-dark divide-y divide-gray-200 dark:divide-gray-border">
            {alertTypes.map((alertType) => {
              const rule = alertRules?.find(r => r.alert_type === alertType)
              const isEnabled = rule?.enabled ?? false
              const threshold = rule?.threshold_value ?? 100
              const windowMin = rule?.threshold_window_minutes ?? 5
              const throttleMin = rule?.throttle_minutes ?? 5
              const peerOverride = rule?.peer_override_hostname ?? ''

              return (
<tr key={alertType} className="hover:bg-gray-50 dark:hover:bg-charcoal-darkest/50">
<td className="px-4 py-2 whitespace-nowrap">
<div className="flex items-center gap-2">
<Bell className="w-4 h-4 text-gray-400" />
<span className="text-sm font-medium text-gray-900 dark:text-light-neutral">
{ALERT_TYPE_LABELS[alertType]}
</span>
</div>
</td>
<td className="px-4 py-2 whitespace-nowrap text-center">
<div className="flex justify-center">
<ToggleSwitch
checked={isEnabled}
onChange={(checked) => handleUpdateRule(rule?.id, 'enabled', checked)}
disabled={mutation.isPending}
/>
</div>
</td>
<td className="px-4 py-2 whitespace-nowrap">
<div className="flex justify-center">
<input
type="number"
min="1"
max="99999"
value={threshold}
onChange={(e) => handleUpdateRule(rule?.id, 'threshold_value', parseInt(e.target.value) || 1)}
onBlur={() => handleUpdateRule(rule?.id, 'threshold_value', threshold)}
disabled={mutation.isPending || !rule}
className="w-20 px-2 py-1 text-center text-sm border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral disabled:opacity-50"
/>
</div>
</td>
<td className="px-4 py-2 whitespace-nowrap">
<div className="flex justify-center">
<select
value={windowMin}
onChange={(e) => handleUpdateRule(rule?.id, 'threshold_window_minutes', parseInt(e.target.value))}
disabled={mutation.isPending || !rule}
className="w-24 px-2 py-1 text-sm border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral disabled:opacity-50"
>
{WINDOW_OPTIONS.map(opt => (
<option key={opt} value={opt}>{opt}</option>
))}
</select>
</div>
</td>
<td className="px-4 py-2 whitespace-nowrap">
<div className="flex justify-center">
<select
value={throttleMin}
onChange={(e) => handleUpdateRule(rule?.id, 'throttle_minutes', parseInt(e.target.value))}
disabled={mutation.isPending || !rule}
className="w-24 px-2 py-1 text-sm border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral disabled:opacity-50"
>
{THROTTLE_OPTIONS.map(opt => (
<option key={opt} value={opt}>{opt}</option>
))}
</select>
</div>
</td>
<td className="px-4 py-2 whitespace-nowrap">
                    <select
                      value={peerOverride || ''}
                      onChange={(e) => handleUpdateRule(rule?.id, 'peer_override_hostname', e.target.value || null)}
                      disabled={mutation.isPending || !rule}
                      className="w-40 px-2 py-1 text-sm border border-gray-300 dark:border-gray-border rounded-none bg-white dark:bg-charcoal-darkest text-gray-900 dark:text-light-neutral disabled:opacity-50"
                    >
                      <option value="">All Peers</option>
                      {peers?.map(peer => (
                        <option key={peer.id} value={peer.hostname}>
                          {peer.hostname}
                        </option>
                      ))}
                    </select>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Info note */}
      <div className="flex items-start gap-2 p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-none">
        <Settings className="w-5 h-5 text-blue-500 mt-0.5" />
        <div className="text-sm text-blue-700 dark:text-blue-400">
          <p className="font-medium">Configuration Notes:</p>
          <ul className="list-disc list-inside mt-1 space-y-1">
            <li><strong>Threshold:</strong> Number of events required to trigger the alert</li>
            <li><strong>Window:</strong> Time period (minutes) over which to count events</li>
            <li><strong>Throttle:</strong> Minimum time between alert notifications</li>
            <li><strong>Peer Override:</strong> Limit alerts to a specific peer (optional)</li>
          </ul>
        </div>
      </div>
    </div>
  )
}