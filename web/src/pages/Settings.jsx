import { Settings as SettingsIcon } from 'lucide-react'

export default function Settings() {
  // TODO: Add loading state: const { isLoading, error, data } = useQuery(...)
  // TODO: Handle error states with error message display

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Settings</h1>
        <p className="text-gray-600 dark:text-amber-muted">Configure your Runic installation</p>
      </div>

      <div className="bg-white dark:bg-charcoal-dark rounded-lg shadow p-6 text-center text-gray-500 dark:text-amber-muted">
        <SettingsIcon className="w-12 h-12 mx-auto mb-4 opacity-50" />
        <p>Settings configuration will be implemented here.</p>
        <p className="text-sm mt-2">This page is a placeholder for future settings options.</p>
      </div>
    </div>
  )
}
