import { Plus } from 'lucide-react'

export default function EmptyState({ icon: Icon, title, message, action, onAction }) {
  return (
    <div className="flex flex-col items-center justify-center py-12 px-4 text-center">
      {Icon && (
        <div className="w-16 h-16 mb-4 rounded-none bg-gray-100 dark:bg-charcoal-dark flex items-center justify-center">
          <Icon className="w-8 h-8 text-gray-400" />
        </div>
      )}
      <h3 className="text-lg font-medium text-gray-900 dark:text-light-neutral mb-1">{title}</h3>
      <p className="text-sm text-gray-500 dark:text-amber-muted mb-4 max-w-sm">{message}</p>
      {action && onAction && (
        <button
          onClick={onAction}
          className="inline-flex items-center gap-2 px-4 py-2 bg-purple-active hover:bg-purple-700 text-white text-sm font-medium rounded-none"
        >
          <Plus className="w-4 h-4" />
          {action}
        </button>
      )}
    </div>
  )
}
