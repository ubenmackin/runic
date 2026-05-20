import { AlertCircle, CheckCircle } from 'lucide-react'

export default function Toast({ toast, index = 0 }) {
  if (!toast) return null

  const isError = toast.type === 'error'
  const bgColor = isError ? 'bg-red-500' : 'bg-green-500'
  const Icon = isError ? AlertCircle : CheckCircle

  const bottomOffset = 16 + index * 56

  return (
    <div
      role="alert"
      aria-live="polite"
      className={`fixed right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-none shadow-none text-white text-sm ${bgColor}`}
      style={{ bottom: `${bottomOffset}px` }}
    >
      <Icon className="w-4 h-4 flex-shrink-0" />
      <span>{toast.message}</span>
    </div>
  )
}
