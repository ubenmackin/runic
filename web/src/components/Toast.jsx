import { AlertCircle, CheckCircle } from 'lucide-react'

export default function Toast({ toast }) {
  if (!toast) return null

  const isError = toast.type === 'error'
  const bgColor = isError ? 'bg-red-500' : 'bg-green-500'
  const Icon = isError ? AlertCircle : CheckCircle

  return (
    <div className={`fixed bottom-4 right-4 z-50 flex items-center gap-2 px-4 py-3 rounded-none shadow-none text-white text-sm ${bgColor}`}>
      <Icon className="w-4 h-4 flex-shrink-0" />
      <span>{toast.message}</span>
    </div>
  )
}
