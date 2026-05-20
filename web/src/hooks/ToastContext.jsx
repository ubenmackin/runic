import { createContext, useContext, useMemo } from 'react'
import Toast from '../components/Toast'
import { useToast } from './useToast'

const ToastContext = createContext(null)

export function useToastContext() {
  const context = useContext(ToastContext)
  if (context === null) {
    throw new Error('useToastContext must be used within a ToastProvider')
  }
  return context
}

export function ToastProvider({ children }) {
  const { toasts, showToast } = useToast()

  const value = useMemo(() => ({ showToast }), [showToast])

  return (
    <ToastContext.Provider value={value}>
      {children}
      {toasts.map((toast, index) => (
        <Toast key={toast.id} toast={toast} index={index} />
      ))}
    </ToastContext.Provider>
  )
}
