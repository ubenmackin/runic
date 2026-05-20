import { createContext, useContext } from 'react'
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

  return (
    <ToastContext.Provider value={showToast}>
      {children}
      {toasts.map((toast, index) => (
        <Toast key={toast.id} toast={toast} index={index} />
      ))}
    </ToastContext.Provider>
  )
}
