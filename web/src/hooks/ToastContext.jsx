import { createContext, useContext } from 'react'
import Toast from '../components/Toast'
import { useToast } from './useToast'

const ToastContext = createContext(null)

export function useToastContext() {
  return useContext(ToastContext)
}

export function ToastProvider({ children }) {
  const { toast, showToast } = useToast()

  return (
    <ToastContext.Provider value={showToast}>
      {children}
      <Toast toast={toast} />
    </ToastContext.Provider>
  )
}
