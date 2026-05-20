import ReactDOM from 'react-dom'
import { X } from 'lucide-react'
import { useFocusTrap } from '../hooks/useFocusTrap'
import { useRef } from 'react'

export default function ConfirmModal({ title, message, onConfirm, onCancel, danger = false }) {
  const modalRef = useRef(null)
  useFocusTrap(modalRef, true)

  const modalContent = (
    <div 
      ref={modalRef} 
      className="fixed inset-0 z-[9999] flex items-center justify-center bg-black/50"
      onKeyDown={(e) => { if (e.key === 'Escape') { e.stopPropagation(); onCancel(); } }}
    >
      <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none w-full max-w-md mx-4 overflow-hidden">
        <div className="flex items-center justify-between p-4 border-b border-gray-200 dark:border-gray-border">
          <h3 className="text-lg font-semibold text-gray-900 dark:text-light-neutral">{title}</h3>
          <button onClick={onCancel} className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded" aria-label="Close modal">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-4">
          <p className="text-gray-600 dark:text-amber-primary">{message}</p>
        </div>
        <div className="flex justify-end gap-3 p-4 border-t border-gray-200 dark:border-gray-border bg-gray-50 dark:bg-charcoal-darkest">
        <button
          onClick={onCancel}
          className="px-4 py-2 text-sm font-medium text-gray-700 dark:text-amber-primary bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-none hover:bg-gray-50 dark:hover:bg-charcoal-darkest"
        >
          Cancel
        </button>
        <button
          onClick={onConfirm}
          className={`px-4 py-2 text-sm font-medium text-white rounded-none ${
            danger
              ? 'bg-red-600 hover:bg-red-700'
              : 'bg-purple-active hover:bg-purple-600 text-white text-[10px] font-bold uppercase px-4 py-2.5 border border-purple-active/20 shadow-[0_0_15px_rgba(159,79,248,0.2)] transition-all'
          }`}
        >
            Confirm
          </button>
        </div>
      </div>
    </div>
  )
  
  return ReactDOM.createPortal(modalContent, document.body)
}