import { useState, useCallback } from 'react'
import { Copy, Check } from 'lucide-react'

/**
 * CopyButton - A button that copies text to clipboard with visual feedback.
 * Shows a checkmark icon briefly after successful copy.
 */
export default function CopyButton({ text, label = 'Copy' }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {
      // Clipboard API not available
    }
  }, [text])

  return (
    <button
      onClick={handleCopy}
      className="p-1 hover:bg-gray-100 dark:hover:bg-charcoal-darkest rounded-none transition-colors"
      aria-label={copied ? 'Copied' : label}
    >
      {copied ? (
        <Check className="w-4 h-4 text-green-500" />
      ) : (
        <Copy className="w-4 h-4 text-gray-400" />
      )}
    </button>
  )
}
