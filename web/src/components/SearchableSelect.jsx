import { useState, useRef, useEffect } from 'react'
import { ChevronDown, Check, Search } from 'lucide-react'

export default function SearchableSelect({ options = [], value, onChange, placeholder = 'Select...' }) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const ref = useRef(null)

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const filtered = options.filter(opt => 
    opt.label.toLowerCase().includes(search.toLowerCase())
  )

  const selected = options.find(o => o.value === value)

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-3 py-2 text-left bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-lg hover:border-purple-active focus:outline-none focus:ring-2 focus:ring-purple-active"
      >
        <span className={selected ? 'text-gray-900 dark:text-light-neutral' : 'text-gray-500'}>
          {selected?.label || placeholder}
        </span>
        <ChevronDown className="w-4 h-4 text-gray-400" />
      </button>
      {open && (
        <div className="absolute z-10 mt-1 w-full bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border rounded-lg shadow-lg">
          <div className="p-2 border-b border-gray-200 dark:border-gray-border">
            <div className="flex items-center gap-2 px-2">
              <Search className="w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search..."
                className="flex-1 text-sm bg-transparent border-none outline-none text-gray-900 dark:text-light-neutral placeholder-gray-400"
                autoFocus
              />
            </div>
          </div>
          <div className="max-h-60 overflow-y-auto">
            {filtered.length === 0 ? (
              <p className="px-3 py-2 text-sm text-gray-500">No options found</p>
            ) : (
              filtered.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => { onChange(opt.value); setOpen(false); setSearch('') }}
                  className="w-full flex items-center justify-between px-3 py-2 text-left hover:bg-gray-100 dark:hover:bg-charcoal-darkest"
                >
                  <span className="text-sm text-gray-900 dark:text-light-neutral">{opt.label}</span>
                  {opt.value === value && <Check className="w-4 h-4 text-purple-active" />}
                </button>
              ))
            )}
          </div>
        </div>
      )}
    </div>
  )
}
