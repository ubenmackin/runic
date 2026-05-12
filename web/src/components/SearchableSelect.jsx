import { useState, useRef, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { ChevronDown, Check, Search } from 'lucide-react'

export default function SearchableSelect({ options = [], value, category, onChange, placeholder = 'Select...', disabled = false }) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [dropdownPos, setDropdownPos] = useState({ top: 0, left: 0, width: 0 })
  const [activeIndex, setActiveIndex] = useState(-1)
  const ref = useRef(null)
  const dropdownRef = useRef(null)
  const optionRefs = useRef([])

  useEffect(() => {
    const handler = (e) => {
      if (ref.current && !ref.current.contains(e.target) && (!dropdownRef.current || !dropdownRef.current.contains(e.target))) setOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const ESTIMATED_DROPDOWN_HEIGHT = 300

  const getDropdownPosition = () => {
    if (!ref.current) return { top: 0, left: 0, width: 0, positionAbove: false }
    const rect = ref.current.getBoundingClientRect()
    const spaceBelow = window.innerHeight - rect.bottom
    const spaceAbove = rect.top
    const positionAbove = spaceBelow < ESTIMATED_DROPDOWN_HEIGHT && spaceAbove > spaceBelow
    return {
      top: positionAbove
        ? rect.top + window.scrollY - ESTIMATED_DROPDOWN_HEIGHT
        : rect.bottom + window.scrollY,
      left: rect.left + window.scrollX,
      width: rect.width,
      positionAbove
    }
  }

  useEffect(() => {
    if (open && ref.current) {
      setDropdownPos(getDropdownPosition())
    }
  }, [open])

  useEffect(() => {
    if (!open) return
    const updatePosition = () => {
      if (ref.current) {
        setDropdownPos(getDropdownPosition())
      }
    }
    window.addEventListener('scroll', updatePosition, true)
    window.addEventListener('resize', updatePosition)
    return () => {
      window.removeEventListener('scroll', updatePosition, true)
      window.removeEventListener('resize', updatePosition)
    }
  }, [open])

  const filtered = options.filter(opt => 
    opt.label.toLowerCase().includes(search.toLowerCase())
  )

  const selected = options.find(o => o.value === value && (category ? o.category === category : true))

  const handleKeyDown = (e) => {
    if (!open) {
      if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
        e.preventDefault()
        setOpen(true)
        setActiveIndex(0)
      }
      return
    }

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault()
        setActiveIndex((prev) => (prev < filtered.length - 1 ? prev + 1 : 0))
        break
      case 'ArrowUp':
        e.preventDefault()
        setActiveIndex((prev) => (prev > 0 ? prev - 1 : filtered.length - 1))
        break
      case 'Enter':
        e.preventDefault()
        if (activeIndex >= 0 && activeIndex < filtered.length) {
          const opt = filtered[activeIndex]
          onChange(opt.value, opt.category)
          setOpen(false)
          setSearch('')
          setActiveIndex(-1)
        }
        break
      case 'Escape':
        e.preventDefault()
        setOpen(false)
        setActiveIndex(-1)
        break
    }
  }

  // Scroll active option into view
  useEffect(() => {
    if (activeIndex >= 0 && optionRefs.current[activeIndex]) {
      optionRefs.current[activeIndex].scrollIntoView({ block: 'nearest' })
    }
  }, [activeIndex])

  return (
    <div className="relative" ref={ref}>
      <button
        type="button"
        onClick={() => !disabled && setOpen(!open)}
        onKeyDown={handleKeyDown}
        disabled={disabled}
        aria-haspopup="listbox"
        aria-expanded={open}
        className={`w-full flex items-center justify-between px-3 py-2 text-left bg-white dark:bg-charcoal-dark border border-gray-300 dark:border-gray-border rounded-none hover:border-purple-active focus:outline-none focus:ring-2 focus:ring-purple-active ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
      >
        <span className={selected ? 'text-gray-900 dark:text-light-neutral' : 'text-gray-500'}>
          {selected?.label || placeholder}
        </span>
        <ChevronDown className="w-4 h-4 text-gray-400" />
      </button>
      {open && createPortal(
        <div
          ref={dropdownRef}
          role="listbox"
          style={{ position: 'absolute', top: dropdownPos.top, left: dropdownPos.left, width: dropdownPos.width }}
          className="z-[9999] bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border rounded-none shadow-none"
        >
          <div className="p-2 border-b border-gray-200 dark:border-gray-border">
            <div className="flex items-center gap-2 px-2">
              <Search className="w-4 h-4 text-gray-400" />
              <input
                type="text"
                value={search}
                onChange={e => !disabled && setSearch(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Search..."
                disabled={disabled}
                className="flex-1 text-sm bg-transparent border-none outline-none text-gray-900 dark:text-light-neutral placeholder-gray-400 disabled:cursor-not-allowed"
                autoFocus
              />
            </div>
          </div>
          <div className="max-h-60 overflow-y-auto">
            {filtered.length === 0 ? (
              <p className="px-3 py-2 text-sm text-gray-500">No options found</p>
            ) : (
              (() => {
                const groups = filtered.reduce((acc, opt) => {
                  const cat = opt.category || 'Other'
                  if (!acc[cat]) acc[cat] = []
                  acc[cat].push(opt)
                  return acc
                }, {})

                let globalIndex = -1
                optionRefs.current = []

                return Object.entries(groups).map(([cat, opts]) => (
                  <div key={cat}>
                    <div className="px-3 py-1 text-[11px] font-bold uppercase tracking-wider text-gray-400 bg-gray-50 dark:bg-charcoal-darkest border-y border-gray-200 dark:border-gray-border first:border-t-0">
                      {cat}
                    </div>
                    {opts.map((opt) => {
                      globalIndex++
                      const idx = globalIndex
                      return (
                        <button
                          key={opt.value}
                          ref={(el) => { optionRefs.current[idx] = el }}
                          role="option"
                          aria-selected={opt.value === value && (!category || opt.category === category)}
                          onKeyDown={handleKeyDown}
                          onClick={() => { onChange(opt.value, opt.category); setOpen(false); setSearch(''); setActiveIndex(-1) }}
                          className={`w-full flex items-center justify-between px-3 py-2 text-left ${
                            idx === activeIndex
                              ? 'bg-purple-active/10 text-purple-active'
                              : 'hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
                          }`}
                        >
                          <span className="text-sm text-gray-900 dark:text-light-neutral">{opt.label}</span>
                          {opt.value === value && (!category || opt.category === category) && <Check className="w-4 h-4 text-purple-active" />}
                        </button>
                      )
                    })}
                  </div>
                ))
              })()
            )}
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}
