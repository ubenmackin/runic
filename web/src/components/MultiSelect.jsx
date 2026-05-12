import { useState, useRef, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { ChevronDown, Check, Search } from 'lucide-react'

export default function MultiSelect({
  options = [],
  values = [],
  onChange,
  placeholder = 'Select...',
  disabled = false,
  showCountBadge = false, // If true, show count badge; if false, show comma-separated labels
}) {
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

  const ESTIMATED_DROPDOWN_HEIGHT = 350

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

  const selectedOptions = options.filter(o => values.includes(o.value))
  const isAllSelected = filtered.length > 0 && filtered.every(opt => values.includes(opt.value))

  // Get display text for the button
  const getDisplayText = () => {
    if (selectedOptions.length === 0) return placeholder
    if (showCountBadge) {
      return `${selectedOptions.length} selected`
    }
    // Show comma-separated labels (truncate if too long)
    const labels = selectedOptions.map(o => o.label).join(', ')
    return labels.length > 30 ? labels.substring(0, 30) + '...' : labels
  }

  const handleToggle = (value) => {
    if (disabled) return
    const newValues = values.includes(value)
      ? values.filter(v => v !== value)
      : [...values, value]
    onChange(newValues)
  }

  const handleSelectAll = () => {
    if (disabled) return
    // Only select filtered options when search is active
    const filteredValues = filtered.map(opt => opt.value)
    if (isAllSelected) {
      // Deselect all filtered
      onChange(values.filter(v => !filteredValues.includes(v)))
    } else {
      // Select all filtered (union with existing non-filtered)
      const nonFilteredSelected = values.filter(v => !filteredValues.includes(v))
      onChange([...nonFilteredSelected, ...filteredValues])
    }
  }

  const handleClearAll = () => {
    if (disabled) return
    // Only clear filtered options when search is active
    const filteredValues = filtered.map(opt => opt.value)
    onChange(values.filter(v => !filteredValues.includes(v)))
  }

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
          handleToggle(filtered[activeIndex].value)
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
        <div className="flex items-center gap-2 flex-1 min-w-0">
          {showCountBadge && selectedOptions.length > 0 && (
            <span className="inline-flex items-center justify-center min-w-[20px] h-5 px-1.5 text-xs font-semibold bg-purple-active text-white rounded-none">
              {selectedOptions.length}
            </span>
          )}
          <span className={`truncate ${selectedOptions.length > 0 ? 'text-gray-900 dark:text-light-neutral' : 'text-gray-500'}`}>
            {getDisplayText()}
          </span>
        </div>
        <ChevronDown className="w-4 h-4 text-gray-400 shrink-0 ml-2" />
      </button>
      {open && createPortal(
        <div
          ref={dropdownRef}
          role="listbox"
          aria-multiselectable="true"
          style={{ position: 'absolute', top: dropdownPos.top, left: dropdownPos.left, width: dropdownPos.width }}
          className="z-[9999] bg-white dark:bg-charcoal-dark border border-gray-200 dark:border-gray-border rounded-none shadow-none"
        >
          {/* Search input */}
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

          {/* Select All / Clear All buttons */}
          <div className="flex border-b border-gray-200 dark:border-gray-border">
            <button
              type="button"
              onClick={handleSelectAll}
              disabled={disabled}
              className="flex-1 px-3 py-2 text-xs font-medium text-purple-active hover:bg-purple-50 dark:hover:bg-purple-active/10 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {isAllSelected ? 'Deselect All' : 'Select All'}
            </button>
            <div className="w-px bg-gray-200 dark:bg-gray-border" />
            <button
              type="button"
              onClick={handleClearAll}
              disabled={disabled || values.length === 0}
              className="flex-1 px-3 py-2 text-xs font-medium text-gray-600 dark:text-amber-muted hover:bg-gray-100 dark:hover:bg-charcoal-darkest disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Clear All
            </button>
          </div>

          {/* Options list */}
          <div className="max-h-60 overflow-y-auto">
            {filtered.length === 0 ? (
              <p className="px-3 py-2 text-sm text-gray-500">No options found</p>
            ) : (
              filtered.map((opt, index) => (
                <button
                  key={opt.value}
                  ref={(el) => { optionRefs.current[index] = el }}
                  role="option"
                  aria-selected={values.includes(opt.value)}
                  onKeyDown={handleKeyDown}
                  onClick={() => { handleToggle(opt.value); setActiveIndex(-1) }}
                  className={`w-full flex items-center gap-3 px-3 py-2 text-left ${
                    index === activeIndex
                      ? 'bg-purple-active/10 text-purple-active'
                      : 'hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
                  }`}
                >
                  {/* Checkbox */}
                  <span className={`w-4 h-4 border flex items-center justify-center ${values.includes(opt.value) ? 'bg-purple-active border-purple-active' : 'border-gray-300 dark:border-gray-500 bg-white dark:bg-charcoal-dark'}`}>
                    {values.includes(opt.value) && (
                      <Check className="w-3 h-3 text-white" />
                    )}
                  </span>
                  <span className="text-sm text-gray-900 dark:text-light-neutral flex-1">{opt.label}</span>
                </button>
              ))
            )}
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}
