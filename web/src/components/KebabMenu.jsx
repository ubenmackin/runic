import { useState, useRef, useEffect } from 'react'
import { MoreVertical } from 'lucide-react'
import PropTypes from 'prop-types'

export default function KebabMenu({ items, className = '' }) {
  const [isOpen, setIsOpen] = useState(false)
  const menuRef = useRef(null)
  const triggerRef = useRef(null)

  // Filter items based on `show` prop (default to true if not provided)
  const visibleItems = items.filter((item) => item.show !== false)

  // Close menu on click outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (
        menuRef.current &&
        !menuRef.current.contains(event.target) &&
        triggerRef.current &&
        !triggerRef.current.contains(event.target)
      ) {
        setIsOpen(false)
      }
    }

    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside)
    }

    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
    }
  }, [isOpen])

  // Close menu on Escape key
  useEffect(() => {
    const handleKeyDown = (event) => {
      if (event.key === 'Escape' && isOpen) {
        setIsOpen(false)
        triggerRef.current?.focus()
      }
    }

    if (isOpen) {
      document.addEventListener('keydown', handleKeyDown)
    }

    return () => {
      document.removeEventListener('keydown', handleKeyDown)
    }
  }, [isOpen])

  const handleToggle = () => {
    setIsOpen((prev) => !prev)
  }

  const handleItemClick = (item) => {
    if (item.disabled) return
    item.onClick()
    setIsOpen(false)
  }

  return (
    <div className="relative inline-block">
      <button
        ref={triggerRef}
        type="button"
        onClick={handleToggle}
        aria-expanded={isOpen}
        aria-haspopup="menu"
        aria-label="Open menu"
        className={`
          flex items-center justify-center
          w-11 h-11 min-w-[44px] min-h-[44px]
          text-gray-500 dark:text-gray-400
          hover:bg-gray-100 dark:hover:bg-charcoal-darkest
          rounded-lg
          transition-colors
          focus:outline-none focus:ring-2 focus:ring-purple-active focus:ring-offset-2
          dark:focus:ring-offset-charcoal-dark
          ${className}
        `}
        data-testid="kebab-menu-trigger"
      >
        <MoreVertical className="w-5 h-5" />
      </button>

      {isOpen && (
        <div
          ref={menuRef}
          role="menu"
          aria-orientation="vertical"
          className={`
            absolute right-0 z-50
            min-w-[160px]
            bg-white dark:bg-charcoal-dark
            border border-gray-200 dark:border-gray-border
            rounded-lg shadow-lg
            py-1
            focus:outline-none
          `}
          data-testid="kebab-menu-dropdown"
        >
          {visibleItems.map((item, index) => {
            const Icon = item.icon
            const isDisabled = item.disabled
            const isDanger = item.danger

            return (
              <button
                key={index}
                type="button"
                role="menuitem"
                disabled={isDisabled}
                onClick={() => handleItemClick(item)}
                className={`
                  w-full
                  flex items-center gap-3
                  px-4 py-3
                  text-sm text-left
                  transition-colors
                  ${
                    isDisabled
                      ? 'text-gray-400 dark:text-gray-600 cursor-not-allowed'
                      : isDanger
                        ? 'text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20'
                        : 'text-gray-700 dark:text-light-neutral hover:bg-gray-100 dark:hover:bg-charcoal-darkest'
                  }
                `}
                data-testid={`menu-item-${index}`}
              >
                {Icon && (
                  <Icon
                    className={`w-4 h-4 shrink-0 ${
                      isDisabled
                        ? 'text-gray-400 dark:text-gray-600'
                        : isDanger
                          ? 'text-red-600 dark:text-red-400'
                          : 'text-gray-500 dark:text-gray-400'
                    }`}
                  />
                )}
                <span>{item.label}</span>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}

KebabMenu.propTypes = {
  items: PropTypes.arrayOf(
    PropTypes.shape({
      label: PropTypes.string.isRequired,
      icon: PropTypes.elementType,
      onClick: PropTypes.func.isRequired,
      disabled: PropTypes.bool,
      show: PropTypes.bool,
      danger: PropTypes.bool,
    })
  ).isRequired,
  className: PropTypes.string,
}
