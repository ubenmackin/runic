import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { Pencil, Trash2, FileCode } from 'lucide-react'
import KebabMenu from './KebabMenu'

describe('KebabMenu', () => {
  const defaultItems = [
    { label: 'Edit', icon: Pencil, onClick: vi.fn() },
    { label: 'Delete', icon: Trash2, onClick: vi.fn(), danger: true },
    { label: 'View Rules', icon: FileCode, onClick: vi.fn() },
  ]

  beforeEach(() => {
    vi.clearAllMocks()
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  describe('rendering', () => {
    test('renders trigger button', () => {
      render(<KebabMenu items={defaultItems} />)

      expect(screen.getByTestId('kebab-menu-trigger')).toBeInTheDocument()
    })

    test('trigger button has correct accessibility attributes', () => {
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      expect(trigger).toHaveAttribute('aria-expanded', 'false')
      expect(trigger).toHaveAttribute('aria-haspopup', 'menu')
      expect(trigger).toHaveAttribute('aria-label', 'Open menu')
    })

    test('trigger button has 44x44px minimum touch target', () => {
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      expect(trigger.className).toContain('w-11')
      expect(trigger.className).toContain('h-11')
      expect(trigger.className).toContain('min-w-[44px]')
      expect(trigger.className).toContain('min-h-[44px]')
    })

    test('menu is not visible initially', () => {
      render(<KebabMenu items={defaultItems} />)

      expect(screen.queryByTestId('kebab-menu-dropdown')).not.toBeInTheDocument()
    })

    test('applies custom className to trigger', () => {
      render(<KebabMenu items={defaultItems} className="custom-class" />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      expect(trigger.className).toContain('custom-class')
    })
  })

  describe('menu open/close', () => {
    test('click opens menu', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      expect(screen.getByTestId('kebab-menu-dropdown')).toBeInTheDocument()
    })

    test('click toggles aria-expanded', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      expect(trigger).toHaveAttribute('aria-expanded', 'false')

      await user.click(trigger)
      expect(trigger).toHaveAttribute('aria-expanded', 'true')
    })

    test('click outside closes menu', async () => {
      const user = userEvent.setup()
      render(
        <div>
          <KebabMenu items={defaultItems} />
          <button data-testid="outside-button">Outside</button>
        </div>
      )

      // Open the menu
      await user.click(screen.getByTestId('kebab-menu-trigger'))
      expect(screen.getByTestId('kebab-menu-dropdown')).toBeInTheDocument()

      // Click outside
      await user.click(screen.getByTestId('outside-button'))
      expect(screen.queryByTestId('kebab-menu-dropdown')).not.toBeInTheDocument()
    })

    test('menu has correct ARIA attributes', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      const dropdown = screen.getByTestId('kebab-menu-dropdown')
      expect(dropdown).toHaveAttribute('role', 'menu')
      expect(dropdown).toHaveAttribute('aria-orientation', 'vertical')
    })
  })

  describe('item interactions', () => {
    test('item click calls onClick and closes menu', async () => {
      const user = userEvent.setup()
      const handleClick = vi.fn()
      const items = [
        { label: 'Edit', icon: Pencil, onClick: handleClick },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))
      await user.click(screen.getByTestId('menu-item-0'))

      expect(handleClick).toHaveBeenCalledTimes(1)
      expect(screen.queryByTestId('kebab-menu-dropdown')).not.toBeInTheDocument()
    })

    test('renders all items with labels', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      expect(screen.getByText('Edit')).toBeInTheDocument()
      expect(screen.getByText('Delete')).toBeInTheDocument()
      expect(screen.getByText('View Rules')).toBeInTheDocument()
    })

    test('renders items with icons', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      // Icons are rendered inside menu items
      const menuItems = screen.getAllByRole('menuitem')
      expect(menuItems).toHaveLength(3)
    })

    test('items have correct role', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      const menuItems = screen.getAllByRole('menuitem')
      expect(menuItems).toHaveLength(3)
    })
  })

  describe('conditional items', () => {
    test('items with show=true are visible', async () => {
      const user = userEvent.setup()
      const items = [
        { label: 'Edit', onClick: vi.fn(), show: true },
        { label: 'Delete', onClick: vi.fn(), show: true },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      expect(screen.getByText('Edit')).toBeInTheDocument()
      expect(screen.getByText('Delete')).toBeInTheDocument()
    })

    test('items with show=false are hidden', async () => {
      const user = userEvent.setup()
      const items = [
        { label: 'Edit', onClick: vi.fn(), show: true },
        { label: 'Delete', onClick: vi.fn(), show: false },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      expect(screen.getByText('Edit')).toBeInTheDocument()
      expect(screen.queryByText('Delete')).not.toBeInTheDocument()
    })

    test('items without show prop are visible by default', async () => {
      const user = userEvent.setup()
      const items = [
        { label: 'Edit', onClick: vi.fn() },
        { label: 'Delete', onClick: vi.fn() },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      expect(screen.getByText('Edit')).toBeInTheDocument()
      expect(screen.getByText('Delete')).toBeInTheDocument()
    })
  })

  describe('disabled items', () => {
    test('disabled items have disabled attribute', async () => {
      const user = userEvent.setup()
      const items = [
        { label: 'Edit', onClick: vi.fn(), disabled: true },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      const menuItem = screen.getByRole('menuitem')
      expect(menuItem).toBeDisabled()
    })

    test('disabled items have disabled styling', async () => {
      const user = userEvent.setup()
      const items = [
        { label: 'Edit', onClick: vi.fn(), disabled: true },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      const menuItem = screen.getByRole('menuitem')
      expect(menuItem.className).toContain('cursor-not-allowed')
    })

    test('disabled items do not trigger onClick', async () => {
      const user = userEvent.setup()
      const handleClick = vi.fn()
      const items = [
        { label: 'Edit', onClick: handleClick, disabled: true },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))
      await user.click(screen.getByTestId('menu-item-0'))

      expect(handleClick).not.toHaveBeenCalled()
    })
  })

  describe('danger items', () => {
    test('danger items have red text styling', async () => {
      const user = userEvent.setup()
      const items = [
        { label: 'Delete', onClick: vi.fn(), danger: true },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      const menuItem = screen.getByRole('menuitem')
      expect(menuItem.className).toContain('text-red-600')
    })

    test('danger items with icons have red icon styling', async () => {
      const user = userEvent.setup()
      const items = [
        { label: 'Delete', icon: Trash2, onClick: vi.fn(), danger: true },
      ]
      render(<KebabMenu items={items} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      const menuItem = screen.getByRole('menuitem')
      expect(menuItem.className).toContain('text-red-600')
    })
  })

  describe('keyboard interactions', () => {
    test('Escape key closes menu', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      await user.click(trigger)
      expect(screen.getByTestId('kebab-menu-dropdown')).toBeInTheDocument()

      await user.keyboard('{Escape}')
      expect(screen.queryByTestId('kebab-menu-dropdown')).not.toBeInTheDocument()
    })

    test('Escape key returns focus to trigger', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      await user.click(trigger)
      await user.keyboard('{Escape}')

      expect(trigger).toHaveFocus()
    })

    test('trigger is focusable with Tab', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      await user.tab()
      expect(screen.getByTestId('kebab-menu-trigger')).toHaveFocus()
    })

    test('trigger has focus ring styling', () => {
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      expect(trigger.className).toContain('focus:ring-2')
      expect(trigger.className).toContain('focus:ring-purple-active')
    })

    test('Enter key toggles menu', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      trigger.focus()
      await user.keyboard('{Enter}')

      expect(screen.getByTestId('kebab-menu-dropdown')).toBeInTheDocument()
    })

    test('Space key toggles menu', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      trigger.focus()
      await user.keyboard(' ')

      expect(screen.getByTestId('kebab-menu-dropdown')).toBeInTheDocument()
    })
  })

  describe('accessibility', () => {
    test('trigger has correct role', () => {
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      expect(trigger).toHaveAttribute('type', 'button')
    })

    test('menu items have correct role', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      await user.click(screen.getByTestId('kebab-menu-trigger'))

      const menuItems = screen.getAllByRole('menuitem')
      expect(menuItems).toHaveLength(3)
    })

    test('aria-expanded updates when menu opens', async () => {
      const user = userEvent.setup()
      render(<KebabMenu items={defaultItems} />)

      const trigger = screen.getByTestId('kebab-menu-trigger')
      expect(trigger).toHaveAttribute('aria-expanded', 'false')

      await user.click(trigger)
      expect(trigger).toHaveAttribute('aria-expanded', 'true')
    })
  })
})
