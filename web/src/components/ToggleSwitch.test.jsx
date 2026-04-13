import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, test, expect, vi } from 'vitest'
import ToggleSwitch from './ToggleSwitch'

describe('ToggleSwitch', () => {
  describe('rendering states', () => {
    test('renders checked state correctly', () => {
      render(<ToggleSwitch checked={true} onChange={() => {}} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle).toBeInTheDocument()
      expect(toggle).toHaveAttribute('aria-checked', 'true')
    })

    test('renders unchecked state correctly', () => {
      render(<ToggleSwitch checked={false} onChange={() => {}} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle).toBeInTheDocument()
      expect(toggle).toHaveAttribute('aria-checked', 'false')
    })

    test('has correct styling when checked', () => {
      render(<ToggleSwitch checked={true} onChange={() => {}} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle.className).toContain('bg-purple-active')
    })

    test('has correct styling when unchecked', () => {
      render(<ToggleSwitch checked={false} onChange={() => {}} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle.className).toContain('bg-gray-200')
    })
  })

  describe('onChange handler', () => {
    test('calls onChange with toggled value when clicked', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      render(<ToggleSwitch checked={false} onChange={handleChange} />)
      
      await user.click(screen.getByRole('switch'))
      
      expect(handleChange).toHaveBeenCalledTimes(1)
      expect(handleChange).toHaveBeenCalledWith(true)
    })

    test('calls onChange with false when currently checked', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      render(<ToggleSwitch checked={true} onChange={handleChange} />)
      
      await user.click(screen.getByRole('switch'))
      
      expect(handleChange).toHaveBeenCalledTimes(1)
      expect(handleChange).toHaveBeenCalledWith(false)
    })
  })

  describe('disabled state', () => {
    test('renders disabled state correctly', () => {
      render(<ToggleSwitch checked={false} onChange={() => {}} disabled={true} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle).toBeDisabled()
    })

    test('does not call onChange when disabled and clicked', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      render(<ToggleSwitch checked={false} onChange={handleChange} disabled={true} />)
      
      await user.click(screen.getByRole('switch'))
      
      expect(handleChange).not.toHaveBeenCalled()
    })

    test('has disabled styling', () => {
      render(<ToggleSwitch checked={false} onChange={() => {}} disabled={true} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle.className).toContain('opacity-50')
      expect(toggle.className).toContain('cursor-not-allowed')
    })

    test('disabled prop defaults to false', () => {
      render(<ToggleSwitch checked={false} onChange={() => {}} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle).not.toBeDisabled()
    })
  })

  describe('keyboard accessibility', () => {
    test('can be focused with Tab', async () => {
      const user = userEvent.setup()
      render(<ToggleSwitch checked={false} onChange={() => {}} />)
      
      await user.tab()
      
      const toggle = screen.getByRole('switch')
      expect(toggle).toHaveFocus()
    })

    test('can be activated with Enter key', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      render(<ToggleSwitch checked={false} onChange={handleChange} />)
      
      const toggle = screen.getByRole('switch')
      toggle.focus()
      await user.keyboard('{Enter}')
      
      expect(handleChange).toHaveBeenCalledTimes(1)
      expect(handleChange).toHaveBeenCalledWith(true)
    })

    test('can be activated with Space key', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      render(<ToggleSwitch checked={true} onChange={handleChange} />)
      
      const toggle = screen.getByRole('switch')
      toggle.focus()
      await user.keyboard(' ')
      
      expect(handleChange).toHaveBeenCalledTimes(1)
      expect(handleChange).toHaveBeenCalledWith(false)
    })

    test('does not respond to keyboard when disabled', async () => {
      const user = userEvent.setup()
      const handleChange = vi.fn()
      render(<ToggleSwitch checked={false} onChange={handleChange} disabled={true} />)
      
      const toggle = screen.getByRole('switch')
      toggle.focus()
      await user.keyboard('{Enter}')
      
      expect(handleChange).not.toHaveBeenCalled()
    })

    test('has focus ring styling', () => {
      render(<ToggleSwitch checked={false} onChange={() => {}} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle.className).toContain('focus:ring-2')
      expect(toggle.className).toContain('focus:ring-purple-active')
    })
  })

  describe('accessibility', () => {
    test('has correct role', () => {
      render(<ToggleSwitch checked={false} onChange={() => {}} />)
      
      expect(screen.getByRole('switch')).toBeInTheDocument()
    })

    test('has type="button" attribute', () => {
      render(<ToggleSwitch checked={false} onChange={() => {}} />)
      
      const toggle = screen.getByRole('switch')
      expect(toggle).toHaveAttribute('type', 'button')
    })
  })
})
