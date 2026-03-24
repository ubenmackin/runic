import { useState } from 'react'

export function useFormState(initialDefaults) {
  const [form, setForm] = useState(initialDefaults)

  // Handle input change events (text, select, radio)
  const handleChange = (e) => {
    const { name, value, type, checked } = e.target
    setForm(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
  }

  // Populate form from an existing record (for editing)
  const setFormForEdit = (item) => {
    setForm({ ...initialDefaults, ...item })
  }

  // Reset form to defaults
  const resetForm = (defaults = initialDefaults) => {
    setForm(defaults)
  }

  return { form, setForm, handleChange, setFormForEdit, resetForm }
}
