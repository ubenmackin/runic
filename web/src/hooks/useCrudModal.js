import { useState } from 'react'
import { useFormState } from './useFormState'

export function useCrudModal(defaultForm) {
  const [modalOpen, setModalOpen] = useState(false)
  const [editItem, setEditItem] = useState(null)
  const { form, setForm, handleChange, setFormForEdit, resetForm } = useFormState(defaultForm)

  const handleOpenAdd = () => {
    setEditItem(null)
    resetForm()
    setModalOpen(true)
  }

  const handleEdit = (item) => {
    setEditItem(item)
    setFormForEdit(item)
    setModalOpen(true)
  }

  const handleCancel = () => {
    setModalOpen(false)
    setEditItem(null)
    resetForm()
  }

  return {
    modalOpen,
    setModalOpen,
    editItem,
    setEditItem,
    form,
    setForm,
    handleChange,
    setFormForEdit,
    handleOpenAdd,
    handleEdit,
    handleCancel,
  }
}
