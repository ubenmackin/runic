import { ArrowUp, ArrowDown, ArrowUpDown } from 'lucide-react'

export default function SortIndicator({ columnKey, sortConfig }) {
  if (sortConfig.key !== columnKey) {
    return <ArrowUpDown className="w-4 h-4 text-gray-400 ml-1" />
  }
  return sortConfig.direction === 'asc'
    ? <ArrowUp className="w-4 h-4 text-runic-500 ml-1" />
    : <ArrowDown className="w-4 h-4 text-runic-500 ml-1" />
}
