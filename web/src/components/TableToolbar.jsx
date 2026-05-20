/**
* @deprecated Use SearchFilterPanel instead.
* This component is deprecated and will be removed in a future version.
* Will be removed in v2.0.
* SearchFilterPanel provides the same functionality with additional features
* like collapsible state persistence and filter chips support.
*/
import SearchInput from './SearchInput'
import RowsPerPageSelect from './RowsPerPageSelect'

export default function TableToolbar({
  searchTerm,
  onSearchChange,
  onClearSearch,
  placeholder = 'Search...',
  rowsPerPage,
  onRowsPerPageChange,
  children,
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <SearchInput
        value={searchTerm}
        onChange={onSearchChange}
        onClear={onClearSearch}
        placeholder={placeholder}
        ariaLabel="Search"
      />
      <div className="flex items-center gap-2">
        <RowsPerPageSelect
          value={rowsPerPage}
          onChange={onRowsPerPageChange}
        />
      </div>
      {children}
    </div>
  )
}
