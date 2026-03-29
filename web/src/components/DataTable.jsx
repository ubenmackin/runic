export default function DataTable({ columns, data, emptyMessage, onRowClick }) {
  if (!data?.length) {
    return emptyMessage ? <p className="text-gray-500 text-sm py-4">{emptyMessage}</p> : null
  }

  return (
    <div className="bg-white dark:bg-charcoal-dark rounded-xl shadow-sm overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 dark:bg-charcoal-darkest">
            <tr>
              {columns.map(col => (
                <th key={col.key} className={`text-left px-4 py-3 font-medium text-gray-500 dark:text-amber-muted ${col.className || ''}`}>
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
            {data.map((item, idx) => (
              <tr 
                key={item.id ?? idx}
                className={`${onRowClick ? 'cursor-pointer' : ''}`}
                onClick={onRowClick ? () => onRowClick(item) : undefined}
              >
                {columns.map(col => (
                  <td key={col.key} className={`px-4 py-3 ${col.cellClassName || ''}`}>
                    {col.render ? col.render(item) : item[col.key]}
                  </td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
