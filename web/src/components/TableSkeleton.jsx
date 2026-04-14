import Skeleton from './Skeleton'

export default function TableSkeleton({ rows = 5, columns = 4 }) {
  return (
    <div className="bg-white dark:bg-charcoal-dark rounded-none shadow-none overflow-hidden">
      <table className="w-full">
        <thead className="bg-gray-50 dark:bg-charcoal-darkest">
          <tr>
            {Array.from({ length: columns }).map((_, i) => (
              <th key={i} className="text-left px-4 py-3">
                <Skeleton width="80px" height="1rem" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-200 dark:divide-gray-border">
          {Array.from({ length: rows }).map((_, i) => (
            <tr key={i}>
              {Array.from({ length: columns }).map((_, j) => (
                <td key={j} className="px-4 py-3">
                  <Skeleton width="100%" height="1.25rem" />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}