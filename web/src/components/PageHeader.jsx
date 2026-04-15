export default function PageHeader({ title, description, actions }) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-light-neutral">{title}</h1>
        <p className="text-gray-600 dark:text-amber-muted">{description}</p>
      </div>
      {actions && (
        <div className="flex items-center gap-1">
          {actions}
        </div>
      )}
    </div>
  )
}
