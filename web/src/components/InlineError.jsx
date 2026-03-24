export default function InlineError({ message }) {
  if (!message) return null
  return (
    <p className="mt-1 text-sm text-red-600 dark:text-red-400">{message}</p>
  )
}
