export default function Skeleton({ width = '100%', height = '1rem', className = '' }) {
  return (
    <div 
      className={`bg-gray-200 dark:bg-charcoal-darkest rounded-none animate-pulse ${className}`}
      style={{ width, height }}
    />
  )
}