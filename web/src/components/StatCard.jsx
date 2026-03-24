export default function StatCard({ icon: Icon, label, value, color = 'text-gray-900 dark:text-white' }) {
  return (
    <div className="bg-white dark:bg-gray-800 rounded-xl shadow-sm p-4">
      <div className="flex items-center gap-3 mb-2">
        <div className="p-2 bg-runic-100 dark:bg-runic-900 rounded-lg">
          <Icon className="w-5 h-5 text-runic-600 dark:text-runic-400" />
        </div>
        <span className="text-sm text-gray-500 dark:text-gray-400">{label}</span>
      </div>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
    </div>
  )
}
