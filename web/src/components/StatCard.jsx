function formatNumber(num) {
  if (typeof num !== 'number') return num
  return num.toLocaleString()
}

export default function StatCard({ icon: Icon, label, value, valueColor = 'text-slate-400' }) {
  return (
    <div className="border border-gray-border bg-charcoal-dark p-3 flex flex-col min-w-[140px] flex-1">
      {Icon && (
        <Icon className="w-4 h-4 text-slate-500 mb-1" />
      )}
      <span className="text-[10px] uppercase tracking-widest text-slate-500">{label}</span>
      <span className={`font-mono text-xl ${valueColor}`}>{formatNumber(value)}</span>
    </div>
  )
}
