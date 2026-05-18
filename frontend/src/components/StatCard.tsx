interface Props {
  label: string
  value: number | string
  sub?: string
  accent?: string
}

export function StatCard({ label, value, sub, accent = 'text-blue-400' }: Props) {
  return (
    <div className="bg-gray-800 rounded-xl p-5 flex flex-col gap-1 border border-gray-700">
      <span className="text-xs text-gray-400 uppercase tracking-wider">{label}</span>
      <span className={`text-3xl font-bold ${accent}`}>{value.toLocaleString()}</span>
      {sub && <span className="text-xs text-gray-500">{sub}</span>}
    </div>
  )
}
