interface Props {
  severity: string | null
}

const colors: Record<string, string> = {
  critical: 'bg-red-600 text-white',
  high: 'bg-orange-500 text-white',
  medium: 'bg-yellow-400 text-black',
  low: 'bg-blue-400 text-white',
  info: 'bg-gray-400 text-white',
  unknown: 'bg-gray-200 text-gray-700',
}

export function SeverityBadge({ severity }: Props) {
  const key = (severity ?? 'unknown').toLowerCase()
  const cls = colors[key] ?? colors.unknown
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold uppercase ${cls}`}>
      {key}
    </span>
  )
}
