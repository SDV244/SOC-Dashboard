import { useQuery } from '@tanstack/react-query'
import type { TimeRange } from '../lib/api'
import { api } from '../lib/api'

const MONTH_NAMES = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic']

const QUICK: { label: string; value: TimeRange }[] = [
  { label: '7d', value: '7d' },
  { label: '30d', value: '30d' },
  { label: '6M', value: '6M' },
]

interface Props {
  value: TimeRange
  onChange: (v: TimeRange) => void
  customStart?: string
  customEnd?: string
  onCustomChange?: (start: string, end: string) => void
}

function lastDayOf(year: number, month: number) {
  return new Date(year, month, 0).getDate()
}

export function TimeRangeSelector({ value, onChange, customStart, customEnd, onCustomChange }: Props) {
  const monthsQ = useQuery({
    queryKey: ['availableMonths'],
    queryFn: api.availableMonths,
    staleTime: 60_000,
  })

  const months = monthsQ.data ?? []

  // Group by year
  const byYear = months.reduce<Record<number, number[]>>((acc, { year, month }) => {
    if (!acc[year]) acc[year] = []
    acc[year].push(month)
    return acc
  }, {})

  function selectMonth(year: number, month: number) {
    const start = `${year}-${String(month).padStart(2, '0')}-01T00:00:00.000Z`
    const last = lastDayOf(year, month)
    const end = `${year}-${String(month).padStart(2, '0')}-${String(last).padStart(2, '0')}T23:59:59.999Z`
    onChange('custom')
    onCustomChange?.(start, end)
  }

  function isMonthSelected(year: number, month: number) {
    if (value !== 'custom' || !customStart) return false
    const prefix = `${year}-${String(month).padStart(2, '0')}-01T`
    return customStart.startsWith(prefix)
  }

  return (
    <div className="flex flex-col gap-2">
      {/* Quick ranges */}
      <div className="flex items-center gap-1">
        <span className="text-xs text-gray-500 mr-1">Rápido:</span>
        <div className="flex gap-1 bg-gray-700 rounded-lg p-1">
          {QUICK.map(o => (
            <button
              key={o.value}
              onClick={() => onChange(o.value)}
              className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
                value === o.value
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-400 hover:text-white'
              }`}
            >
              {o.label}
            </button>
          ))}
          <button
            onClick={() => onChange('custom')}
            className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
              value === 'custom'
                ? 'bg-blue-600 text-white'
                : 'text-gray-400 hover:text-white'
            }`}
          >
            Custom
          </button>
        </div>
      </div>

      {/* Available months grouped by year */}
      {months.length > 0 && (
        <div className="flex flex-col gap-1">
          <span className="text-xs text-gray-500">Meses con datos:</span>
          {Object.entries(byYear).sort(([a], [b]) => Number(a) - Number(b)).map(([year, ms]) => (
            <div key={year} className="flex items-center gap-1">
              <span className="text-xs text-gray-600 font-mono w-10 shrink-0">{year}</span>
              <div className="flex gap-1 flex-wrap">
                {ms.map(m => {
                  const selected = isMonthSelected(Number(year), m)
                  return (
                    <button
                      key={m}
                      onClick={() => selectMonth(Number(year), m)}
                      className={`px-2 py-0.5 rounded text-xs font-medium transition-colors ${
                        selected
                          ? 'bg-blue-600 text-white'
                          : 'bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-white'
                      }`}
                    >
                      {MONTH_NAMES[m - 1]}
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Custom date inputs */}
      {value === 'custom' && (
        <div className="flex items-center gap-2">
          <input
            type="datetime-local"
            value={customStart ? customStart.slice(0, 16) : ''}
            onChange={e => onCustomChange?.(e.target.value + ':00.000Z', customEnd ?? '')}
            className="bg-gray-700 border border-gray-600 text-white rounded px-2 py-1 text-xs"
          />
          <span className="text-gray-500 text-xs">→</span>
          <input
            type="datetime-local"
            value={customEnd ? customEnd.slice(0, 16) : ''}
            onChange={e => onCustomChange?.(customStart ?? '', e.target.value + ':00.000Z')}
            className="bg-gray-700 border border-gray-600 text-white rounded px-2 py-1 text-xs"
          />
        </div>
      )}
    </div>
  )
}
