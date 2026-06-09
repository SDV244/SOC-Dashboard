import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { format, eachDayOfInterval, subMonths } from 'date-fns'
import { ShieldCheck, ShieldAlert, AlertTriangle, CheckCircle2 } from 'lucide-react'
import { api } from '../lib/api'

const INDEXES = ['adr', 'syslog', 'wineventlog', 'users', 'assets']

const PCI_CONTROLS = [
  { id: '10.2', title: 'Eventos auditables capturados', desc: 'Logs de acceso, autenticación y cambios en CDE' },
  { id: '10.4', title: 'Revisión diaria de logs críticos', desc: 'Revisión automatizada de eventos de seguridad' },
  { id: '10.5.1', title: '3 meses disponibles en línea', desc: 'Logs accesibles inmediatamente sin proceso de recuperación' },
  { id: '10.5.2', title: '12 meses de retención total', desc: 'Logs archivados y recuperables por al menos 12 meses' },
  { id: '10.7', title: 'Detección de fallas en controles', desc: 'Alertas cuando los logs dejan de llegar (gap detection)' },
]

function HeatmapCalendar({ days, months }: { days: { day: string; count: number }[]; months: number }) {
  const end = new Date()
  const start = subMonths(end, months)
  const allDays = eachDayOfInterval({ start, end })
  const countByDay = Object.fromEntries(days.map(d => [d.day, d.count]))

  const maxCount = Math.max(...days.map(d => d.count), 1)

  function opacity(count: number) {
    if (!count) return 'bg-gray-800'
    const pct = count / maxCount
    if (pct > 0.75) return 'bg-emerald-500'
    if (pct > 0.40) return 'bg-emerald-600'
    if (pct > 0.10) return 'bg-emerald-800'
    return 'bg-emerald-900'
  }

  const weeks: Date[][] = []
  let week: Date[] = []
  allDays.forEach((d, i) => {
    week.push(d)
    if (week.length === 7 || i === allDays.length - 1) {
      weeks.push(week)
      week = []
    }
  })

  return (
    <div className="overflow-x-auto">
      <div className="flex gap-0.5">
        {weeks.map((w, wi) => (
          <div key={wi} className="flex flex-col gap-0.5">
            {w.map(d => {
              const key = format(d, 'yyyy-MM-dd')
              const count = countByDay[key] ?? 0
              return (
                <div
                  key={key}
                  title={`${key}: ${count.toLocaleString()} eventos`}
                  className={`w-3 h-3 rounded-sm ${opacity(count)}`}
                />
              )
            })}
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2 mt-2 text-xs text-gray-500">
        <span>Sin datos</span>
        <span className="w-3 h-3 rounded-sm bg-gray-800 inline-block" />
        <span className="w-3 h-3 rounded-sm bg-emerald-900 inline-block" />
        <span className="w-3 h-3 rounded-sm bg-emerald-700 inline-block" />
        <span className="w-3 h-3 rounded-sm bg-emerald-500 inline-block" />
        <span>Alto volumen</span>
      </div>
    </div>
  )
}

function CoverageCard({ index, months }: { index: string; months: number }) {
  const q = useQuery({
    queryKey: ['coverage', index, months],
    queryFn: () => api.coverage(index, months),
    staleTime: 5 * 60 * 1000,
  })

  if (q.isLoading) return (
    <div className="bg-gray-800 rounded-xl p-5 border border-gray-700 animate-pulse">
      <div className="h-4 bg-gray-700 rounded w-1/3 mb-3" />
      <div className="h-16 bg-gray-700 rounded" />
    </div>
  )

  const data = q.data
  if (!data || data.error) return (
    <div className="bg-gray-800 rounded-xl p-5 border border-red-900">
      <p className="text-red-400 text-sm font-mono">{data?.error ?? 'Error al cargar'}</p>
    </div>
  )

  return (
    <div className={`bg-gray-800 rounded-xl p-5 border ${data.compliant ? 'border-emerald-700' : 'border-red-800'}`}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {data.compliant
            ? <ShieldCheck size={16} className="text-emerald-400" />
            : <ShieldAlert size={16} className="text-red-400" />}
          <span className="font-semibold text-white font-mono text-sm">{index}</span>
        </div>
        <div className="text-right">
          <span className={`text-lg font-bold ${data.compliant ? 'text-emerald-400' : 'text-red-400'}`}>
            {data.coverage_pct}%
          </span>
          <p className="text-xs text-gray-500">{data.days_with_data}/{data.required_days} días</p>
        </div>
      </div>
      <HeatmapCalendar days={data.days} months={months} />
    </div>
  )
}

export function Compliance() {
  const [months, setMonths] = useState(3)

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">PCI DSS Compliance</h1>
        <div className="flex items-center gap-2">
          <span className="text-xs text-gray-400">Ventana:</span>
          {[1, 3, 6, 12].map(m => (
            <button
              key={m}
              onClick={() => setMonths(m)}
              className={`px-3 py-1 rounded text-sm ${months === m ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
            >
              {m}M
            </button>
          ))}
        </div>
      </div>

      {/* PCI Controls summary */}
      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
        <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
          Controles PCI DSS 4.0 — Requisito 10
        </h2>
        <div className="space-y-2">
          {PCI_CONTROLS.map(c => (
            <div key={c.id} className="flex items-start gap-3 py-2 border-b border-gray-700/50 last:border-0">
              <span className="text-xs bg-gray-700 text-blue-300 px-1.5 py-0.5 rounded font-mono whitespace-nowrap mt-0.5">
                {c.id}
              </span>
              <div className="flex-1">
                <p className="text-sm text-white">{c.title}</p>
                <p className="text-xs text-gray-500">{c.desc}</p>
              </div>
              {c.id === '10.5.1'
                ? <AlertTriangle size={14} className="text-yellow-400 mt-1 flex-shrink-0" />
                : <CheckCircle2 size={14} className="text-emerald-400 mt-1 flex-shrink-0" />}
            </div>
          ))}
        </div>
        <div className="mt-3 p-3 bg-blue-900/20 border border-blue-700/40 rounded text-xs text-blue-300">
          <CheckCircle2 size={12} className="inline mr-1 text-emerald-400" />
          <strong>Req 10.5.1:</strong> Cobertura de logs calculada sobre datos locales (parquet). Los heatmaps muestran los días con datos disponibles en los últimos {months} meses.
        </div>
      </div>

      {/* Coverage heatmaps por índice */}
      <div>
        <h2 className="text-sm font-semibold text-gray-300 mb-3 uppercase tracking-wider">
          Cobertura de Logs en OCI — Últimos {months} meses
        </h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {INDEXES.map(idx => (
            <CoverageCard key={idx} index={idx} months={months} />
          ))}
        </div>
      </div>
    </div>
  )
}
