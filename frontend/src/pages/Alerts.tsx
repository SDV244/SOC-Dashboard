import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTimeRange } from '../TimeRangeContext'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  Legend, CartesianGrid,
} from 'recharts'
import { format, parseISO } from 'date-fns'
import { api, toIso } from '../lib/api'
import { TimeRangeSelector } from '../components/TimeRangeSelector'

const MSG_CLASS_COLORS: Record<string, string> = {
  interflow_traffic: '#3b82f6',
  firewall: '#f97316',
  unknown: '#6b7280',
}

export function Alerts() {
  const { range, setRange, customStart, setCustomStart, customEnd, setCustomEnd } = useTimeRange()
  const { start, end } = useMemo(() => toIso(range, customStart, customEnd), [range, customStart, customEnd])

  const timeline = useQuery({
    queryKey: ['alertsTimeline', start, end],
    queryFn: () => api.alertsTimeline({ start, end, granularity: range === '24h' ? 'hour' : 'day' }),
  })

  const threats = useQuery({
    queryKey: ['topThreats', start, end],
    queryFn: () => api.topThreats({ start, end, limit: 15 }),
  })

  const msgClasses = [...new Set(timeline.data?.map(r => r.msg_class) ?? [])]
  const timelineByPeriod = Object.values(
    (timeline.data ?? []).reduce<Record<string, Record<string, unknown>>>((acc, r) => {
      const key = r.period
      if (!acc[key]) acc[key] = { period: key }
      acc[key][r.msg_class] = r.count
      return acc
    }, {})
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Alertas (ADR)</h1>
        <TimeRangeSelector value={range} onChange={r => { setRange(r) }} customStart={customStart} customEnd={customEnd} onCustomChange={(s, e) => { setRange('custom'); setCustomStart(s); setCustomEnd(e) }} />
      </div>

      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
        <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
          Timeline por Tipo de Evento
        </h2>
        {timeline.isLoading ? (
          <div className="h-52 flex items-center justify-center text-gray-500">Cargando...</div>
        ) : (
          <ResponsiveContainer width="100%" height={240}>
            <BarChart data={timelineByPeriod}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis
                dataKey="period"
                tickFormatter={v => {
                  try { return format(parseISO(v as string), range === '24h' ? 'HH:mm' : 'MM/dd') }
                  catch { return String(v) }
                }}
                tick={{ fill: '#9ca3af', fontSize: 11 }}
              />
              <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
              <Legend />
              {msgClasses.map(mc => (
                <Bar
                  key={mc}
                  dataKey={mc}
                  stackId="a"
                  fill={MSG_CLASS_COLORS[mc] ?? '#6b7280'}
                  radius={mc === msgClasses[msgClasses.length - 1] ? [2, 2, 0, 0] : [0, 0, 0, 0]}
                />
              ))}
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>

      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
        <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
          Top Dispositivos con Threat Score &gt; 0
        </h2>
        {threats.isLoading ? (
          <p className="text-gray-500">Cargando...</p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-gray-400 text-xs border-b border-gray-700">
                <th className="text-left py-2">#</th>
                <th className="text-left py-2">Dispositivo</th>
                <th className="text-right py-2">Max Threat Score</th>
                <th className="text-right py-2">Eventos</th>
                <th className="text-right py-2">Última vez</th>
              </tr>
            </thead>
            <tbody>
              {threats.data?.map((t, i) => (
                <tr key={t.device} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="py-2 text-gray-500">{i + 1}</td>
                  <td className="py-2 text-white font-mono text-xs">{t.device}</td>
                  <td className="py-2 text-right text-orange-400 font-semibold">{t.max_threat_score}</td>
                  <td className="py-2 text-right text-blue-400">{t.count.toLocaleString()}</td>
                  <td className="py-2 text-right text-gray-400">
                    {t.last_seen ? format(parseISO(String(t.last_seen)), 'MM/dd HH:mm') : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
