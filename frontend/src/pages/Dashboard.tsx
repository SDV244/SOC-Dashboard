import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTimeRange } from '../TimeRangeContext'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer, Legend, CartesianGrid, PieChart, Pie, Cell,
} from 'recharts'
import { format, parseISO } from 'date-fns'
import { api, toIso } from '../lib/api'
import { StatCard } from '../components/StatCard'
import { TimeRangeSelector } from '../components/TimeRangeSelector'

const MSG_CLASS_COLORS: Record<string, string> = {
  interflow_traffic: '#3b82f6',
  firewall: '#f97316',
  unknown: '#6b7280',
}

const APP_COLORS = ['#3b82f6', '#10b981', '#f97316', '#8b5cf6', '#ec4899', '#eab308', '#6b7280']

const REP_COLORS: Record<string, string> = {
  Good: '#10b981',
  Bad: '#dc2626',
  unknown: '#6b7280',
}

export function Dashboard() {
  const { range, setRange, customStart, setCustomStart, customEnd, setCustomEnd } = useTimeRange()
  const { start, end } = useMemo(() => toIso(range, customStart, customEnd), [range, customStart, customEnd])

  const overview = useQuery({
    queryKey: ['overview', start, end],
    queryFn: () => api.overview({ start, end }),
  })

  const timeline = useQuery({
    queryKey: ['timeline', start, end],
    queryFn: () => api.alertsTimeline({ start, end, granularity: range === '24h' ? 'hour' : 'day' }),
  })

  const topDomains = useQuery({
    queryKey: ['topDomains', start, end],
    queryFn: () => api.networkTopDomains({ start, end }),
  })

  const apps = useQuery({
    queryKey: ['apps', start, end],
    queryFn: () => api.networkApps({ start, end }),
  })

  const geo = useQuery({
    queryKey: ['geo', start, end],
    queryFn: () => api.networkGeo({ start, end }),
  })

  const ov = overview.data

  const msgClasses = [...new Set(timeline.data?.map(r => r.msg_class) ?? [])]
  const timelineByPeriod = Object.values(
    (timeline.data ?? []).reduce<Record<string, Record<string, unknown>>>((acc, r) => {
      const key = String(r.period)
      if (!acc[key]) acc[key] = { period: key }
      acc[key][r.msg_class] = r.count
      return acc
    }, {})
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Dashboard</h1>
        <TimeRangeSelector value={range} onChange={r => { setRange(r) }} customStart={customStart} customEnd={customEnd} onCustomChange={(s, e) => { setRange('custom'); setCustomStart(s); setCustomEnd(e) }} />
      </div>

      {overview.isLoading && <p className="text-gray-400">Cargando...</p>}
      {overview.error && <p className="text-red-400">Error al cargar datos</p>}

      {ov && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard label="Total Eventos" value={ov.total_events} />
          <StatCard
            label="Threat Score >50"
            value={ov.threat_score_high}
            accent="text-red-400"
            sub="eventos de alto riesgo"
          />
          <StatCard
            label="Detecciones DGA"
            value={ov.dga_detections}
            accent="text-orange-400"
            sub="domain generation algorithm"
          />
          <StatCard
            label="DNS Tunneling"
            value={ov.tunneling_events}
            accent="text-yellow-400"
            sub="tunelización detectada"
          />
        </div>
      )}

      {/* Row 1: Timeline + Top Domains */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
            Eventos por Hora (tipo)
          </h2>
          {timeline.isLoading ? (
            <div className="h-48 flex items-center justify-center text-gray-500">Cargando...</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={timelineByPeriod}>
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis
                  dataKey="period"
                  tickFormatter={v => {
                    try { return format(parseISO(v as string), range === '24h' ? 'HH:mm' : 'MM/dd') }
                    catch { return String(v) }
                  }}
                  tick={{ fill: '#9ca3af', fontSize: 10 }}
                />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} labelStyle={{ color: '#f9fafb' }} />
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
            Top Dominios Consultados
          </h2>
          {topDomains.isLoading ? (
            <div className="h-48 flex items-center justify-center text-gray-500">Cargando...</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={topDomains.data?.slice(0, 12)} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis
                  dataKey="domain"
                  type="category"
                  width={145}
                  tick={{ fill: '#9ca3af', fontSize: 10 }}
                  tickFormatter={v => (String(v).length > 22 ? String(v).slice(0, 22) + '…' : String(v))}
                />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1f2937', border: 'none' }}
                  formatter={(value, _name, props) => [
                    `${value} queries — ${props.payload.reputation}${props.payload.is_dga === 'yes' ? ' · DGA' : ''}`,
                    'consultas',
                  ]}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {topDomains.data?.slice(0, 12).map((entry, idx) => (
                    <Cell key={idx} fill={REP_COLORS[entry.reputation] ?? '#6b7280'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
          <div className="flex gap-3 mt-2 text-xs text-gray-500">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-emerald-500 inline-block" /> Good</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-600 inline-block" /> Bad</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-gray-500 inline-block" /> Unknown</span>
          </div>
        </div>
      </div>

      {/* Row 2: App Distribution + Geo */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
            Distribución por Protocolo / App
          </h2>
          {apps.isLoading ? (
            <div className="h-48 flex items-center justify-center text-gray-500">Cargando...</div>
          ) : (
            <div className="flex items-center gap-4">
              <ResponsiveContainer width="50%" height={200}>
                <PieChart>
                  <Pie
                    data={apps.data}
                    dataKey="count"
                    nameKey="app"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {apps.data?.map((_entry, idx) => (
                      <Cell key={idx} fill={APP_COLORS[idx % APP_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#1f2937', border: 'none' }}
                    formatter={(v, name) => [`${v}`, name]}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-col gap-1.5 text-xs">
                {apps.data?.map((entry, idx) => (
                  <div key={entry.app} className="flex items-center gap-2">
                    <span
                      className="w-2.5 h-2.5 rounded-sm flex-shrink-0"
                      style={{ backgroundColor: APP_COLORS[idx % APP_COLORS.length] }}
                    />
                    <span className="text-gray-300 font-mono">{entry.app}</span>
                    <span className="text-gray-500 ml-auto pl-4">{entry.count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
            Top Países Origen (Src IP)
          </h2>
          {geo.isLoading ? (
            <div className="h-48 flex items-center justify-center text-gray-500">Cargando...</div>
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={geo.data?.slice(0, 12)} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <YAxis
                  dataKey="country"
                  type="category"
                  width={40}
                  tick={{ fill: '#9ca3af', fontSize: 11, fontWeight: 600 }}
                />
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                <Bar dataKey="count" fill="#8b5cf6" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>
    </div>
  )
}
