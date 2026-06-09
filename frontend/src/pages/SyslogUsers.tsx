import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useTimeRange } from '../TimeRangeContext'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid,
} from 'recharts'
import { api, toIso } from '../lib/api'
import { TimeRangeSelector } from '../components/TimeRangeSelector'

export function SyslogUsers() {
  const { range, setRange, customStart, setCustomStart, customEnd, setCustomEnd } = useTimeRange()
  const { start, end } = useMemo(() => toIso(range, customStart, customEnd), [range, customStart, customEnd])

  const syslog = useQuery({
    queryKey: ['syslogVolume', start, end],
    queryFn: () => api.syslogVolume({ start, end }),
  })

  const users = useQuery({
    queryKey: ['usersActivity', start, end],
    queryFn: () => api.usersActivity({ start, end }),
  })

  const assets = useQuery({
    queryKey: ['assetsActivity', start, end],
    queryFn: () => api.assetsActivity({ start, end }),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Syslog / Usuarios / Assets</h1>
        <TimeRangeSelector value={range} onChange={r => { setRange(r) }} customStart={customStart} customEnd={customEnd} onCustomChange={(s, e) => { setRange('custom'); setCustomStart(s); setCustomEnd(e) }} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
            Top Hosts (Syslog + WinEvent)
          </h2>
          {syslog.isLoading ? <p className="text-gray-500">Cargando...</p> : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={syslog.data?.by_host ?? []} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                <YAxis dataKey="host" type="category" width={120} tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                <Bar dataKey="count" fill="#22c55e" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
            Top Tipos de Evento
          </h2>
          {syslog.isLoading ? <p className="text-gray-500">Cargando...</p> : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={syslog.data?.by_event_type ?? []} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                <YAxis dataKey="event_type" type="category" width={120} tick={{ fill: '#9ca3af', fontSize: 10 }} />
                <Tooltip contentStyle={{ backgroundColor: '#1f2937', border: 'none' }} />
                <Bar dataKey="count" fill="#a78bfa" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>

        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
            Top Usuarios
          </h2>
          {users.isLoading ? <p className="text-gray-500">Cargando...</p> : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-400 text-xs border-b border-gray-700">
                  <th className="text-left py-2">Usuario</th>
                  <th className="text-right py-2">Eventos</th>
                </tr>
              </thead>
              <tbody>
                {users.data?.top_users.map(u => (
                  <tr key={u.user} className="border-b border-gray-700/50">
                    <td className="py-2 text-gray-300 font-mono text-xs">{u.user}</td>
                    <td className="py-2 text-right text-purple-400 font-semibold">{u.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
          <h2 className="text-sm font-semibold text-gray-300 mb-4 uppercase tracking-wider">
            Top Assets / Hosts Globales
          </h2>
          {assets.isLoading ? <p className="text-gray-500">Cargando...</p> : (
            <table className="w-full text-sm">
              <thead>
                <tr className="text-gray-400 text-xs border-b border-gray-700">
                  <th className="text-left py-2">Asset</th>
                  <th className="text-right py-2">Eventos</th>
                </tr>
              </thead>
              <tbody>
                {assets.data?.top_assets.map(a => (
                  <tr key={a.asset} className="border-b border-gray-700/50">
                    <td className="py-2 text-gray-300 font-mono text-xs">{a.asset}</td>
                    <td className="py-2 text-right text-green-400 font-semibold">{a.count.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
