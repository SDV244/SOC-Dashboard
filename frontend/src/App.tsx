import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { LayoutDashboard, Shield, ScrollText, Activity, Settings, ShieldCheck } from 'lucide-react'
import { Dashboard } from './pages/Dashboard'
import { Alerts } from './pages/Alerts'
import { LogBrowser } from './pages/LogBrowser'
import { SyslogUsers } from './pages/SyslogUsers'
import { Compliance } from './pages/Compliance'
import { Settings as SettingsPage } from './pages/Settings'

const qc = new QueryClient({ defaultOptions: { queries: { staleTime: 30_000, retry: 1 } } })

const NAV = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/alerts', icon: Shield, label: 'Alertas' },
  { to: '/syslog', icon: Activity, label: 'Syslog / Usuarios' },
  { to: '/logs', icon: ScrollText, label: 'Log Browser' },
  { to: '/compliance', icon: ShieldCheck, label: 'PCI Compliance' },
  { to: '/settings', icon: Settings, label: 'Configuración' },
]

function Sidebar() {
  return (
    <aside className="w-56 min-h-screen bg-gray-900 border-r border-gray-800 flex flex-col">
      <div className="px-5 py-6 border-b border-gray-800">
        <span className="text-white font-bold text-lg tracking-tight">SOC</span>
        <span className="text-blue-400 font-bold text-lg"> Dashboard</span>
      </div>
      <nav className="flex-1 py-4 px-2 space-y-1">
        {NAV.map(({ to, icon: Icon, label, end }) => (
          <NavLink
            key={to}
            to={to}
            end={end}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors ${
                isActive
                  ? 'bg-blue-600/20 text-blue-400'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
              }`
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}
      </nav>
      <div className="px-5 py-4 border-t border-gray-800 text-xs text-gray-600">
        StellarCyber XDR Logs
      </div>
    </aside>
  )
}

export default function App() {
  return (
    <QueryClientProvider client={qc}>
      <BrowserRouter>
        <div className="flex min-h-screen bg-gray-950 text-white">
          <Sidebar />
          <main className="flex-1 p-6 overflow-auto">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/alerts" element={<Alerts />} />
              <Route path="/syslog" element={<SyslogUsers />} />
              <Route path="/logs" element={<LogBrowser />} />
              <Route path="/compliance" element={<Compliance />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Routes>
          </main>
        </div>
      </BrowserRouter>
    </QueryClientProvider>
  )
}
