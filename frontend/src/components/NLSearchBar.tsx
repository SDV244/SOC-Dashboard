import { useState } from 'react'
import { Sparkles, Loader2, X, ChevronRight } from 'lucide-react'
import type { BrowseLogsParams } from '../lib/api'

interface NLResult {
  filters: Partial<BrowseLogsParams>
  query: string
  error?: string
}

interface Props {
  onApply: (filters: Partial<BrowseLogsParams & { start?: string; end?: string }>) => void
}

const FILTER_LABELS: Record<string, (v: unknown) => string> = {
  index:           v => `Índice: ${v}`,
  search:          v => `Búsqueda: "${v}"`,
  threat_score_min: v => `Score ≥ ${v}`,
  is_dga:          v => v === 'yes' ? 'DGA detectado' : 'Sin DGA',
  is_tunneling:    () => 'Tunneling',
  app_name:        v => `App: ${v}`,
  src_country:     v => `País: ${v}`,
  domain:          v => `Dominio: ${v}`,
}

export function NLSearchBar({ onApply }: Props) {
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<NLResult | null>(null)

  const search = async () => {
    if (!input.trim()) return
    setLoading(true)
    setResult(null)
    try {
      const resp = await fetch('/api/logs/nl-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: input }),
      })
      const data = await resp.json()
      setResult(data)
      if (data.filters && Object.keys(data.filters).length > 0) {
        onApply(data.filters)
      }
    } catch {
      setResult({ filters: {}, query: input, error: 'Error de conexión con el servidor' })
    } finally {
      setLoading(false)
    }
  }

  const appliedLabels = result?.filters
    ? Object.entries(result.filters)
        .filter(([k, v]) => v != null && v !== '' && v !== false && FILTER_LABELS[k])
        .map(([k, v]) => FILTER_LABELS[k](v))
    : []

  return (
    <div className="bg-gray-800/60 border border-gray-700 rounded-xl p-3 space-y-2">
      <div className="flex items-center gap-2">
        <Sparkles size={14} className="text-purple-400 shrink-0" />
        <span className="text-xs text-purple-300 font-medium">Búsqueda con IA</span>
        <span className="text-xs text-gray-500">— solo tu consulta se envía, nunca los logs</span>
      </div>
      <div className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && search()}
          placeholder='Ej: "eventos DGA de China con score alto" · "logins fallidos en Windows ayer"'
          className="flex-1 bg-gray-700 border border-gray-600 text-white rounded px-3 py-1.5 text-sm placeholder:text-gray-500 focus:outline-none focus:border-purple-500"
        />
        {input && (
          <button onClick={() => { setInput(''); setResult(null) }} className="text-gray-500 hover:text-white">
            <X size={14} />
          </button>
        )}
        <button
          onClick={search}
          disabled={loading || !input.trim()}
          className="flex items-center gap-1.5 bg-purple-700 hover:bg-purple-600 disabled:opacity-40 text-white px-3 py-1.5 rounded text-sm"
        >
          {loading ? <Loader2 size={13} className="animate-spin" /> : <Sparkles size={13} />}
          Buscar
        </button>
      </div>

      {result && (
        <div className="text-xs">
          {result.error ? (
            <span className="text-red-400">
              {result.error.includes('429') || result.error.includes('Límite')
                ? 'Límite de peticiones alcanzado. Los modelos gratuitos tienen cuota baja — intenta en 1-2 minutos.'
                : result.error}
            </span>
          ) : appliedLabels.length > 0 ? (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-gray-500">Filtros aplicados:</span>
              {appliedLabels.map((label, i) => (
                <span key={i} className="flex items-center gap-1 bg-purple-900/50 text-purple-300 border border-purple-700 px-2 py-0.5 rounded-full">
                  <ChevronRight size={10} />{label}
                </span>
              ))}
            </div>
          ) : (
            <span className="text-gray-500">No se extrajeron filtros. Puedes refinar la búsqueda o usar los filtros manuales.</span>
          )}
        </div>
      )}
    </div>
  )
}
