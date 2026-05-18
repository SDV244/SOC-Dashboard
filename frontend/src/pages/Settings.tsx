import { useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { RefreshCw, Save, Play, Database, Zap, CalendarDays, CheckCircle2, Circle } from 'lucide-react'
import { api, type Config } from '../lib/api'

const MONTH_NAMES = ['Ene', 'Feb', 'Mar', 'Abr', 'May', 'Jun', 'Jul', 'Ago', 'Sep', 'Oct', 'Nov', 'Dic']

export function Settings() {
  const qc = useQueryClient()
  const [form, setForm] = useState<Partial<Config>>({})
  const [syncParams, setSyncParams] = useState({ index: '', year: '', month: '', day: '' })
  const [polling, setPolling] = useState(false)

  const configQuery = useQuery({ queryKey: ['config'], queryFn: api.getConfig })
  const statusQuery = useQuery({
    queryKey: ['ingestStatus'],
    queryFn: api.ingestStatus,
    refetchInterval: polling ? 2000 : false,
  })

  useEffect(() => {
    if (configQuery.data) setForm(configQuery.data)
  }, [configQuery.data])

  useEffect(() => {
    if (statusQuery.data && !statusQuery.data.running && polling) setPolling(false)
  }, [statusQuery.data, polling])

  const saveMut = useMutation({
    mutationFn: () => api.updateConfig(form),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['config'] }),
  })

  const syncMut = useMutation({
    mutationFn: () =>
      api.triggerSync({
        index: syncParams.index || undefined,
        year: syncParams.year ? Number(syncParams.year) : undefined,
        month: syncParams.month ? Number(syncParams.month) : undefined,
        day: syncParams.day ? Number(syncParams.day) : undefined,
      }),
    onSuccess: () => { setPolling(true); qc.invalidateQueries({ queryKey: ['ingestStatus'] }) },
  })

  const loadMut = useMutation({
    mutationFn: api.triggerLoad,
    onSuccess: () => { setPolling(true); qc.invalidateQueries({ queryKey: ['ingestStatus'] }) },
  })

  const running = statusQuery.data?.running
  const syncSt = statusQuery.data?.sync_status

  function field(key: keyof Config) {
    return {
      value: (form[key] as string) ?? '',
      onChange: (e: React.ChangeEvent<HTMLInputElement>) =>
        setForm(f => ({ ...f, [key]: e.target.value })),
      className: 'w-full bg-gray-700 border border-gray-600 text-white rounded px-3 py-2 text-sm font-mono',
    }
  }

  const [monthsBack, setMonthsBack] = useState(24)
  const [parquetPolling, setParquetPolling] = useState(false)
  const [convertingMonths, setConvertingMonths] = useState<Set<string>>(new Set())

  const parquetQuery = useQuery({
    queryKey: ['parquetStatus'],
    queryFn: api.parquetStatus,
    refetchInterval: parquetPolling || convertingMonths.size > 0 ? 3000 : 15000,
  })

  useEffect(() => {
    if (parquetQuery.data && !parquetQuery.data.sync.running && parquetPolling) setParquetPolling(false)
  }, [parquetQuery.data, parquetPolling])

  const convertMut = useMutation({
    mutationFn: () => api.parquetConvert(monthsBack),
    onSuccess: () => { setParquetPolling(true); qc.invalidateQueries({ queryKey: ['parquetStatus'] }) },
  })

  const refreshMut = useMutation({
    mutationFn: api.parquetRefresh,
    onSuccess: () => { setParquetPolling(true); qc.invalidateQueries({ queryKey: ['parquetStatus'] }) },
  })

  const parquetSt = parquetQuery.data
  const isConverting = parquetSt?.sync.running ?? false

  // Build set of converted (year, month) pairs — any index counts
  const convertedSet = useMemo(() => {
    const s = new Set<string>()
    for (const m of parquetSt?.converted_months ?? []) {
      s.add(`${m.year}:${m.month}`)
    }
    return s
  }, [parquetSt?.converted_months])

  // Generate last 24 months grouped by year
  const monthGrid = useMemo(() => {
    const now = new Date()
    const rows: { year: number; months: number[] }[] = []
    const yearMap = new Map<number, number[]>()
    for (let i = 23; i >= 0; i--) {
      const d = new Date(now.getFullYear(), now.getMonth() - i, 1)
      const y = d.getFullYear()
      const m = d.getMonth() + 1
      if (!yearMap.has(y)) yearMap.set(y, [])
      yearMap.get(y)!.push(m)
    }
    for (const [year, months] of yearMap) rows.push({ year, months })
    return rows
  }, [])

  async function handleMonthClick(year: number, month: number) {
    const key = `${year}:${month}`
    if (convertingMonths.has(key)) return
    setConvertingMonths(prev => new Set([...prev, key]))
    try {
      await api.parquetConvertMonth(year, month)
      qc.invalidateQueries({ queryKey: ['parquetStatus'] })
    } finally {
      // Keep in converting set until parquetStatus shows it converted
      setTimeout(() => {
        setConvertingMonths(prev => { const s = new Set(prev); s.delete(key); return s })
      }, 60000) // remove spinner after 60s max
    }
  }

  return (
    <div className="space-y-6 max-w-2xl">
      <h1 className="text-2xl font-bold text-white">Configuración</h1>

      {/* S3 / OCI config */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 space-y-4">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">S3 / OCI</h2>
        {([
          ['s3_endpoint', 'S3 Endpoint URL'],
          ['s3_bucket', 'Bucket'],
          ['s3_region', 'Región'],
          ['org_id', 'Organization ID'],
          ['tenant_id', 'Tenant ID'],
        ] as [keyof Config, string][]).map(([k, label]) => (
          <div key={k}>
            <label className="block text-xs text-gray-400 mb-1">{label}</label>
            <input {...field(k)} />
          </div>
        ))}
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider pt-2">Local</h2>
        {([
          ['local_sync_path', 'Carpeta local de sync'],
          ['db_path', 'Ruta base de datos DuckDB'],
        ] as [keyof Config, string][]).map(([k, label]) => (
          <div key={k}>
            <label className="block text-xs text-gray-400 mb-1">{label}</label>
            <input {...field(k)} />
          </div>
        ))}
        <button
          onClick={() => saveMut.mutate()}
          disabled={saveMut.isPending}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded text-sm"
        >
          <Save size={14} /> {saveMut.isPending ? 'Guardando...' : 'Guardar configuración'}
        </button>
        {saveMut.isSuccess && <p className="text-green-400 text-xs">Guardado correctamente</p>}
      </div>

      {/* Sync */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 space-y-4">
        <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Sync S3 → Local</h2>
        <div className="grid grid-cols-2 gap-3">
          {([
            ['index', 'Índice (opcional, ej: adr)'],
            ['year', 'Año (ej: 2026)'],
            ['month', 'Mes (ej: 01)'],
            ['day', 'Día (ej: 01)'],
          ] as [string, string][]).map(([k, label]) => (
            <div key={k}>
              <label className="block text-xs text-gray-400 mb-1">{label}</label>
              <input
                value={syncParams[k as keyof typeof syncParams]}
                onChange={e => setSyncParams(p => ({ ...p, [k]: e.target.value }))}
                placeholder="vacío = todos"
                className="w-full bg-gray-700 border border-gray-600 text-white rounded px-3 py-2 text-sm"
              />
            </div>
          ))}
        </div>
        <div className="flex gap-3">
          <button
            onClick={() => syncMut.mutate()}
            disabled={running || syncMut.isPending}
            className="flex items-center gap-2 bg-orange-600 hover:bg-orange-500 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
          >
            <Play size={14} /> {running ? 'Sincronizando...' : 'Sync + Cargar'}
          </button>
          <button
            onClick={() => loadMut.mutate()}
            disabled={running || loadMut.isPending}
            className="flex items-center gap-2 bg-gray-600 hover:bg-gray-500 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
          >
            <RefreshCw size={14} /> Solo cargar archivos locales
          </button>
        </div>
        <div className="bg-gray-900 rounded p-3 text-xs space-y-1">
          <p className="text-gray-400">
            Estado:{' '}
            <span className={`font-semibold ${running ? 'text-yellow-400' : syncSt?.status === 'ok' ? 'text-green-400' : 'text-gray-300'}`}>
              {running ? 'En proceso...' : syncSt?.status ?? 'never'}
            </span>
          </p>
          {syncSt?.last_sync && (
            <p className="text-gray-500">Último sync: {new Date(syncSt.last_sync).toLocaleString()}</p>
          )}
        </div>
      </div>

      {/* Parquet Bulk Conversion */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 space-y-4">
        <div className="flex items-center gap-2">
          <Zap size={16} className="text-yellow-400" />
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
            Parquet — Conversión Masiva
          </h2>
        </div>
        <p className="text-xs text-gray-400">
          Convierte N meses hacia atrás desde hoy. Los meses ya convertidos se saltan automáticamente.
        </p>
        <div className="flex items-center gap-3">
          <label className="text-xs text-gray-400 whitespace-nowrap">Meses hacia atrás:</label>
          <input
            type="number"
            min={1}
            max={36}
            value={monthsBack}
            onChange={e => setMonthsBack(Number(e.target.value))}
            className="w-20 bg-gray-700 border border-gray-600 text-white rounded px-2 py-1 text-sm"
          />
          <button
            onClick={() => convertMut.mutate()}
            disabled={isConverting || convertMut.isPending}
            className="flex items-center gap-2 bg-yellow-600 hover:bg-yellow-500 text-white px-4 py-2 rounded text-sm disabled:opacity-50"
          >
            <Database size={14} />
            {isConverting ? 'Convirtiendo...' : 'Convertir histórico'}
          </button>
          <button
            onClick={() => refreshMut.mutate()}
            disabled={isConverting}
            className="flex items-center gap-2 bg-blue-700 hover:bg-blue-600 text-white px-3 py-2 rounded text-sm disabled:opacity-50"
            title="Re-convierte mes actual y anterior"
          >
            <RefreshCw size={14} />
            Actualizar
          </button>
        </div>

        {isConverting && (parquetSt?.sync as { current?: string })?.current && (
          <div className="flex items-center gap-2 text-sm text-yellow-300 animate-pulse">
            <RefreshCw size={14} className="animate-spin" />
            Procesando: {(parquetSt?.sync as { current?: string }).current}
          </div>
        )}

        {isConverting && parquetSt?.sync.pct !== undefined && (
          <div className="space-y-1">
            <div className="flex justify-between text-xs text-gray-400">
              <span>Progreso</span>
              <span>{parquetSt.sync.pct}%</span>
            </div>
            <div className="w-full bg-gray-700 rounded-full h-2">
              <div
                className="bg-yellow-500 h-2 rounded-full transition-all"
                style={{ width: `${parquetSt.sync.pct}%` }}
              />
            </div>
          </div>
        )}

        {(parquetSt?.sync.progress?.length ?? 0) > 0 && (
          <div className="bg-gray-900 rounded p-3 max-h-32 overflow-y-auto space-y-0.5">
            {[...(parquetSt?.sync.progress ?? [])].reverse().slice(0, 15).map((p, i) => (
              <div key={i} className="flex justify-between text-xs">
                <span className="text-gray-400 font-mono">{p.month}</span>
                <span className={p.status.startsWith('error') ? 'text-red-400' : p.status === 'skipped (already done)' ? 'text-gray-600' : 'text-green-400'}>
                  {p.status}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Month Calendar — specific month conversion */}
      <div className="bg-gray-800 rounded-xl p-6 border border-gray-700 space-y-4">
        <div className="flex items-center gap-2">
          <CalendarDays size={16} className="text-blue-400" />
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">
            Seleccionar Meses Específicos
          </h2>
        </div>
        <p className="text-xs text-gray-400">
          Haz clic en cualquier mes para convertirlo a Parquet y calcular estadísticas diarias.
          <span className="text-green-400 ml-1">Verde = ya convertido</span>,{' '}
          <span className="text-gray-500 ml-1">gris = pendiente</span>.
        </p>

        <div className="space-y-3">
          {monthGrid.map(({ year, months }) => (
            <div key={year} className="flex items-center gap-2">
              <span className="text-xs text-gray-500 font-mono w-10 shrink-0">{year}</span>
              <div className="flex gap-1.5 flex-wrap">
                {months.map(m => {
                  const key = `${year}:${m}`
                  const done = convertedSet.has(key)
                  const converting = convertingMonths.has(key)
                  return (
                    <button
                      key={m}
                      onClick={() => !done && !converting && handleMonthClick(year, m)}
                      disabled={done || converting}
                      title={done ? `${MONTH_NAMES[m - 1]} ${year} — convertido` : `Convertir ${MONTH_NAMES[m - 1]} ${year}`}
                      className={[
                        'w-14 py-1.5 rounded text-xs font-medium transition-all flex items-center justify-center gap-1',
                        done
                          ? 'bg-green-900/60 text-green-400 border border-green-700 cursor-default'
                          : converting
                          ? 'bg-yellow-900/60 text-yellow-300 border border-yellow-700 cursor-wait animate-pulse'
                          : 'bg-gray-700 text-gray-400 border border-gray-600 hover:bg-blue-800 hover:text-white hover:border-blue-500 cursor-pointer',
                      ].join(' ')}
                    >
                      {converting ? (
                        <RefreshCw size={10} className="animate-spin" />
                      ) : done ? (
                        <CheckCircle2 size={10} />
                      ) : (
                        <Circle size={10} />
                      )}
                      {MONTH_NAMES[m - 1]}
                    </button>
                  )
                })}
              </div>
            </div>
          ))}
        </div>

        <div className="flex items-center gap-4 text-xs text-gray-500 pt-1">
          <span className="flex items-center gap-1"><CheckCircle2 size={12} className="text-green-400" /> Convertido</span>
          <span className="flex items-center gap-1"><RefreshCw size={12} className="text-yellow-400" /> Convirtiendo</span>
          <span className="flex items-center gap-1"><Circle size={12} className="text-gray-500" /> Pendiente (click para convertir)</span>
        </div>

        {/* Converted months summary */}
        {(parquetSt?.converted_months?.length ?? 0) > 0 && (
          <details className="text-xs pt-1">
            <summary className="text-gray-500 cursor-pointer hover:text-gray-300">
              Detalle: {parquetSt?.total_converted} meses convertidos
            </summary>
            <div className="mt-2 grid grid-cols-4 gap-1 text-gray-400 max-h-48 overflow-y-auto">
              <span className="font-semibold text-gray-500">Index</span>
              <span className="font-semibold text-gray-500">Mes</span>
              <span className="font-semibold text-gray-500 text-right">Filas</span>
              <span className="font-semibold text-gray-500 text-right">Fecha</span>
              {parquetSt?.converted_months.map((m, i) => (
                <>
                  <span key={`i${i}`} className="font-mono">{m.index}</span>
                  <span key={`d${i}`}>{m.year}-{String(m.month).padStart(2, '0')}</span>
                  <span key={`r${i}`} className="text-right text-green-400">{m.row_count.toLocaleString()}</span>
                  <span key={`t${i}`} className="text-right text-gray-600">{new Date(m.converted_at).toLocaleDateString()}</span>
                </>
              ))}
            </div>
          </details>
        )}
      </div>
    </div>
  )
}
