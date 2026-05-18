import { useState, useCallback, useMemo, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { format, parseISO } from 'date-fns'
import { ChevronDown, ChevronRight, Download, ShieldAlert, X, Search, Info } from 'lucide-react'
import { api, toIso, type LogRow, type BrowseLogsParams, type TimeRange } from '../lib/api'
import { TimeRangeSelector } from '../components/TimeRangeSelector'
import { NLSearchBar } from '../components/NLSearchBar'

const GLOSSARY = [
  { term: 'ADE',        def: 'Alert Detection Engine — alertas correlacionadas de alto nivel' },
  { term: 'ADR',        def: 'Alert Detection Raw — eventos sin correlacionar del motor de detección' },
  { term: 'Threat Score', def: 'Puntuación de amenaza 0-100 asignada por el motor ML' },
  { term: 'DGA',        def: 'Domain Generation Algorithm — técnica de malware para evadir bloqueos DNS' },
  { term: 'Tunneling',  def: 'Exfiltración de datos encubierta dentro de protocolos legítimos (ej. DNS)' },
  { term: 'Kill Chain', def: 'Fases del ataque: Reconocimiento → Armado → Entrega → Explotación → Post-explotación' },
  { term: 'C&C',        def: 'Command & Control — infraestructura de comunicación del atacante' },
  { term: 'Syslog',     def: 'Logs de sistema/red: firewalls, switches, endpoints Linux' },
  { term: 'WinEventLog', def: 'Windows Event Log — autenticaciones, procesos, cambios de política AD' },
  { term: 'Maltrace',   def: 'Trazas de comportamiento malicioso detectadas por el sensor de red' },
]

function GlossaryTooltip() {
  const [open, setOpen] = useState(false)
  return (
    <div className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex items-center gap-1 text-xs text-gray-400 hover:text-white bg-gray-800 border border-gray-700 px-2 py-1.5 rounded-lg"
      >
        <Info size={12} /> Glosario
      </button>
      {open && (
        <div className="absolute right-0 top-full mt-1 z-50 bg-gray-900 border border-gray-700 rounded-xl p-4 w-96 shadow-xl">
          <p className="text-xs font-semibold text-gray-300 mb-3 uppercase tracking-wider">Índices y Términos</p>
          <div className="space-y-2">
            {GLOSSARY.map(g => (
              <div key={g.term}>
                <span className="text-blue-400 font-mono text-xs font-semibold">{g.term}</span>
                <span className="text-gray-400 text-xs"> — {g.def}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

const COUNTRIES: Record<string, string> = {
  US: 'Estados Unidos', CN: 'China', RU: 'Rusia', BR: 'Brasil',
  DE: 'Alemania', GB: 'Reino Unido', FR: 'Francia', IN: 'India',
  VE: 'Venezuela', CO: 'Colombia', MX: 'México', AR: 'Argentina',
  NL: 'Países Bajos', UA: 'Ucrania', IR: 'Irán', KP: 'Corea del Norte',
}

function ThreatScoreBadge({ score }: { score: number | null }) {
  if (score === null || score === undefined) return <span className="text-gray-600 text-xs">—</span>
  const color =
    score > 75 ? 'bg-red-900 text-red-300' :
    score > 50 ? 'bg-orange-900 text-orange-300' :
    score > 0  ? 'bg-yellow-900 text-yellow-300' :
                 'bg-gray-800 text-gray-500'
  return (
    <span className={`inline-flex items-center gap-1 text-xs font-mono px-1.5 py-0.5 rounded ${color}`}>
      {score > 0 && <ShieldAlert size={10} />}{score}
    </span>
  )
}

function ActiveFilter({ label, onRemove }: { label: string; onRemove: () => void }) {
  return (
    <span className="inline-flex items-center gap-1 bg-blue-900/50 text-blue-300 border border-blue-700 text-xs px-2 py-0.5 rounded-full">
      {label}
      <button onClick={onRemove} className="hover:text-white"><X size={10} /></button>
    </span>
  )
}

function UserTypeahead({ value, options, onChange }: {
  value: string
  options: string[]
  onChange: (v: string) => void
}) {
  const [open, setOpen] = useState(false)
  const [input, setInput] = useState(value)
  const ref = useRef<HTMLDivElement>(null)

  const filtered = useMemo(
    () => options.filter(u => u.toLowerCase().includes(input.toLowerCase())).slice(0, 15),
    [options, input]
  )

  return (
    <div ref={ref} className="relative">
      <div className="relative">
        <Search size={12} className="absolute left-2 top-1/2 -translate-y-1/2 text-gray-400" />
        <input
          value={input}
          onChange={e => { setInput(e.target.value); setOpen(true) }}
          onFocus={() => setOpen(true)}
          onBlur={() => setTimeout(() => setOpen(false), 150)}
          placeholder="Buscar usuario…"
          className="bg-gray-700 border border-gray-600 text-white rounded pl-7 pr-2 py-1 text-sm w-44"
        />
        {value && (
          <button onClick={() => { setInput(''); onChange(''); }} className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white">
            <X size={10} />
          </button>
        )}
      </div>
      {open && filtered.length > 0 && (
        <div className="absolute z-50 mt-1 w-full bg-gray-800 border border-gray-600 rounded shadow-lg max-h-48 overflow-y-auto">
          {filtered.map(u => (
            <button
              key={u}
              onMouseDown={() => { onChange(u); setInput(u); setOpen(false) }}
              className="block w-full text-left px-3 py-1.5 text-sm text-gray-300 hover:bg-gray-700 hover:text-white"
            >
              {u}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

function RawPanel({ raw }: { raw: Record<string, unknown> }) {
  const important = ['threat_score', 'severity', 'is_dga', 'is_tunneling', 'srcip', 'dstip',
    'srcport', 'dstport', 'proto', 'appid_name', 'domain_list', 'domain_reputation',
    'kill_chain_stage', 'tactic', 'technique', 'msg_class', 'engid_name',
    'hostname', 'login_type', 'login_result', 'process_name', 'event_id',
    'srcip_reputation', 'dstip_reputation']
  const top: Record<string, unknown> = {}
  const rest: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(raw)) {
    if (important.includes(k)) top[k] = v
    else rest[k] = v
  }
  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-3 p-2">
      <div>
        <p className="text-xs text-gray-500 mb-1 uppercase tracking-wider">Campos clave</p>
        <pre className="text-xs bg-gray-900 text-green-400 p-3 rounded overflow-auto max-h-48 font-mono">
          {JSON.stringify(top, null, 2)}
        </pre>
      </div>
      <div>
        <p className="text-xs text-gray-500 mb-1 uppercase tracking-wider">Todos los campos</p>
        <pre className="text-xs bg-gray-900 text-gray-400 p-3 rounded overflow-auto max-h-48 font-mono">
          {JSON.stringify(rest, null, 2)}
        </pre>
      </div>
    </div>
  )
}

function LogRowItem({ row }: { row: LogRow }) {
  const [open, setOpen] = useState(false)
  const threatScore = row.raw?.threat_score != null ? Number(row.raw.threat_score) : null
  const appName = (row.raw?.appid_name as string) || (row.raw?.login_type as string) || '-'
  const isDga = row.raw?.is_dga === 'yes'
  const isTunneling = Number(row.raw?.is_tunneling) > 0
  const geoObj = row.raw?.srcip_geo as Record<string, unknown> | null
  const srcCountry = (geoObj?.countryCode as string) || (row.raw?.country_code as string) || '-'
  const killChain = row.raw?.kill_chain_stage as string | undefined
  const tactic = row.raw?.tactic as string | undefined
  const loginResult = row.raw?.login_result as string | undefined
  const processName = row.raw?.process_name as string | undefined

  return (
    <>
      <tr
        className="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
        onClick={() => setOpen(o => !o)}
      >
        <td className="py-2 px-2 text-gray-500 w-6">
          {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
        </td>
        <td className="py-2 text-gray-400 text-xs whitespace-nowrap">
          {row.ts ? format(parseISO(row.ts), 'MM/dd HH:mm:ss') : '-'}
        </td>
        <td className="py-2 px-2">
          <span className="text-xs bg-gray-700 text-blue-300 px-1.5 py-0.5 rounded font-mono">
            {row.index}
          </span>
        </td>
        <td className="py-2 px-2 text-gray-300 text-xs font-mono max-w-[120px] truncate" title={row.host ?? ''}>
          {typeof row.host === 'string' && row.host.startsWith('{')
            ? (() => { try { const o = JSON.parse(row.host); return o.name || o.hostname || o.ip || row.host } catch { return row.host } })()
            : (row.host ?? '-')}
        </td>
        <td className="py-2 px-2 text-gray-400 text-xs max-w-[100px] truncate" title={row.event_type ?? (row.raw?.msg_class as string) ?? ''}>
          {row.event_type ?? (row.raw?.msg_class as string) ?? '-'}
        </td>
        <td className="py-2 px-2 text-gray-300 text-xs max-w-[100px] truncate" title={row.user_name ?? ''}>
          {row.user_name ?? '-'}
        </td>
        <td className="py-2 px-2"><ThreatScoreBadge score={threatScore} /></td>
        <td className="py-2 px-2 text-gray-400 text-xs">{appName}</td>
        <td className="py-2 px-2 text-gray-500 text-xs font-mono">{row.src_ip ?? '-'}</td>
        <td className="py-2 px-2 text-gray-500 text-xs font-bold">{srcCountry}</td>
        <td className="py-2 px-2 text-xs space-x-1">
          {isDga && <span className="bg-red-900 text-red-300 px-1.5 py-0.5 rounded text-xs">DGA</span>}
          {isTunneling && <span className="bg-purple-900 text-purple-300 px-1.5 py-0.5 rounded text-xs">TUN</span>}
          {killChain && <span className="bg-gray-700 text-gray-300 px-1.5 py-0.5 rounded text-xs" title={tactic}>{killChain}</span>}
          {loginResult && loginResult.toLowerCase().includes('fail') && (
            <span className="bg-orange-900/60 text-orange-300 px-1.5 py-0.5 rounded text-xs">FAIL</span>
          )}
          {processName && !killChain && !isDga && (
            <span className="bg-gray-800 text-gray-400 px-1.5 py-0.5 rounded text-xs font-mono truncate max-w-[80px]" title={processName}>{processName.split(/[\\/]/).pop()}</span>
          )}
        </td>
      </tr>
      {open && (
        <tr className="bg-gray-900/60">
          <td colSpan={11}><RawPanel raw={row.raw} /></td>
        </tr>
      )}
    </>
  )
}

export function LogBrowser() {
  const [page, setPage] = useState(1)
  const [range, setRange] = useState<TimeRange>('7d')
  const [customStart, setCustomStart] = useState('')
  const [customEnd, setCustomEnd] = useState('')
  const { start, end } = useMemo(() => toIso(range, customStart, customEnd), [range, customStart, customEnd])

  const [index, setIndex]               = useState('')
  const [appName, setAppName]           = useState('')
  const [threatScoreMin, setThreatScoreMin] = useState(0)
  const [isDga, setIsDga]               = useState<'' | 'yes' | 'no'>('')
  const [isTunneling, setIsTunneling]   = useState(false)
  const [srcCountry, setSrcCountry]     = useState('')
  const [host, setHost]                 = useState('')
  const [userName, setUserName]         = useState('')
  const [searchInput, setSearchInput]   = useState('')
  const [domainInput, setDomainInput]   = useState('')
  const [search, setSearch]             = useState('')
  const [domain, setDomain]             = useState('')

  const indexes  = useQuery({ queryKey: ['indexes'],  queryFn: api.logIndexes })
  const usersQ   = useQuery({ queryKey: ['logUsers'], queryFn: api.logUsers })

  const THREAT_INDEXES = new Set(['ade', 'adr', 'maltrace', 'scan'])
  const NETWORK_INDEXES = new Set(['ade', 'adr', 'maltrace', 'scan', 'ser'])
  const WIN_INDEXES = new Set(['wineventlog'])

  const showThreatFilters = !index || THREAT_INDEXES.has(index)
  const showNetworkFilters = !index || NETWORK_INDEXES.has(index)
  const showWinFilters = WIN_INDEXES.has(index)

  const filterParams: BrowseLogsParams = {
    page, page_size: 50,
    index: index || undefined,
    host: host || undefined,
    user_name: userName || undefined,
    search: search || undefined,
    start, end,
    threat_score_min: threatScoreMin > 0 ? threatScoreMin : undefined,
    is_dga: isDga || undefined,
    is_tunneling: isTunneling || undefined,
    app_name: appName || undefined,
    src_country: srcCountry || undefined,
    domain: domain || undefined,
  }

  const logsQuery = useQuery({
    queryKey: ['logs', filterParams],
    queryFn: () => api.browseLogs(filterParams),
  })

  const applySearch = useCallback(() => {
    setSearch(searchInput)
    setDomain(domainInput)
    setPage(1)
  }, [searchInput, domainInput])

  const applyNLResult = useCallback((filters: Partial<BrowseLogsParams>) => {
    if (filters.index)            setIndex(filters.index)
    if (filters.search)           { setSearch(filters.search); setSearchInput(filters.search) }
    if (filters.threat_score_min != null) setThreatScoreMin(filters.threat_score_min)
    if (filters.is_dga)           setIsDga(filters.is_dga as '' | 'yes' | 'no')
    if (filters.is_tunneling)     setIsTunneling(true)
    if (filters.app_name)         setAppName(filters.app_name)
    if (filters.src_country)      setSrcCountry(filters.src_country)
    if (filters.domain)           { setDomain(filters.domain); setDomainInput(filters.domain) }
    setPage(1)
  }, [])

  const reset = useCallback(() => {
    setPage(1); setIndex(''); setAppName(''); setThreatScoreMin(0)
    setIsDga(''); setIsTunneling(false); setSrcCountry('')
    setDomain(''); setDomainInput(''); setHost(''); setUserName('')
    setSearch(''); setSearchInput('')
  }, [])

  const activeFilters = [
    index        && { label: `Índice: ${index}`,         clear: () => { setIndex(''); setPage(1) } },
    userName     && { label: `Usuario: ${userName}`,     clear: () => { setUserName(''); setPage(1) } },
    host         && { label: `Host: ${host}`,            clear: () => { setHost(''); setPage(1) } },
    srcCountry   && { label: `País: ${srcCountry}`,      clear: () => { setSrcCountry(''); setPage(1) } },
    isDga === 'yes' && { label: 'DGA detectado',         clear: () => { setIsDga(''); setPage(1) } },
    isTunneling  && { label: 'Tunneling',                clear: () => { setIsTunneling(false); setPage(1) } },
    threatScoreMin > 0 && { label: `Score ≥ ${threatScoreMin}`, clear: () => { setThreatScoreMin(0); setPage(1) } },
    domain       && { label: `Dominio: ${domain}`,       clear: () => { setDomain(''); setDomainInput(''); setPage(1) } },
    search       && { label: `Búsqueda: "${search}"`,    clear: () => { setSearch(''); setSearchInput(''); setPage(1) } },
  ].filter(Boolean) as { label: string; clear: () => void }[]

  const inputCls = "bg-gray-700 border border-gray-600 text-white rounded px-2 py-1 text-sm"
  const labelCls = "text-xs text-gray-400 mb-1"
  const logs = logsQuery.data

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Log Browser</h1>
          <p className="text-gray-500 text-sm mt-0.5">Búsqueda sobre todos los índices</p>
        </div>
        <div className="flex items-center gap-3">
          <GlossaryTooltip />
          <TimeRangeSelector value={range} onChange={r => { setRange(r); setPage(1) }} customStart={customStart} customEnd={customEnd} onCustomChange={(s, e) => { setCustomStart(s); setCustomEnd(e); setPage(1) }} />
          <a
            href={api.exportUrl({ index: index || undefined, host: host || undefined, search: search || undefined, start, end })}
            download="soc_logs.csv"
            className="flex items-center gap-2 bg-gray-700 hover:bg-gray-600 text-white px-3 py-1.5 rounded text-sm"
          >
            <Download size={14} /> CSV
          </a>
        </div>
      </div>

      {/* NL Search */}
      <NLSearchBar onApply={applyNLResult} />

      {/* Filters */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 space-y-3">
        {/* Row 1: identity filters */}
        <div className="flex flex-wrap gap-3 items-end">
          <div className="flex flex-col">
            <span className={labelCls}>Índice</span>
            <select value={index} onChange={e => { setIndex(e.target.value); setPage(1) }} className={inputCls}>
              <option value="">Todos los índices</option>
              {indexes.data?.map(i => <option key={i} value={i}>{i}</option>)}
            </select>
          </div>

          <div className="flex flex-col">
            <span className={labelCls}>Usuario</span>
            <UserTypeahead value={userName} options={usersQ.data ?? []} onChange={v => { setUserName(v); setPage(1) }} />
          </div>

          <div className="flex flex-col">
            <span className={labelCls}>Host</span>
            <input placeholder="hostname…" value={host}
              onChange={e => { setHost(e.target.value); setPage(1) }}
              className={`${inputCls} w-36`}
            />
          </div>

          {showNetworkFilters && (
            <div className="flex flex-col">
              <span className={labelCls}>País Origen</span>
              <select value={srcCountry} onChange={e => { setSrcCountry(e.target.value); setPage(1) }} className={inputCls}>
                <option value="">Todos los países</option>
                {Object.entries(COUNTRIES).map(([code, name]) => (
                  <option key={code} value={code}>{code} — {name}</option>
                ))}
                <option value="OTHER">Otro (código ISO)</option>
              </select>
            </div>
          )}

          {srcCountry === 'OTHER' && (
            <div className="flex flex-col">
              <span className={labelCls}>Código ISO</span>
              <input placeholder="XX" maxLength={2}
                onChange={e => setSrcCountry(e.target.value.toUpperCase())}
                className={`${inputCls} w-16`}
              />
            </div>
          )}
        </div>

        {/* Row 2: threat filters — solo índices de red/amenaza */}
        {showThreatFilters && (
          <div className="flex flex-wrap gap-3 items-end">
            <div className="flex flex-col">
              <span className={labelCls}>Threat Score ≥</span>
              <div className="flex items-center gap-2">
                <input type="range" min={0} max={100} step={5} value={threatScoreMin}
                  onChange={e => { setThreatScoreMin(Number(e.target.value)); setPage(1) }}
                  className="w-24 accent-orange-500"
                />
                <span className={`text-xs font-mono w-8 ${threatScoreMin > 75 ? 'text-red-400' : threatScoreMin > 50 ? 'text-orange-400' : threatScoreMin > 0 ? 'text-yellow-400' : 'text-gray-500'}`}>
                  {threatScoreMin || '—'}
                </span>
              </div>
            </div>

            <div className="flex flex-col">
              <span className={labelCls}>DGA</span>
              <select value={isDga} onChange={e => { setIsDga(e.target.value as '' | 'yes' | 'no'); setPage(1) }} className={inputCls}>
                <option value="">Todos</option>
                <option value="yes">DGA detectado</option>
                <option value="no">Sin DGA</option>
              </select>
            </div>

            <div className="flex flex-col">
              <span className={labelCls}>Tunneling DNS</span>
              <select value={isTunneling ? 'yes' : ''} onChange={e => { setIsTunneling(e.target.value === 'yes'); setPage(1) }} className={inputCls}>
                <option value="">Todos</option>
                <option value="yes">Solo tunneling</option>
              </select>
            </div>

            <div className="flex flex-col">
              <span className={labelCls}>Protocolo / App</span>
              <select value={appName} onChange={e => { setAppName(e.target.value); setPage(1) }} className={inputCls}>
                <option value="">Todos</option>
                {['dns','http','https','ftp','smtp','ssh','rdp','smb'].map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
          </div>
        )}

        {/* Row 2b: Windows-specific filters */}
        {showWinFilters && (
          <div className="flex flex-wrap gap-3 items-end">
            <div className="flex flex-col">
              <span className={labelCls}>Tipo de evento</span>
              <select value={search} onChange={e => { setSearch(e.target.value); setSearchInput(e.target.value); setPage(1) }} className={`${inputCls} w-52`}>
                <option value="">Todos</option>
                <option value="4624">4624 — Inicio sesión exitoso</option>
                <option value="4625">4625 — Inicio sesión fallido</option>
                <option value="4648">4648 — Inicio sesión con credenciales explícitas</option>
                <option value="4688">4688 — Proceso creado</option>
                <option value="4698">4698 — Tarea programada creada</option>
                <option value="4720">4720 — Usuario creado</option>
                <option value="4732">4732 — Miembro agregado a grupo</option>
                <option value="4776">4776 — Validación NTLM</option>
                <option value="7045">7045 — Servicio instalado</option>
              </select>
            </div>
          </div>
        )}

        {/* Row 3: free text */}
        <div className="flex flex-wrap gap-2 items-end">
          <div className="flex flex-col">
            <span className={labelCls}>Dominio</span>
            <input placeholder="ejemplo.com…" value={domainInput}
              onChange={e => setDomainInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && applySearch()}
              className={`${inputCls} w-48`}
            />
          </div>
          <div className="flex flex-col">
            <span className={labelCls}>Búsqueda libre</span>
            <input placeholder="IP, host, usuario, evento…" value={searchInput}
              onChange={e => setSearchInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && applySearch()}
              className={`${inputCls} w-56`}
            />
          </div>
          <button onClick={applySearch} className="flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white px-3 py-1.5 rounded text-sm">
            <Search size={13} /> Buscar
          </button>
          {activeFilters.length > 0 && (
            <button onClick={reset} className="text-gray-400 hover:text-white text-sm px-2 py-1.5 rounded border border-gray-600 hover:border-gray-400">
              Limpiar todo
            </button>
          )}
        </div>

        {/* Active filter badges */}
        {activeFilters.length > 0 && (
          <div className="flex flex-wrap gap-2 pt-1">
            {activeFilters.map((f, i) => (
              <ActiveFilter key={i} label={f.label} onRemove={f.clear} />
            ))}
          </div>
        )}
      </div>

      {/* Results */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-x-auto">
        {logsQuery.isLoading ? (
          <div className="p-8 text-center text-gray-500">Cargando logs...</div>
        ) : logsQuery.error ? (
          <div className="p-8 text-center text-red-400">Error al cargar logs</div>
        ) : (
          <>
            <div className="px-4 py-2 border-b border-gray-700 text-xs text-gray-400 flex justify-between">
              <span>{logs?.total.toLocaleString()} registros encontrados</span>
              {logsQuery.isFetching && <span className="text-blue-400 animate-pulse">Actualizando…</span>}
            </div>
            <table className="w-full text-sm min-w-[1000px]">
              <thead>
                <tr className="text-gray-400 text-xs border-b border-gray-700 bg-gray-900/40">
                  <th className="w-6" />
                  <th className="text-left py-2">Timestamp</th>
                  <th className="text-left py-2 px-2">Índice</th>
                  <th className="text-left py-2 px-2">Host</th>
                  <th className="text-left py-2 px-2">Tipo</th>
                  <th className="text-left py-2 px-2">Usuario</th>
                  <th className="text-left py-2 px-2">Score</th>
                  <th className="text-left py-2 px-2">App</th>
                  <th className="text-left py-2 px-2">Src IP</th>
                  <th className="text-left py-2 px-2">País</th>
                  <th className="text-left py-2 px-2">Flags</th>
                </tr>
              </thead>
              <tbody>
                {logs?.items.map(row => <LogRowItem key={row.id} row={row} />)}
                {logs?.items.length === 0 && (
                  <tr><td colSpan={10} className="py-8 text-center text-gray-500">Sin resultados para los filtros aplicados</td></tr>
                )}
              </tbody>
            </table>
            <div className="flex items-center justify-between px-4 py-3 border-t border-gray-700">
              <button disabled={page <= 1} onClick={() => setPage(p => p - 1)}
                className="px-3 py-1 bg-gray-700 rounded text-sm disabled:opacity-40 hover:bg-gray-600">
                ← Anterior
              </button>
              <span className="text-gray-400 text-sm">Página {page} de {logs?.pages ?? 1}</span>
              <button disabled={page >= (logs?.pages ?? 1)} onClick={() => setPage(p => p + 1)}
                className="px-3 py-1 bg-gray-700 rounded text-sm disabled:opacity-40 hover:bg-gray-600">
                Siguiente →
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
