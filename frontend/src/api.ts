const BASE = '/api'

async function get<T>(path: string, params?: Record<string, string | number | boolean | undefined>): Promise<T> {
  const url = new URL(BASE + path, window.location.origin)
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null) url.searchParams.set(k, String(v))
    }
  }
  const res = await fetch(url.toString())
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

async function put<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json() as Promise<T>
}

export type TimeRange = '24h' | '7d' | '30d' | '6M' | '2026' | 'custom'

export function toIso(range: TimeRange, customStart?: string, customEnd?: string) {
  const now = new Date()
  if (range === 'custom') return { start: customStart ?? '', end: customEnd ?? '' }
  if (range === '2026') return { start: '2026-01-01T00:00:00.000Z', end: now.toISOString() }
  const start = new Date(now)
  if (range === '6M') {
    start.setMonth(now.getMonth() - 6)
  } else {
    const offsets: Record<string, number> = { '24h': 1, '7d': 7, '30d': 30 }
    start.setDate(now.getDate() - (offsets[range] ?? 7))
  }
  return { start: start.toISOString(), end: now.toISOString() }
}

// ---- KPI types ----

export interface Overview {
  total_events: number
  threat_score_high: number
  dga_detections: number
  tunneling_events: number
  unique_external_ips: number
  by_index: Record<string, number>
  time_range: { min: string | null; max: string | null }
}

export interface AlertPoint {
  period: string
  msg_class: string
  count: number
}

export interface ThreatDevice {
  device: string
  max_threat_score: number
  count: number
  last_seen: string
}

export interface DomainStat {
  domain: string
  count: number
  reputation: string
  is_dga: string
}

export interface AppStat {
  app: string
  count: number
}

export interface GeoStat {
  country: string
  count: number
}

export interface NetworkThreat {
  device: string
  threat_score: number
  app: string
  is_dga: string
  ts: string
}

export interface SyslogVolume {
  by_host: { host: string; count: number }[]
  by_event_type: { event_type: string; count: number }[]
  timeline: { period: string; index: string; count: number }[]
}

export interface UsersActivity {
  top_users: { user: string; count: number; last_seen: string }[]
  user_events: { user: string; event_type: string; count: number }[]
}

export interface AssetsActivity {
  top_assets: { asset: string; count: number; last_seen: string }[]
}

export interface LogRow {
  id: string
  index: string
  ts: string
  severity: string | null
  host: string | null
  user_name: string | null
  event_type: string | null
  src_ip: string | null
  dst_ip: string | null
  raw: Record<string, unknown>
}

export interface LogsPage {
  total: number
  page: number
  page_size: number
  pages: number
  items: LogRow[]
}

export interface BrowseLogsParams {
  page?: number
  page_size?: number
  index?: string
  start?: string
  end?: string
  host?: string
  user_name?: string
  severity?: string
  search?: string
  threat_score_min?: number
  is_dga?: string
  is_tunneling?: boolean
  app_name?: string
  src_country?: string
  domain?: string
}

export interface CoverageDay {
  day: string
  count: number
}

export interface CoverageReport {
  index: string
  months_requested: number
  required_days: number
  days_with_data: number
  coverage_pct: number
  compliant: boolean
  days: CoverageDay[]
  error?: string
}

export interface IngestStatus {
  running: boolean
  last_result: Record<string, unknown>
  sync_status: { last_sync: string | null; status: string; details: string }
}

export interface Config {
  s3_endpoint: string
  s3_bucket: string
  s3_region: string
  org_id: string
  tenant_id: string
  local_sync_path: string
  db_path: string
  indexes: string[]
}

export interface ParquetMonthStatus {
  index: string
  year: number
  month: number
  row_count: number
  converted_at: string
}

export interface ParquetSyncStatus {
  sync: {
    running: boolean
    progress: { month: string; status: string }[]
    pct?: number
    error: string[] | null
    started_at?: string
    finished_at?: string
  }
  converted_months: ParquetMonthStatus[]
  total_converted: number
}

export const api = {
  overview: (p: Record<string, string | undefined>) => get<Overview>('/kpis/overview', p),
  alertsTimeline: (p: Record<string, string | undefined>) => get<AlertPoint[]>('/kpis/alerts/timeline', p),
  topThreats: (p: Record<string, string | number | undefined>) => get<ThreatDevice[]>('/kpis/alerts/top-threats', p),
  syslogVolume: (p: Record<string, string | undefined>) => get<SyslogVolume>('/kpis/syslog/volume', p),
  usersActivity: (p: Record<string, string | undefined>) => get<UsersActivity>('/kpis/users/activity', p),
  assetsActivity: (p: Record<string, string | undefined>) => get<AssetsActivity>('/kpis/assets/activity', p),

  coverage: (index: string, months: number) => get<CoverageReport>('/kpis/coverage', { index, months: String(months) }),

  networkTopDomains: (p: Record<string, string | undefined>) => get<DomainStat[]>('/kpis/network/top-domains', p),
  networkApps: (p: Record<string, string | undefined>) => get<AppStat[]>('/kpis/network/apps', p),
  networkGeo: (p: Record<string, string | undefined>) => get<GeoStat[]>('/kpis/network/geo', p),
  networkThreats: (p: Record<string, string | undefined>) => get<NetworkThreat[]>('/kpis/network/threats', p),

  browseLogs: (p: BrowseLogsParams) => get<LogsPage>('/logs/browse', p as Record<string, string | number | boolean | undefined>),
  logIndexes: () => get<string[]>('/logs/indexes'),
  logUsers: () => get<string[]>('/logs/users'),
  triggerSync: (body: Record<string, unknown>) => post<{ status: string }>('/ingest/sync', body),
  triggerLoad: () => post<{ status: string }>('/ingest/load'),
  ingestStatus: () => get<IngestStatus>('/ingest/status'),
  getConfig: () => get<Config>('/config'),
  updateConfig: (body: Partial<Config>) => put<{ status: string; updated: string[] }>('/config', body),
  parquetStatus: () => get<ParquetSyncStatus>('/admin/parquet/status'),
  parquetConvert: (months_back: number) =>
    post<{ started: boolean; message: string }>(`/admin/parquet/convert?months_back=${months_back}`),
  parquetConvertMonth: (year: number, month: number) =>
    post<{ started: boolean; year: number; month: number }>(`/admin/parquet/convert-month?year=${year}&month=${month}`),
  parquetRefresh: () =>
    post<{ started: boolean; message: string }>('/admin/parquet/refresh'),

  exportUrl: (params: Record<string, string | undefined>) => {
    const url = new URL('/api/logs/export', window.location.origin)
    for (const [k, v] of Object.entries(params)) {
      if (v) url.searchParams.set(k, v)
    }
    return url.toString()
  },
}
