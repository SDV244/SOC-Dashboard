import { createContext, useContext, useState } from 'react'
import type { ReactNode } from 'react'
import type { TimeRange } from './lib/api'

interface TimeRangeCtx {
  range: TimeRange
  setRange: (r: TimeRange) => void
  customStart: string
  setCustomStart: (s: string) => void
  customEnd: string
  setCustomEnd: (e: string) => void
}

const TimeRangeContext = createContext<TimeRangeCtx | null>(null)

export function TimeRangeProvider({ children }: { children: ReactNode }) {
  const [range, setRange] = useState<TimeRange>('7d')
  const [customStart, setCustomStart] = useState('')
  const [customEnd, setCustomEnd] = useState('')

  return (
    <TimeRangeContext.Provider value={{ range, setRange, customStart, setCustomStart, customEnd, setCustomEnd }}>
      {children}
    </TimeRangeContext.Provider>
  )
}

export function useTimeRange() {
  const ctx = useContext(TimeRangeContext)
  if (!ctx) throw new Error('useTimeRange must be used within TimeRangeProvider')
  return ctx
}
