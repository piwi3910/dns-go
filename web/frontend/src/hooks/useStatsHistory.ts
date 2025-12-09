import { useState, useEffect, useCallback, useRef } from 'react'
import type { Stats } from '@/lib/api'

export interface StatsHistoryPoint {
  timestamp: number
  time: string
  memory_mb: number
  goroutines: number
  cache_hit_rate: number
  rrset_hit_rate: number
  cache_hits: number
  cache_misses: number
  rrset_hits: number
  rrset_misses: number
  in_flight_queries: number
  uptime_seconds: number
}

const MAX_HISTORY_POINTS = 60 // Keep 60 data points (1 minute at 1 second intervals)

export function useStatsHistory(stats: Stats | null) {
  const [history, setHistory] = useState<StatsHistoryPoint[]>([])
  const lastUpdateRef = useRef<number>(0)
  const prevStatsRef = useRef<{
    cache_hits: number
    cache_misses: number
    rrset_hits: number
    rrset_misses: number
  } | null>(null)

  const addDataPoint = useCallback((currentStats: Stats) => {
    const now = Date.now()

    // Only add a new point every second
    if (now - lastUpdateRef.current < 1000) {
      return
    }
    lastUpdateRef.current = now

    const timeString = new Date(now).toLocaleTimeString('en-US', {
      hour12: false,
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })

    // Calculate deltas for rate calculation
    const prevStats = prevStatsRef.current
    let cacheHitsDelta = currentStats.cache.message_cache.hits
    let cacheMissesDelta = currentStats.cache.message_cache.misses
    let rrsetHitsDelta = currentStats.cache.rrset_cache.hits
    let rrsetMissesDelta = currentStats.cache.rrset_cache.misses

    if (prevStats) {
      cacheHitsDelta = currentStats.cache.message_cache.hits - prevStats.cache_hits
      cacheMissesDelta = currentStats.cache.message_cache.misses - prevStats.cache_misses
      rrsetHitsDelta = currentStats.cache.rrset_cache.hits - prevStats.rrset_hits
      rrsetMissesDelta = currentStats.cache.rrset_cache.misses - prevStats.rrset_misses
    }

    prevStatsRef.current = {
      cache_hits: currentStats.cache.message_cache.hits,
      cache_misses: currentStats.cache.message_cache.misses,
      rrset_hits: currentStats.cache.rrset_cache.hits,
      rrset_misses: currentStats.cache.rrset_cache.misses
    }

    const newPoint: StatsHistoryPoint = {
      timestamp: now,
      time: timeString,
      memory_mb: currentStats.server.memory_mb,
      goroutines: currentStats.server.num_goroutines,
      cache_hit_rate: currentStats.cache.message_cache.hit_rate * 100,
      rrset_hit_rate: currentStats.cache.rrset_cache.hit_rate * 100,
      cache_hits: cacheHitsDelta,
      cache_misses: cacheMissesDelta,
      rrset_hits: rrsetHitsDelta,
      rrset_misses: rrsetMissesDelta,
      in_flight_queries: currentStats.resolver.in_flight_queries,
      uptime_seconds: currentStats.server.uptime_seconds
    }

    setHistory(prev => {
      const updated = [...prev, newPoint]
      // Keep only the last MAX_HISTORY_POINTS
      if (updated.length > MAX_HISTORY_POINTS) {
        return updated.slice(-MAX_HISTORY_POINTS)
      }
      return updated
    })
  }, [])

  useEffect(() => {
    if (stats) {
      addDataPoint(stats)
    }
  }, [stats, addDataPoint])

  // Calculate QPS from history (queries per second based on cache activity)
  const calculateQPS = useCallback(() => {
    if (history.length < 2) return 0
    const recent = history.slice(-5) // Last 5 seconds
    const totalQueries = recent.reduce((sum, p) => sum + p.cache_hits + p.cache_misses, 0)
    return totalQueries / Math.max(recent.length, 1)
  }, [history])

  return {
    history,
    currentQPS: calculateQPS()
  }
}
