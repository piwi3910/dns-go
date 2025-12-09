import { useState, useEffect } from 'react'
import { Database, Trash2, AlertCircle, RefreshCw, CheckCircle } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Progress } from '@/components/ui/progress'
import { cacheApi, type CacheStats as CacheStatsType } from '@/lib/api'
import { formatBytes, formatNumber } from '@/lib/utils'

export function Cache() {
  const [stats, setStats] = useState<CacheStatsType | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [clearing, setClearing] = useState<string | null>(null)

  const fetchStats = async () => {
    try {
      const data = await cacheApi.stats()
      setStats(data)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch cache stats')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchStats()
    const interval = setInterval(fetchStats, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleClear = async (cacheType: 'all' | 'message' | 'rrset' | 'infra') => {
    if (!confirm(`Are you sure you want to clear the ${cacheType} cache?`)) return

    setClearing(cacheType)
    setError(null)
    setSuccess(null)

    try {
      await cacheApi.clear(cacheType)
      setSuccess(`Successfully cleared ${cacheType} cache`)
      fetchStats()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to clear cache')
    } finally {
      setClearing(null)
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="text-center">
          <div className="mb-4 h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading cache statistics...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Cache Management</h1>
          <p className="text-muted-foreground">View and manage DNS cache</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchStats}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button
            variant="destructive"
            onClick={() => handleClear('all')}
            disabled={clearing !== null}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            {clearing === 'all' ? 'Clearing...' : 'Clear All Caches'}
          </Button>
        </div>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {success && (
        <Alert variant="success">
          <CheckCircle className="h-4 w-4" />
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      {stats && (
        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Database className="h-5 w-5" />
                    Message Cache
                  </CardTitle>
                  <CardDescription>Complete DNS response cache (L1)</CardDescription>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleClear('message')}
                  disabled={clearing !== null}
                >
                  {clearing === 'message' ? 'Clearing...' : 'Clear'}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Entries</p>
                  <p className="text-2xl font-bold">{formatNumber(stats.message_cache.entries)}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Size</p>
                  <p className="text-2xl font-bold">
                    {formatBytes(stats.message_cache.size_bytes)}
                  </p>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-muted-foreground">Hit Rate</span>
                  <span className="font-medium">
                    {(stats.message_cache.hit_rate * 100).toFixed(1)}%
                  </span>
                </div>
                <Progress value={stats.message_cache.hit_rate * 100} />
              </div>

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="flex items-center justify-between rounded-lg bg-green-500/10 p-3">
                  <span className="text-muted-foreground">Hits</span>
                  <Badge variant="success">{formatNumber(stats.message_cache.hits)}</Badge>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-red-500/10 p-3">
                  <span className="text-muted-foreground">Misses</span>
                  <Badge variant="destructive">{formatNumber(stats.message_cache.misses)}</Badge>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Database className="h-5 w-5" />
                    RRset Cache
                  </CardTitle>
                  <CardDescription>Individual resource record cache (L2)</CardDescription>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleClear('rrset')}
                  disabled={clearing !== null}
                >
                  {clearing === 'rrset' ? 'Clearing...' : 'Clear'}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Entries</p>
                  <p className="text-2xl font-bold">{formatNumber(stats.rrset_cache.entries)}</p>
                </div>
                <div>
                  <p className="text-sm text-muted-foreground">Size</p>
                  <p className="text-2xl font-bold">
                    {formatBytes(stats.rrset_cache.size_bytes)}
                  </p>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-muted-foreground">Hit Rate</span>
                  <span className="font-medium">
                    {(stats.rrset_cache.hit_rate * 100).toFixed(1)}%
                  </span>
                </div>
                <Progress value={stats.rrset_cache.hit_rate * 100} />
              </div>

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div className="flex items-center justify-between rounded-lg bg-green-500/10 p-3">
                  <span className="text-muted-foreground">Hits</span>
                  <Badge variant="success">{formatNumber(stats.rrset_cache.hits)}</Badge>
                </div>
                <div className="flex items-center justify-between rounded-lg bg-red-500/10 p-3">
                  <span className="text-muted-foreground">Misses</span>
                  <Badge variant="destructive">{formatNumber(stats.rrset_cache.misses)}</Badge>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card className="md:col-span-2">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="flex items-center gap-2">
                    <Database className="h-5 w-5" />
                    Infrastructure Cache
                  </CardTitle>
                  <CardDescription>Upstream server metrics and health data</CardDescription>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleClear('infra')}
                  disabled={clearing !== null}
                >
                  {clearing === 'infra' ? 'Clearing...' : 'Clear'}
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-4">
                <div>
                  <p className="text-sm text-muted-foreground">Entries</p>
                  <p className="text-2xl font-bold">{formatNumber(stats.infra_cache.entries)}</p>
                </div>
                <p className="text-sm text-muted-foreground">
                  Stores RTT, failure rates, and health metrics for upstream servers
                </p>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
