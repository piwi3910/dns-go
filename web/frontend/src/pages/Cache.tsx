import { useState, useEffect } from 'react'
import { Database, Trash2, AlertCircle, RefreshCw, CheckCircle, Server, Layers, Info } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Progress } from '@/components/ui/progress'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { distributedCacheApi, type DistributedCacheResponse, type WorkerCacheInfo } from '@/lib/api'
import { formatBytes, formatNumber } from '@/lib/utils'

export function Cache() {
  const [cacheData, setCacheData] = useState<DistributedCacheResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [clearing, setClearing] = useState<string | null>(null)
  const [selectedWorker, setSelectedWorker] = useState<string>('all')

  const fetchStats = async () => {
    try {
      const data = await distributedCacheApi.get()
      setCacheData(data)
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

  const handleClear = async (cacheType: 'all' | 'message' | 'rrset' | 'infra', target: 'all' | 'worker' = 'all') => {
    const targetDesc = target === 'all' ? 'all workers' : 'selected worker'
    if (!confirm(`Are you sure you want to clear the ${cacheType} cache on ${targetDesc}?`)) return

    setClearing(`${target}-${cacheType}`)
    setError(null)
    setSuccess(null)

    try {
      const result = await distributedCacheApi.clear({
        target,
        workerIds: target === 'worker' && selectedWorker !== 'all' ? [selectedWorker] : undefined,
        cacheType,
      })
      const workerCount = result.clearedCount
      setSuccess(`Successfully cleared ${cacheType} cache on ${workerCount} worker(s)`)
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

  const renderWorkerCache = (worker: WorkerCacheInfo) => (
    <Card key={worker.workerId} className="border-l-4 border-l-primary">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Server className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-base">{worker.workerId}</CardTitle>
            <Badge variant={worker.status === 'healthy' ? 'success' : 'destructive'}>
              {worker.status}
            </Badge>
          </div>
          <span className="text-sm text-muted-foreground">{worker.address}</span>
        </div>
        <CardDescription>Cluster: {worker.clusterName}</CardDescription>
      </CardHeader>
      <CardContent>
        <div className="grid gap-4 md:grid-cols-2">
          {/* Message Cache */}
          <div className="rounded-lg border p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-medium flex items-center gap-2">
                <Database className="h-4 w-4" />
                Message Cache (L1)
              </h4>
              <Badge variant="outline">{formatBytes(worker.messageCache.size_bytes)}</Badge>
            </div>
            <div className="space-y-1">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Hit Rate</span>
                <span className="font-medium">{worker.messageCache.hit_rate.toFixed(1)}%</span>
              </div>
              <Progress value={worker.messageCache.hit_rate} className="h-2" />
            </div>
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="text-center p-2 rounded bg-green-500/10">
                <div className="font-medium text-green-600">{formatNumber(worker.messageCache.hits)}</div>
                <div className="text-muted-foreground">Hits</div>
              </div>
              <div className="text-center p-2 rounded bg-red-500/10">
                <div className="font-medium text-red-600">{formatNumber(worker.messageCache.misses)}</div>
                <div className="text-muted-foreground">Misses</div>
              </div>
              <div className="text-center p-2 rounded bg-yellow-500/10">
                <div className="font-medium text-yellow-600">{formatNumber(worker.messageCache.evicts)}</div>
                <div className="text-muted-foreground">Evicts</div>
              </div>
            </div>
          </div>

          {/* RRset Cache */}
          <div className="rounded-lg border p-4 space-y-3">
            <div className="flex items-center justify-between">
              <h4 className="font-medium flex items-center gap-2">
                <Database className="h-4 w-4" />
                RRset Cache (L2)
              </h4>
              <Badge variant="outline">{formatBytes(worker.rrsetCache.size_bytes)}</Badge>
            </div>
            <div className="space-y-1">
              <div className="flex justify-between text-sm">
                <span className="text-muted-foreground">Hit Rate</span>
                <span className="font-medium">{worker.rrsetCache.hit_rate.toFixed(1)}%</span>
              </div>
              <Progress value={worker.rrsetCache.hit_rate} className="h-2" />
            </div>
            <div className="grid grid-cols-3 gap-2 text-xs">
              <div className="text-center p-2 rounded bg-green-500/10">
                <div className="font-medium text-green-600">{formatNumber(worker.rrsetCache.hits)}</div>
                <div className="text-muted-foreground">Hits</div>
              </div>
              <div className="text-center p-2 rounded bg-red-500/10">
                <div className="font-medium text-red-600">{formatNumber(worker.rrsetCache.misses)}</div>
                <div className="text-muted-foreground">Misses</div>
              </div>
              <div className="text-center p-2 rounded bg-yellow-500/10">
                <div className="font-medium text-yellow-600">{formatNumber(worker.rrsetCache.evicts)}</div>
                <div className="text-muted-foreground">Evicts</div>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Distributed Cache Management</h1>
          <p className="text-muted-foreground">View and manage DNS cache across all workers</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchStats}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button
            variant="destructive"
            onClick={() => handleClear('all', 'all')}
            disabled={clearing !== null}
          >
            <Trash2 className="mr-2 h-4 w-4" />
            {clearing === 'all-all' ? 'Clearing...' : 'Clear All Caches'}
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

      {cacheData && (
        <>
          {/* Architecture Info */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-lg">
                <Layers className="h-5 w-5" />
                Cache Architecture
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-4 items-center">
                <Badge variant="outline" className="text-sm">
                  Mode: {cacheData.mode}
                </Badge>
                <Badge variant="outline" className="text-sm">
                  L1: {cacheData.architecture.l1Type}
                </Badge>
                <Badge variant="outline" className="text-sm">
                  L2: {cacheData.architecture.l2Type}
                </Badge>
                <Badge variant="outline" className="text-sm">
                  Replication: {cacheData.architecture.replication}
                </Badge>
                <Badge variant="outline" className="text-sm">
                  Invalidation: {cacheData.architecture.invalidation}
                </Badge>
              </div>
              <p className="mt-3 text-sm text-muted-foreground flex items-center gap-2">
                <Info className="h-4 w-4" />
                {cacheData.architecture.description}
              </p>
              <div className="mt-2 flex gap-2 flex-wrap">
                {cacheData.architecture.features.map((feature) => (
                  <Badge key={feature} variant="secondary" className="text-xs">
                    {feature}
                  </Badge>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Aggregated Stats */}
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Total Workers</p>
                  <p className="text-3xl font-bold">{cacheData.aggregated.workerCount}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Avg Hit Rate</p>
                  <p className="text-3xl font-bold text-green-600">
                    {cacheData.aggregated.averageHitRate.toFixed(1)}%
                  </p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Total Hits</p>
                  <p className="text-3xl font-bold">{formatNumber(cacheData.aggregated.totalHits)}</p>
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="text-center">
                  <p className="text-sm text-muted-foreground">Total Size</p>
                  <p className="text-3xl font-bold">{formatBytes(cacheData.aggregated.totalSizeBytes)}</p>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Worker Filter and Clear Options */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg">Cache Operations</CardTitle>
                <div className="flex items-center gap-2">
                  <span className="text-sm text-muted-foreground">Target:</span>
                  <Select value={selectedWorker} onValueChange={setSelectedWorker}>
                    <SelectTrigger className="w-[200px]">
                      <SelectValue placeholder="Select worker" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Workers</SelectItem>
                      {cacheData.workers.map((worker) => (
                        <SelectItem key={worker.workerId} value={worker.workerId}>
                          {worker.workerId}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleClear('message', selectedWorker === 'all' ? 'all' : 'worker')}
                  disabled={clearing !== null}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Clear Message Cache
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleClear('rrset', selectedWorker === 'all' ? 'all' : 'worker')}
                  disabled={clearing !== null}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Clear RRset Cache
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleClear('infra', selectedWorker === 'all' ? 'all' : 'worker')}
                  disabled={clearing !== null}
                >
                  <Trash2 className="mr-2 h-4 w-4" />
                  Clear Infra Cache
                </Button>
                {cacheData.sharedCache && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleClear('all', 'shared' as 'all')}
                    disabled={clearing !== null}
                  >
                    <Trash2 className="mr-2 h-4 w-4" />
                    Clear Shared Cache
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Shared Cache (if available) */}
          {cacheData.sharedCache && (
            <Card className="border-l-4 border-l-blue-500">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Database className="h-5 w-5 text-blue-500" />
                      Shared Cache ({cacheData.sharedCache.type})
                    </CardTitle>
                    <CardDescription>
                      {cacheData.sharedCache.address} - Status: {cacheData.sharedCache.status}
                    </CardDescription>
                  </div>
                  <Badge variant={cacheData.sharedCache.status === 'connected' ? 'success' : 'destructive'}>
                    {cacheData.sharedCache.status}
                  </Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid gap-4 md:grid-cols-4">
                  <div>
                    <p className="text-sm text-muted-foreground">Hits</p>
                    <p className="text-xl font-bold">{formatNumber(cacheData.sharedCache.stats.hits)}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Misses</p>
                    <p className="text-xl font-bold">{formatNumber(cacheData.sharedCache.stats.misses)}</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Hit Rate</p>
                    <p className="text-xl font-bold">{cacheData.sharedCache.stats.hit_rate.toFixed(1)}%</p>
                  </div>
                  <div>
                    <p className="text-sm text-muted-foreground">Size</p>
                    <p className="text-xl font-bold">{formatBytes(cacheData.sharedCache.stats.size_bytes)}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Per-Worker Cache Stats */}
          <div className="space-y-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Server className="h-5 w-5" />
              Per-Worker Cache Statistics
            </h2>
            {cacheData.workers
              .filter((w) => selectedWorker === 'all' || w.workerId === selectedWorker)
              .map(renderWorkerCache)}
          </div>
        </>
      )}
    </div>
  )
}
