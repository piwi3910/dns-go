import { useEffect, useState } from 'react'
import {
  Server,
  MapPin,
  Activity,
  RefreshCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
  Clock,
  Cpu,
  HardDrive,
  Zap,
  Filter,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { formatNumber, formatBytes, formatUptime } from '@/lib/utils'
import { clustersApi, type ClusterWorker, type WorkersResponse } from '@/lib/api'

export function Workers() {
  const [data, setData] = useState<WorkersResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [filterCluster, setFilterCluster] = useState<string>('all')
  const [filterRegion, setFilterRegion] = useState<string>('all')

  const fetchWorkers = async () => {
    try {
      setError(null)
      const response = await clustersApi.getWorkers(
        filterCluster !== 'all' ? filterCluster : undefined
      )
      setData(response)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch workers')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchWorkers()
    const interval = setInterval(fetchWorkers, 5000)
    return () => clearInterval(interval)
  }, [filterCluster])

  const getStatusIcon = (status: ClusterWorker['status']) => {
    switch (status) {
      case 'Running':
        return <CheckCircle2 className="h-4 w-4 text-emerald-500" />
      case 'Stopped':
        return <XCircle className="h-4 w-4 text-gray-500" />
      case 'Starting':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
      case 'Error':
        return <AlertTriangle className="h-4 w-4 text-red-500" />
      default:
        return <Activity className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusBadge = (status: ClusterWorker['status']) => {
    const variants: Record<ClusterWorker['status'], 'success' | 'destructive' | 'secondary' | 'outline'> = {
      Running: 'success',
      Stopped: 'secondary',
      Starting: 'outline',
      Error: 'destructive',
      Unknown: 'secondary',
    }
    return <Badge variant={variants[status] || 'secondary'}>{status}</Badge>
  }

  if (loading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="text-center">
          <div className="mb-4 h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading workers...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <Card className="w-full max-w-md">
          <CardContent className="pt-6 text-center">
            <AlertTriangle className="h-12 w-12 text-orange-500 mx-auto mb-4" />
            <h3 className="font-semibold mb-2">Failed to Load Workers</h3>
            <p className="text-sm text-muted-foreground mb-4">{error}</p>
            <Button onClick={fetchWorkers}>
              <RefreshCcw className="h-4 w-4 mr-2" />
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  const workers = data?.workers || []
  const clusters = Object.keys(data?.byCluster || {})
  const regions = Object.keys(data?.byRegion || {})

  // Filter workers by region (cluster filter is handled server-side)
  const filteredWorkers =
    filterRegion === 'all'
      ? workers
      : workers.filter((w) => w.region === filterRegion)

  const runningWorkers = filteredWorkers.filter((w) => w.status === 'Running')
  const avgQPS =
    runningWorkers.length > 0
      ? runningWorkers.reduce((sum, w) => sum + w.metrics.qps, 0) / runningWorkers.length
      : 0
  const avgCacheHitRate =
    runningWorkers.length > 0
      ? runningWorkers.reduce((sum, w) => sum + w.metrics.cacheHitRate, 0) / runningWorkers.length
      : 0

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Workers</h1>
          <p className="text-muted-foreground">DNS workers across all clusters</p>
        </div>
        <Button variant="outline" onClick={fetchWorkers}>
          <RefreshCcw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Server className="h-4 w-4" />
              Total Workers
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{filteredWorkers.length}</div>
            <p className="text-xs text-muted-foreground">
              {runningWorkers.length} running
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Zap className="h-4 w-4" />
              Avg QPS
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{formatNumber(avgQPS)}</div>
            <p className="text-xs text-muted-foreground">per worker</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Avg Cache Hit Rate
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{avgCacheHitRate.toFixed(1)}%</div>
            <Progress value={avgCacheHitRate} className="h-2 mt-2" />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <MapPin className="h-4 w-4" />
              Regions
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{regions.length}</div>
            <p className="text-xs text-muted-foreground">{clusters.length} clusters</p>
          </CardContent>
        </Card>
      </div>

      {/* Filters */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4 text-muted-foreground" />
              <span className="text-sm font-medium">Filters:</span>
            </div>
            <Select value={filterCluster} onValueChange={setFilterCluster}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Clusters" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Clusters</SelectItem>
                {clusters.map((cluster) => (
                  <SelectItem key={cluster} value={cluster}>
                    {cluster} ({data?.byCluster[cluster] || 0})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={filterRegion} onValueChange={setFilterRegion}>
              <SelectTrigger className="w-[180px]">
                <SelectValue placeholder="All Regions" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Regions</SelectItem>
                {regions.map((region) => (
                  <SelectItem key={region} value={region}>
                    {region} ({data?.byRegion[region] || 0})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Workers Table */}
      {filteredWorkers.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Server className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="font-semibold mb-2">No Workers Found</h3>
            <p className="text-sm text-muted-foreground">
              {filterCluster !== 'all' || filterRegion !== 'all'
                ? 'Try adjusting your filters.'
                : 'Workers will appear here once they connect.'}
            </p>
          </CardContent>
        </Card>
      ) : (
        <Card>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b bg-muted/50">
                    <th className="text-left p-4 font-medium text-sm">Worker</th>
                    <th className="text-left p-4 font-medium text-sm">Location</th>
                    <th className="text-left p-4 font-medium text-sm">Status</th>
                    <th className="text-right p-4 font-medium text-sm">QPS</th>
                    <th className="text-right p-4 font-medium text-sm">Cache Hit</th>
                    <th className="text-right p-4 font-medium text-sm">Memory</th>
                    <th className="text-right p-4 font-medium text-sm">CPU</th>
                    <th className="text-right p-4 font-medium text-sm">Uptime</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredWorkers.map((worker) => (
                    <tr
                      key={worker.id}
                      className="border-b transition-colors hover:bg-muted/50"
                    >
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(worker.status)}
                          <div>
                            <p className="font-mono text-sm font-medium">
                              {worker.id.slice(0, 8)}...
                            </p>
                            <p className="text-xs text-muted-foreground">
                              {worker.address}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="p-4">
                        <div className="flex items-center gap-2">
                          <MapPin className="h-4 w-4 text-muted-foreground" />
                          <div>
                            <p className="text-sm">{worker.clusterName}</p>
                            <p className="text-xs text-muted-foreground">
                              {worker.region}
                              {worker.zone && ` / ${worker.zone}`}
                            </p>
                          </div>
                        </div>
                      </td>
                      <td className="p-4">{getStatusBadge(worker.status)}</td>
                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Zap className="h-3 w-3 text-muted-foreground" />
                          <span className="font-mono text-sm">
                            {formatNumber(worker.metrics.qps)}
                          </span>
                        </div>
                      </td>
                      <td className="p-4 text-right">
                        <span
                          className={`font-mono text-sm ${
                            worker.metrics.cacheHitRate >= 80
                              ? 'text-emerald-500'
                              : worker.metrics.cacheHitRate >= 50
                              ? 'text-orange-500'
                              : 'text-red-500'
                          }`}
                        >
                          {worker.metrics.cacheHitRate.toFixed(1)}%
                        </span>
                      </td>
                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <HardDrive className="h-3 w-3 text-muted-foreground" />
                          <span className="font-mono text-sm">
                            {formatBytes(worker.metrics.memoryMB * 1024 * 1024)}
                          </span>
                        </div>
                      </td>
                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Cpu className="h-3 w-3 text-muted-foreground" />
                          <span
                            className={`font-mono text-sm ${
                              worker.metrics.cpuPercent >= 80
                                ? 'text-red-500'
                                : worker.metrics.cpuPercent >= 60
                                ? 'text-orange-500'
                                : ''
                            }`}
                          >
                            {worker.metrics.cpuPercent.toFixed(1)}%
                          </span>
                        </div>
                      </td>
                      <td className="p-4 text-right">
                        <div className="flex items-center justify-end gap-1">
                          <Clock className="h-3 w-3 text-muted-foreground" />
                          <span className="font-mono text-sm">
                            {formatUptime(worker.metrics.uptime)}
                          </span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Distribution by Cluster/Region */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Workers by Cluster</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(data?.byCluster || {}).map(([cluster, count]) => (
              <div key={cluster} className="flex items-center justify-between">
                <span className="text-sm">{cluster}</span>
                <div className="flex items-center gap-2">
                  <Progress
                    value={(count / (data?.totalCount || 1)) * 100}
                    className="h-2 w-24"
                  />
                  <span className="text-sm font-mono w-8 text-right">{count}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Workers by Region</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {Object.entries(data?.byRegion || {}).map(([region, count]) => (
              <div key={region} className="flex items-center justify-between">
                <span className="text-sm">{region}</span>
                <div className="flex items-center gap-2">
                  <Progress
                    value={(count / (data?.totalCount || 1)) * 100}
                    className="h-2 w-24"
                  />
                  <span className="text-sm font-mono w-8 text-right">{count}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
