import { useEffect, useState } from 'react'
import {
  Globe,
  MapPin,
  Server,
  Activity,
  RefreshCcw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Loader2,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { formatNumber } from '@/lib/utils'
import { clustersApi, type ClusterInfo, type ClustersResponse } from '@/lib/api'

export function Clusters() {
  const [data, setData] = useState<ClustersResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchClusters = async () => {
    try {
      setError(null)
      const response = await clustersApi.list()
      setData(response)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch clusters')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchClusters()
    const interval = setInterval(fetchClusters, 5000)
    return () => clearInterval(interval)
  }, [])

  const getStatusIcon = (status: ClusterInfo['status']) => {
    switch (status) {
      case 'Ready':
        return <CheckCircle2 className="h-4 w-4 text-emerald-500" />
      case 'NotReady':
        return <XCircle className="h-4 w-4 text-red-500" />
      case 'Connecting':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
      case 'Error':
        return <AlertTriangle className="h-4 w-4 text-orange-500" />
      default:
        return <Activity className="h-4 w-4 text-gray-500" />
    }
  }

  const getStatusBadge = (status: ClusterInfo['status']) => {
    const variants: Record<ClusterInfo['status'], 'success' | 'destructive' | 'secondary' | 'outline'> = {
      Ready: 'success',
      NotReady: 'destructive',
      Connecting: 'secondary',
      Error: 'destructive',
    }
    return <Badge variant={variants[status] || 'secondary'}>{status}</Badge>
  }

  if (loading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="text-center">
          <div className="mb-4 h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading clusters...</p>
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
            <h3 className="font-semibold mb-2">Failed to Load Clusters</h3>
            <p className="text-sm text-muted-foreground mb-4">{error}</p>
            <Button onClick={fetchClusters}>
              <RefreshCcw className="h-4 w-4 mr-2" />
              Retry
            </Button>
          </CardContent>
        </Card>
      </div>
    )
  }

  const clusters = data?.clusters || []

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Clusters</h1>
          <p className="text-muted-foreground">Multi-cluster deployment overview</p>
        </div>
        <Button variant="outline" onClick={fetchClusters}>
          <RefreshCcw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </div>

      {/* Summary Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Globe className="h-4 w-4" />
              Total Clusters
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{clusters.length}</div>
            <p className="text-xs text-muted-foreground">
              {clusters.filter(c => c.status === 'Ready').length} ready
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Server className="h-4 w-4" />
              Total Workers
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">{data?.totalWorkers || 0}</div>
            <p className="text-xs text-muted-foreground">
              {data?.healthyWorkers || 0} healthy
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Activity className="h-4 w-4" />
              Health Rate
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-3xl font-bold">
              {data?.totalWorkers
                ? ((data.healthyWorkers / data.totalWorkers) * 100).toFixed(1)
                : 0}%
            </div>
            <Progress
              value={data?.totalWorkers ? (data.healthyWorkers / data.totalWorkers) * 100 : 0}
              className="h-2 mt-2"
            />
          </CardContent>
        </Card>
      </div>

      {/* Clusters List */}
      {clusters.length === 0 ? (
        <Card>
          <CardContent className="py-12 text-center">
            <Globe className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
            <h3 className="font-semibold mb-2">No Clusters Registered</h3>
            <p className="text-sm text-muted-foreground">
              Register clusters using ClusterRegistration CRD in your management cluster.
            </p>
          </CardContent>
        </Card>
      ) : (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {clusters.map((cluster) => (
            <Card key={cluster.name} className="overflow-hidden">
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base font-semibold flex items-center gap-2">
                    {getStatusIcon(cluster.status)}
                    {cluster.displayName || cluster.name}
                  </CardTitle>
                  {getStatusBadge(cluster.status)}
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                {/* Location */}
                <div className="flex items-center gap-2 text-sm text-muted-foreground">
                  <MapPin className="h-4 w-4" />
                  <span>{cluster.region}</span>
                  {cluster.zone && (
                    <>
                      <span className="text-muted-foreground/50">|</span>
                      <span>{cluster.zone}</span>
                    </>
                  )}
                </div>

                {/* Worker Stats */}
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Workers</span>
                    <span className="font-medium">
                      {cluster.healthyWorkers}/{cluster.workerCount}
                    </span>
                  </div>
                  <Progress
                    value={
                      cluster.workerCount
                        ? (cluster.healthyWorkers / cluster.workerCount) * 100
                        : 0
                    }
                    className="h-2"
                  />
                </div>

                {/* Capacity */}
                <div className="grid grid-cols-3 gap-2 pt-2 border-t">
                  <div className="text-center">
                    <p className="text-xs text-muted-foreground">Max</p>
                    <p className="text-sm font-semibold">
                      {formatNumber(cluster.capacity.maxWorkers)}
                    </p>
                  </div>
                  <div className="text-center">
                    <p className="text-xs text-muted-foreground">Current</p>
                    <p className="text-sm font-semibold">
                      {formatNumber(cluster.capacity.currentWorkers)}
                    </p>
                  </div>
                  <div className="text-center">
                    <p className="text-xs text-muted-foreground">Available</p>
                    <p className="text-sm font-semibold text-emerald-500">
                      {formatNumber(cluster.capacity.availableWorkers)}
                    </p>
                  </div>
                </div>

                {/* Labels */}
                {Object.keys(cluster.labels || {}).length > 0 && (
                  <div className="flex flex-wrap gap-1 pt-2 border-t">
                    {Object.entries(cluster.labels).slice(0, 3).map(([key, value]) => (
                      <Badge key={key} variant="outline" className="text-xs">
                        {key}: {value}
                      </Badge>
                    ))}
                    {Object.keys(cluster.labels).length > 3 && (
                      <Badge variant="outline" className="text-xs">
                        +{Object.keys(cluster.labels).length - 3} more
                      </Badge>
                    )}
                  </div>
                )}

                {/* Last Heartbeat */}
                <div className="text-xs text-muted-foreground pt-2 border-t">
                  Last seen: {new Date(cluster.lastHeartbeat).toLocaleString()}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
