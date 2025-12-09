import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Globe,
  Server,
  MapPin,
  ArrowRight,
  CheckCircle2,
  XCircle,
  Loader2,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'
import { clustersApi, type ClustersResponse, type ClusterInfo } from '@/lib/api'

export function ClusterOverview() {
  const [data, setData] = useState<ClustersResponse | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await clustersApi.list()
        setData(response)
      } catch (err) {
        // Clusters API might not be available, which is fine
        console.error('Failed to fetch clusters:', err)
      } finally {
        setLoading(false)
      }
    }

    fetchData()
    const interval = setInterval(fetchData, 5000)
    return () => clearInterval(interval)
  }, [])

  const getStatusIcon = (status: ClusterInfo['status']) => {
    switch (status) {
      case 'Ready':
        return <CheckCircle2 className="h-3 w-3 text-emerald-500" />
      case 'NotReady':
        return <XCircle className="h-3 w-3 text-red-500" />
      case 'Connecting':
        return <Loader2 className="h-3 w-3 text-blue-500 animate-spin" />
      default:
        return <XCircle className="h-3 w-3 text-orange-500" />
    }
  }

  // Don't show if loading or no cluster data
  if (loading) {
    return null
  }

  if (!data || data.clusters.length === 0) {
    return null
  }

  const healthRate = data.totalWorkers
    ? (data.healthyWorkers / data.totalWorkers) * 100
    : 0

  // Group clusters by region
  const byRegion = data.clusters.reduce((acc, cluster) => {
    const region = cluster.region || 'Unknown'
    if (!acc[region]) {
      acc[region] = []
    }
    acc[region].push(cluster)
    return acc
  }, {} as Record<string, ClusterInfo[]>)

  return (
    <Card>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Globe className="h-4 w-4" />
            Multi-Cluster Overview
          </CardTitle>
          <Button variant="ghost" size="sm" asChild>
            <Link to="/clusters" className="flex items-center gap-1">
              View All
              <ArrowRight className="h-3 w-3" />
            </Link>
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Summary */}
        <div className="grid grid-cols-3 gap-4">
          <div className="text-center">
            <p className="text-2xl font-bold">{data.clusters.length}</p>
            <p className="text-xs text-muted-foreground">Clusters</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold">{data.totalWorkers}</p>
            <p className="text-xs text-muted-foreground">Workers</p>
          </div>
          <div className="text-center">
            <p className="text-2xl font-bold text-emerald-500">
              {healthRate.toFixed(0)}%
            </p>
            <p className="text-xs text-muted-foreground">Healthy</p>
          </div>
        </div>

        {/* Health Bar */}
        <div className="space-y-1">
          <div className="flex justify-between text-xs">
            <span className="text-muted-foreground">Overall Health</span>
            <span>
              {data.healthyWorkers}/{data.totalWorkers}
            </span>
          </div>
          <Progress value={healthRate} className="h-2" />
        </div>

        {/* Clusters by Region */}
        <div className="space-y-2">
          {Object.entries(byRegion).map(([region, clusters]) => (
            <div key={region} className="rounded-lg border p-2">
              <div className="flex items-center gap-2 mb-2">
                <MapPin className="h-3 w-3 text-muted-foreground" />
                <span className="text-xs font-medium">{region}</span>
                <Badge variant="outline" className="text-xs ml-auto">
                  {clusters.reduce((sum, c) => sum + c.workerCount, 0)} workers
                </Badge>
              </div>
              <div className="flex flex-wrap gap-1">
                {clusters.map((cluster) => (
                  <div
                    key={cluster.name}
                    className="flex items-center gap-1 rounded bg-muted/50 px-2 py-1"
                  >
                    {getStatusIcon(cluster.status)}
                    <span className="text-xs">
                      {cluster.displayName || cluster.name}
                    </span>
                    <span className="text-xs text-muted-foreground">
                      ({cluster.healthyWorkers}/{cluster.workerCount})
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>

        {/* Quick Actions */}
        <div className="flex gap-2 pt-2 border-t">
          <Button variant="outline" size="sm" className="flex-1" asChild>
            <Link to="/clusters">
              <Globe className="h-4 w-4 mr-1" />
              Clusters
            </Link>
          </Button>
          <Button variant="outline" size="sm" className="flex-1" asChild>
            <Link to="/workers">
              <Server className="h-4 w-4 mr-1" />
              Workers
            </Link>
          </Button>
        </div>
      </CardContent>
    </Card>
  )
}
