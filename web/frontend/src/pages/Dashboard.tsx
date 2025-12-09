import { useEffect, useState } from 'react'
import {
  Clock,
  Cpu,
  Database,
  Server,
  HardDrive,
  Zap,
  TrendingUp,
  BarChart3,
  Globe,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { Badge } from '@/components/ui/badge'
import { StatsCard } from '@/components/dashboard/StatsCard'
import { AreaChartCard } from '@/components/charts/AreaChartCard'
import { MultiLineChart } from '@/components/charts/MultiLineChart'
import { formatNumber, formatBytes, formatUptime, formatDuration } from '@/lib/utils'
import { upstreamsApi, type Stats, type UpstreamStats } from '@/lib/api'
import { useStatsHistory } from '@/hooks/useStatsHistory'

interface DashboardProps {
  stats: Stats | null
}

export function Dashboard({ stats }: DashboardProps) {
  const [upstreams, setUpstreams] = useState<UpstreamStats[]>([])
  const { history, currentQPS } = useStatsHistory(stats)

  useEffect(() => {
    const fetchUpstreams = async () => {
      try {
        const data = await upstreamsApi.list()
        setUpstreams(data.upstreams)
      } catch (error) {
        console.error('Failed to fetch upstreams:', error)
      }
    }

    fetchUpstreams()
    const interval = setInterval(fetchUpstreams, 5000)
    return () => clearInterval(interval)
  }, [])

  if (!stats) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="text-center">
          <div className="mb-4 h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading statistics...</p>
        </div>
      </div>
    )
  }

  // Prepare sparkline data for stats cards
  const memorySparkline = history.map(h => ({ value: h.memory_mb }))
  const goroutineSparkline = history.map(h => ({ value: h.goroutines }))
  const qpsSparkline = history.map(h => ({ value: h.cache_hits + h.cache_misses }))

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header Section */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Dashboard</h1>
          <p className="text-muted-foreground">Real-time DNS server monitoring</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline" className="text-emerald-500 border-emerald-500/50">
            <span className="mr-1.5 h-2 w-2 rounded-full bg-emerald-500 animate-pulse" />
            Live
          </Badge>
          <Badge variant="secondary">v{stats.server.version}</Badge>
        </div>
      </div>

      {/* Key Metrics Row */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatsCard
          title="Queries/sec"
          value={currentQPS.toFixed(1)}
          description="Current throughput"
          icon={Zap}
          sparklineData={qpsSparkline}
          sparklineColor="hsl(var(--chart-1))"
        />
        <StatsCard
          title="Uptime"
          value={formatUptime(stats.server.uptime_seconds)}
          description="Server running time"
          icon={Clock}
        />
        <StatsCard
          title="Memory"
          value={formatBytes(stats.server.memory_mb * 1024 * 1024)}
          description="Current allocation"
          icon={HardDrive}
          sparklineData={memorySparkline}
          sparklineColor="hsl(var(--chart-2))"
        />
        <StatsCard
          title="Goroutines"
          value={stats.server.num_goroutines}
          description={`${stats.server.num_cpu} CPUs available`}
          icon={Cpu}
          sparklineData={goroutineSparkline}
          sparklineColor="hsl(var(--chart-3))"
        />
      </div>

      {/* Charts Row */}
      <div className="grid gap-4 md:grid-cols-2">
        <AreaChartCard
          title="Cache Activity"
          subtitle="Hits and misses over time"
          icon={TrendingUp}
          data={history}
          dataKey="cache_hits"
          color="hsl(var(--chart-1))"
          gradientId="cacheHitsGradient"
          valueFormatter={(v) => formatNumber(v)}
        />
        <MultiLineChart
          title="Cache Hit Rates"
          subtitle="Message cache vs RRset cache"
          icon={BarChart3}
          data={history}
          series={[
            { key: 'cache_hit_rate', name: 'Message Cache', color: 'hsl(var(--chart-1))' },
            { key: 'rrset_hit_rate', name: 'RRset Cache', color: 'hsl(var(--chart-2))' },
          ]}
          valueFormatter={(v) => `${v.toFixed(1)}%`}
        />
      </div>

      {/* Cache Stats Row */}
      <div className="grid gap-4 md:grid-cols-2">
        <Card className="overflow-hidden">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Database className="h-4 w-4" />
              Message Cache
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Hit Rate</span>
                <span className="font-semibold text-emerald-500">
                  {(stats.cache.message_cache.hit_rate * 100).toFixed(1)}%
                </span>
              </div>
              <Progress
                value={stats.cache.message_cache.hit_rate * 100}
                className="h-2"
              />
            </div>
            <div className="grid grid-cols-3 gap-4 pt-2 border-t">
              <div>
                <p className="text-xs text-muted-foreground">Hits</p>
                <p className="text-lg font-semibold text-emerald-500">
                  {formatNumber(stats.cache.message_cache.hits)}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Misses</p>
                <p className="text-lg font-semibold text-orange-500">
                  {formatNumber(stats.cache.message_cache.misses)}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Evictions</p>
                <p className="text-lg font-semibold text-red-500">
                  {formatNumber(stats.cache.message_cache.evicts)}
                </p>
              </div>
            </div>
            <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 border-t">
              <span>Size: {formatBytes(stats.cache.message_cache.size_bytes)}</span>
              <span>Max: {formatBytes(stats.cache.message_cache.max_size_bytes)}</span>
              <span>{stats.cache.message_cache.num_shards} shards</span>
            </div>
          </CardContent>
        </Card>

        <Card className="overflow-hidden">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Database className="h-4 w-4" />
              RRset Cache
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Hit Rate</span>
                <span className="font-semibold text-emerald-500">
                  {(stats.cache.rrset_cache.hit_rate * 100).toFixed(1)}%
                </span>
              </div>
              <Progress
                value={stats.cache.rrset_cache.hit_rate * 100}
                className="h-2"
              />
            </div>
            <div className="grid grid-cols-3 gap-4 pt-2 border-t">
              <div>
                <p className="text-xs text-muted-foreground">Hits</p>
                <p className="text-lg font-semibold text-emerald-500">
                  {formatNumber(stats.cache.rrset_cache.hits)}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Misses</p>
                <p className="text-lg font-semibold text-orange-500">
                  {formatNumber(stats.cache.rrset_cache.misses)}
                </p>
              </div>
              <div>
                <p className="text-xs text-muted-foreground">Evictions</p>
                <p className="text-lg font-semibold text-red-500">
                  {formatNumber(stats.cache.rrset_cache.evicts)}
                </p>
              </div>
            </div>
            <div className="flex items-center justify-between text-xs text-muted-foreground pt-2 border-t">
              <span>Size: {formatBytes(stats.cache.rrset_cache.size_bytes)}</span>
              <span>Max: {formatBytes(stats.cache.rrset_cache.max_size_bytes)}</span>
              <span>{stats.cache.rrset_cache.num_shards} shards</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* System Info and Upstreams Row */}
      <div className="grid gap-4 md:grid-cols-3">
        {/* System Info */}
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Server className="h-4 w-4" />
              System Info
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Version</span>
              <Badge variant="secondary">{stats.server.version}</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Go Version</span>
              <span className="text-sm font-medium">{stats.server.go_version}</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Resolver Mode</span>
              <Badge variant="outline">{stats.resolver.mode}</Badge>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">In-Flight Queries</span>
              <span className="text-sm font-medium">{stats.resolver.in_flight_queries}</span>
            </div>
            <div className="flex items-center justify-between pt-2 border-t">
              <span className="text-sm text-muted-foreground">Zones</span>
              <span className="text-sm font-medium">
                {stats.zones.count} ({formatNumber(stats.zones.total_records)} records)
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Upstream Servers */}
        <Card className="md:col-span-2">
          <CardHeader className="pb-2">
            <CardTitle className="flex items-center gap-2 text-sm font-medium">
              <Globe className="h-4 w-4" />
              Upstream Servers
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {upstreams.length === 0 ? (
                <p className="text-sm text-muted-foreground py-4 text-center">
                  No upstream servers configured
                </p>
              ) : (
                upstreams.map((upstream) => (
                  <div
                    key={upstream.address}
                    className="flex items-center justify-between rounded-lg border p-3 transition-colors hover:bg-muted/50"
                  >
                    <div className="flex items-center gap-3">
                      <div
                        className={`h-2.5 w-2.5 rounded-full ${
                          upstream.healthy
                            ? 'bg-emerald-500 shadow-lg shadow-emerald-500/50'
                            : 'bg-red-500 shadow-lg shadow-red-500/50'
                        }`}
                      />
                      <div>
                        <p className="font-mono text-sm font-medium">{upstream.address}</p>
                        <p className="text-xs text-muted-foreground">
                          {formatNumber(upstream.queries)} queries
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-6">
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">RTT</p>
                        <p className="text-sm font-semibold">{formatDuration(upstream.rtt_ms)}</p>
                      </div>
                      <div className="text-right">
                        <p className="text-xs text-muted-foreground">Failures</p>
                        <p className={`text-sm font-semibold ${upstream.failures > 0 ? 'text-orange-500' : ''}`}>
                          {upstream.failures}
                        </p>
                      </div>
                      <Badge variant={upstream.healthy ? 'success' : 'destructive'}>
                        {upstream.healthy ? 'Healthy' : 'Down'}
                      </Badge>
                    </div>
                  </div>
                ))
              )}
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
