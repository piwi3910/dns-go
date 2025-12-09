import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { formatDuration, formatNumber } from '@/lib/utils'
import type { UpstreamStats } from '@/lib/api'

interface UpstreamHealthProps {
  upstreams: UpstreamStats[]
}

export function UpstreamHealth({ upstreams }: UpstreamHealthProps) {
  return (
    <Card className="col-span-2">
      <CardHeader>
        <CardTitle className="text-sm font-medium">Upstream Servers</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-3">
          {upstreams.length === 0 ? (
            <p className="text-sm text-muted-foreground">No upstream servers configured</p>
          ) : (
            upstreams.map((upstream) => (
              <div
                key={upstream.address}
                className="flex items-center justify-between rounded-lg border p-3"
              >
                <div className="flex items-center gap-3">
                  <div
                    className={`h-2 w-2 rounded-full ${
                      upstream.healthy ? 'bg-green-500' : 'bg-red-500'
                    }`}
                  />
                  <div>
                    <p className="font-mono text-sm">{upstream.address}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatNumber(upstream.queries)} queries
                    </p>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-sm">
                  <div className="text-right">
                    <p className="text-muted-foreground">RTT</p>
                    <p className="font-medium">{formatDuration(upstream.rtt_ms)}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-muted-foreground">Failures</p>
                    <p className="font-medium">{upstream.failures}</p>
                  </div>
                  <Badge variant={upstream.healthy ? 'success' : 'destructive'}>
                    {upstream.healthy ? 'Healthy' : 'Unhealthy'}
                  </Badge>
                </div>
              </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  )
}
