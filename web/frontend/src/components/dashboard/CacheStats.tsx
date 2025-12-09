import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Progress } from '@/components/ui/progress'
import { formatBytes, formatNumber } from '@/lib/utils'

interface CacheStatsProps {
  title: string
  hits: number
  misses: number
  hitRate: number
  entries?: number
  sizeBytes?: number
}

export function CacheStats({ title, hits, misses, hitRate, entries, sizeBytes }: CacheStatsProps) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div>
          <div className="flex items-center justify-between text-sm mb-1">
            <span className="text-muted-foreground">Hit Rate</span>
            <span className="font-medium">{(hitRate * 100).toFixed(1)}%</span>
          </div>
          <Progress value={hitRate * 100} />
        </div>

        <div className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <p className="text-muted-foreground">Hits</p>
            <p className="font-medium text-green-600">{formatNumber(hits)}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Misses</p>
            <p className="font-medium text-red-600">{formatNumber(misses)}</p>
          </div>
          {entries !== undefined && (
            <div>
              <p className="text-muted-foreground">Entries</p>
              <p className="font-medium">{formatNumber(entries)}</p>
            </div>
          )}
          {sizeBytes !== undefined && (
            <div>
              <p className="text-muted-foreground">Size</p>
              <p className="font-medium">{formatBytes(sizeBytes)}</p>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  )
}
