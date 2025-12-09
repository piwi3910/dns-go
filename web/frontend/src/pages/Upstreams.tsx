import { useState, useEffect } from 'react'
import type { FormEvent } from 'react'
import { Plus, Trash2, Server, AlertCircle, RefreshCw } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { Progress } from '@/components/ui/progress'
import { upstreamsApi, type UpstreamStats } from '@/lib/api'
import { formatDuration, formatNumber } from '@/lib/utils'

export function Upstreams() {
  const [upstreams, setUpstreams] = useState<UpstreamStats[]>([])
  const [mode, setMode] = useState<string>('')
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [newUpstream, setNewUpstream] = useState('')
  const [isSubmitting, setIsSubmitting] = useState(false)

  const fetchUpstreams = async () => {
    try {
      const data = await upstreamsApi.list()
      setUpstreams(data.upstreams || [])
      setMode(data.mode)
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch upstreams')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchUpstreams()
    const interval = setInterval(fetchUpstreams, 5000)
    return () => clearInterval(interval)
  }, [])

  const handleAddUpstream = async (e: FormEvent) => {
    e.preventDefault()
    if (!newUpstream.trim()) return

    setIsSubmitting(true)
    setError(null)

    try {
      let address = newUpstream.trim()
      if (!address.includes(':')) {
        address += ':53'
      }

      const currentAddresses = upstreams.map((u) => u.address)
      await upstreamsApi.update([...currentAddresses, address])

      setNewUpstream('')
      fetchUpstreams()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add upstream')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleRemoveUpstream = async (address: string) => {
    if (!confirm(`Remove upstream "${address}"?`)) return

    try {
      const newAddresses = upstreams.filter((u) => u.address !== address).map((u) => u.address)
      await upstreamsApi.update(newAddresses)
      fetchUpstreams()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to remove upstream')
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="text-center">
          <div className="mb-4 h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading upstreams...</p>
        </div>
      </div>
    )
  }

  const healthyCount = upstreams.filter((u) => u.healthy).length

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Upstream Servers</h1>
          <p className="text-muted-foreground">
            Manage DNS upstream servers ({mode} mode)
          </p>
        </div>
        <Button variant="outline" onClick={fetchUpstreams}>
          <RefreshCw className="mr-2 h-4 w-4" />
          Refresh
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Total Upstreams</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{upstreams.length}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Healthy</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-green-600">{healthyCount}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Unhealthy</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-600">
              {upstreams.length - healthyCount}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Plus className="h-5 w-5" />
            Add Upstream
          </CardTitle>
          <CardDescription>Add a new upstream DNS server</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleAddUpstream} className="flex gap-2">
            <div className="flex-1">
              <Label htmlFor="upstream" className="sr-only">
                Upstream Address
              </Label>
              <Input
                id="upstream"
                value={newUpstream}
                onChange={(e) => setNewUpstream(e.target.value)}
                placeholder="8.8.8.8:53 or 1.1.1.1"
              />
            </div>
            <Button type="submit" disabled={isSubmitting || !newUpstream.trim()}>
              {isSubmitting ? 'Adding...' : 'Add'}
            </Button>
          </form>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Upstream Servers
          </CardTitle>
          <CardDescription>
            {upstreams.length} server{upstreams.length !== 1 ? 's' : ''} configured
          </CardDescription>
        </CardHeader>
        <CardContent>
          {upstreams.length === 0 ? (
            <p className="text-sm text-muted-foreground text-center py-8">
              No upstream servers configured. Add one above.
            </p>
          ) : (
            <div className="space-y-4">
              {upstreams.map((upstream) => (
                <div
                  key={upstream.address}
                  className="rounded-lg border p-4 space-y-3"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div
                        className={`h-3 w-3 rounded-full ${
                          upstream.healthy ? 'bg-green-500' : 'bg-red-500'
                        }`}
                      />
                      <span className="font-mono font-medium">{upstream.address}</span>
                      <Badge variant={upstream.healthy ? 'success' : 'destructive'}>
                        {upstream.healthy ? 'Healthy' : 'Unhealthy'}
                      </Badge>
                    </div>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-8 w-8 text-destructive hover:text-destructive"
                      onClick={() => handleRemoveUpstream(upstream.address)}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>

                  <div className="grid grid-cols-4 gap-4 text-sm">
                    <div>
                      <p className="text-muted-foreground">RTT</p>
                      <p className="font-medium">{formatDuration(upstream.rtt_ms)}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Queries</p>
                      <p className="font-medium">{formatNumber(upstream.queries)}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Failures</p>
                      <p className="font-medium text-red-600">{upstream.failures}</p>
                    </div>
                    <div>
                      <p className="text-muted-foreground">Failure Rate</p>
                      <p className="font-medium">
                        {(upstream.failure_rate * 100).toFixed(1)}%
                      </p>
                    </div>
                  </div>

                  <div>
                    <div className="flex justify-between text-xs text-muted-foreground mb-1">
                      <span>Success Rate</span>
                      <span>{((1 - upstream.failure_rate) * 100).toFixed(1)}%</span>
                    </div>
                    <Progress
                      value={(1 - upstream.failure_rate) * 100}
                      indicatorClassName={
                        upstream.failure_rate > 0.5
                          ? 'bg-red-500'
                          : upstream.failure_rate > 0.1
                          ? 'bg-yellow-500'
                          : 'bg-green-500'
                      }
                    />
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
