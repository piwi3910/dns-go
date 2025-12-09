import { useState, useEffect } from 'react'
import { Settings, Save, AlertCircle, CheckCircle, RefreshCw } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { configApi, type ServerConfig } from '@/lib/api'

export function Config() {
  const [config, setConfig] = useState<ServerConfig | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [isSaving, setIsSaving] = useState(false)

  // Editable state
  const [prefetchEnabled, setPrefetchEnabled] = useState(false)
  const [prefetchHits, setPrefetchHits] = useState(0)
  const [prefetchTTL, setPrefetchTTL] = useState(0)
  const [minTTL, setMinTTL] = useState(0)
  const [maxTTL, setMaxTTL] = useState(0)
  const [negativeTTL, setNegativeTTL] = useState(0)
  const [resolverMode, setResolverMode] = useState('')
  const [enableCoalescing, setEnableCoalescing] = useState(false)
  const [logLevel, setLogLevel] = useState('')
  const [enableQueryLog, setEnableQueryLog] = useState(false)
  const [numParallel, setNumParallel] = useState(2)
  const [fallbackToRecursive, setFallbackToRecursive] = useState(true)

  const fetchConfig = async () => {
    try {
      const data = await configApi.get()
      setConfig(data)

      // Initialize editable state
      setPrefetchEnabled(data.cache.prefetch.enabled)
      setPrefetchHits(data.cache.prefetch.threshold_hits)
      setPrefetchTTL(data.cache.prefetch.threshold_ttl_percent)
      setMinTTL(data.cache.min_ttl_seconds)
      setMaxTTL(data.cache.max_ttl_seconds)
      setNegativeTTL(data.cache.negative_ttl_seconds)
      setResolverMode(data.resolver.mode)
      setEnableCoalescing(data.resolver.enable_coalescing)
      setLogLevel(data.logging.level)
      setEnableQueryLog(data.logging.enable_query_log)
      if (data.resolver.parallel) {
        setNumParallel(data.resolver.parallel.num_parallel)
        setFallbackToRecursive(data.resolver.parallel.fallback_to_recursive)
      }

      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch configuration')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchConfig()
  }, [])

  const handleSave = async () => {
    setIsSaving(true)
    setError(null)
    setSuccess(null)

    try {
      await configApi.update({
        cache: {
          prefetch: {
            enabled: prefetchEnabled,
            threshold_hits: prefetchHits,
            threshold_ttl_percent: prefetchTTL,
          },
          min_ttl_seconds: minTTL,
          max_ttl_seconds: maxTTL,
          negative_ttl_seconds: negativeTTL,
        },
        resolver: {
          mode: resolverMode,
          enable_coalescing: enableCoalescing,
          parallel: {
            num_parallel: numParallel,
            fallback_to_recursive: fallbackToRecursive,
          },
        },
        logging: {
          level: logLevel,
          enable_query_log: enableQueryLog,
        },
      })
      setSuccess('Configuration saved successfully')
      fetchConfig()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to save configuration')
    } finally {
      setIsSaving(false)
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="text-center">
          <div className="mb-4 h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading configuration...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Configuration</h1>
          <p className="text-muted-foreground">Server settings and preferences</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={fetchConfig}>
            <RefreshCw className="mr-2 h-4 w-4" />
            Refresh
          </Button>
          <Button onClick={handleSave} disabled={isSaving}>
            <Save className="mr-2 h-4 w-4" />
            {isSaving ? 'Saving...' : 'Save Changes'}
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

      {config && (
        <div className="grid gap-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Server Settings
              </CardTitle>
              <CardDescription>Read-only server configuration (requires restart to change)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <Label className="text-muted-foreground">Listen Address</Label>
                  <p className="font-medium">{config.server.listen_address}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">TCP Enabled</Label>
                  <p className="font-medium">{config.server.enable_tcp ? 'Yes' : 'No'}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Workers</Label>
                  <p className="font-medium">{config.server.num_workers}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">pprof Address</Label>
                  <p className="font-medium">{config.server.pprof_address}</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Resolver Settings</CardTitle>
              <CardDescription>Configure DNS resolution behavior</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="mode">Resolution Mode</Label>
                  <Select
                    id="mode"
                    value={resolverMode}
                    onValueChange={setResolverMode}
                  >
                    <option value="forwarding">Forwarding</option>
                    <option value="recursive">Recursive</option>
                    <option value="parallel">Parallel</option>
                  </Select>
                  <p className="text-xs text-muted-foreground">
                    How the server resolves queries not in cache
                  </p>
                </div>

                <div className="flex items-center justify-between rounded-lg border p-4">
                  <div>
                    <Label>Request Coalescing</Label>
                    <p className="text-xs text-muted-foreground">
                      Deduplicate identical concurrent queries
                    </p>
                  </div>
                  <Switch
                    checked={enableCoalescing}
                    onCheckedChange={setEnableCoalescing}
                  />
                </div>
              </div>

              {resolverMode === 'parallel' && (
                <div className="grid gap-4 md:grid-cols-2 pt-4 border-t">
                  <div className="space-y-2">
                    <Label htmlFor="numParallel">Parallel Queries</Label>
                    <Input
                      id="numParallel"
                      type="number"
                      min={1}
                      max={10}
                      value={numParallel}
                      onChange={(e) => setNumParallel(parseInt(e.target.value) || 2)}
                    />
                    <p className="text-xs text-muted-foreground">
                      Number of upstreams to query in parallel
                    </p>
                  </div>

                  <div className="flex items-center justify-between rounded-lg border p-4">
                    <div>
                      <Label>Fallback to Recursive</Label>
                      <p className="text-xs text-muted-foreground">
                        Try recursive resolution if all upstreams fail
                      </p>
                    </div>
                    <Switch
                      checked={fallbackToRecursive}
                      onCheckedChange={setFallbackToRecursive}
                    />
                  </div>
                </div>
              )}

              <div className="pt-4 border-t">
                <Label className="text-muted-foreground">Current Upstreams</Label>
                <div className="flex flex-wrap gap-1 mt-1">
                  {config.resolver.upstreams.map((addr) => (
                    <Badge key={addr} variant="outline">{addr}</Badge>
                  ))}
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Manage upstreams on the Upstreams page
                </p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Cache Settings</CardTitle>
              <CardDescription>Configure DNS response caching</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-3">
                <div className="space-y-2">
                  <Label htmlFor="minTTL">Minimum TTL (seconds)</Label>
                  <Input
                    id="minTTL"
                    type="number"
                    min={0}
                    value={minTTL}
                    onChange={(e) => setMinTTL(parseInt(e.target.value) || 0)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="maxTTL">Maximum TTL (seconds)</Label>
                  <Input
                    id="maxTTL"
                    type="number"
                    min={0}
                    value={maxTTL}
                    onChange={(e) => setMaxTTL(parseInt(e.target.value) || 0)}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="negativeTTL">Negative TTL (seconds)</Label>
                  <Input
                    id="negativeTTL"
                    type="number"
                    min={0}
                    value={negativeTTL}
                    onChange={(e) => setNegativeTTL(parseInt(e.target.value) || 0)}
                  />
                </div>
              </div>

              <div className="pt-4 border-t space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <Label>Prefetch</Label>
                    <p className="text-xs text-muted-foreground">
                      Refresh popular entries before expiry
                    </p>
                  </div>
                  <Switch
                    checked={prefetchEnabled}
                    onCheckedChange={setPrefetchEnabled}
                  />
                </div>

                {prefetchEnabled && (
                  <div className="grid gap-4 md:grid-cols-2">
                    <div className="space-y-2">
                      <Label htmlFor="prefetchHits">Hit Threshold</Label>
                      <Input
                        id="prefetchHits"
                        type="number"
                        min={1}
                        value={prefetchHits}
                        onChange={(e) => setPrefetchHits(parseInt(e.target.value) || 1)}
                      />
                      <p className="text-xs text-muted-foreground">
                        Minimum hits before prefetching
                      </p>
                    </div>
                    <div className="space-y-2">
                      <Label htmlFor="prefetchTTL">TTL Threshold (%)</Label>
                      <Input
                        id="prefetchTTL"
                        type="number"
                        min={1}
                        max={100}
                        value={prefetchTTL}
                        onChange={(e) => setPrefetchTTL(parseFloat(e.target.value) || 10)}
                      />
                      <p className="text-xs text-muted-foreground">
                        Prefetch when TTL below this percentage
                      </p>
                    </div>
                  </div>
                )}
              </div>

              <div className="pt-4 border-t grid gap-4 md:grid-cols-2">
                <div>
                  <Label className="text-muted-foreground">Message Cache Size</Label>
                  <p className="font-medium">{config.cache.message_cache.max_size_mb} MB ({config.cache.message_cache.num_shards} shards)</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">RRset Cache Size</Label>
                  <p className="font-medium">{config.cache.rrset_cache.max_size_mb} MB ({config.cache.rrset_cache.num_shards} shards)</p>
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Logging</CardTitle>
              <CardDescription>Configure logging behavior</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div className="space-y-2">
                  <Label htmlFor="logLevel">Log Level</Label>
                  <Select
                    id="logLevel"
                    value={logLevel}
                    onValueChange={setLogLevel}
                  >
                    <option value="debug">Debug</option>
                    <option value="info">Info</option>
                    <option value="warn">Warning</option>
                    <option value="error">Error</option>
                  </Select>
                </div>

                <div className="flex items-center justify-between rounded-lg border p-4">
                  <div>
                    <Label>Query Logging</Label>
                    <p className="text-xs text-muted-foreground">
                      Log all DNS queries (may impact performance)
                    </p>
                  </div>
                  <Switch
                    checked={enableQueryLog}
                    onCheckedChange={setEnableQueryLog}
                  />
                </div>
              </div>

              <div className="pt-4 border-t">
                <Label className="text-muted-foreground">Log Format</Label>
                <p className="font-medium">{config.logging.format}</p>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>API Settings</CardTitle>
              <CardDescription>Web API configuration (read-only)</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <Label className="text-muted-foreground">API Enabled</Label>
                  <p className="font-medium">{config.api.enabled ? 'Yes' : 'No'}</p>
                </div>
                <div>
                  <Label className="text-muted-foreground">Listen Address</Label>
                  <p className="font-medium">{config.api.listen_address}</p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
