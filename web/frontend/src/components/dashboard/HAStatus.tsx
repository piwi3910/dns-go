import { useEffect, useState } from 'react'
import {
  Shield,
  Crown,
  Users,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  RefreshCcw,
  Activity,
  Vote,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { haApi, type HAStatus as HAStatusType } from '@/lib/api'

export function HAStatus() {
  const [status, setStatus] = useState<HAStatusType | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [failoverLoading, setFailoverLoading] = useState(false)

  const fetchStatus = async () => {
    try {
      setError(null)
      const data = await haApi.status()
      setStatus(data)
    } catch (err) {
      // HA might not be enabled, which is fine
      if (err instanceof Error && err.message.includes('404')) {
        setStatus(null)
      } else {
        setError(err instanceof Error ? err.message : 'Failed to fetch HA status')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleFailover = async () => {
    if (!confirm('Are you sure you want to trigger a failover?')) return

    setFailoverLoading(true)
    try {
      await haApi.forceFailover()
      await fetchStatus()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failover failed')
    } finally {
      setFailoverLoading(false)
    }
  }

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 3000) // More frequent for HA
    return () => clearInterval(interval)
  }, [])

  // Don't show if HA is not enabled or not available
  if (loading) {
    return null
  }

  if (!status || !status.enabled) {
    return null
  }

  const quorumPercent = status.quorum.votersTotal
    ? (status.quorum.votersReachable / status.quorum.votersTotal) * 100
    : 0

  return (
    <Card className={status.fencing.isFenced ? 'border-red-500/50' : ''}>
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Shield className="h-4 w-4" />
            High Availability
          </CardTitle>
          <div className="flex items-center gap-2">
            <Badge variant={status.mode === 'ActiveActive' ? 'default' : 'secondary'}>
              {status.mode}
            </Badge>
            {status.fencing.isFenced && (
              <Badge variant="destructive">FENCED</Badge>
            )}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Fencing Alert */}
        {status.fencing.isFenced && (
          <div className="rounded-lg bg-red-500/10 border border-red-500/30 p-3">
            <div className="flex items-start gap-2">
              <AlertTriangle className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-red-500">System Fenced</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {status.fencing.reason}
                </p>
              </div>
            </div>
          </div>
        )}

        {/* Leader Status */}
        <div className="flex items-center justify-between rounded-lg border p-3">
          <div className="flex items-center gap-3">
            <div
              className={`h-10 w-10 rounded-lg flex items-center justify-center ${
                status.leader.isLeader
                  ? 'bg-amber-500/10 text-amber-500'
                  : 'bg-muted text-muted-foreground'
              }`}
            >
              <Crown className="h-5 w-5" />
            </div>
            <div>
              <p className="text-sm font-medium">
                {status.leader.isLeader ? 'This Instance is Leader' : 'Follower'}
              </p>
              <p className="text-xs text-muted-foreground">
                Leader: {status.leader.leaderID.slice(0, 12)}...
                {status.leader.leaderCluster && ` (${status.leader.leaderCluster})`}
              </p>
            </div>
          </div>
          {!status.leader.isLeader && (
            <Button
              variant="outline"
              size="sm"
              onClick={handleFailover}
              disabled={failoverLoading}
            >
              {failoverLoading ? (
                <RefreshCcw className="h-4 w-4 animate-spin" />
              ) : (
                'Failover'
              )}
            </Button>
          )}
        </div>

        {/* Quorum Status */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2">
              <Vote className="h-4 w-4 text-muted-foreground" />
              Quorum ({status.quorum.quorumType})
            </span>
            <span className="flex items-center gap-2">
              {status.quorum.hasQuorum ? (
                <>
                  <CheckCircle2 className="h-4 w-4 text-emerald-500" />
                  <span className="text-emerald-500 font-medium">Has Quorum</span>
                </>
              ) : (
                <>
                  <XCircle className="h-4 w-4 text-red-500" />
                  <span className="text-red-500 font-medium">No Quorum</span>
                </>
              )}
            </span>
          </div>
          <Progress value={quorumPercent} className="h-2" />
          <p className="text-xs text-muted-foreground text-right">
            {status.quorum.votersReachable}/{status.quorum.votersTotal} voters reachable
          </p>
        </div>

        {/* Cluster Votes */}
        {status.quorum.clusterVotes.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Cluster Votes
            </p>
            <div className="space-y-1">
              {status.quorum.clusterVotes.map((vote) => (
                <div
                  key={vote.clusterID}
                  className="flex items-center justify-between text-sm rounded-lg bg-muted/50 p-2"
                >
                  <span className="flex items-center gap-2">
                    {vote.voteValid ? (
                      <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                    ) : (
                      <XCircle className="h-3 w-3 text-red-500" />
                    )}
                    {vote.clusterID}
                  </span>
                  <span className="text-muted-foreground">
                    {vote.workersVoting}/{vote.workersTotal} workers
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Control Plane Instances */}
        {status.controlPlanes.length > 0 && (
          <div className="space-y-2 pt-2 border-t">
            <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
              Control Plane Instances
            </p>
            <div className="space-y-1">
              {status.controlPlanes.map((cp) => (
                <div
                  key={cp.id}
                  className="flex items-center justify-between text-sm rounded-lg border p-2"
                >
                  <div className="flex items-center gap-2">
                    {cp.isLeader && <Crown className="h-3 w-3 text-amber-500" />}
                    <span className="font-mono">{cp.id.slice(0, 12)}...</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-muted-foreground">
                      {cp.clusterRef}
                    </span>
                    <Badge
                      variant={
                        cp.status === 'Active'
                          ? 'success'
                          : cp.status === 'Standby'
                          ? 'secondary'
                          : 'destructive'
                      }
                      className="text-xs"
                    >
                      {cp.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Last Check */}
        <div className="text-xs text-muted-foreground text-right pt-2 border-t">
          Last check: {new Date(status.quorum.lastCheck).toLocaleTimeString()}
        </div>
      </CardContent>
    </Card>
  )
}
