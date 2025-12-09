import { useState, useEffect } from 'react'
import type { FormEvent } from 'react'
import { Plus, Trash2, Globe, AlertCircle, FileText } from 'lucide-react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Textarea } from '@/components/ui/textarea'
import { Badge } from '@/components/ui/badge'
import { Alert, AlertDescription } from '@/components/ui/alert'
import { zonesApi, type ZoneInfo, type ZoneDetail } from '@/lib/api'

export function Zones() {
  const [zones, setZones] = useState<ZoneInfo[]>([])
  const [selectedZone, setSelectedZone] = useState<ZoneDetail | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [showAddForm, setShowAddForm] = useState(false)
  const [newZone, setNewZone] = useState({ origin: '', zoneContent: '' })
  const [isSubmitting, setIsSubmitting] = useState(false)

  const fetchZones = async () => {
    try {
      const data = await zonesApi.list()
      setZones(data.zones || [])
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch zones')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchZones()
  }, [])

  const handleSelectZone = async (origin: string) => {
    try {
      const data = await zonesApi.get(origin)
      setSelectedZone(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to fetch zone details')
    }
  }

  const handleAddZone = async (e: FormEvent) => {
    e.preventDefault()
    setIsSubmitting(true)
    setError(null)

    try {
      let origin = newZone.origin.trim()
      if (!origin.endsWith('.')) {
        origin += '.'
      }

      await zonesApi.create({
        origin,
        zone_file_content: newZone.zoneContent || undefined,
      })

      setNewZone({ origin: '', zoneContent: '' })
      setShowAddForm(false)
      fetchZones()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create zone')
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleDeleteZone = async (origin: string) => {
    if (!confirm(`Are you sure you want to delete zone "${origin}"?`)) {
      return
    }

    try {
      await zonesApi.delete(origin)
      if (selectedZone?.origin === origin) {
        setSelectedZone(null)
      }
      fetchZones()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to delete zone')
    }
  }

  if (isLoading) {
    return (
      <div className="flex h-[50vh] items-center justify-center">
        <div className="text-center">
          <div className="mb-4 h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto" />
          <p className="text-muted-foreground">Loading zones...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Zone Management</h1>
          <p className="text-muted-foreground">Manage authoritative DNS zones</p>
        </div>
        <Button onClick={() => setShowAddForm(true)}>
          <Plus className="mr-2 h-4 w-4" />
          Add Zone
        </Button>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertCircle className="h-4 w-4" />
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}

      {showAddForm && (
        <Card>
          <CardHeader>
            <CardTitle>Add New Zone</CardTitle>
            <CardDescription>Create a new authoritative DNS zone</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleAddZone} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="origin">Zone Origin</Label>
                <Input
                  id="origin"
                  value={newZone.origin}
                  onChange={(e) => setNewZone({ ...newZone, origin: e.target.value })}
                  placeholder="example.com"
                  required
                />
                <p className="text-xs text-muted-foreground">
                  The domain name for this zone (trailing dot will be added automatically)
                </p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="zoneContent">Zone File Content (Optional)</Label>
                <Textarea
                  id="zoneContent"
                  value={newZone.zoneContent}
                  onChange={(e) => setNewZone({ ...newZone, zoneContent: e.target.value })}
                  placeholder={`$ORIGIN example.com.\n$TTL 3600\n@  IN  SOA  ns1.example.com. admin.example.com. (\n    2024010101 ; serial\n    3600       ; refresh\n    1800       ; retry\n    604800     ; expire\n    86400      ; minimum\n)\n@  IN  NS   ns1.example.com.\n@  IN  A    192.0.2.1`}
                  className="font-mono text-sm h-48"
                />
              </div>

              <div className="flex gap-2">
                <Button type="submit" disabled={isSubmitting}>
                  {isSubmitting ? 'Creating...' : 'Create Zone'}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => {
                    setShowAddForm(false)
                    setNewZone({ origin: '', zoneContent: '' })
                  }}
                >
                  Cancel
                </Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Zones
            </CardTitle>
            <CardDescription>
              {zones.length} zone{zones.length !== 1 ? 's' : ''} configured
            </CardDescription>
          </CardHeader>
          <CardContent>
            {zones.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-8">
                No zones configured. Add a zone to get started.
              </p>
            ) : (
              <div className="space-y-2">
                {zones.map((zone) => (
                  <div
                    key={zone.origin}
                    className={`flex items-center justify-between rounded-lg border p-3 cursor-pointer transition-colors ${
                      selectedZone?.origin === zone.origin
                        ? 'border-primary bg-primary/5'
                        : 'hover:bg-accent'
                    }`}
                    onClick={() => handleSelectZone(zone.origin)}
                  >
                    <div>
                      <p className="font-mono font-medium">{zone.origin}</p>
                      <p className="text-xs text-muted-foreground">
                        {zone.record_count} record{zone.record_count !== 1 ? 's' : ''}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="secondary">{zone.record_count}</Badge>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-8 w-8 text-destructive hover:text-destructive"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleDeleteZone(zone.origin)
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Zone Details
            </CardTitle>
            <CardDescription>
              {selectedZone ? selectedZone.origin : 'Select a zone to view details'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {selectedZone ? (
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">Origin</p>
                    <p className="font-mono font-medium">{selectedZone.origin}</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Records</p>
                    <p className="font-medium">{selectedZone.record_count}</p>
                  </div>
                </div>

                <div>
                  <p className="text-sm text-muted-foreground mb-2">Records</p>
                  <div className="max-h-64 overflow-auto rounded-md border bg-muted/30 p-3">
                    <pre className="font-mono text-xs whitespace-pre-wrap">
                      {selectedZone.records?.length > 0
                        ? selectedZone.records.join('\n')
                        : 'No records'}
                    </pre>
                  </div>
                </div>

                {selectedZone.transfer_acl && selectedZone.transfer_acl.length > 0 && (
                  <div>
                    <p className="text-sm text-muted-foreground mb-2">Transfer ACL</p>
                    <div className="flex flex-wrap gap-1">
                      {selectedZone.transfer_acl.map((acl) => (
                        <Badge key={acl} variant="outline">
                          {acl}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground text-center py-8">
                Click on a zone to view its details
              </p>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
