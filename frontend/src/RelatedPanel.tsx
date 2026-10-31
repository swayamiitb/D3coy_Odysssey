import { Network } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Badge, Panel } from './ui'

interface Related { cve_id: string; similarity: number; kev: boolean; title: string; org_risk: number | null; org_exposed: boolean }

export function RelatedPanel({ orgId, cveId }: { orgId: string; cveId: string }) {
  const [data, setData] = useState<{ model: string; related: Related[] }>()
  useEffect(() => {
    setData(undefined)
    fetch(`/api/alerts/${orgId}/${cveId}/related`).then((r) => r.json()).then(setData).catch(() => undefined)
  }, [orgId, cveId])
  if (!data || data.related.length === 0) return null
  return (
    <Panel title="Related threats" right={<span className="flex items-center gap-1 text-xs text-mute"><Network size={12} /> SecureBERT 2.0 similarity</span>}>
      <ul className="space-y-2 text-xs">
        {data.related.map((r) => (
          <li key={r.cve_id} className="flex items-start gap-2">
            <span className="w-10 shrink-0 text-right font-mono text-mute">{r.similarity.toFixed(2)}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1">
                <span className="font-mono text-accent">{r.cve_id}</span>
                {r.kev && <Badge tone="crit">KEV</Badge>}
                {r.org_exposed && <Badge tone="crit">also exposed here</Badge>}
              </div>
              <div className="truncate text-mute" title={r.title}>{r.title}</div>
            </div>
          </li>
        ))}
      </ul>
    </Panel>
  )
}
