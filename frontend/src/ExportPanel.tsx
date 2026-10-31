import { Copy, Download, FileText, Share2, X } from 'lucide-react'
import { useState } from 'react'
import { Panel } from './ui'

type Report = { title: string; status: string; basis: string; sections: Record<string, unknown> }

function asText(r: Report): string {
  const lines = [r.title, r.status, r.basis, '']
  for (const [section, body] of Object.entries(r.sections)) {
    lines.push(section)
    const render = (v: unknown, indent = '  '): void => {
      if (Array.isArray(v)) v.forEach((x) => (typeof x === 'object' ? render(x, indent) : lines.push(`${indent}- ${x}`)))
      else if (v && typeof v === 'object') Object.entries(v).forEach(([k, x]) =>
        typeof x === 'object' && x ? (lines.push(`${indent}${k}:`), render(x, indent + '  ')) : lines.push(`${indent}${k}: ${x ?? '—'}`))
      else lines.push(`${indent}${v}`)
    }
    render(body)
    lines.push('')
  }
  return lines.join('\n')
}

function download(name: string, content: string, type = 'application/json') {
  const url = URL.createObjectURL(new Blob([content], { type }))
  const a = Object.assign(document.createElement('a'), { href: url, download: name })
  a.click()
  URL.revokeObjectURL(url)
}

export function CertInReportModal({ orgId, cveId, onClose }: { orgId: string; cveId: string; onClose: () => void }) {
  const [report, setReport] = useState<Report>()
  if (!report) fetch(`/api/alerts/${orgId}/${cveId}/certin-report`).then((r) => r.json()).then(setReport)
  return (
    <div className="fixed inset-0 z-30 flex items-center justify-center bg-black/60 p-6" onClick={onClose}>
      <div className="max-h-full w-[760px] overflow-auto rounded-2xl border border-line bg-panel p-6" onClick={(e) => e.stopPropagation()}>
        <div className="mb-3 flex items-start justify-between gap-4">
          <div>
            <div className="text-xs uppercase tracking-wider text-crit">{report?.status ?? 'Preparing draft…'}</div>
            <h3 className="text-lg font-semibold">{report?.title}</h3>
            <p className="text-xs text-mute">{report?.basis}</p>
          </div>
          <button onClick={onClose} className="text-mute hover:text-text"><X size={18} /></button>
        </div>
        {report && (
          <>
            <pre className="whitespace-pre-wrap rounded-lg bg-ink p-4 font-mono text-xs leading-relaxed text-text">{asText(report)}</pre>
            <div className="mt-3 flex gap-2">
              <button onClick={() => navigator.clipboard.writeText(asText(report))}
                      className="flex items-center gap-1 rounded-full bg-action px-4 py-2 text-sm font-semibold text-ink"><Copy size={14} /> Copy text</button>
              <button onClick={() => download(`CERT-In-draft-${orgId}-${cveId}.json`, JSON.stringify(report, null, 2))}
                      className="flex items-center gap-1 rounded-full px-4 py-2 text-sm text-mute ring-1 ring-line hover:text-text"><Download size={14} /> JSON</button>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

export function ExportPanel({ orgId, cveId, compromise }: { orgId: string; cveId: string; compromise: boolean }) {
  const [open, setOpen] = useState(false)
  const [stixInfo, setStixInfo] = useState<string>()
  const exportStix = async () => {
    const bundle = await (await fetch(`/api/alerts/${orgId}/${cveId}/stix?tlp=AMBER`)).json()
    download(`stix21-${orgId}-${cveId}.json`, JSON.stringify(bundle, null, 2))
    setStixInfo(`${bundle.objects.length} STIX objects · TLP:AMBER`)
  }
  return (
    <Panel title="Share & report">
      <div className="flex flex-wrap gap-2">
        <button onClick={() => setOpen(true)}
                className={`flex items-center gap-1 rounded-full px-4 py-2 text-sm font-semibold ${compromise ? 'bg-comp text-ink' : 'bg-panel-2 text-text ring-1 ring-line'}`}>
          <FileText size={14} /> CERT-In incident report (draft)
        </button>
        <button onClick={exportStix} className="flex items-center gap-1 rounded-full bg-panel-2 px-4 py-2 text-sm ring-1 ring-line">
          <Share2 size={14} /> STIX 2.1 bundle
        </button>
      </div>
      {stixInfo && <div className="mt-2 text-xs text-ok">Exported {stixInfo}</div>}
      <div className="mt-2 text-xs text-mute">Drafts are generated locally and never sent; an analyst reviews and files them.</div>
      {open && <CertInReportModal orgId={orgId} cveId={cveId} onClose={() => setOpen(false)} />}
    </Panel>
  )
}
