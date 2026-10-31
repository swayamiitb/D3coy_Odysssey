import { Crosshair, ShieldPlus } from 'lucide-react'
import { Badge, Panel } from './ui'

export interface AttackMap {
  techniques: { id: string; name: string; why: string; tactics: string[]; url: string }[]
  mitigations: { id: string; name: string; covers: number; description: string; url: string }[]
  source: string
}

export function AttackPanel({ attack }: { attack?: AttackMap | null }) {
  if (!attack || attack.techniques.length === 0) return null
  return (
    <Panel title="Attack pattern · MITRE ATT&CK" right={<span className="text-xs text-mute">rules, not generated</span>}>
      <ul className="space-y-1.5 text-xs">
        {attack.techniques.map((t) => (
          <li key={t.id} className="flex items-start gap-2">
            <Crosshair size={12} className="mt-0.5 shrink-0 text-crit" />
            <div>
              <a href={t.url} target="_blank" rel="noreferrer" className="font-mono text-accent hover:underline">{t.id}</a>{' '}
              <span>{t.name}</span> <span className="text-mute">· {t.tactics.join(', ')}</span>
              <div className="text-mute">{t.why}</div>
            </div>
          </li>
        ))}
      </ul>
      <div className="mb-1.5 mt-3 flex items-center gap-1 text-xs uppercase tracking-wider text-mute"><ShieldPlus size={12} /> Official mitigations</div>
      <ul className="space-y-1.5 text-xs">
        {attack.mitigations.map((m) => (
          <li key={m.id}>
            <a href={m.url} target="_blank" rel="noreferrer" className="font-mono text-ok hover:underline">{m.id}</a>{' '}
            <span className="font-medium">{m.name}</span> <Badge>covers {m.covers} technique{m.covers > 1 ? 's' : ''}</Badge>
            <div className="text-mute">{m.description}</div>
          </li>
        ))}
      </ul>
      <div className="mt-2 text-[11px] text-mute">{attack.source}</div>
    </Panel>
  )
}
