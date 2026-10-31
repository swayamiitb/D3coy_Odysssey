import { BrainCircuit } from 'lucide-react'
import { Panel } from './ui'

export interface Bayes {
  p_compromise: number
  prior: number
  decision: 'compromised' | 'hunt' | 'no evidence of compromise'
  factors: { factor: string; value: number; detail: string }[]
}

const TONE: Record<Bayes['decision'], string> = {
  compromised: 'text-comp',
  hunt: 'text-high',
  'no evidence of compromise': 'text-ok',
}

export function DecisionPanel({ bayes }: { bayes?: Bayes }) {
  if (!bayes) return null
  const pct = bayes.p_compromise * 100
  return (
    <Panel title="Decision model · Bayesian compromise probability"
           right={<span className="flex items-center gap-1 text-xs text-mute"><BrainCircuit size={12} /> explainable, 0 VRAM</span>}>
      <div className="flex items-center gap-4">
        <div className="text-center">
          <div className={`font-mono text-4xl font-semibold ${TONE[bayes.decision]}`}>{pct < 1 ? pct.toFixed(2) : pct.toFixed(1)}%</div>
          <div className={`text-xs font-semibold uppercase ${TONE[bayes.decision]}`}>{bayes.decision}</div>
        </div>
        <div className="flex-1">
          <div className="relative h-2 rounded-full bg-panel-2">
            <div className="absolute inset-y-0 left-0 rounded-full bg-comp" style={{ width: `${Math.max(pct, 0.5)}%` }} />
            <div className="absolute inset-y-[-3px] w-px bg-high" style={{ left: '20%' }} title="hunt threshold 20%" />
            <div className="absolute inset-y-[-3px] w-px bg-comp" style={{ left: '50%' }} title="compromise threshold 50%" />
          </div>
          <div className="mt-1 flex justify-between text-[10px] text-mute"><span>0%</span><span>hunt 20%</span><span>compromised 50%</span><span>100%</span></div>
        </div>
      </div>
      <ol className="mt-3 space-y-1 text-xs">
        {bayes.factors.map((f, i) => (
          <li key={i} className="flex items-baseline gap-2">
            <span className="w-16 shrink-0 text-right font-mono">{i === 0 ? `${(f.value * 100).toFixed(1)}%` : `×${f.value}`}</span>
            <span>{f.factor}</span>
            <span className="text-mute">· {f.detail}</span>
          </li>
        ))}
      </ol>
      <div className="mt-2 text-[11px] text-mute">
        Prior from exposure × exploitation × reachability; telemetry enters as likelihood ratios. All probabilities live in
        config/scoring.json and are hashed into every alert.
      </div>
    </Panel>
  )
}
