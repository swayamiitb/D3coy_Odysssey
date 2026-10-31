import { useState } from 'react'

export interface HeatData { rows: string[]; cols: string[]; values: number[][]; normalise?: 'row' | 'row-range' | 'global'; marks?: [number, number][] }

const HUE: Record<string, string> = {
  crit: 'var(--color-crit)', action: 'var(--color-text)', accent: 'var(--color-accent)', high: 'var(--color-high)',
  comp: 'var(--color-comp)',
}

/** Sequential single-hue heatmap: zero is a distinct grey, and intensity is square-root scaled so low values stay visible.
 *  normalise 'row' scales each row to its own peak. 'row-range' runs each row linearly from its quietest to its busiest
 *  day, for steady series whose story is the variation. Outlined marks highlight cells. */
export function Heatmap({ data, hue = 'accent', unit = '', cellH = 16, labelW = 190, dateCols = true }: {
  data: HeatData; hue?: keyof typeof HUE; unit?: string; cellH?: number; labelW?: number; dateCols?: boolean
}) {
  const [hover, setHover] = useState<[number, number]>()
  const { rows, cols, values } = data
  if (!rows.length || !cols.length) return <div className="text-sm text-mute">No data yet.</div>
  const globalMax = Math.max(1, ...values.flat())
  const ranges = values.map((r) => {
    const pos = r.filter((v) => v > 0)
    return pos.length ? [Math.min(...pos), Math.max(...pos)] : [0, 1]
  })
  const marks = new Set((data.marks ?? []).map(([r, c]) => `${r}:${c}`))
  const level = (r: number, v: number) => {
    if (data.normalise === 'row-range') {
      const [lo, hi] = ranges[r]
      return hi > lo ? (v - lo) / (hi - lo) : 0.5
    }
    const max = data.normalise === 'row' ? Math.max(1, ...values[r]) : globalMax
    return Math.sqrt(v / max)
  }
  const fill = (x: number) => `color-mix(in oklab, ${HUE[hue]} ${Math.round(10 + 85 * x)}%, var(--color-panel))`
  const every = dateCols ? Math.max(1, Math.ceil(cols.length / 12)) : 1
  const h = hover ? { row: rows[hover[0]], col: cols[hover[1]], v: values[hover[0]][hover[1]] } : undefined
  return (
    <div>
      <div className="mb-2 h-5 text-sm">
        {h ? <span><b>{h.row}</b> <span className="text-mute">· {h.col} ·</span> <b>{h.v.toLocaleString('en-IN')}</b>{unit && <span className="text-mute"> {unit}</span>}</span>
          : <span className="text-mute">Hover a cell for its value</span>}
      </div>
      <div className="overflow-x-auto pb-1">
        <div className="grid gap-[2px]" style={{ gridTemplateColumns: `${labelW}px repeat(${cols.length}, minmax(${dateCols ? 6 : 40}px, 1fr))` }}
             onMouseLeave={() => setHover(undefined)} role="table" aria-label="heatmap">
          {rows.map((row, r) => (
            <div key={row} className="contents" role="row">
              <div className="truncate pr-3 text-xs leading-none" style={{ height: cellH, lineHeight: `${cellH}px` }} title={row} role="rowheader">{row}</div>
              {values[r].map((v, c) => (
                <div key={c} role="cell" onMouseEnter={() => setHover([r, c])}
                     className={`rounded-[3px] ${marks.has(`${r}:${c}`) ? 'ring-2 ring-comp ring-offset-1 ring-offset-panel' : ''} ${hover?.[0] === r && hover?.[1] === c ? 'outline outline-2 outline-text' : ''}`}
                     style={{ height: cellH, background: v > 0 ? fill(level(r, v)) : 'var(--color-panel-2)' }}
                     title={`${row} · ${cols[c]}: ${v}`} />
              ))}
            </div>
          ))}
          <div />
          {cols.map((col, c) => (
            <div key={col} className={`whitespace-nowrap pt-1 text-[11px] text-faint ${dateCols ? 'overflow-visible' : 'truncate'}`}>
              {c % every === 0 ? (dateCols ? col.slice(5) : col) : ''}
            </div>
          ))}
        </div>
      </div>
      <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-mute">
        <span>{data.normalise === 'row-range' ? 'quietest' : 'less'}</span>
        {[0.1, 0.3, 0.55, 0.78, 1].map((x) => (
          <span key={x} className="h-3 w-4 rounded-[3px]" style={{ background: fill(x) }} />
        ))}
        <span>{data.normalise === 'row-range' ? 'busiest day, per row' : `more${data.normalise === 'row' ? ' (relative to each row)' : ''}`}</span>
        <span className="ml-3 inline-block h-3 w-4 rounded-[3px] bg-panel-2" /> <span>none</span>
        {data.marks && data.marks.length > 0 && <><span className="ml-3 inline-block h-3 w-4 rounded-[3px] ring-2 ring-comp" /> <span>detected surge</span></>}
      </div>
    </div>
  )
}
