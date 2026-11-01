// The site's front page: our landing story. It decides its data mode first (live API, saved snapshot in /demo, or
// labelled sample data), and if it ever fails to render, the Odyssey console is still one click away.
import { Component, useEffect, useState, type ReactNode } from 'react'
import { detectMode } from './data'
import { Landing } from './Landing'

class Boundary extends Component<{ children: ReactNode }, { failed: boolean }> {
  state = { failed: false }
  static getDerivedStateFromError() { return { failed: true } }
  componentDidCatch(e: unknown) { console.error('landing', e) }
  render() {
    if (!this.state.failed) return this.props.children
    return (
      <div className="landing flex flex-col items-center justify-center gap-5 p-8 text-center">
        <p className="text-[18px]">The story couldn't load.</p>
        <a href="/?view=now" className="pill pill-primary">Open the console</a>
      </div>
    )
  }
}

export function LandingRoot() {
  const [ready, setReady] = useState(false)
  useEffect(() => { detectMode().then(() => setReady(true)) }, [])
  if (!ready) return <div className="landing p-6 text-[15px] text-mute">Connecting to Odyssey…</div>
  return <Boundary><Landing /></Boundary>
}
