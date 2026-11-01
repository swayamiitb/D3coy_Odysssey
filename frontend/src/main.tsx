import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { LandingRoot } from './landing/LandingRoot'

// The site opens on the landing story (src/landing/); any ?view=…, ?org=… or ?nolive URL is the Odyssey console.
const q = new URLSearchParams(window.location.search)
const landing = !q.has('view') && !q.has('org') && !q.has('nolive')
// The console wears the Uber black-and-white theme (index.css, html.soc), or all black when the analyst chose the
// night shift; applied before the first paint so nothing flashes. The landing keeps its own .landing scope.
if (!landing) {
  document.documentElement.classList.add('soc')
  try { if (localStorage.getItem('odyssey-night') === '1') document.documentElement.classList.add('night') } catch { /* private mode */ }
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {landing ? <LandingRoot /> : <App />}
  </StrictMode>,
)
