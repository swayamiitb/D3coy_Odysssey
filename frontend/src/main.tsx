import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { LandingRoot } from './landing/LandingRoot'

// The site opens on the landing story (src/landing/); any ?view=…, ?org=… or ?nolive URL is the Odyssey console.
const q = new URLSearchParams(window.location.search)
const landing = !q.has('view') && !q.has('org') && !q.has('nolive')

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    {landing ? <LandingRoot /> : <App />}
  </StrictMode>,
)
