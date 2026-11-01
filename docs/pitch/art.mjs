// Artwork for the Odyssey pitch deck: a tricolour India with the operators' states, chakra marks and tricolour washes.
// Emits one HTML page per asset under art/; render_art.ps1 screenshots each with headless Edge (transparent background).
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs'

const india = JSON.parse(readFileSync('D:/DECOY/frontend/node_modules/@svg-maps/india/index.js', 'utf8').replace(/^export default /, ''))
const world = JSON.parse(readFileSync('D:/DECOY/data/sim/world.json', 'utf8'))
const perState = {}
for (const o of world.orgs) perState[o.state] = (perState[o.state] || 0) + 1
const COMPROMISED = 'Maharashtra'
mkdirSync('art', { recursive: true })

const SAFFRON = '#F28C28', WHITE = '#FBF7F0', GREEN = '#15843A', NAVY = '#0F1B3D', RED = '#E5383B'

function indiaSvg({ dark }) {
  const paths = india.locations.map((l) => `<path id="s-${l.id}" d="${l.path}" />`).join('\n')
  const stroke = dark ? NAVY : '#FFFFFF'
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 612 696" width="1224" height="1392">
<defs>
  <linearGradient id="tri" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0" stop-color="${SAFFRON}"/><stop offset="0.31" stop-color="${SAFFRON}"/>
    <stop offset="0.38" stop-color="${WHITE}"/><stop offset="0.62" stop-color="${WHITE}"/>
    <stop offset="0.69" stop-color="${GREEN}"/><stop offset="1" stop-color="${GREEN}"/>
  </linearGradient>
  <clipPath id="land">${paths}</clipPath>
  <filter id="shadow" x="-10%" y="-10%" width="130%" height="130%"><feDropShadow dx="0" dy="6" stdDeviation="8" flood-color="${dark ? '#000000' : '#0F1B3D'}" flood-opacity="${dark ? 0.55 : 0.18}"/></filter>
</defs>
<g filter="url(#shadow)"><rect x="0" y="0" width="612" height="696" fill="url(#tri)" clip-path="url(#land)"/></g>
<g id="borders" fill="none" stroke="${stroke}" stroke-width="0.7" stroke-opacity="${dark ? 0.9 : 0.95}">${paths}</g>
<g id="marks"></g>
<script><![CDATA[
  const per = ${JSON.stringify(perState)}; const names = ${JSON.stringify(Object.fromEntries(india.locations.map((l) => [l.id, l.name])))};
  const g = document.getElementById('marks'); const NS = 'http://www.w3.org/2000/svg';
  for (const [id, name] of Object.entries(names)) {
    const n = per[name]; if (!n) continue;
    const el = document.querySelector('#borders #s-' + id); if (!el) continue;
    const b = el.getBBox(); let cx = b.x + b.width / 2, cy = b.y + b.height / 2;
    if (name === 'Delhi') { cx = b.x + b.width / 2; cy = b.y + b.height / 2; }
    const r = 5 + n * 1.6; const comp = name === '${COMPROMISED}';
    const halo = document.createElementNS(NS, 'circle'); halo.setAttribute('cx', cx); halo.setAttribute('cy', cy); halo.setAttribute('r', r + 5);
    halo.setAttribute('fill', comp ? '${RED}' : '${NAVY}'); halo.setAttribute('fill-opacity', '0.22'); g.appendChild(halo);
    const dot = document.createElementNS(NS, 'circle'); dot.setAttribute('cx', cx); dot.setAttribute('cy', cy); dot.setAttribute('r', r);
    dot.setAttribute('fill', comp ? '${RED}' : '${NAVY}'); dot.setAttribute('stroke', '#FFFFFF'); dot.setAttribute('stroke-width', '2'); g.appendChild(dot);
    const t = document.createElementNS(NS, 'text'); t.setAttribute('x', cx); t.setAttribute('y', cy + 3.2); t.setAttribute('text-anchor', 'middle');
    t.setAttribute('font-family', 'Calibri, Arial, sans-serif'); t.setAttribute('font-size', '9'); t.setAttribute('font-weight', '700'); t.setAttribute('fill', '#FFFFFF');
    t.textContent = String(n); g.appendChild(t);
  }
]]></script>
</svg>`
}

function chakraSvg(color) {
  let spokes = ''
  for (let i = 0; i < 24; i++) {
    spokes += `<g transform="rotate(${i * 15} 300 300)"><path d="M300 92 L306 300 L294 300 Z" fill="${color}"/><circle cx="300" cy="86" r="7" fill="${color}"/></g>`
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 600 600" width="1200" height="1200">
<circle cx="300" cy="300" r="286" fill="none" stroke="${color}" stroke-width="12"/>
<circle cx="300" cy="300" r="262" fill="none" stroke="${color}" stroke-width="3"/>
${spokes}
<circle cx="300" cy="300" r="44" fill="none" stroke="${color}" stroke-width="10"/>
<circle cx="300" cy="300" r="14" fill="${color}"/>
</svg>`
}

function washSvg({ dark }) {
  const base = dark ? NAVY : '#FFFFFF'
  const a = dark ? 0.42 : 0.2, b = dark ? 0.36 : 0.16
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 1080" width="1920" height="1080">
<defs>
  <radialGradient id="g1" cx="0" cy="0" r="1"><stop offset="0" stop-color="${SAFFRON}" stop-opacity="${a}"/><stop offset="0.55" stop-color="${SAFFRON}" stop-opacity="${a * 0.35}"/><stop offset="1" stop-color="${SAFFRON}" stop-opacity="0"/></radialGradient>
  <radialGradient id="g2" cx="1" cy="1" r="1"><stop offset="0" stop-color="${GREEN}" stop-opacity="${b}"/><stop offset="0.55" stop-color="${GREEN}" stop-opacity="${b * 0.35}"/><stop offset="1" stop-color="${GREEN}" stop-opacity="0"/></radialGradient>
</defs>
<rect width="1920" height="1080" fill="${base}"/>
<rect width="1920" height="1080" fill="url(#g1)"/>
<rect width="1920" height="1080" fill="url(#g2)"/>
<g opacity="${dark ? 0.08 : 0.05}" transform="translate(1540 540) scale(0.9)">${chakraSvg(dark ? '#FFFFFF' : NAVY).replace(/<svg[^>]*>|<\/svg>/g, '').replace(/cx="300" cy="300"/g, 'cx="0" cy="0"').replace(/rotate\((\d+) 300 300\)/g, 'rotate($1 0 0)').replace(/M300 92 L306 300 L294 300/g, 'M0 -208 L6 0 L-6 0').replace(/cx="300" cy="86"/g, 'cx="0" cy="-214"')}</g>
</svg>`
}

function bandSvg() {
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1920 180" width="1920" height="180">
<defs><linearGradient id="h" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stop-color="${SAFFRON}"/><stop offset="0.5" stop-color="${WHITE}"/><stop offset="1" stop-color="${GREEN}"/></linearGradient></defs>
<rect width="1920" height="180" fill="url(#h)"/>
</svg>`
}

const page = (svg, w, h, transparent) => `<!doctype html><html><head><meta charset="utf-8"><style>html,body{margin:0;padding:0;width:${w}px;height:${h}px;overflow:hidden;background:${transparent ? 'transparent' : 'transparent'}}svg{display:block}</style></head><body>${svg}</body></html>`

const assets = [
  ['india_light', indiaSvg({ dark: false }), 1224, 1392],
  ['india_dark', indiaSvg({ dark: true }), 1224, 1392],
  ['chakra_navy', chakraSvg(NAVY), 1200, 1200],
  ['chakra_white', chakraSvg('#FFFFFF'), 1200, 1200],
  ['chakra_saffron', chakraSvg(SAFFRON), 1200, 1200],
  ['wash_light', washSvg({ dark: false }), 1920, 1080],
  ['wash_dark', washSvg({ dark: true }), 1920, 1080],
  ['band', bandSvg(), 1920, 180],
]
const list = []
for (const [name, svg, w, h] of assets) {
  writeFileSync(`art/${name}.html`, page(svg, w, h, true))
  list.push(`${name},${w},${h}`)
}
writeFileSync('art/list.txt', list.join('\n'))
console.log('art pages:', list.join(' '))
