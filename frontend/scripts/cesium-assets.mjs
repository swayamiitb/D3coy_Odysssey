// Copies the static files CesiumJS needs at run time (web workers, third-party decoders, textures including the
// bundled Natural Earth II imagery that serves the globe offline, and the widget CSS) from node_modules into
// public/cesium, where Vite serves them at /cesium/ (CESIUM_BASE_URL). Runs on `npm install` (postinstall) and is
// safe to re-run; public/cesium is generated and not committed.
import { cp, mkdir, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')
const src = join(root, 'node_modules', 'cesium', 'Build', 'Cesium')
const dst = join(root, 'public', 'cesium')

try {
  await stat(src)
} catch {
  console.log('cesium-assets: cesium is not installed yet; nothing to copy')
  process.exit(0)
}
await mkdir(dst, { recursive: true })
for (const dir of ['Assets', 'Workers', 'ThirdParty', 'Widgets']) {
  await cp(join(src, dir), join(dst, dir), { recursive: true, force: true })
  console.log(`cesium-assets: ${dir} -> public/cesium/${dir}`)
}
