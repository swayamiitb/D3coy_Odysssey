/*
 * Odyssey Shield agent for Node/Express (and Connect-style middleware).
 *
 * Forwards every request to Odyssey's HTTP shield for attack detection; in enforce mode a request the shield blocks
 * is dropped inline with 403.
 *
 *   const { odysseyShield } = require('./agent/odyssey_express')
 *   app.use(odysseyShield({ appId: 'ops-console', name: 'Ops Console', orgId: 'TEL-01', mode: 'enforce' }))
 *
 * Dependency-free (uses Node's built-in http/https), fail-open, and non-blocking in monitor mode. Set the shield URL
 * with the ODYSSEY_SHIELD_URL env var (default http://127.0.0.1:8000). Mount this BEFORE your body parser if you want
 * request bodies inspected; it reads the raw body without consuming it for downstream handlers.
 */
'use strict'

const http = require('http')
const https = require('https')
const { URL } = require('url')

const SHIELD = (process.env.ODYSSEY_SHIELD_URL || 'http://127.0.0.1:8000').replace(/\/$/, '')
const FORWARD = ['user-agent', 'referer', 'referrer', 'cookie', 'x-forwarded-for', 'x-real-ip',
  'content-type', 'x-api-version', 'x-odyssey-redteam', 'x-odyssey-rt-case']
const BODY_LIMIT = 64 * 1024

function post (path, payload, timeout, cb) {
  const url = new URL(SHIELD + path)
  const body = Buffer.from(JSON.stringify(payload))
  const lib = url.protocol === 'https:' ? https : http
  const req = lib.request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'content-length': body.length },
    timeout
  }, (res) => {
    let data = ''
    res.on('data', (c) => { data += c })
    res.on('end', () => { try { cb(null, JSON.parse(data || '{}')) } catch (e) { cb(e) } })
  })
  req.on('error', (e) => cb(e))
  req.on('timeout', () => { req.destroy(); cb(new Error('timeout')) })
  req.end(body)
}

function odysseyShield (opts) {
  const meta = {
    app: opts.appId, name: opts.name || opts.appId, base_url: opts.baseUrl || null,
    mode: opts.mode || 'monitor', org_id: opts.orgId || null, framework: opts.framework || 'express'
  }
  post('/api/sensor/register', meta, 1500, () => {})

  return function (req, res, next) {
    const chunks = []
    let size = 0
    req.on('data', (c) => { if (size < BODY_LIMIT) chunks.push(c.slice(0, BODY_LIMIT - size)); size += c.length })

    const finish = () => {
      const headers = {}
      for (const h of FORWARD) if (req.headers[h]) headers[h] = req.headers[h]
      const xff = (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      const event = {
        ...meta,
        ts: new Date().toISOString(),
        method: req.method,
        path: (req.originalUrl || req.url || '').split('?')[0],
        query: (req.originalUrl || req.url || '').split('?')[1] || '',
        body: Buffer.concat(chunks).toString('utf8'),
        source_ip: xff || (req.socket && req.socket.remoteAddress) || '',
        host: req.headers.host,
        headers
      }

      if (meta.mode === 'enforce') {
        post('/api/sensor/http', event, 2000, (err, resp) => {
          if (!err && resp && resp.decision === 'block') {
            // The synchronous ingest already recorded this request; do not re-send it.
            res.statusCode = 403
            res.setHeader('content-type', 'application/json')
            res.setHeader('x-blocked-by', 'odyssey-shield')
            return res.end(JSON.stringify({ error: 'blocked', by: 'Odyssey HTTP shield' }))
          }
          next() // fail-open
        })
      } else {
        res.on('finish', () => { event.status = res.statusCode; post('/api/sensor/http', event, 2000, () => {}) })
        next()
      }
    }

    // Wait for the body if there is one; otherwise proceed immediately.
    if (req.method === 'GET' || req.method === 'HEAD') finish()
    else { req.on('end', finish); req.on('error', finish) }
  }
}

module.exports = { odysseyShield }
