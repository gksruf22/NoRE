// Production-minded canary collector. ANY request to a canary route means
// someone extracted a decoy secret/endpoint from your bundle and probed it.
//
//   node examples/canary-collector.mjs                 # serve on :8787
//   node examples/canary-collector.mjs --selfcheck     # run the logic self-check
//
// Build with: nore({ canaries: { collector: 'http://localhost:8787' } })
//
// Operational notes (addressing real deployment concerns):
//  - De-dup: the same (canary, client) within DEDUP_MS alerts once, so a retry
//    loop doesn't spam you.
//  - Rate limit: per-IP request cap protects the collector from flooding.
//  - Privacy: client IPs are stored HASHED by default (set HASH_IPS=0 to keep
//    raw). Decide your own retention; this demo keeps counts in memory only.
//  - Auth: the hit endpoint must stay open (attackers won't authenticate), but
//    the /stats read endpoint requires NORE_COLLECTOR_KEY.
import { createServer } from 'node:http'
import { createHash } from 'node:crypto'

const DEDUP_MS = Number(process.env.DEDUP_MS ?? 10 * 60_000)
const RATE_MAX = Number(process.env.RATE_MAX ?? 60) // requests per IP per minute
const RATE_MS = 60_000
const HASH_IPS = process.env.HASH_IPS !== '0'

export function maskIp(ip, hash = true) {
  if (!ip) return 'unknown'
  return hash ? 'ip_' + createHash('sha256').update(ip).digest('hex').slice(0, 12) : ip
}

// First hit for (key) in the window alerts; repeats inside the window are deduped.
export function makeDedup(windowMs) {
  const seen = new Map() // key -> lastMs
  return {
    alert(key, now) {
      const last = seen.get(key)
      seen.set(key, now)
      if (last !== undefined && now - last < windowMs) return false
      return true
    },
    _seen: seen
  }
}

// Rolling per-key counter; allow() is false once max is exceeded within windowMs.
export function makeRateLimit(max, windowMs) {
  const hits = new Map() // key -> {start, count}
  return {
    allow(key, now) {
      const h = hits.get(key)
      if (!h || now - h.start >= windowMs) {
        hits.set(key, { start: now, count: 1 })
        return true
      }
      h.count++
      return h.count <= max
    }
  }
}

if (process.argv.includes('--selfcheck')) {
  const assert = (c, m) => {
    if (!c) throw new Error('selfcheck failed: ' + m)
  }
  const d = makeDedup(1000)
  assert(d.alert('a|1', 0) === true, 'first hit alerts')
  assert(d.alert('a|1', 500) === false, 'repeat within window deduped')
  assert(d.alert('a|1', 1500) === true, 'after window alerts again')
  assert(d.alert('b|1', 1500) === true, 'different key alerts')
  const r = makeRateLimit(2, 1000)
  assert(r.allow('x', 0) && r.allow('x', 10) && !r.allow('x', 20), 'rate limit trips after max')
  assert(r.allow('x', 1100) === true, 'rate window resets')
  assert(maskIp('1.2.3.4').startsWith('ip_') && maskIp('1.2.3.4', false) === '1.2.3.4', 'ip masking')
  console.log('selfcheck OK')
  process.exit(0)
}

const PORT = process.env.PORT ?? 8787
const dedup = makeDedup(DEDUP_MS)
const rate = makeRateLimit(RATE_MAX, RATE_MS)
const counts = new Map() // canary id -> total hits (in-memory; wire to durable storage for retention)

createServer((req, res) => {
  const now = Date.now()
  const ip = maskIp(req.socket.remoteAddress, HASH_IPS)

  // Guarded read endpoint.
  if (req.url?.startsWith('/stats')) {
    if (!process.env.NORE_COLLECTOR_KEY || req.headers['x-nore-key'] !== process.env.NORE_COLLECTOR_KEY) {
      res.writeHead(401).end('{"error":"unauthorized"}')
      return
    }
    res.writeHead(200, { 'content-type': 'application/json' })
    res.end(JSON.stringify(Object.fromEntries(counts)))
    return
  }

  if (!rate.allow(ip, now)) {
    res.writeHead(429).end('{"ok":true}') // look boring; don't reveal the limit
    return
  }

  // Extract the canary id from the route/query (…/c/<id> or ?k=<id>).
  const id = (req.url?.match(/\/c\/([A-Za-z0-9_]+)/) ?? req.url?.match(/[?&]k=([A-Za-z0-9_]+)/) ?? [])[1] ?? req.url
  counts.set(id, (counts.get(id) ?? 0) + 1)

  if (dedup.alert(`${id}|${ip}`, now)) {
    // Route to your real alerting (Slack/email/SIEM). Demo logs to stderr.
    console.error('🪤  CANARY TRIPPED:', JSON.stringify({ at: new Date(now).toISOString(), id, ip, ua: req.headers['user-agent'] ?? '', url: req.url }))
  }
  res.writeHead(200, { 'content-type': 'application/json' }).end('{"ok":true}')
}).listen(PORT, () => console.log(`canary collector on :${PORT} (dedup ${DEDUP_MS}ms, rate ${RATE_MAX}/min, ip hashing ${HASH_IPS})`))
