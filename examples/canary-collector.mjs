// Minimal canary collector. Deploy anywhere reachable (its URL becomes your
// `collector`). ANY request that lands here means someone extracted a decoy
// secret/endpoint from your bundle and probed it — a reverse engineer, or an AI
// agent told to "find and test this app's keys". There are no false positives:
// real app code never touches these routes.
//
//   node examples/canary-collector.mjs   # listens on :8787
// then build with  nore({ canaries: { collector: 'http://localhost:8787' } })
import { createServer } from 'node:http'

const PORT = process.env.PORT ?? 8787
createServer((req, res) => {
  const hit = {
    at: new Date().toISOString(),
    url: req.url,
    ip: req.socket.remoteAddress,
    ua: req.headers['user-agent'] ?? '',
    auth: req.headers['authorization'] ?? ''
  }
  // Route your real alerting here (Slack, email, SIEM). For the demo we log.
  console.error('🪤  CANARY TRIPPED:', JSON.stringify(hit))
  res.writeHead(200, { 'content-type': 'application/json' })
  res.end('{"ok":true}') // look boring so the prober doesn't suspect a trap
}).listen(PORT, () => console.log(`canary collector on :${PORT}`))
