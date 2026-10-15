// Reverse-engineering tripwires ("canaries"). We inject decoy secrets and
// endpoints into the shipped bundle that look like real leaked config but are
// never used by the app. Any request that reaches them proves someone extracted
// secrets from your bundle — a reverse engineer, or (increasingly) an AI agent
// told to "find the API keys in this app and try them". Zero false positives by
// construction: real code never touches a canary.
//
// This is the opposite of obfuscation. Obfuscation hides; canaries are left in
// cleartext *on purpose* so an extractor surfaces them and takes the bait.

import { randomBytes } from 'node:crypto'

export interface CanaryOptions {
  /** Your collector base URL. A hit to any canary route here = someone is poking. */
  collector: string
  /** How many decoys to plant. Default 4. */
  count?: number
  /** Optional seed id prefix so you can group a release's canaries. */
  release?: string
}

export interface Canary {
  id: string
  kind: 'endpoint' | 'apiKey' | 'adminFlag'
  /** Human label, for your collector dashboard. */
  label: string
  /** The bait value as it appears in the bundle. */
  value: string
}

const LABELS = [
  { kind: 'endpoint', label: 'internal admin API', path: 'internal/v2/admin' },
  { kind: 'apiKey', label: 'live secret key', path: 'v1/charge' },
  { kind: 'adminFlag', label: 'staff override flag', path: 'flags/staff-override' },
  { kind: 'endpoint', label: 'debug data export', path: 'internal/export' },
  { kind: 'apiKey', label: 'service account token', path: 'v1/accounts' },
  { kind: 'adminFlag', label: 'feature kill switch', path: 'flags/kill-switch' }
] as const

function newId(release?: string): string {
  const r = randomBytes(6).toString('hex')
  return release ? `${release}_${r}` : r
}

/** Build a set of canaries. Each embeds a collector URL carrying its unique id. */
export function generateCanaries(opts: CanaryOptions): Canary[] {
  const base = opts.collector.replace(/\/+$/, '')
  const n = Math.max(1, Math.min(opts.count ?? 4, LABELS.length))
  return LABELS.slice(0, n).map((spec) => {
    const id = newId(opts.release)
    const hit = `${base}/c/${id}` // the real beacon: any request here is logged
    if (spec.kind === 'apiKey') {
      // A key-looking value whose "docs" point at the collector, so an agent
      // that tries the key POSTs to our endpoint.
      return { id, kind: spec.kind, label: spec.label, value: `sk_live_${id}` } satisfies Canary
    }
    if (spec.kind === 'adminFlag') {
      return { id, kind: spec.kind, label: spec.label, value: hit } satisfies Canary
    }
    return { id, kind: spec.kind, label: spec.label, value: `${base}/${spec.path}?k=${id}` } satisfies Canary
  })
}

/**
 * JS that plants the canaries in the bundle. Kept in CLEARTEXT (injected after
 * obfuscation) and made unremovable by assigning to a global with a side effect,
 * so tree-shaking/minification can't drop the "unused" decoys. Harmless at runtime.
 */
export function canaryBanner(canaries: Canary[], collector: string): string {
  const base = collector.replace(/\/+$/, '')
  const cfg = {
    apiBase: base,
    endpoints: {} as Record<string, string>,
    keys: {} as Record<string, string>,
    flags: {} as Record<string, boolean>
  }
  for (const c of canaries) {
    if (c.kind === 'endpoint') cfg.endpoints[c.label.replace(/\s+/g, '_')] = c.value
    else if (c.kind === 'apiKey') cfg.keys[c.label.replace(/\s+/g, '_')] = c.value
    else cfg.flags[c.label.replace(/\s+/g, '_')] = true
  }
  // Readable, plausible "leaked config". The try/catch + global assignment is a
  // side effect, so the block survives dead-code elimination.
  return (
    `\n/* app runtime config */\n` +
    `;(function(){var __APP_CONFIG=${JSON.stringify(cfg)};` +
    `try{(typeof window!=="undefined"?window:globalThis).__APP_CONFIG=__APP_CONFIG;}catch(e){}})();\n`
  )
}
