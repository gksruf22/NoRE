// A committed ignore file records reviewed false positives WITH a reason, so the
// same suppressions apply locally and in CI (the review's "오탐 관리" point).
//
// nore-ignore.json:
//   { "ignore": [
//       { "id": "secret:Google/Firebase API key", "reason": "public Firebase config, referrer-restricted" },
//       { "id": "internal-hosts", "reason": "staging URLs are intentional in the preview build" }
//   ] }
// A bare array of strings also works: { "ignore": ["internal-hosts"] }.
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'

export interface IgnoreEntry {
  id: string
  reason?: string
}

export function parseIgnoreConfig(text: string): IgnoreEntry[] {
  let obj: any
  try {
    obj = JSON.parse(text)
  } catch {
    return []
  }
  const list = Array.isArray(obj) ? obj : obj?.ignore
  if (!Array.isArray(list)) return []
  return list
    .map((e) => (typeof e === 'string' ? { id: e } : e && typeof e.id === 'string' ? { id: e.id, reason: e.reason } : null))
    .filter((e): e is IgnoreEntry => !!e)
}

// Load the first nore-ignore.json found in the given dirs (in order).
export function loadIgnoreFile(dirs: string[]): IgnoreEntry[] {
  for (const d of dirs) {
    const p = join(d, 'nore-ignore.json')
    if (existsSync(p)) return parseIgnoreConfig(readFileSync(p, 'utf8'))
  }
  return []
}
