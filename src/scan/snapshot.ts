// Deployment change detection. Record a snapshot of a built directory, then diff
// a later build against it to catch UNEXPECTED code changes — a supply-chain
// tamper, a dependency that shifted, a stray file. Filenames in modern bundles
// are content-hashed, so we diff by a hash-stripped "logical" key: a changed
// chunk shows up as changed, not as remove+add.
import { createHash } from 'node:crypto'
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

export interface Snapshot {
  version: 1
  createdAt: string
  files: Record<string, { sha256: string; bytes: number }>
}

function walk(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

export function takeSnapshot(root: string): Snapshot {
  const files: Snapshot['files'] = {}
  for (const f of walk(root)) {
    const buf = readFileSync(f)
    files[relative(root, f) || f] = { sha256: createHash('sha256').update(buf).digest('hex'), bytes: buf.length }
  }
  return { version: 1, createdAt: new Date().toISOString(), files }
}

// Strip a content-hash segment so index-a1b2c3d4.js and index-e5f6g7h8.js share
// a logical key (index-*.js). Covers common bundler hash shapes.
export function logicalKey(path: string): string {
  return path.replace(/[-.][A-Za-z0-9_]{8,}(?=\.[a-z0-9]+$)/i, '-*')
}

export interface SnapshotDiff {
  added: string[] // current paths with no counterpart in base
  removed: string[] // base paths gone from current
  changed: string[] // same logical key, different content
}

export function diffSnapshots(base: Snapshot, cur: Snapshot): SnapshotDiff {
  const group = (snap: Snapshot) => {
    const m = new Map<string, { paths: string[]; hashes: Set<string> }>()
    for (const [path, info] of Object.entries(snap.files)) {
      const k = logicalKey(path)
      const g = m.get(k) ?? { paths: [], hashes: new Set() }
      g.paths.push(path)
      g.hashes.add(info.sha256)
      m.set(k, g)
    }
    return m
  }
  const b = group(base)
  const c = group(cur)
  const added: string[] = []
  const removed: string[] = []
  const changed: string[] = []
  for (const [k, g] of c) {
    if (!b.has(k)) added.push(...g.paths)
    else if (![...g.hashes].every((h) => b.get(k)!.hashes.has(h)) || g.hashes.size !== b.get(k)!.hashes.size)
      changed.push(...g.paths)
  }
  for (const [k, g] of b) if (!c.has(k)) removed.push(...g.paths)
  return { added: added.sort(), removed: removed.sort(), changed: changed.sort() }
}
