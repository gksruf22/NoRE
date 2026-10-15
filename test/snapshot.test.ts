import { describe, it, expect } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { takeSnapshot, diffSnapshots, logicalKey } from '../src/scan/snapshot.js'

describe('logicalKey', () => {
  it('strips content-hash segments so hashed variants share a key', () => {
    expect(logicalKey('assets/index-a1b2c3d4.js')).toBe('assets/index-*.js')
    expect(logicalKey('assets/index-a1b2c3d4.js')).toBe(logicalKey('assets/index-zzzzzzzz.js'))
    expect(logicalKey('index.html')).toBe('index.html') // no hash, unchanged
  })
})

describe('diffSnapshots', () => {
  function build(files: Record<string, string>): string {
    const d = mkdtempSync(join(tmpdir(), 'snap-'))
    for (const [p, c] of Object.entries(files)) {
      const full = join(d, p)
      mkdirSync(join(full, '..'), { recursive: true })
      writeFileSync(full, c)
    }
    return d
  }

  it('reports no changes for an identical build', () => {
    const a = build({ 'assets/app-1111aaaa.js': 'x' })
    const b = build({ 'assets/app-1111aaaa.js': 'x' })
    const d = diffSnapshots(takeSnapshot(a), takeSnapshot(b))
    expect(d).toEqual({ added: [], removed: [], changed: [] })
    rmSync(a, { recursive: true }); rmSync(b, { recursive: true })
  })

  it('detects a content change as changed (not add+remove), and new/removed files', () => {
    const a = build({ 'assets/app-1111aaaa.js': 'old', 'gone-2222bbbb.js': 'g' })
    const b = build({ 'assets/app-9999cccc.js': 'new', 'extra.js': 'e' })
    const d = diffSnapshots(takeSnapshot(a), takeSnapshot(b))
    expect(d.changed).toContain('assets/app-9999cccc.js')
    expect(d.added).toContain('extra.js')
    expect(d.removed).toContain('gone-2222bbbb.js')
    rmSync(a, { recursive: true }); rmSync(b, { recursive: true })
  })
})
