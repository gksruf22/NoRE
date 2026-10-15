import { describe, it, expect } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseIgnoreConfig, loadIgnoreFile } from '../src/scan/ignorefile.js'
import { scan } from '../src/scan/scanner.js'

describe('parseIgnoreConfig', () => {
  it('accepts {ignore:[{id,reason}]} and a bare string array', () => {
    expect(parseIgnoreConfig('{"ignore":[{"id":"internal-hosts","reason":"staging ok"}]}')).toEqual([{ id: 'internal-hosts', reason: 'staging ok' }])
    expect(parseIgnoreConfig('{"ignore":["credential"]}')).toEqual([{ id: 'credential' }])
    expect(parseIgnoreConfig('garbage')).toEqual([])
  })
})

describe('nore-ignore.json end to end', () => {
  it('suppresses the matching finding and records it under suppressed', () => {
    const d = mkdtempSync(join(tmpdir(), 'nore-ig-'))
    writeFileSync(join(d, 'app.js'), 'const u="https://admin.staging.internal/x";')
    const entries = loadIgnoreFile([d]) // none yet
    expect(entries).toEqual([])
    writeFileSync(join(d, 'nore-ignore.json'), JSON.stringify({ ignore: [{ id: 'internal-hosts', reason: 'intentional' }] }))
    const ids = loadIgnoreFile([d]).map((e) => e.id)
    const r = scan(d, { ignore: ids })
    expect(r.findings.some((f) => f.id === 'internal-hosts')).toBe(false)
    expect(r.suppressed.some((f) => f.id === 'internal-hosts')).toBe(true)
    rmSync(d, { recursive: true, force: true })
  })
})
