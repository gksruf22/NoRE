import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync, mkdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scan } from '../src/scan/scanner.js'

let dir: string
beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'nore-scan-'))
})
afterAll(() => rmSync(dir, { recursive: true, force: true }))

function fresh(): string {
  const d = join(dir, Math.random().toString(36).slice(2))
  mkdirSync(d, { recursive: true })
  return d
}

describe('scan', () => {
  it('fails a build that ships a source map with original source', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'console.log("hi")\n//# sourceMappingURL=app.js.map')
    writeFileSync(
      join(d, 'app.js.map'),
      JSON.stringify({ version: 3, sources: ['src/secret.ts'], sourcesContent: ['const KEY="x"'] })
    )
    const r = scan(d)
    expect(r.grade).toBe('F')
    expect(r.findings.some((f) => f.id === 'sourcemaps')).toBe(true)
  })

  it('flags a real-looking secret but ignores declared canaries', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'const k="sk_live_REAL1234567890ABCDEFGH"; const c="sk_live_canary01";')
    // Without a manifest, the secret is flagged.
    expect(scan(d).findings.some((f) => f.id === 'secrets')).toBe(true)

    // Declare the canary -> it must not be penalized, and shows as a positive.
    writeFileSync(
      join(d, 'nore-canaries.json'),
      JSON.stringify({ canaries: [{ value: 'sk_live_REAL1234567890ABCDEFGH' }, { value: 'sk_live_canary01' }] })
    )
    const r = scan(d)
    expect(r.findings.some((f) => f.id === 'secrets')).toBe(false)
    expect(r.findings.some((f) => f.id === 'canaries')).toBe(true)
  })

  it('does not count base64 string-array blobs as readable strings', () => {
    const d = fresh()
    // 40 base64 blobs like an obfuscator string array — must NOT read as cleartext.
    const arr = Array.from({ length: 40 }, (_, i) => `"${Buffer.from('payload' + i).toString('base64')}"`)
    writeFileSync(join(d, 'app.js'), `const a=[${arr.join(',')}];`)
    const r = scan(d)
    expect(r.findings.some((f) => f.id === 'cleartext-strings')).toBe(false)
  })
})

describe('anti-LLM verdict', () => {
  it('reports none/weak for plain code and flags it', () => {
    const d = fresh()
    const plain = Array.from({ length: 5 }, (_, i) =>
      `export function computeTotalPrice_${i}(items){return items.reduce((a,b)=>a+b.price,0)}`
    ).join('\n')
    writeFileSync(join(d, 'app.js'), plain)
    const r = scan(d)
    expect(['none', 'weak']).toContain(r.antiLlm.verdict)
  })

  it('detects multiple stacked transforms in high-preset output', async () => {
    const JavaScriptObfuscator = (await import('javascript-obfuscator')).default
    const { PRESETS } = await import('../src/build/vite-plugin.js')
    const src = Array.from({ length: 20 }, (_, i) =>
      `export function h${i}(p){const u='/api/v1/x${i}';let s=0;for(let k=0;k<p.length;k++)s+=p.charCodeAt(k);return u+s}`
    ).join('\n')
    const d = fresh()
    writeFileSync(join(d, 'app.js'), JavaScriptObfuscator.obfuscate(src, PRESETS.high as any).getObfuscatedCode())
    const r = scan(d)
    // high always applies string-array encoding, so it must never read as plain.
    expect(['partial', 'strong']).toContain(r.antiLlm.verdict)
    expect(r.findings.some((f) => f.id === 'shallow-obfuscation')).toBe(false)
  })
})

import { renderBadge } from '../src/scan/badge.js'

describe('renderBadge', () => {
  it('produces a valid SVG embedding the grade and score', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'export const x=1')
    const svg = renderBadge(scan(d))
    expect(svg.startsWith('<svg')).toBe(true)
    expect(svg.trim().endsWith('</svg>')).toBe(true)
    expect(svg).toMatch(/[A-F] \d+\/100/)
  })
})

import { endpointJson } from '../src/scan/badge.js'

describe('endpointJson', () => {
  it('emits a valid shields.io endpoint schema', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'export const x=1')
    const j = JSON.parse(endpointJson(scan(d)))
    expect(j.schemaVersion).toBe(1)
    expect(j.label).toBe('RE exposure')
    expect(j.message).toMatch(/[A-F] \d+\/100/)
    expect(typeof j.color).toBe('string')
  })
})
