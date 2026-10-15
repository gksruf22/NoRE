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
    expect(scan(d).findings.some((f) => f.category === 'credential')).toBe(true)

    // Declare the canary -> it must not be penalized, and shows as a positive.
    writeFileSync(
      join(d, 'nore-canaries.json'),
      JSON.stringify({ canaries: [{ value: 'sk_live_REAL1234567890ABCDEFGH' }, { value: 'sk_live_canary01' }] })
    )
    const r = scan(d)
    expect(r.findings.some((f) => f.category === 'credential')).toBe(false)
    expect(r.findings.some((f) => f.id === 'canaries')).toBe(true)
  })

  it('does not count base64 string-array blobs as readable strings', () => {
    const d = fresh()
    // 40 base64 blobs like an obfuscator string array — must NOT read as cleartext.
    const arr = Array.from({ length: 40 }, (_, i) => `"${Buffer.from('payload' + i).toString('base64')}"`)
    writeFileSync(join(d, 'app.js'), `const a=[${arr.join(',')}];`)
    const r = scan(d)
    expect(r.findings.some((f) => f.id === 'readable-strings')).toBe(false)
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

describe('inline source maps', () => {
  it('flags a base64 data-URI source map embedded in the JS', () => {
    const d = fresh()
    const map = Buffer.from(JSON.stringify({ version: 3, sources: ['src/a.ts'], sourcesContent: ['const SECRET=1'] })).toString('base64')
    writeFileSync(join(d, 'app.js'), `console.log(1)\n//# sourceMappingURL=data:application/json;charset=utf-8;base64,${map}`)
    const r = scan(d)
    expect(r.findings.some((f) => f.id === 'inline-sourcemap')).toBe(true)
    expect(r.grade).toBe('F')
  })
})

describe('expanded threat detection', () => {
  it('flags a private key and an internal host, not clean code', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), [
      'const pem = "-----BEGIN RSA PRIVATE KEY-----MIIEx";',
      'const api = "https://admin.staging.internal/api";',
      'const ok = "https://api.example.com/v1";'
    ].join('\n'))
    const r = scan(d)
    expect(r.findings.some((f) => f.category === 'credential')).toBe(true)
    expect(r.findings.some((f) => f.id === 'internal-hosts')).toBe(true)
  })

  it('does not flag public URLs or normal code as internal', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'const u="https://cdn.example.com/x";const v="https://api.github.com";')
    const r = scan(d)
    expect(r.findings.some((f) => f.id === 'internal-hosts')).toBe(false)
  })
})

import { toSarif } from '../src/scan/sarif.js'

describe('evidence, severity, ignore, sarif', () => {
  function withSecret(): string {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'line1\nconst k="sk_live_REALkey1234567890ABCD";')
    return d
  }

  it('attaches file:line evidence to a credential finding (match redacted)', () => {
    const r = scan(withSecret())
    const sec = r.findings.find((f) => f.category === 'credential')!
    expect(sec.locations?.[0].file).toBe('app.js')
    expect(sec.locations?.[0].line).toBe(2)
    expect(sec.locations?.[0].match).not.toContain('REALkey1234567890') // redacted
    expect(sec.remediation.length).toBeGreaterThan(0)
  })

  it('separates severity from the exposure score', () => {
    const r = scan(withSecret())
    expect(r.severityCounts.critical).toBeGreaterThanOrEqual(1)
    // readable strings/identifiers are INFO, not a vulnerability severity
    const info = r.findings.filter((f) => f.severity === 'info').map((f) => f.id)
    expect(r.findings.every((f) => f.severity !== 'high' || f.category !== 'exposure')).toBe(true)
    void info
  })

  it('--ignore suppresses a finding and its penalty', () => {
    const base = scan(withSecret())
    const ignored = scan(withSecret(), { ignore: ['credential'] })
    expect(base.findings.some((f) => f.category === 'credential')).toBe(true)
    expect(ignored.findings.some((f) => f.category === 'credential')).toBe(false)
    expect(ignored.score).toBeGreaterThanOrEqual(base.score)
  })

  it('emits valid SARIF with a result and location', () => {
    const sarif = JSON.parse(toSarif(scan(withSecret())))
    expect(sarif.version).toBe('2.1.0')
    expect(sarif.runs[0].tool.driver.name).toBe('NoRE')
    const res = sarif.runs[0].results.find((x: any) => x.ruleId.startsWith('secret:'))
    expect(res.level).toBe('error')
    expect(res.locations[0].physicalLocation.region.startLine).toBe(2)
  })
})

import { saveBaseline, loadBaseline, isNewFinding } from '../src/scan/baseline.js'

describe('baseline (new-only gating)', () => {
  it('treats recorded findings as known and new ones as new', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'const k="sk_live_OLDkey1234567890ABCD";')
    const r1 = scan(d)
    const bl = join(d, 'baseline.json')
    const n = saveBaseline(bl, r1.findings)
    expect(n).toBeGreaterThan(0)

    const base = loadBaseline(bl)!
    // same build: nothing new
    expect(r1.findings.every((f) => !isNewFinding(f, base))).toBe(true)

    // add a new secret: its finding is now new
    writeFileSync(join(d, 'app.js'), 'const k="sk_live_OLDkey1234567890ABCD";const n2="sk_live_NEWkey0987654321ZZZZ";')
    const r2 = scan(d)
    const cred = r2.findings.find((f) => f.category === 'credential')!
    expect(isNewFinding(cred, base)).toBe(true)
  })

  it('loadBaseline returns null when the file is absent', () => {
    expect(loadBaseline(join(dir, 'nope.json'))).toBeNull()
  })
})

describe('secret classification (public vs real)', () => {
  it('flags a Firebase/Google key as medium, not critical', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'const k="AIzaSyD-1234567890abcdefghijklmnopqrstuv";')
    const f = scan(d).findings.find((x) => x.category === 'credential')!
    expect(f.severity).toBe('medium')
    expect(f.title).toMatch(/Review/)
  })

  it('does not flag publishable keys (pk_live_)', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'const k="pk_live_1234567890ABCDEFGH";')
    expect(scan(d).findings.some((x) => x.category === 'credential')).toBe(false)
  })

  it('still flags a real server secret as critical', () => {
    const d = fresh()
    writeFileSync(join(d, 'app.js'), 'const k="sk_live_1234567890ABCDEFGH";')
    const f = scan(d).findings.find((x) => x.category === 'credential')!
    expect(f.severity).toBe('critical')
  })
})
