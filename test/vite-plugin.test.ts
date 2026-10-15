import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { build, type Rollup } from 'vite'
import { nore } from '../src/build/vite-plugin.js'

let dir: string
let output: Rollup.OutputChunk[] | any[]

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'nore-'))
  // A recognizable secret string we expect obfuscation to hide.
  writeFileSync(join(dir, 'entry.js'), `export const secret = "SUPER_SECRET_TOKEN"; console.log(secret);`)

  const result: any = await build({
    root: dir,
    logLevel: 'silent',
    plugins: [nore()],
    build: {
      write: false,
      lib: { entry: join(dir, 'entry.js'), formats: ['es'], fileName: 'bundle' }
    }
  })
  output = (Array.isArray(result) ? result[0] : result).output
})

afterAll(() => rmSync(dir, { recursive: true, force: true }))

describe('nore vite plugin', () => {
  it('emits no sourcemap files', () => {
    expect(output.some((o: any) => o.fileName.endsWith('.map'))).toBe(false)
  })

  it('emits the integrity manifest', () => {
    const manifest = output.find((o: any) => o.fileName === 'nore-integrity.json')
    expect(manifest).toBeDefined()
    const hashes = JSON.parse(manifest.source)
    expect(Object.keys(hashes).length).toBeGreaterThan(0)
    for (const h of Object.values(hashes)) expect(h).toMatch(/^[0-9a-f]{64}$/)
  })

  it('obfuscates away the plaintext secret', () => {
    const chunk = output.find((o: any) => o.type === 'chunk')
    expect(chunk.code).not.toContain('SUPER_SECRET_TOKEN')
  })
})

import JavaScriptObfuscator from 'javascript-obfuscator'
import { PRESETS } from '../src/build/vite-plugin.js'

describe('obfuscation presets', () => {
  const sample = `const token = "SUPER_SECRET_TOKEN"; export function f(x){ return token.length + x }`

  it('every preset encodes the plaintext string away', () => {
    for (const name of ['low', 'medium', 'high'] as const) {
      const out = JavaScriptObfuscator.obfuscate(sample, PRESETS[name] as any).getObfuscatedCode()
      expect(out, name).not.toContain('SUPER_SECRET_TOKEN')
    }
  })

  it('higher presets produce larger output (more transformation)', () => {
    const size = (name: 'low' | 'medium' | 'high') =>
      JavaScriptObfuscator.obfuscate(sample, PRESETS[name] as any).getObfuscatedCode().length
    expect(size('high')).toBeGreaterThan(size('low'))
  })
})

import { selectForObfuscation } from '../src/build/vite-plugin.js'

describe('selective obfuscation', () => {
  it('skips vendor chunks by default, obfuscates app chunks', () => {
    const vendor = { name: 'vendor', moduleIds: ['/x/node_modules/react/index.js'] }
    const app = { name: 'index', moduleIds: ['/x/src/main.ts'] }
    expect(selectForObfuscation(vendor, {})).toBe(false)
    expect(selectForObfuscation(app, {})).toBe(true)
    expect(selectForObfuscation(vendor, { obfuscateVendor: true })).toBe(true)
  })

  it('exclude wins over include', () => {
    const chunk = { name: 'hot', fileName: 'hot.js', moduleIds: ['/x/src/hot.ts'] }
    expect(selectForObfuscation(chunk, { exclude: ['hot'] })).toBe(false)
    expect(selectForObfuscation(chunk, { include: [/src/] })).toBe(true)
    expect(selectForObfuscation(chunk, { include: ['other'] })).toBe(false)
    expect(selectForObfuscation(chunk, { include: [/src/], exclude: [/hot/] })).toBe(false)
  })
})
