import { describe, it, expect } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { execFileSync } from 'node:child_process'
import JavaScriptObfuscator from 'javascript-obfuscator'
import { PRESETS } from '../src/build/vite-plugin.js'

// Proves high-preset obfuscation PRESERVES BEHAVIOR for the patterns that most
// often break under obfuscation: dynamic import + code splitting, and reflection
// (computed property access). We obfuscate both chunks and execute in real Node.
const MATH = `export function add(a, b) { return a + b }\nexport function tag() { return 'math-chunk' }`
const ENTRY = `export async function run() {
  const m = await import('./math.mjs')          // dynamic import -> split chunk
  const obj = { alpha: 10, beta: 20 }
  const key = 'al' + 'pha'                        // reflection: computed key
  return m.add(2, 3) + (obj[key] + Object.keys(obj).length) + m.tag().length
}` // 5 + (10+2) + 10 = 27

function runBuilt(obfuscate: boolean): number {
  const d = mkdtempSync(join(tmpdir(), 'nore-rt-'))
  try {
    const t = (s: string) =>
      obfuscate ? JavaScriptObfuscator.obfuscate(s, PRESETS.high as any).getObfuscatedCode() : s
    writeFileSync(join(d, 'math.mjs'), t(MATH))
    writeFileSync(join(d, 'entry.mjs'), t(ENTRY))
    const url = 'file://' + join(d, 'entry.mjs')
    const script = `import(${JSON.stringify(url)}).then(m=>m.run()).then(r=>{process.stdout.write(String(r));process.exit(0)}).catch(e=>{process.stderr.write(e.message);process.exit(3)})`
    return Number(execFileSync(process.execPath, ['-e', script], { timeout: 15000 }).toString().trim())
  } finally {
    rmSync(d, { recursive: true, force: true })
  }
}

describe('obfuscated code still runs (behavior preserved)', () => {
  it('dynamic import + code splitting + reflection survive preset high', () => {
    const plain = runBuilt(false)
    const obf = runBuilt(true)
    expect(plain).toBe(27)
    expect(obf).toBe(27)
  }, 40000)
})
