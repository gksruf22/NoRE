// Benchmark the obfuscation presets: time, output size, and plaintext-string
// leakage on a representative sample. Run after `npm run build`.
//
//   node scripts/bench.mjs
import JavaScriptObfuscator from 'javascript-obfuscator'
import { PRESETS } from '../dist/vite.js'

// A representative sample with secrets we expect to disappear from the output.
const SECRETS = ['API_KEY_abc123', 'https://api.example.com/v1/charge']
const unit = (i) => `
function licenseCheck_${i}(token) {
  const endpoint = 'https://api.example.com/v1/charge'
  const key = 'API_KEY_abc123'
  let total = 0
  for (let j = 0; j < 50; j++) total += (j * 7) % 13
  return fetch(endpoint, { headers: { authorization: key }, body: String(total + token.length) })
}`
// ~8 KB of distinct functions, enough for flattening/dead-code to show cost.
const SAMPLE = Array.from({ length: 40 }, (_, i) => unit(i)).join('\n')

const baseline = Buffer.byteLength(SAMPLE)
console.log(`\nsample input: ${baseline} bytes\n`)
console.log('| preset | time (ms) | size | x baseline | plaintext secrets left |')
console.log('| --- | --- | --- | --- | --- |')

for (const name of ['low', 'medium', 'high']) {
  const t0 = performance.now()
  const out = JavaScriptObfuscator.obfuscate(SAMPLE, PRESETS[name]).getObfuscatedCode()
  const ms = (performance.now() - t0).toFixed(0)
  const leaked = SECRETS.filter((s) => out.includes(s)).length
  const size = Buffer.byteLength(out)
  const ratio = (size / baseline).toFixed(1)
  console.log(`| ${name} | ${ms} | ${(size / 1024).toFixed(1)} KB | ${ratio}x | ${leaked}/${SECRETS.length} |`)
}
console.log(`\n0/${SECRETS.length} plaintext secrets = all string literals encoded away.\n`)
