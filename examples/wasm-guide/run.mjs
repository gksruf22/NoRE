import { readFileSync } from 'node:fs'
const bytes = readFileSync(new URL('./build/secret.wasm', import.meta.url))
const { instance } = await WebAssembly.instantiate(bytes, { env: { abort() {} } })
const wasmFn = instance.exports.d0

function jsFn(code, rounds) {
  let h = 0x1505
  for (let r = 0; r < rounds; r++) {
    h = (((h << 5) + h) ^ ((code >> ((r & 7) * 4)) & 0xf) ^ r) | 0
    h = Math.imul(h, 0x9e3779b1) & 0x7fffffff
  }
  return h & 0xffff
}

const ROUNDS = 4000, N = 20_000
const time = (fn) => { fn(1, ROUNDS); const t = performance.now(); let x = 0; for (let i = 0; i < N; i++) x ^= fn(i, ROUNDS); return { ms: performance.now() - t, x } }
const js = time(jsFn), wasm = time(wasmFn)
console.log(`correctness: js and wasm agree = ${js.x === wasm.x}`)
console.log(`JS   : ${js.ms.toFixed(0)} ms`)
console.log(`WASM : ${wasm.ms.toFixed(0)} ms  (${(js.ms / wasm.ms).toFixed(2)}x vs JS)`)
console.log(`wasm: ${bytes.length} bytes; algorithm + constants are NOT in any readable string`)
