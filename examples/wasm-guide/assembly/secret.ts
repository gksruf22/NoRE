// A sensitive, compute-heavy routine (think key derivation / anti-tamper hash
// with many mixing rounds). Compiled to WebAssembly it ships as opaque bytecode
// — no strings, no identifiers, no source. For integer logic its speed ties
// well-written JS (V8 JITs both), but crucially it avoids the ~5x slowdown that
// obfuscating the SAME hot logic in JS would cost — protection at no runtime
// price. (For tiny one-liners the JS<->WASM call boundary dominates, so keep
// WASM for real per-call work.)
//
// The one thing that leaks is the EXPORT NAME. The readable name `deriveTag`
// stays internal; we re-export it under a meaningless `d0`, so nothing
// meaningful appears in the wasm export table. `asc --optimize` already drops
// the internal `name` section, so only `d0` is visible.
function deriveTag(code: i32, rounds: i32): i32 {
  let h: i32 = 0x1505
  for (let r = 0; r < rounds; r++) {
    h = ((h << 5) + h) ^ ((code >> ((r & 7) * 4)) & 0xf) ^ r
    h = (h * 0x9e3779b1) & 0x7fffffff
  }
  return h & 0xffff
}
export { deriveTag as d0 }
