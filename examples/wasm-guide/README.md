# Moving sensitive logic to WebAssembly

The strongest protection isn't obfuscating JavaScript — it's **not shipping the
logic as JavaScript at all**. Compile a sensitive routine (license/entitlement
checks, key derivation, anti-tamper, proprietary algorithms) to WebAssembly and
it ships as opaque bytecode: no source, no identifiers, no string literals, and
far weaker decompiler/LLM support than JS.

## Why WASM (measured, honestly)

Run it: `npm install && npm start` (compiles `assembly/secret.ts` → wasm, then
benchmarks it against the same algorithm in JS).

| | speed vs JS | opacity |
|---|---|---|
| plain JS | 1× | readable source |
| **obfuscated JS (preset high)** | **~0.2× (≈5× slower)** | opaque-ish, LLM-reversible when shallow |
| **WASM** | **~1× (ties well-written JS)** | opaque bytecode, no source/strings |

The key comparison is the middle vs. bottom row: to protect a **hot** routine,
heavy JS obfuscation makes it ~5× slower (see `npm run perf` in the repo root),
while WASM keeps native speed **and** is more opaque. For *integer* logic WASM
doesn't beat well-written JS on raw speed — V8 JITs both — so WASM's win here is
**protection at no runtime cost**, which obfuscation can't offer. WASM pulls
clearly ahead on heavier numeric/memory/SIMD work.

## Gotchas (learned from this example)

- **Integer semantics differ.** WASM `i32` wraps; JS `*` is float64 and loses
  precision past 2^53. Match them with `Math.imul` and `| 0` (see `run.mjs`), or
  your JS reference and the wasm will silently disagree.
- **The JS↔WASM call boundary has per-call overhead.** For tiny functions called
  millions of times, that overhead can make WASM *slower*. Move **chunks of
  work** across the boundary, not one-liners.
- **Export names leak — so rename them.** The export table is the one place a
  readable name can appear. This example keeps `deriveTag` internal and
  re-exports it as `d0` (`export { deriveTag as d0 }`); with `asc --optimize`
  dropping the internal name section, `strings build/secret.wasm` then shows **no
  readable names at all**. The algorithm and its constants are never strings.

## How it fits NoRE

Layer it: WASM for the few routines that must stay secret, `nore/vite` obfuscation
+ canaries for the surrounding app, and the `nore` scanner/guard on top. WASM is
the vault for the crown jewels; NoRE hardens everything around it.
