# Changelog

## Unreleased

### Added — the differentiators

- **Exposure scanner + CLI** (`npx nore scan <dir>`): parses built JS with acorn
  and grades reverse-engineering exposure A–F (shipped source maps, cleartext
  strings, readable identifiers, missing obfuscation, secret-shaped tokens).
  `--json` and `--min <grade>` (CI gate) supported.
- **Canary tripwires** (`nore/vite` `canaries` option): injects decoy
  secrets/endpoints into the bundle and emits a private `nore-canaries.json`.
  A probe to any canary route alerts your collector — zero false positives.
  Example collector in `examples/canary-collector.mjs`.

### Added — anti-LLM depth + WASM guide

- Scanner now reports an **anti-LLM deobfuscation** verdict: fingerprints the
  obfuscation transforms present and flags bundles that are only minified/renamed
  (which LLMs can unwind per JsDeObsBench). Heuristic lower bound — judges on
  reliable signals (string-array / control-flow presence), not an exact count, so
  it won't falsely flag genuinely-obfuscated output.
- Scanner `--badge [file]` (static SVG) and `--endpoint [file]` (shields.io
  endpoint JSON for a live, auto-updating badge).
- **GitHub Action** (`action.yml`): runs `nore scan` in CI, fails below a grade
  threshold, and can emit the live-badge JSON. Builds from its own checkout, so
  it works without an npm release.
- `examples/wasm-guide`: runnable AssemblyScript→WASM walkthrough for moving
  sensitive logic out of JS entirely, with measured JS-vs-WASM numbers, the
  integer-semantics / call-boundary gotchas, and export-name stripping
  (`export { deriveTag as d0 }`) so no readable names remain in the wasm.

### Added — scanner: inline source maps

- Scanner now detects source maps embedded inline in the shipped JS (base64
  data-URI) and bundle `sourceMappingURL` references, not just separate `.map`
  files — a common, severe leak the file scan missed.

### Changed — presets tuned from research

- Presets re-tuned from JsDeObsBench (arXiv:2506.20170): string obfuscation is the
  hardest axis for LLM deobfuscation and stacking >6 transforms collapses it.
  `medium`/`high` now harden the string array (function wrappers, index shift,
  rotate/shuffle; `high` adds chained calls + calls-transform) and `high` stacks
  9+ transforms. Runtime cost on realistic code is ~unchanged (~5×); output size
  grows (amortizes on real bundles; use selective obfuscation to contain it).

### Added — performance (research-backed)

- **Selective obfuscation**: `include` / `exclude` (substring or RegExp) and
  automatic vendor-chunk skipping (`obfuscateVendor: false` by default). On an
  app + framework-sized vendor, app-only obfuscation was ~20× faster to build
  and shipped ~6× smaller, with vendor running at native speed. Grounded in the
  obfuscator's own request (#177) and perf literature (Häyrynen 2022).
- `npm run perf` reports build size, wire (gzip) size, and runtime overhead.

### Added — hardening

- Electron main-process guard (`nore/electron`): `--inspect` /
  `--remote-debugging-port` flag detection, inspector-session polling, asar
  integrity (`fileSha256`, `verifyAsarIntegrity`).
- Obfuscation presets `low` / `medium` / `high` plus `npm run bench`.

### Fixed

- `devtoolsOpen` used `console.debug` (hidden by default in Chrome) so the getter
  trap never fired; now `console.log`, and the detector is opt-in.

## 0.1.0

Initial release: runtime guard (`createGuard`) and Vite hardening plugin
(`nore/vite`) with sourcemap stripping, obfuscation, and an integrity manifest.
