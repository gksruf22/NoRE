# Changelog

## Unreleased

### Added — supply-chain & runtime test coverage

- Scanner checks HTML for external `<script src="https://…">` without
  Subresource Integrity (SRI) — a compromised CDN could swap the script (OWASP).
- Test coverage for the runtime guard (integrity-mismatch firing, no-false-fire,
  idempotent stop) and every response strategy (callback/halt/beacon/throttle).

### Added — hardcoded credential detection & hardened canary collector

- Scanner detects hardcoded `Authorization: Bearer <token>` and `Basic <base64>`
  headers (templated values and prose like "Basic understanding" are not flagged).
- `examples/canary-collector.mjs` now de-dups repeat probes, rate-limits per IP,
  hashes client IPs by default (privacy), guards `/stats` with `NORE_COLLECTOR_KEY`,
  and ships a `--selfcheck`.

### Added — deployment change detection

- `nore snapshot <dir>` records file hashes of a build; `nore diff <dir>
  --against <snapshot>` reports added/removed/changed files (exit 1 on any
  change) to catch supply-chain tampering or unexpected drift. Diffs by a
  hash-stripped logical key so a changed content-hashed chunk reads as *changed*,
  not remove+add.

### Changed — fewer secret false positives

- Secret findings are now classified: real server credentials stay `critical`;
  keys usually meant to be public (Firebase/Google `AIza…`, JWTs) are `medium`
  "review" with restrict-don't-panic guidance; publishable keys
  (`pk_live_`/`pk_test_`) are never flagged.

### Added — obfuscation behavior test

- An executing test proves high-preset obfuscation preserves behavior for
  dynamic import, code splitting, and reflection (computed property access).
  Confirmed `debugProtection` does not break Node/SSR execution.

### Added — baseline (new-only CI gating)

- `--baseline <file>` records current findings; later runs mark findings NEW vs
  known, and with `--fail-on` only NEW findings fail the build — so a project
  with existing warnings can adopt NoRE and still block new regressions.
  `--update-baseline` rewrites it; keys ignore hashed filenames/line shifts.
  New `baseline` input on the GitHub Action.

### Changed — scanner credibility (accuracy & DX over more detectors)

- Findings now carry **severity separate from the exposure score** (`critical`
  for credentials/source maps … `info` for merely-readable strings — readable
  code is no longer treated as a vulnerability), a **file:line location**, the
  matched pattern (secrets redacted), a **remediation**, and a **category**.
- Report includes `severityCounts`; a secret match is labeled *review required*,
  not a confirmed leak.
- CLI: `--fail-on <severity>` (gate on real risk, independent of `--min` grade),
  `--ignore <ids/categories>` (suppress reviewed false positives, affects score
  and gating), `--format sarif` (GitHub Code Scanning) and `--format json`.
- GitHub Action gains `fail-on`, `ignore`, `format` inputs.
- Honesty: softened the canary "zero false positives" claim (a stray crawler can
  trip one; a silent canary is not proof of no RE) and added a WASM caveat
  (a binary is not a vault).

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

- Scanner threat coverage expanded: private keys, more token shapes
  (Slack/npm/OpenAI/GitHub PAT), and internal/infra URLs (localhost, private IPs,
  `.internal`/`.local`/`.corp` hosts) that leak topology.

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
