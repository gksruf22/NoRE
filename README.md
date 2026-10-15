# NoRE

[![CI](https://github.com/gksruf22/nore/actions/workflows/ci.yml/badge.svg)](https://github.com/gksruf22/nore/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/nore.svg)](https://www.npmjs.com/package/nore)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Defend your web / Electron JavaScript app against AI-assisted reverse
engineering — tools like [REA](https://github.com/morluto/rea) that scrape your
bundle and let an agent extract your endpoints and secrets automatically.

Obfuscation alone is a commodity. NoRE adds the two things that aren't:

### 🎯 1. Score your exposure — `npx nore scan ./dist`

See exactly what an attacker (or their AI agent) can recover from your shipped
bundle, as an **A–F grade** with fixes. Gate it in CI with `--min B`.

```
  NoRE exposure report  ./dist
  grade  F   score 35/100

  ● CRITICAL  1 source map shipped — 2 original source files recoverable verbatim   -65
  ● HIGH      82% of strings are in cleartext                                        -20
```

### 🪤 2. Catch the reverse engineer — canary tripwires

NoRE plants **decoy** secrets and endpoints in your bundle that look real but are
never referenced by your code. When a reverse engineer — or an AI agent told to
"find and test this app's keys" — extracts and probes one, your collector gets a
hit that tells you *who* and *when*. Because your own code never touches a canary,
a hit is **almost always a real probe, not a false alarm** (a stray crawler or
your own security scan can still trip one — authenticate the collector and filter
noise). And a *silent* canary doesn't prove no one is reverse-engineering: a
careful analyst can read the code without taking the bait.

```
🪤  CANARY TRIPPED: {"url":"/internal/v2/admin?k=c9dca14e71f7","ip":"…","auth":"Bearer sk_live_stolen"}
```

Plus the hardening you'd expect:

- **Runtime guard** (`nore`, zero deps) — debugger/CDP/devtools/tamper detection.
- **Vite plugin** (`nore/vite`) — sourcemap stripping, obfuscation, integrity + canaries.
- **Electron main guard** (`nore/electron`) — debug-flag, inspector and asar checks.

## What it counters

| REA capability | NoRE countermeasure | Strength |
| --- | --- | --- |
| `recover_javascript_sources`, `analyze_web_bundle` (static source recovery) | Vite plugin: sourcemaps off + obfuscation | **Strong, verified** |
| CDP/debugger attach to a **Node/Electron-main** process | `inspectorAttached` | **Strong** |
| on-disk patching of shipped assets | `integrity` self-check | Moderate (fail-open, hookable) |
| a human with devtools paused/open | `debuggerTiming` / `devtoolsOpen` | Weak heuristic |
| headless automation drivers | `automationFlags` | Weak (misses CDP-attach to a normal browser) |

### Be honest about what the runtime guard can and can't do

For a plain **browser** page, the strong defense is the build-time hardening, not
the runtime detectors. A passive CDP reader (which is how REA observes a web
page — attach to a `--remote-debugging-port` Chrome and read scripts) sets no
`navigator.webdriver`, opens no console, and triggers no `debugger` pause, so it
is **not reliably detectable from page JS**. The runtime detectors mainly catch a
human poking around with devtools, and the `inspectorAttached` detector only has
teeth in Node/Electron-main (where `node:inspector.url()` is a real signal).

So: **make what the attacker reads useless (obfuscation + no sourcemaps); don't
rely on catching the attacker.** Verified with the deobfuscator REA wraps
([Wakaru](https://github.com/pionxzh/wakaru)) — a sourcemapped build hands over
the original source verbatim, while a NoRE build yields control-flow-flattened
code with every string encoded. See [`examples/`](./examples).

## ⚠️ Honest ceiling

Client-side JavaScript protection **cannot fully prevent** reverse engineering.
The detectors run in the same JS context an attacker can hook, and obfuscation
can be undone with enough effort. The goal is to **raise cost**, not to guarantee
secrecy. Keep anything that must stay secret on the server. NoRE is a speed bump,
not a vault.

## Install

```sh
npm install nore
```

## Runtime guard

```ts
import { createGuard } from 'nore'

const guard = createGuard({
  interval: 1000,                 // poll cadence (ms)
  strategy: 'callback',           // default; non-destructive
  onDetect: (e) => console.warn('RE tooling detected:', e.detector),
  // Optional self-integrity check (hash emitted by the Vite plugin):
  // integrity: { url: '/assets/index-abc123.js', hash: '<sha256>' }
})

// guard.stop() when you no longer need it
```

Strategies: `callback` (default), `beacon` (POST the event to `beaconUrl`),
`throttle` (busy-delay to make single-stepping tedious), `halt` (throw — opt-in,
a false positive bricks the page).

## Vite plugin

```ts
// vite.config.ts
import { nore } from 'nore/vite'

export default {
  plugins: [nore({ obfuscate: true })]  // only applies on `vite build`
}
```

It forces `build.sourcemap = false`, obfuscates each chunk, and emits
`nore-integrity.json` (`filename -> sha256`) you can feed into the guard's
`integrity` option:

```ts
import hashes from './nore-integrity.json'
createGuard({
  integrity: { url: '/assets/index-abc123.js', hash: hashes['assets/index-abc123.js'] }
})
```

### Presets

`preset` trades protection against build time and bundle size (`obfuscatorOptions`
still overrides individual settings). Measured on an ~11.6 KB sample (`npm run bench`):

| preset | build | size | transforms | plaintext secrets |
| --- | --- | --- | --- | --- |
| `low` | 64 ms | 1.5× | ~3 | 0 |
| `medium` | 72 ms | 3.9× | ~6 | 0 |
| `high` (default) | 138 ms | 10.8× | 9+ | 0 |

The tiers are tuned from [JsDeObsBench](https://arxiv.org/abs/2506.20170), which
measured how well LLMs (incl. GPT-4o) deobfuscate JS: **string obfuscation is the
hardest single axis** (correctness 0.47 vs 0.79 for plain compaction), and once
**more than six transforms are stacked, LLMs and baseline tools "almost
completely fail".** So every tier makes string encoding the backbone;
`medium`/`high` harden the string array with function wrappers + index shift
(the most resistant dimension), and `high` stacks 9+ transforms — past the
collapse threshold.

```ts
nore({ preset: 'medium' })
```

The size column is on a tiny sample (fixed decoder overhead dominates); it
amortizes on real bundles, and selective obfuscation keeps it off code that
doesn't need it. `low` already removes readable strings — the single biggest win.

**Compatibility:** obfuscation preserves behavior for the patterns that usually
break under it — **dynamic import, code splitting, and reflection / computed
property access** — verified by an executing test (object keys are not mangled,
so name-based access is safe). `debugProtection` hinders interactive debugging by
design but does not break normal execution (incl. in Node/SSR).

### Performance cost (measured — `npm run perf`)

Obfuscation is not free. Two kinds of code, very different costs:

| preset | realistic code | tight hot loop |
|---|---|---|
| none | 1× | 1× |
| low | **~3×** | 12–50×* |
| medium | **~5×** | — |
| high | **~5×** | 36–140×* |

"Realistic code" = per call that does real work (build an object, `JSON.stringify`,
filter) — **~3–7× slower per execution**. For code that runs **once** (setup, a
click handler) that's invisible.

\*The tight-hot-loop column (a loop doing nothing but arithmetic + string access)
is a worst case **and not a stable measurement** — it swings run to run (we saw
36× and 140× for the same code) because the clean loop is JIT-optimized to an
unrealistic floor while the obfuscated one can't be. Treat it as a direction, not
a figure: **don't obfuscate hot compute paths.**

Obfuscation also makes output less compressible, so gzipped size grows more than
raw. The runtime guard, canaries and scanner add negligible cost (build-time or a
1 Hz poll).

This matches the literature: a performance study
([Häyrynen 2022](https://jyx.jyu.fi/bitstream/handle/123456789/81685/1/URN:NBN:fi:jyu-202206143294.pdf))
measured control-flow flattening at **7–44% slower on Chrome** and literal
transforms at 10–29% on *real* programs — tens of percent, not the multiples a
tight micro-loop shows.

### Selective obfuscation (the real win — `exclude` / vendor skip)

The cheapest way to cut cost is to not obfuscate code that doesn't need it. NoRE
**skips vendor chunks (`node_modules`) by default** — dependencies are public
code, so obfuscating them is pure cost. Measured on an app (3 KB) + framework-
sized vendor (79 KB) at `high`:

| | build time | shipped (gzip) |
|---|---|---|
| obfuscate everything | 823 ms | 119 KB |
| **app-only (default)** | **40 ms** | **18 KB** |
| | **20× faster** | **6.4× smaller** |

…and the vendor (the hottest code) runs at native speed. Target your own code,
and carve hot modules out explicitly:

```ts
nore({
  exclude: [/src\/engine\//, 'worker'],   // leave hot paths alone
  // include: [/src\/billing\//],          // or: obfuscate ONLY these
  // obfuscateVendor: true,                // opt back in if you must
})
```

> This is the research-recommended approach — the obfuscator's own tracker asks
> for exactly this
> ([#177](https://github.com/javascript-obfuscator/javascript-obfuscator/issues/177)).
> **Rule of thumb:** harden the modules worth protecting; leave the rest.

## Electron main process

A browser page can't reliably detect a passive CDP reader — but the Electron
**main** process can, because launch flags and `node:inspector` are visible to
it. Import `nore/electron` in your main entry:

```ts
import { createMainGuard, fileSha256 } from 'nore/electron'

createMainGuard({
  // asar: { path: '.../app.asar', hash: '<fileSha256 at build time>' },
  onViolation: (reason) => log.warn('NoRE:', reason),
  strategy: 'callback' // or 'exit' / 'throw' (opt-in, destructive)
})
```

It flags `--inspect` / `--remote-debugging-port` launch flags at startup, polls
`inspector.url()` for an attached CDP/debugger session, and (optionally) verifies
the packaged `app.asar` against a hash you pin with `fileSha256`.

## Scanner CLI

```sh
npx nore scan ./dist                          # graded report with file:line evidence
npx nore scan ./dist --min B                  # fail below RE-exposure grade B
npx nore scan ./dist --fail-on critical       # fail only on real risk, any grade
npx nore scan ./dist --ignore "secret:OpenAI API key"  # suppress a reviewed false positive
npx nore scan ./dist --baseline nore-baseline.json --fail-on critical  # fail only on NEW issues
npx nore scan ./dist --format sarif > nore.sarif       # GitHub Code Scanning
npx nore scan ./dist --format json            # machine-readable
npx nore scan ./dist --badge badge.svg        # static SVG grade badge
npx nore scan ./dist --endpoint badge.json    # live badge (shields.io endpoint)
```

Each finding carries a **severity** (the security risk — `critical` for a
credential or shipped source map, `info` for merely-readable strings), a
`file:line` **location**, the matched pattern (secrets redacted), and a
**remediation**. Severity is kept separate from the RE-exposure **grade**: use
`--min` to gate on how reverse-engineerable the bundle is, and `--fail-on` to
gate only on real risk (so a readable-but-safe bundle doesn't fail CI). A pattern
match is flagged as *review required*, never asserted as a confirmed leak.

**Secret findings are classified, not blindly flagged:** real server-side
credentials (Stripe `sk_live_`, AWS, GitHub, Slack, npm, OpenAI, private keys)
are `critical`; keys usually meant to be public (Firebase/Google `AIza…`, JWTs)
are `medium` "review" with guidance to restrict rather than panic; and
publishable keys (`pk_live_`/`pk_test_`) are never flagged.

**Adopt on a legacy app with `--baseline`:** the first run records existing
findings; later runs gate only on **new** ones. So a project with 20 known
warnings can still block a PR that introduces a new `critical` — no big-bang
cleanup required. Keys are build-stable (ignore hashed filenames and line
shifts). Re-record with `--update-baseline`.

Drop the grade into your README. Static SVG: `![RE exposure](./badge.svg)`. Or a
**live** badge — host the endpoint JSON (commit it, or write it in CI) and point
shields at it:

```md
![RE exposure](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/you/app/main/badge.json)
```

### GitHub Action (CI gate)

Fail a PR that ships reverse-engineerable code. This repo is itself an action:

```yaml
- run: npm ci && npm run build        # produce ./dist
- uses: gksruf22/nore@v1
  with:
    dir: dist
    min-grade: B                      # fail the job below grade B
    endpoint: nore-badge.json         # optional: emit a live-badge JSON
```

See [`action.yml`](./action.yml) and [`.github/workflows/example-exposure.yml`](./.github/workflows/example-exposure.yml).

The scanner parses your built JS (via `acorn`) and checks for: source maps
(separate `.map`, inline data-URI, or referenced) and how many original files
they leak; cleartext strings; readable identifiers; obfuscation depth; secret-
shaped tokens (Stripe/AWS/GitHub/Slack/npm/OpenAI keys, JWTs, private keys); and
internal/infra URLs that leak topology. It reads a `nore-canaries.json` left by
the plugin so your own decoys aren't flagged.

It also reports an **anti-LLM deobfuscation** verdict — it fingerprints which
obfuscation transforms are present and warns when a bundle is only
minified/renamed, which [JsDeObsBench](https://arxiv.org/abs/2506.20170) shows an
LLM can still unwind. (It's a heuristic lower bound: it reliably tells
obfuscated from not, and flags clearly shallow output, rather than claiming an
exact transform count.)

## WebAssembly for the crown jewels

The strongest protection is not shipping the logic as JavaScript at all. Moving a
sensitive routine to WebAssembly ships it as opaque bytecode (no source, strings
or identifiers) at **native speed** — so unlike heavy JS obfuscation (~5× slower
on hot paths) it costs nothing at runtime. A runnable, measured walkthrough —
including the integer-semantics and call-boundary gotchas — is in
[`examples/wasm-guide`](./examples/wasm-guide). Use it for the few routines that
must stay secret, and `nore/vite` + canaries for everything around them.

**Caveat:** WASM is still code shipped to the client. It raises the bar (fewer
tools, no source), but a binary is not a vault — it can be disassembled and its
constants read, and anything it fetches is still observable. True secrets belong
on the server; WASM protects *logic*, not data.

## Canary tripwires

Turn on canaries in the plugin and point them at a collector you control:

```ts
nore({ canaries: { collector: 'https://canary.yourapp.com', count: 4 } })
```

The plugin injects decoy config (fake endpoints, `sk_live_…` keys, admin flags)
into the bundle in cleartext and writes a **private** `nore-canaries.json`
(id → label) alongside your build — keep that file, don't deploy it. Any request
that reaches a canary route is a reverse engineer probing extracted "secrets".
A minimal collector is in [`examples/canary-collector.mjs`](./examples/canary-collector.mjs);
route its hits to your own alerting.

> Canary tokens are a known idea; what's new here is planting them in a frontend
> bundle as anti-RE tripwires, wired through the build. They complement
> obfuscation — one hides, the other watches.

## Example

A runnable Vite demo lives in [`examples/vite-demo`](./examples/vite-demo). Build
it, then grep the output to see the obfuscation and sourcemap stripping, and open
it with devtools to watch the guard fire. See [`examples/README.md`](./examples/README.md)
for reproducing a REA attack against it.

## Development

```sh
npm install
npm run build && npm test && npm run typecheck
```

See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

[MIT](./LICENSE)
