# Contributing to NoRE

Thanks for helping raise the cost of reverse engineering.

## Setup

```sh
npm install
npm run build      # dist/ (ESM + CJS + d.ts)
npm test           # vitest
npm run typecheck  # tsc --noEmit
```

## Ground rules

- **Keep the runtime guard dependency-free.** `src/runtime/` must not pull in
  any runtime dependency and must run in browser, Electron renderer, and
  Node/Electron-main. Gate platform-specific detectors on `detectEnv()` / `hasNode`.
- **Every non-trivial detector or response needs a test.** Look at
  `test/detectors.test.ts` — the inspector test opens a real CDP session.
- **Be honest about limits.** A detector that only works under narrow conditions
  should say so in a comment. No security theater.

## Adding a detector

1. Add a `Detector` factory to `src/runtime/detectors.ts`.
2. Wire it into `buildDetectors()` in `src/runtime/guard.ts`, gated by env.
3. Add a test proving it fires on the real condition and stays quiet otherwise.

## Adding a bundler plugin

The Vite plugin (`src/build/vite-plugin.ts`) is the template: force sourcemaps
off, obfuscate chunks, emit the integrity manifest. webpack/rollup/esbuild
equivalents are welcome.
