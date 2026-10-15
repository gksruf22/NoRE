// Individual detectors. Each returns a { name, test } where test() === true means
// "analysis tooling is likely present". Keep them cheap: the guard runs them on an
// interval. Detectors only applicable to an env are assembled in guard.ts.

import { hasNode } from '../env.js'

export type Detector = { name: string; test: () => boolean }

// --- Node / Electron-main: the strongest signal we have -------------------
// REA's observe_web_session attaches over CDP, which opens an inspector session.
// node:inspector.url() returns a ws:// endpoint whenever a session is active.
export async function inspectorAttached(): Promise<Detector | null> {
  if (!hasNode) return null
  try {
    // Non-literal specifier + @vite-ignore so browser bundlers don't try to
    // resolve node:inspector and ship a dead polyfill chunk.
    const spec = 'node:inspector'
    const inspector: any = await import(/* @vite-ignore */ spec)
    return {
      name: 'inspectorAttached',
      // url() is truthy while a debugger/CDP client is connected (or --inspect waiting).
      test: () => Boolean(inspector.url())
    }
  } catch {
    return null // not a node context
  }
}

// --- Any env: timing of a debugger statement ------------------------------
// If execution is paused/stepped (a client is attached and breaking), the span
// around `debugger` balloons far past a few ms.
// ponytail: heuristic; a client that disables breakpoints evades it. It is the
// primary cross-env signal because window-size tricks don't exist outside browsers.
export function debuggerTiming(thresholdMs = 100): Detector {
  return {
    name: 'debuggerTiming',
    test: () => {
      const t0 = performance.now()
      // eslint-disable-next-line no-debugger
      debugger
      return performance.now() - t0 > thresholdMs
    }
  }
}

// --- Browser: automation / headless markers -------------------------------
export function automationFlags(): Detector {
  return {
    name: 'automationFlags',
    test: () => {
      const nav = globalThis.navigator as any
      if (nav?.webdriver === true) return true
      // Headless Chrome historically ships an empty plugins list + no languages.
      if (nav && nav.languages && nav.languages.length === 0) return true
      return false
    }
  }
}

// --- Browser: devtools open -----------------------------------------------
// Getter trap: devtools evaluating/logging the object reads `id`, flipping the flag.
// ponytail: heuristic, pair with debuggerTiming as the primary signal.
export function devtoolsOpen(): Detector {
  let opened = false
  const bait: any = {}
  Object.defineProperty(bait, 'id', {
    get() {
      opened = true
      return ''
    }
  })
  return {
    name: 'devtoolsOpen',
    test: () => {
      opened = false
      // Logging the object makes an OPEN devtools read `id` to build its preview;
      // closed devtools never reads it. Must be console.log — console.debug is
      // Verbose-level and hidden by default, so its getter would never fire.
      // ponytail: this writes to the console each poll, so the guard leaves it
      // OFF by default (opt-in via { devtools: true }).
      console.log(bait)
      return opened
    }
  }
}
