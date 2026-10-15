import { detectEnv } from '../env.js'
import {
  type Detector,
  inspectorAttached,
  debuggerTiming,
  automationFlags,
  devtoolsOpen
} from './detectors.js'
import { runResponse, type ResponseConfig } from './responses.js'
import { verifyIntegrity } from './integrity.js'

export interface GuardConfig extends ResponseConfig {
  /** Detection poll interval in ms. Default 1000. */
  interval?: number
  /** Include the `debugger`-timing trap. Default true. */
  debuggerTrap?: boolean
  /** Include browser devtools-open heuristic. Off by default: it polls the
   * console and is a weak, bypassable signal. Enable with `devtools: true`. */
  devtools?: boolean
  /** Self-integrity check against a build-time hash (injected by the Vite plugin). */
  integrity?: { url: string; hash: string }
}

export interface Guard {
  stop(): void
}

async function buildDetectors(cfg: GuardConfig): Promise<Detector[]> {
  const env = detectEnv()
  const list: Detector[] = []

  const nodeDetector = await inspectorAttached()
  if (nodeDetector) list.push(nodeDetector)

  if (cfg.debuggerTrap !== false) list.push(debuggerTiming())

  if (env === 'browser' || env === 'electron-renderer') {
    list.push(automationFlags())
    if (cfg.devtools === true) list.push(devtoolsOpen())
  }
  return list
}

export function createGuard(cfg: GuardConfig = {}): Guard {
  let stopped = false
  let timer: ReturnType<typeof setInterval> | undefined
  const fired = new Set<string>() // debounce: one response per detector

  const fire = (name: string) => {
    if (fired.has(name)) return
    fired.add(name)
    runResponse({ detector: name, at: Date.now() }, cfg)
  }

  void (async () => {
    const detectors = await buildDetectors(cfg)

    if (cfg.integrity) {
      const ok = await verifyIntegrity(cfg.integrity.hash, cfg.integrity.url)
      if (!ok) fire('integrity')
    }

    const tick = () => {
      if (stopped) return
      for (const d of detectors) {
        try {
          if (d.test()) fire(d.name)
        } catch {
          /* a throwing detector must never crash the host app */
        }
      }
    }
    tick()
    if (stopped) return
    timer = setInterval(tick, cfg.interval ?? 1000)
    ;(timer as any).unref?.() // never keep a node process alive just for the guard
  })()

  return {
    stop() {
      stopped = true
      if (timer) clearInterval(timer)
    }
  }
}
