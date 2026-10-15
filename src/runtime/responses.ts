// Response strategies run when a detector fires. Default is non-destructive
// ('callback'): never break a real user's app on a false positive. Destructive
// options are explicit opt-in.

export type Strategy = 'callback' | 'throttle' | 'halt' | 'beacon'

export interface DetectionEvent {
  detector: string
  at: number
}

export interface ResponseConfig {
  strategy?: Strategy
  onDetect?: (e: DetectionEvent) => void
  beaconUrl?: string
  // 'throttle' busy-delays the loop by this many ms to make stepping painful.
  throttleMs?: number
}

export function runResponse(e: DetectionEvent, cfg: ResponseConfig): void {
  cfg.onDetect?.(e)
  switch (cfg.strategy ?? 'callback') {
    case 'callback':
      return
    case 'beacon': {
      const url = cfg.beaconUrl
      if (!url) return
      try {
        // sendBeacon survives a page unload; fall back to fetch in node.
        const nav = globalThis.navigator as any
        if (nav?.sendBeacon) nav.sendBeacon(url, JSON.stringify(e))
        else void fetch(url, { method: 'POST', body: JSON.stringify(e), keepalive: true })
      } catch {
        /* best-effort */
      }
      return
    }
    case 'throttle': {
      const until = performance.now() + (cfg.throttleMs ?? 3000)
      while (performance.now() < until) {
        /* ponytail: blocking busy-wait by design — makes single-stepping tedious */
      }
      return
    }
    case 'halt':
      // Stop the app cold. Caller opted in knowing a false positive bricks the page.
      throw new Error('NoRE: analysis environment detected')
  }
}
