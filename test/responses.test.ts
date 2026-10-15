import { describe, it, expect, vi, afterEach } from 'vitest'
import { runResponse } from '../src/runtime/responses.js'

const ev = { detector: 'test', at: 0 }

describe('runResponse', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('callback (default) calls onDetect and does not throw', () => {
    const seen: string[] = []
    expect(() => runResponse(ev, { onDetect: (e) => seen.push(e.detector) })).not.toThrow()
    expect(seen).toEqual(['test'])
  })

  it('halt throws', () => {
    expect(() => runResponse(ev, { strategy: 'halt' })).toThrow(/analysis environment/)
  })

  it('beacon posts to the configured url', () => {
    const calls: any[] = []
    vi.stubGlobal('navigator', { sendBeacon: (u: string, b: string) => calls.push([u, b]) })
    runResponse(ev, { strategy: 'beacon', beaconUrl: 'https://x/report' })
    expect(calls[0][0]).toBe('https://x/report')
  })

  it('throttle busy-waits roughly the configured time', () => {
    const t0 = performance.now()
    runResponse(ev, { strategy: 'throttle', throttleMs: 30 })
    expect(performance.now() - t0).toBeGreaterThanOrEqual(20)
  })

  it('onDetect runs even with a destructive strategy, before it fires', () => {
    const seen: string[] = []
    expect(() => runResponse(ev, { strategy: 'halt', onDetect: (e) => seen.push(e.detector) })).toThrow()
    expect(seen).toEqual(['test'])
  })
})
