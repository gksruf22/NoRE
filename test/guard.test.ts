import { describe, it, expect, vi, afterEach } from 'vitest'
import { createGuard } from '../src/runtime/guard.js'
import { sha256Hex } from '../src/runtime/integrity.js'

const enc = new TextEncoder()
const fetchReturning = (text: string) =>
  vi.fn(async () => ({ arrayBuffer: async () => enc.encode(text).buffer }))

describe('createGuard integrity wiring', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('fires onDetect("integrity") when the fetched bytes do not match the hash', async () => {
    vi.stubGlobal('fetch', fetchReturning('tampered'))
    const hash = await sha256Hex('original') // expected != tampered
    const detector = await new Promise<string>((resolve) => {
      const g = createGuard({
        interval: 10,
        integrity: { url: '/app.js', hash },
        onDetect: (e) => {
          g.stop()
          resolve(e.detector)
        }
      })
      setTimeout(() => resolve('timeout'), 2000)
    })
    expect(detector).toBe('integrity')
  })

  it('does NOT fire integrity when the bytes match', async () => {
    vi.stubGlobal('fetch', fetchReturning('original'))
    const hash = await sha256Hex('original')
    let fired = false
    const g = createGuard({ interval: 10, integrity: { url: '/app.js', hash }, onDetect: (e) => { if (e.detector === 'integrity') fired = true } })
    await new Promise((r) => setTimeout(r, 200))
    g.stop()
    expect(fired).toBe(false)
  })

  it('stop() is safe to call and idempotent', () => {
    const g = createGuard({ interval: 1000 })
    expect(() => { g.stop(); g.stop() }).not.toThrow()
  })
})
