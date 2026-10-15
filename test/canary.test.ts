import { describe, it, expect } from 'vitest'
import { generateCanaries, canaryBanner } from '../src/build/canary.js'

describe('canaries', () => {
  it('generates unique canaries that all reference the collector', () => {
    const cs = generateCanaries({ collector: 'https://c.example.com/', count: 4 })
    expect(cs).toHaveLength(4)
    expect(new Set(cs.map((c) => c.id)).size).toBe(4) // unique ids
    // endpoint/flag canaries embed the collector; key canaries embed the id.
    for (const c of cs) {
      if (c.kind === 'apiKey') expect(c.value).toContain(c.id)
      else expect(c.value).toContain('c.example.com')
    }
  })

  it('banner is cleartext, self-installing, and syntactically valid', () => {
    const cs = generateCanaries({ collector: 'https://c.example.com', count: 3 })
    const banner = canaryBanner(cs, 'https://c.example.com')
    expect(banner).toContain('__APP_CONFIG')
    expect(banner).toContain('sk_live_') // the bait is readable, by design
    expect(() => new Function(banner)).not.toThrow() // valid JS, harmless
  })
})
