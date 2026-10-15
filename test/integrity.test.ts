import { describe, it, expect, vi, afterEach } from 'vitest'
import { sha256Hex, verifyIntegrity } from '../src/runtime/integrity.js'

describe('sha256Hex', () => {
  it('matches the known SHA-256 of "abc"', async () => {
    expect(await sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    )
  })
})

describe('verifyIntegrity', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('returns true when the fetched bytes match the expected hash', async () => {
    const hash = await sha256Hex('abc')
    vi.stubGlobal('fetch', async () => ({ arrayBuffer: async () => new TextEncoder().encode('abc').buffer }))
    expect(await verifyIntegrity(hash, '/x.js')).toBe(true)
  })

  it('returns false when the bytes were tampered with', async () => {
    const hash = await sha256Hex('abc')
    vi.stubGlobal('fetch', async () => ({ arrayBuffer: async () => new TextEncoder().encode('abc!').buffer }))
    expect(await verifyIntegrity(hash, '/x.js')).toBe(false)
  })

  it('fails open when fetch throws', async () => {
    vi.stubGlobal('fetch', async () => { throw new Error('blocked') })
    expect(await verifyIntegrity('deadbeef', '/x.js')).toBe(true)
  })
})
