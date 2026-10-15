import { describe, it, expect, vi, afterEach } from 'vitest'
import { inspectorAttached, debuggerTiming, automationFlags } from '../src/runtime/detectors.js'

describe('debuggerTiming', () => {
  it('is false when no debugger pauses execution', () => {
    expect(debuggerTiming().test()).toBe(false)
  })
})

describe('automationFlags', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('flags navigator.webdriver', () => {
    vi.stubGlobal('navigator', { webdriver: true })
    expect(automationFlags().test()).toBe(true)
  })

  it('is false for a normal navigator', () => {
    vi.stubGlobal('navigator', { webdriver: false, languages: ['en'] })
    expect(automationFlags().test()).toBe(false)
  })
})

describe('inspectorAttached (node)', () => {
  it('exists in node and detects an open inspector session', async () => {
    const det = await inspectorAttached()
    expect(det).not.toBeNull()
    expect(det!.test()).toBe(false) // no session yet

    const inspector = await import('node:inspector')
    try {
      inspector.open(0) // bind an ephemeral port -> url() becomes truthy
      expect(det!.test()).toBe(true)
    } finally {
      inspector.close()
    }
  })
})
