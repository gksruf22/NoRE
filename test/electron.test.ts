import { describe, it, expect, afterEach } from 'vitest'
import { writeFileSync, rmSync, mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  debugLaunchFlags,
  inspectorActive,
  fileSha256,
  verifyAsarIntegrity,
  createMainGuard
} from '../src/electron/main-guard.js'

describe('debugLaunchFlags', () => {
  const savedArgv = process.argv
  afterEach(() => {
    process.argv = savedArgv
  })

  it('detects --inspect and --remote-debugging-port in argv', () => {
    process.argv = [...savedArgv, '--remote-debugging-port=9222']
    expect(debugLaunchFlags()).toContain('--remote-debugging-port')
  })

  it('is empty under a normal launch', () => {
    process.argv = ['node', 'app.js']
    expect(debugLaunchFlags()).toEqual([])
  })
})

describe('inspectorActive', () => {
  it('flips true while an inspector session is open', async () => {
    const inspector = await import('node:inspector')
    expect(inspectorActive()).toBe(false)
    try {
      inspector.open(0)
      expect(inspectorActive()).toBe(true)
    } finally {
      inspector.close()
    }
  })
})

describe('asar integrity', () => {
  let dir: string
  afterEach(() => dir && rmSync(dir, { recursive: true, force: true }))

  it('verifies a matching hash and rejects a tampered file', async () => {
    dir = mkdtempSync(join(tmpdir(), 'nore-asar-'))
    const f = join(dir, 'app.asar')
    writeFileSync(f, 'pretend-asar-bytes')
    const hash = await fileSha256(f)
    expect(await verifyAsarIntegrity(f, hash)).toBe(true)

    writeFileSync(f, 'pretend-asar-bytes-TAMPERED')
    expect(await verifyAsarIntegrity(f, hash)).toBe(false)
  })

  it('fails closed on a missing file', async () => {
    expect(await verifyAsarIntegrity('/no/such/app.asar', 'deadbeef')).toBe(false)
  })
})

describe('createMainGuard', () => {
  const savedArgv = process.argv
  afterEach(() => {
    process.argv = savedArgv
  })

  it('reports a launch-flag violation via onViolation (callback strategy)', () => {
    process.argv = [...savedArgv, '--inspect']
    const seen: string[] = []
    const g = createMainGuard({ onViolation: (r) => seen.push(r), strategy: 'callback' })
    g.stop()
    expect(seen.some((r) => r.includes('--inspect'))).toBe(true)
  })
})
