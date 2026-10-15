// Hardening for the Electron MAIN process (and plain Node). Unlike a browser
// page, here anti-analysis signals are real: node:inspector.url() is truthy
// while a CDP/debugger client is attached, and launch flags like --inspect /
// --remote-debugging-port are visible in argv.
//
// This is where catching the attacker actually works — a renderer page cannot.

import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import inspector from 'node:inspector'

// Flags that expose the process to CDP / a debugger. --remote-debugging-port is
// how an Electron renderer is opened to tools like REA's observe_web_session.
const DEBUG_FLAGS = [
  '--inspect',
  '--inspect-brk',
  '--inspect-port',
  '--remote-debugging-port',
  '--remote-debugging-pipe'
]

/** Returns the debug launch flags present in this process, if any. */
export function debugLaunchFlags(): string[] {
  const argv = [...process.execArgv, ...process.argv]
  return DEBUG_FLAGS.filter((flag) => argv.some((a) => a === flag || a.startsWith(flag + '=')))
}

/** True while a debugger / CDP client is attached (or --inspect is waiting). */
export function inspectorActive(): boolean {
  return Boolean(inspector.url())
}

/** SHA-256 of a file as hex. Use at build time to pin an asar hash. */
export async function fileSha256(path: string): Promise<string> {
  return createHash('sha256').update(await readFile(path)).digest('hex')
}

/** True when the file at `path` matches `expectedHash` (unmodified). */
export async function verifyAsarIntegrity(path: string, expectedHash: string): Promise<boolean> {
  try {
    return (await fileSha256(path)) === expectedHash
  } catch {
    return false // missing/unreadable asar is a failure, not a pass
  }
}

export type MainStrategy = 'callback' | 'throw' | 'exit'

export interface MainGuardConfig {
  /** Poll interval in ms for the inspector check. Default 2000. */
  interval?: number
  /** Pin the packaged asar: { path, hash } (hash from `fileSha256` at build). */
  asar?: { path: string; hash: string }
  /** Called with a short reason on every violation. */
  onViolation?: (reason: string) => void
  /** What to do after onViolation. Default 'callback' (non-destructive). */
  strategy?: MainStrategy
  /** process.exit code for strategy 'exit'. Default 1. */
  exitCode?: number
}

export interface MainGuard {
  stop(): void
}

export function createMainGuard(cfg: MainGuardConfig = {}): MainGuard {
  let timer: ReturnType<typeof setInterval> | undefined
  const fired = new Set<string>()

  const violate = (reason: string) => {
    if (fired.has(reason)) return
    fired.add(reason)
    cfg.onViolation?.(reason)
    switch (cfg.strategy ?? 'callback') {
      case 'throw':
        throw new Error(`NoRE: ${reason}`)
      case 'exit':
        process.exit(cfg.exitCode ?? 1)
      case 'callback':
      default:
        return
    }
  }

  // Synchronous startup checks: launch flags are set before any client connects.
  for (const flag of debugLaunchFlags()) violate(`debug launch flag ${flag}`)

  if (cfg.asar) {
    void verifyAsarIntegrity(cfg.asar.path, cfg.asar.hash).then((ok) => {
      if (!ok) violate('asar integrity mismatch')
    })
  }

  const tick = () => {
    if (inspectorActive()) violate('inspector/CDP session attached')
  }
  tick()
  timer = setInterval(tick, cfg.interval ?? 2000)
  timer.unref?.() // never hold the process open just for the guard

  return {
    stop() {
      if (timer) clearInterval(timer)
    }
  }
}
