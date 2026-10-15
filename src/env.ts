// Runtime environment detection. Detectors use this to only run where they apply.

export type Env = 'browser' | 'electron-renderer' | 'node'

export function detectEnv(): Env {
  const hasWindow = typeof window !== 'undefined' && typeof document !== 'undefined'
  const isElectronRenderer =
    hasWindow &&
    typeof (globalThis as any).process?.versions?.electron === 'string'
  if (isElectronRenderer) return 'electron-renderer'
  if (hasWindow) return 'browser'
  return 'node'
}

// True in any context that has access to Node built-ins (node or electron main).
export const hasNode =
  typeof (globalThis as any).process?.versions?.node === 'string'
