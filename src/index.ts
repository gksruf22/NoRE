// Public runtime API. Import in your app entry:
//   import { createGuard } from 'nore'
//   createGuard({ onDetect: (e) => console.warn('RE tooling:', e.detector) })

export { createGuard } from './runtime/guard.js'
export type { Guard, GuardConfig } from './runtime/guard.js'
export type { Strategy, DetectionEvent, ResponseConfig } from './runtime/responses.js'
export { sha256Hex, verifyIntegrity } from './runtime/integrity.js'
export { detectEnv } from './env.js'
