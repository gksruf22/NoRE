import { createHash } from 'node:crypto'
import JavaScriptObfuscator from 'javascript-obfuscator'
import type { Plugin } from 'vite'
import { generateCanaries, canaryBanner, type CanaryOptions } from './canary.js'

export type Preset = 'low' | 'medium' | 'high'

export interface NoreOptions {
  /** Run javascript-obfuscator over build chunks. Default true. */
  obfuscate?: boolean
  /** Protection/perf tradeoff. Default 'high'. */
  preset?: Preset
  /** Override / extend the chosen preset. */
  obfuscatorOptions?: Record<string, unknown>
  /** Emit `nore-integrity.json` (filename -> sha256) for runtime self-checks. Default true. */
  integrityManifest?: boolean
  /** Plant reverse-engineering tripwires (decoy secrets/endpoints). Off unless set. */
  canaries?: CanaryOptions
  /**
   * Only obfuscate chunks whose name or source module path matches one of these
   * (substring or RegExp). When set, everything else is left untouched — the
   * research-backed way to keep cost off code that doesn't need protecting.
   */
  include?: (string | RegExp)[]
  /** Never obfuscate chunks matching these (substring or RegExp). Wins over include. */
  exclude?: (string | RegExp)[]
  /**
   * Obfuscate vendor chunks (code from node_modules). Default false: dependencies
   * are public code, so obfuscating them is pure cost (size + the biggest runtime
   * hit) for no protection. Leave off unless you have a specific reason.
   */
  obfuscateVendor?: boolean
}

function matchesAny(haystacks: string[], patterns?: (string | RegExp)[]): boolean {
  if (!patterns?.length) return false
  return patterns.some((p) =>
    haystacks.some((h) => (typeof p === 'string' ? h.includes(p) : p.test(h)))
  )
}

export interface ChunkInfo {
  name?: string
  fileName?: string
  moduleIds?: readonly string[]
}

/** Pure selective-obfuscation decision (exported for testing). */
export function selectForObfuscation(chunk: ChunkInfo, options: NoreOptions): boolean {
  const ids = [...(chunk.moduleIds ?? [])]
  const names = [chunk.name ?? '', chunk.fileName ?? '', ...ids]
  if (matchesAny(names, options.exclude)) return false
  const isVendor =
    /vendor/i.test(chunk.name ?? '') ||
    (ids.length > 0 && ids.every((id) => id.includes('node_modules')))
  if (isVendor && !options.obfuscateVendor) return false
  if (options.include?.length) return matchesAny(names, options.include)
  return true
}

// Presets trade runtime speed / bundle size against how hard recovery is.
//
// Tuned from JsDeObsBench (arXiv:2506.20170): against LLM/automated deobfuscation
// *string obfuscation* is the single hardest axis (correctness 0.47 vs 0.79 for
// plain compaction), and stacking >6 distinct transforms makes LLMs and baseline
// tools "almost completely fail". So every tier makes string encoding the
// backbone; medium/high add indirection to the string array (wrappers, index
// shift) — the most resistant dimension — and high stacks well past 6 transforms.
export const PRESETS: Record<Preset, Record<string, unknown>> = {
  // Fast, small: identifier mangling + full string encoding. ~3 transforms —
  // cheap, but below the stacking threshold, so an LLM can still make headway.
  low: {
    compact: true,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 1,
    splitStrings: true,
    identifierNamesGenerator: 'hexadecimal'
  },
  // Balanced: string-array indirection (wrappers + index shift + rotate/shuffle)
  // plus partial control-flow flattening and self-defending. ~6 transforms.
  medium: {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.5,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 1,
    stringArrayWrappersType: 'function',
    stringArrayWrappersCount: 2,
    stringArrayIndexShift: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    splitStrings: true,
    selfDefending: true,
    identifierNamesGenerator: 'hexadecimal'
  },
  // Maximum: hardened string array (chained function wrappers + calls transform),
  // full flow flattening, dead code, self-defending + debug protection. Well past
  // the 6-transform "deobfuscation collapse" threshold. Largest/slowest output.
  high: {
    compact: true,
    controlFlowFlattening: true,
    controlFlowFlatteningThreshold: 0.75,
    deadCodeInjection: true,
    deadCodeInjectionThreshold: 0.4,
    stringArray: true,
    stringArrayEncoding: ['base64'],
    stringArrayThreshold: 1,
    stringArrayWrappersType: 'function',
    stringArrayWrappersCount: 5,
    stringArrayWrappersChainedCalls: true,
    stringArrayIndexShift: true,
    stringArrayRotate: true,
    stringArrayShuffle: true,
    stringArrayCallsTransform: true,
    stringArrayCallsTransformThreshold: 0.75,
    splitStrings: true,
    selfDefending: true,
    debugProtection: true,
    identifierNamesGenerator: 'hexadecimal'
  }
}

export function nore(options: NoreOptions = {}): Plugin {
  const doObfuscate = options.obfuscate !== false
  const doManifest = options.integrityManifest !== false
  const preset = PRESETS[options.preset ?? 'high']
  // Generate canaries once (stable ids across all chunks in this build).
  const canaries = options.canaries ? generateCanaries(options.canaries) : []

  return {
    name: 'nore',
    apply: 'build',

    config() {
      // Sourcemaps hand the original source straight to a reverse engineer.
      return { build: { sourcemap: false } }
    },

    renderChunk(code, chunk) {
      let out = code
      if (doObfuscate && selectForObfuscation(chunk, options)) {
        out = JavaScriptObfuscator.obfuscate(out, {
          ...preset,
          ...(options.obfuscatorOptions ?? {})
        } as Parameters<typeof JavaScriptObfuscator.obfuscate>[1]).getObfuscatedCode()
      }
      // Plant canaries in CLEARTEXT after obfuscation, on the entry chunk only,
      // so an extractor finds the bait among otherwise-opaque code.
      if (canaries.length && chunk.isEntry) {
        out += canaryBanner(canaries, options.canaries!.collector)
      }
      if (out === code) return null
      return { code: out, map: null }
    },

    generateBundle(_opts, bundle) {
      if (doManifest) {
        const hashes: Record<string, string> = {}
        for (const [name, output] of Object.entries(bundle)) {
          if (output.type !== 'chunk') continue
          hashes[name] = createHash('sha256').update(output.code).digest('hex')
        }
        this.emitFile({
          type: 'asset',
          fileName: 'nore-integrity.json',
          source: JSON.stringify(hashes, null, 2)
        })
      }
      if (canaries.length) {
        // Private manifest mapping canary id -> label for your collector dashboard.
        // Do NOT ship this to users; keep it with your build artifacts.
        this.emitFile({
          type: 'asset',
          fileName: 'nore-canaries.json',
          source: JSON.stringify({ collector: options.canaries!.collector, canaries }, null, 2)
        })
      }
    }
  }
}

export default nore
export { generateCanaries, canaryBanner } from './canary.js'
export type { Canary, CanaryOptions } from './canary.js'
