// Reverse-engineering EXPOSURE scanner. Point it at a built web app (a dist/
// directory) and it reports, with an A–F grade, how much an attacker — or an AI
// agent told to "extract this app's secrets and endpoints" — can recover.
//
// Honest: this measures static exposure of shipped artifacts. A high grade means
// "cheap to read", not "we proved it's safe". It is a smoke alarm, not a vault.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, extname } from 'node:path'
import { parse } from 'acorn'
import { simple as walkSimple } from 'acorn-walk'

export type Severity = 'critical' | 'high' | 'medium' | 'info'

export interface Finding {
  id: string
  severity: Severity
  title: string
  detail: string
  /** Points subtracted from 100. */
  penalty: number
}

export interface ScanReport {
  root: string
  filesScanned: number
  bytesScanned: number
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  /** Estimated resistance to LLM/automated deobfuscation (JsDeObsBench). */
  antiLlm: { transforms: string[]; verdict: 'strong' | 'partial' | 'weak' | 'none' }
  findings: Finding[]
}

const JS_EXT = new Set(['.js', '.mjs', '.cjs'])

// Fingerprints of javascript-obfuscator transforms, used to estimate how many
// distinct transforms are stacked. JsDeObsBench (arXiv:2506.20170) found LLM +
// automated deobfuscation "almost completely fails" past ~6 stacked transforms.
// Heuristic lower-bound estimate — calibrated to javascript-obfuscator output.
const TRANSFORM_FINGERPRINTS: [string, RegExp][] = [
  ['identifier-mangling', /_0x[a-f0-9]{4,}/],
  // string-array rotation decoder: a `for(;;)try{ ... parseInt` self-ordering IIFE,
  // or the classic push(shift()) rotation.
  ['string-array', /for\s*\(\s*;;\s*\)\s*try\s*\{[\s\S]{0,200}?parseInt|\bpush\b[\s\S]{0,40}?\bshift\b\s*\(\s*\)/],
  // wrapper functions delegating to the decoder: `function d(a,f){return A(...)}`
  ['string-array-wrappers', /function\s+\w+\s*\(\s*\w+\s*,\s*\w+\s*\)\s*\{\s*return\s+\w+\s*\(/],
  // control-flow flattening: pipe-ordered dispatch string or numbered switch cases.
  ['control-flow-flattening', /['"](?:\d+\|){2,}\d+['"]|switch\s*\([\s\S]{0,30}?\)\s*\{\s*case\s*['"]?\d/],
  ['split-strings', /(?:'[^']{1,6}'\s*\+\s*){3,}/],
  ['debug/self-defending', /\bdebugger\b|constructor\s*\(\s*['"]return/]
]

// Fingerprinting undercounts individual transforms, so we judge on reliable
// SIGNALS rather than an exact count: the presence of string-array encoding and
// control-flow flattening (the two axes JsDeObsBench found hardest) is a true
// positive when seen; only identifier renaming is "shallow".
function antiLlmVerdict(t: Set<string>): ScanReport['antiLlm']['verdict'] {
  if (t.size === 0) return 'none'
  const strings = t.has('string-array') || t.has('string-array-wrappers')
  const flow = t.has('control-flow-flattening')
  if (strings && flow) return 'strong'
  if (strings || flow) return 'partial'
  return 'weak' // only renaming / debug traps — an LLM can still make headway
}

function walkFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    const s = statSync(p)
    if (s.isDirectory()) walkFiles(p, out)
    else out.push(p)
  }
  return out
}

// Looks like a human-readable word/identifier (not a mangled hex/short name).
const READABLE = /^[a-z_$][a-zA-Z0-9_$]{3,}$/
// Common leaked-secret shapes. Best-effort; cleartext secrets in a bundle are
// always worth flagging regardless.
const SECRET_PATTERNS: [string, RegExp][] = [
  ['Stripe secret key', /sk_live_[A-Za-z0-9]{10,}/],
  ['Google API key', /AIza[0-9A-Za-z_\-]{30,}/],
  ['AWS access key', /AKIA[0-9A-Z]{12,}/],
  ['GitHub token', /gh[pousr]_[A-Za-z0-9]{20,}/],
  ['GitHub fine-grained PAT', /github_pat_[A-Za-z0-9_]{30,}/],
  ['Slack token', /xox[baprs]-[0-9A-Za-z-]{10,}/],
  ['npm token', /npm_[A-Za-z0-9]{36}/],
  ['OpenAI API key', /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/],
  ['private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/],
  ['JWT', /eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\./]
]

// Internal/infra hosts that shouldn't appear in a public bundle — they leak
// topology (staging, admin panels, private networks). Matched only inside string
// literals (via the AST walk) to keep false positives near zero.
const INTERNAL_HOST = /^https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|[a-z0-9.-]+\.(?:internal|local|corp|intranet))(?:[:/]|$)/i

// A string is "meaningful" to an attacker if it reads like words/URLs/paths —
// NOT if it's a base64/hex blob (which is what string-array encoding produces,
// and must not count as readable or obfuscation looks ineffective).
const BLOB = /^[A-Za-z0-9+/=_-]{12,}$/ // base64/token-ish, single run
const HEX = /^[0-9a-fx]{6,}$/i
function isMeaningful(s: string): boolean {
  if (s.length < 4) return false
  if (HEX.test(s)) return false
  if (BLOB.test(s) && !/\s/.test(s)) return false // long single token, no spaces
  if (/:\/\//.test(s)) return true // URL
  if (/\s/.test(s)) return true // has spaces => human text
  return /[A-Za-z]{3,}[-_/. ][A-Za-z]{3,}/.test(s) // two word-ish parts
}

// Read the private canary manifest if the build left one here, so we don't
// penalize NoRE's own decoy secrets/endpoints.
function loadCanaryValues(root: string): Set<string> {
  const set = new Set<string>()
  try {
    const m = JSON.parse(readFileSync(join(root, 'nore-canaries.json'), 'utf8'))
    for (const c of m.canaries ?? []) if (typeof c.value === 'string') set.add(c.value)
  } catch {
    /* no manifest */
  }
  return set
}

function gradeFor(score: number): ScanReport['grade'] {
  if (score >= 90) return 'A'
  if (score >= 75) return 'B'
  if (score >= 60) return 'C'
  if (score >= 40) return 'D'
  return 'F'
}

export function scan(root: string): ScanReport {
  const files = walkFiles(root)
  const jsFiles = files.filter((f) => JS_EXT.has(extname(f)))
  const mapFiles = files.filter((f) => f.endsWith('.map'))

  const findings: Finding[] = []
  let bytes = 0
  const canaryValues = loadCanaryValues(root)

  // 1. Source maps — the single most damaging leak: original source verbatim.
  if (mapFiles.length) {
    let recoverable = 0
    for (const m of mapFiles) {
      try {
        const json = JSON.parse(readFileSync(m, 'utf8'))
        if (Array.isArray(json.sourcesContent)) {
          recoverable += json.sourcesContent.filter((s: unknown) => typeof s === 'string').length
        }
      } catch {
        /* ignore unparsable map */
      }
    }
    findings.push({
      id: 'sourcemaps',
      severity: 'critical',
      title: `${mapFiles.length} source map(s) shipped`,
      detail:
        recoverable > 0
          ? `${recoverable} original source file(s) are recoverable verbatim from sourcesContent. Set build.sourcemap=false (or use nore/vite).`
          : `Source maps let an attacker reconstruct original structure. Set build.sourcemap=false.`,
      penalty: recoverable > 0 ? 65 : 45
    })
  }

  // Parse JS once; collect string literals and identifiers.
  let totalStrings = 0
  let readableStrings = 0
  let totalIds = 0
  let readableIds = 0
  const secretsFound = new Set<string>()
  const internalHosts = new Set<string>()
  const transforms = new Set<string>()
  let inlineMapSources = 0 // original files recoverable from inline (data-URI) maps
  let externalMapRef = false

  for (const f of jsFiles) {
    const code = readFileSync(f, 'utf8')
    bytes += Buffer.byteLength(code)

    // Inline source maps embedded in the shipped JS — a common, severe leak that
    // a separate-.map scan misses entirely.
    const inline = code.match(/sourceMappingURL=data:application\/json[^,]*;base64,([A-Za-z0-9+/=]+)/)
    if (inline) {
      try {
        const map = JSON.parse(Buffer.from(inline[1], 'base64').toString('utf8'))
        if (Array.isArray(map.sourcesContent)) {
          inlineMapSources += map.sourcesContent.filter((s: unknown) => typeof s === 'string').length
        } else inlineMapSources += 1
      } catch {
        inlineMapSources += 1
      }
    } else if (/\/\/[#@]\s*sourceMappingURL=/.test(code)) {
      externalMapRef = true
    }

    for (const [label, re] of SECRET_PATTERNS) {
      const hit = code.match(re)
      // Ignore a match that is one of our own canaries.
      if (hit && !canaryValues.has(hit[0])) secretsFound.add(label)
    }
    // Count distinct obfuscation transforms present (anti-LLM estimate).
    for (const [name, re] of TRANSFORM_FINGERPRINTS) if (re.test(code)) transforms.add(name)

    try {
      const ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module' })
      walkSimple(ast, {
        Literal(node: any) {
          if (typeof node.value !== 'string') return
          if (canaryValues.has(node.value)) return // don't count our decoys
          totalStrings++
          if (isMeaningful(node.value)) readableStrings++
          if (INTERNAL_HOST.test(node.value)) internalHosts.add(node.value)
        },
        Identifier(node: any) {
          totalIds++
          if (READABLE.test(node.name)) readableIds++
        }
      })
    } catch {
      // Unparsable — could be aggressive obfuscation OR just unusual code, so we
      // infer nothing. Transform signals come only from explicit fingerprints.
    }
  }

  const strRatio = totalStrings ? readableStrings / totalStrings : 0
  const idRatio = totalIds ? readableIds / totalIds : 0

  // 1b. Inline source maps baked into the shipped JS (common and severe).
  if (inlineMapSources > 0) {
    findings.push({
      id: 'inline-sourcemap',
      severity: 'critical',
      title: `Inline source map embedded in shipped JS`,
      detail: `${inlineMapSources} original source file(s) are recoverable from a data-URI source map inside the bundle. Set build.sourcemap=false (or use nore/vite).`,
      penalty: 65
    })
  } else if (externalMapRef && !mapFiles.length) {
    findings.push({
      id: 'sourcemap-ref',
      severity: 'medium',
      title: 'Bundle references a source map',
      detail: 'A //# sourceMappingURL comment points to a map. If that map is deployed, original source is recoverable. Strip it.',
      penalty: 10
    })
  }

  // 2. Cleartext readable strings.
  if (readableStrings > 20 && strRatio > 0.2) {
    const pct = Math.round(strRatio * 100)
    findings.push({
      id: 'cleartext-strings',
      severity: strRatio > 0.5 ? 'high' : 'medium',
      title: `${readableStrings} readable string literals (${pct}% of strings)`,
      detail: 'URLs, messages and keys are in cleartext. Enable string-array encoding (nore/vite).',
      penalty: strRatio > 0.5 ? 20 : 10
    })
  }

  // 3. Readable identifiers (function/variable names intact).
  if (totalIds > 50 && idRatio > 0.3) {
    const pct = Math.round(idRatio * 100)
    findings.push({
      id: 'readable-identifiers',
      severity: 'medium',
      title: `${pct}% of identifiers are human-readable`,
      detail: 'Original function/variable names survive. Enable identifier mangling (nore/vite).',
      penalty: 15
    })
  }

  // 4. Obfuscation depth vs. LLM/automated deobfuscation (JsDeObsBench).
  const verdict = antiLlmVerdict(transforms)
  if (jsFiles.length && verdict === 'none' && idRatio > 0.3) {
    findings.push({
      id: 'no-obfuscation',
      severity: 'high',
      title: 'No obfuscation detected',
      detail: 'Plain minified JS — trivial for an LLM to restore. Add obfuscation (nore/vite preset high).',
      penalty: 15
    })
  } else if (jsFiles.length && verdict === 'weak') {
    findings.push({
      id: 'shallow-obfuscation',
      severity: 'medium',
      title: `Shallow obfuscation: looks like minification/renaming only`,
      detail: `Only ${transforms.size} transform(s) fingerprinted (${[...transforms].join(', ')}). Research (JsDeObsBench) shows LLMs reliably fail only once many transforms are stacked. Use nore/vite preset "high".`,
      penalty: 12
    })
  }

  // 5. Secrets in the bundle.
  if (secretsFound.size) {
    findings.push({
      id: 'secrets',
      severity: 'critical',
      title: `Potential secret(s) in bundle: ${[...secretsFound].join(', ')}`,
      detail: 'Secrets shipped to the client are public. Move them server-side and rotate them.',
      penalty: 25
    })
  }

  // 6. Internal/infra hosts leaking topology.
  if (internalHosts.size) {
    const sample = [...internalHosts].slice(0, 3).join(', ')
    findings.push({
      id: 'internal-hosts',
      severity: 'medium',
      title: `${internalHosts.size} internal/infra URL(s) in bundle`,
      detail: `Internal hosts reveal your topology to an attacker (e.g. ${sample}). Strip staging/admin/private URLs from production builds.`,
      penalty: 10
    })
  }

  // Positive signal: reverse-engineering tripwires are planted.
  if (canaryValues.size) {
    findings.push({
      id: 'canaries',
      severity: 'info',
      title: `${canaryValues.size} reverse-engineering canaries planted`,
      detail: 'Decoy secrets/endpoints will alert your collector if an attacker probes them.',
      penalty: 0
    })
  }

  const penalty = findings.reduce((s, f) => s + f.penalty, 0)
  const score = Math.max(0, 100 - penalty)
  return {
    root,
    filesScanned: jsFiles.length,
    bytesScanned: bytes,
    score,
    grade: gradeFor(score),
    antiLlm: { transforms: [...transforms], verdict },
    findings: findings.sort((a, b) => b.penalty - a.penalty)
  }
}

