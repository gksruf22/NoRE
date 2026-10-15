// Reverse-engineering EXPOSURE scanner. Point it at a built web app (a dist/
// directory) and it reports, with an A–F grade, how much an attacker — or an AI
// agent told to "extract this app's secrets and endpoints" — can recover.
//
// Honest: this measures static exposure of shipped artifacts. A high grade means
// "cheap to read", not "we proved it's safe". It is a smoke alarm, not a vault.

import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join, extname, relative } from 'node:path'
import { parse } from 'acorn'
import { simple as walkSimple } from 'acorn-walk'

// Security risk severity — separate from the RE-exposure score. 'info' means
// "reviewer should look", not "this is a vulnerability" (e.g. readable strings).
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical']

export interface Evidence {
  file: string // relative to scan root
  line: number
  match?: string // the matched text (redacted for secrets)
}

export interface Finding {
  id: string
  severity: Severity
  /** What kind of issue: 'credential' | 'sourcemap' | 'exposure' | 'obfuscation' | 'infra' | 'canary'. */
  category: string
  title: string
  detail: string
  /** How to fix it. */
  remediation: string
  /** Where it was found (omitted for bundle-wide statistics). */
  locations?: Evidence[]
  /** Points subtracted from the RE-exposure score (0 for info-only). */
  penalty: number
}

export interface ScanReport {
  root: string
  filesScanned: number
  bytesScanned: number
  /** RE-exposure score/grade — how recoverable the bundle is (NoRE's own metric). */
  score: number
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  /** Count of findings per security severity — the risk view, distinct from grade. */
  severityCounts: Record<Severity, number>
  /** Estimated resistance to LLM/automated deobfuscation (JsDeObsBench). */
  antiLlm: { transforms: string[]; verdict: 'strong' | 'partial' | 'weak' | 'none' }
  findings: Finding[]
}

// Stable keys for a finding, for baseline diffing across builds. Deliberately
// excludes file name and line (both shift between builds: hashed filenames,
// code motion); keyed on the finding id plus the matched value where there is
// one (so a NEW secret/host is a new key, but a moved one is not).
export function findingKeys(f: Finding): string[] {
  const matches = (f.locations ?? []).map((l) => l.match).filter((m): m is string => !!m)
  if (matches.length) return [...new Set(matches.map((m) => `${f.id}::${m}`))]
  return [f.id]
}

// Line number (1-based) of a character offset in source.
function lineAt(code: string, index: number): number {
  let line = 1
  for (let i = 0; i < index && i < code.length; i++) if (code.charCodeAt(i) === 10) line++
  return line
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

const redact = (s: string) => (s.length > 10 ? s.slice(0, 6) + '…' + s.slice(-2) : s.slice(0, 3) + '…')

export interface ScanOptions {
  /** Suppress findings whose id or category matches one of these (reviewed false positives). */
  ignore?: string[]
}

export function scan(root: string, opts: ScanOptions = {}): ScanReport {
  const files = walkFiles(root)
  const jsFiles = files.filter((f) => JS_EXT.has(extname(f)))
  const mapFiles = files.filter((f) => f.endsWith('.map'))
  const rel = (f: string) => relative(root, f) || f

  const findings: Finding[] = []
  let bytes = 0
  const canaryValues = loadCanaryValues(root)

  // 1. Separate .map files — original source verbatim.
  if (mapFiles.length) {
    let recoverable = 0
    for (const m of mapFiles) {
      try {
        const json = JSON.parse(readFileSync(m, 'utf8'))
        if (Array.isArray(json.sourcesContent))
          recoverable += json.sourcesContent.filter((s: unknown) => typeof s === 'string').length
      } catch {
        /* ignore unparsable map */
      }
    }
    findings.push({
      id: 'sourcemaps',
      severity: 'critical',
      category: 'sourcemap',
      title: `${mapFiles.length} source map(s) shipped`,
      detail:
        recoverable > 0
          ? `${recoverable} original source file(s) are recoverable verbatim from sourcesContent.`
          : `Source maps let an attacker reconstruct original structure.`,
      remediation: 'Set build.sourcemap=false (nore/vite does this), or keep maps in a private error-tracker only and never deploy them.',
      locations: mapFiles.map((m) => ({ file: rel(m), line: 1 })),
      penalty: recoverable > 0 ? 65 : 45
    })
  }

  let totalStrings = 0
  let readableStrings = 0
  let totalIds = 0
  let readableIds = 0
  const secretHits = new Map<string, Evidence[]>()
  const internalHits: Evidence[] = []
  const transforms = new Set<string>()
  const inlineMapHits: Evidence[] = []
  const sourcemapRefHits: Evidence[] = []
  let inlineMapSources = 0

  for (const f of jsFiles) {
    const code = readFileSync(f, 'utf8')
    bytes += Buffer.byteLength(code)
    const file = rel(f)

    const inline = code.match(/sourceMappingURL=data:application\/json[^,]*;base64,([A-Za-z0-9+/=]+)/)
    if (inline) {
      inlineMapHits.push({ file, line: lineAt(code, inline.index ?? 0) })
      try {
        const map = JSON.parse(Buffer.from(inline[1], 'base64').toString('utf8'))
        inlineMapSources += Array.isArray(map.sourcesContent)
          ? map.sourcesContent.filter((s: unknown) => typeof s === 'string').length
          : 1
      } catch {
        inlineMapSources += 1
      }
    } else {
      const ref = code.match(/\/\/[#@]\s*sourceMappingURL=/)
      if (ref) sourcemapRefHits.push({ file, line: lineAt(code, ref.index ?? 0) })
    }

    // Secrets: record every occurrence with location (match redacted).
    for (const [label, re] of SECRET_PATTERNS) {
      const g = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g')
      for (const m of code.matchAll(g)) {
        if (canaryValues.has(m[0])) continue // our own decoy
        const arr = secretHits.get(label) ?? []
        arr.push({ file, line: lineAt(code, m.index ?? 0), match: redact(m[0]) })
        secretHits.set(label, arr)
      }
    }

    for (const [name, re] of TRANSFORM_FINGERPRINTS) if (re.test(code)) transforms.add(name)

    try {
      const ast = parse(code, { ecmaVersion: 'latest', sourceType: 'module', locations: true })
      walkSimple(ast, {
        Literal(node: any) {
          if (typeof node.value !== 'string') return
          if (canaryValues.has(node.value)) return
          totalStrings++
          if (isMeaningful(node.value)) readableStrings++
          if (INTERNAL_HOST.test(node.value) && internalHits.length < 50)
            internalHits.push({ file, line: node.loc?.start.line ?? 0, match: node.value })
        },
        Identifier(node: any) {
          totalIds++
          if (READABLE.test(node.name)) readableIds++
        }
      })
    } catch {
      // Unparsable — infer nothing (transform signals come from fingerprints only).
    }
  }

  const strRatio = totalStrings ? readableStrings / totalStrings : 0
  const idRatio = totalIds ? readableIds / totalIds : 0

  // Inline source maps baked into the JS.
  if (inlineMapSources > 0) {
    findings.push({
      id: 'inline-sourcemap',
      severity: 'critical',
      category: 'sourcemap',
      title: 'Inline source map embedded in shipped JS',
      detail: `${inlineMapSources} original source file(s) are recoverable from a data-URI source map inside the bundle.`,
      remediation: 'Set build.sourcemap=false so no map (inline or file) ships.',
      locations: inlineMapHits,
      penalty: 65
    })
  } else if (sourcemapRefHits.length && !mapFiles.length) {
    findings.push({
      id: 'sourcemap-ref',
      severity: 'medium',
      category: 'sourcemap',
      title: 'Bundle references a source map',
      detail: 'A //# sourceMappingURL comment points to a map; if that map is deployed, original source is recoverable.',
      remediation: 'Strip the reference and do not deploy the .map, or block it at the web server.',
      locations: sourcemapRefHits,
      penalty: 10
    })
  }

  // Credentials — the only findings we call out as likely real risk; still
  // "review required", not "confirmed leak" (a pattern match is not proof).
  for (const [label, locs] of secretHits) {
    findings.push({
      id: `secret:${label}`,
      severity: 'critical',
      category: 'credential',
      title: `Possible ${label} in bundle (${locs.length}×)`,
      detail: `A string matching a ${label} pattern is shipped to the client. Pattern match ≠ confirmed leak — verify whether it is a real credential.`,
      remediation: 'If real: revoke and rotate it, and move server-managed credentials to the backend. If it is a publishable key or a false positive, suppress it with --ignore.',
      locations: locs.slice(0, 20),
      penalty: 25
    })
  }

  // Internal/infra hosts — lower severity (topology hint, not a credential).
  if (internalHits.length) {
    findings.push({
      id: 'internal-hosts',
      severity: 'low',
      category: 'infra',
      title: `${internalHits.length} internal/infra URL(s) in bundle`,
      detail: 'Internal hosts (localhost, private IPs, .internal/.local) reveal topology to an attacker.',
      remediation: 'Strip staging/admin/private URLs from production builds; use env-specific config.',
      locations: internalHits.slice(0, 20),
      penalty: 10
    })
  }

  // Obfuscation depth (JsDeObsBench). Counts toward RE-exposure, not a security vuln.
  const verdict = antiLlmVerdict(transforms)
  if (jsFiles.length && verdict === 'none' && idRatio > 0.3) {
    findings.push({
      id: 'no-obfuscation',
      severity: 'medium',
      category: 'obfuscation',
      title: 'No obfuscation detected',
      detail: 'Plain minified JS — trivial for an LLM to restore.',
      remediation: 'Add obfuscation with the nore/vite plugin (preset "high").',
      penalty: 15
    })
  } else if (jsFiles.length && verdict === 'weak') {
    findings.push({
      id: 'shallow-obfuscation',
      severity: 'low',
      category: 'obfuscation',
      title: 'Shallow obfuscation (minification/renaming only)',
      detail: `Only ${transforms.size} transform(s) fingerprinted (${[...transforms].join(', ')}). JsDeObsBench shows LLMs fail reliably only once many transforms are stacked.`,
      remediation: 'Use nore/vite preset "high" to stack string-array + control-flow transforms.',
      penalty: 12
    })
  }

  // Readable strings/identifiers — INFO: exposure signal, NOT a vulnerability.
  if (readableStrings > 20 && strRatio > 0.2) {
    findings.push({
      id: 'readable-strings',
      severity: 'info',
      category: 'exposure',
      title: `${readableStrings} readable string literals (${Math.round(strRatio * 100)}% of strings)`,
      detail: 'Readable strings are expected in unobfuscated code and are not a vulnerability by themselves — review them for anything sensitive.',
      remediation: 'Enable string-array encoding (nore/vite) if you want them hidden.',
      penalty: strRatio > 0.5 ? 20 : 10
    })
  }
  if (totalIds > 50 && idRatio > 0.3) {
    findings.push({
      id: 'readable-identifiers',
      severity: 'info',
      category: 'exposure',
      title: `${Math.round(idRatio * 100)}% of identifiers are human-readable`,
      detail: 'Original names survive. Informational for RE exposure, not a security issue on its own.',
      remediation: 'Enable identifier mangling (nore/vite).',
      penalty: 15
    })
  }

  // Positive signal: canaries planted.
  if (canaryValues.size) {
    findings.push({
      id: 'canaries',
      severity: 'info',
      category: 'canary',
      title: `${canaryValues.size} reverse-engineering canaries planted`,
      detail: 'Decoy secrets/endpoints will alert your collector if an attacker probes them.',
      remediation: '',
      penalty: 0
    })
  }

  // Suppress reviewed false positives (by finding id or category).
  const ignore = new Set(opts.ignore ?? [])
  const kept = ignore.size
    ? findings.filter((f) => !ignore.has(f.id) && !ignore.has(f.category))
    : findings

  const score = Math.max(0, 100 - kept.reduce((s, f) => s + f.penalty, 0))
  const severityCounts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of kept) severityCounts[f.severity]++
  const rank = (s: Severity) => SEVERITY_ORDER.indexOf(s)
  return {
    root,
    filesScanned: jsFiles.length,
    bytesScanned: bytes,
    score,
    grade: gradeFor(score),
    severityCounts,
    antiLlm: { transforms: [...transforms], verdict },
    findings: kept.sort((a, b) => rank(b.severity) - rank(a.severity) || b.penalty - a.penalty)
  }
}

