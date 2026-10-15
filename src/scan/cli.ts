#!/usr/bin/env node
import { statSync, writeFileSync } from 'node:fs'
import { scan, SEVERITY_ORDER, type Severity } from './scanner.js'
import { renderBadge, endpointJson } from './badge.js'
import { toSarif } from './sarif.js'

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m', cyan: '\x1b[36m', blue: '\x1b[34m'
}
const color = process.stdout.isTTY
const paint = (s: string, c: string) => (color ? c + s + C.reset : s)

const SEV: Record<Severity, string> = {
  critical: C.red, high: C.red, medium: C.yellow, low: C.blue, info: C.dim
}
const GRADE_COLOR: Record<string, string> = { A: C.green, B: C.green, C: C.yellow, D: C.yellow, F: C.red }

function help(): never {
  console.log(`nore — reverse-engineering exposure scanner

Usage:
  nore scan <dir> [options]

Options:
  --min <grade>        Exit non-zero if the RE-exposure grade is below <grade> (A–F)
  --fail-on <severity> Exit non-zero if any finding is at/above <severity>
                       (critical|high|medium|low) — gate on real risk, not grade
  --ignore <a,b,...>   Suppress findings by id or category (reviewed false positives)
  --format <fmt>       text (default) | json | sarif
  --json               Shorthand for --format json
  --badge [file]       Write an SVG grade badge (stdout if no file)
  --endpoint [file]    Write shields.io endpoint JSON for a live badge

Examples:
  npx nore scan ./dist --min B
  npx nore scan ./dist --fail-on critical --ignore "secret:OpenAI API key"
  npx nore scan ./dist --format sarif > nore.sarif
  npx nore scan ./dist --endpoint nore-badge.json`)
  process.exit(2)
}

const argv = process.argv.slice(2)
if (argv[0] !== 'scan' || !argv[1] || argv.includes('-h') || argv.includes('--help')) help()

const dir = argv[1]
const valueOf = (flag: string): string | undefined => {
  const i = argv.indexOf(flag)
  if (i < 0) return undefined
  const v = argv[i + 1]
  return v && !v.startsWith('-') ? v : undefined
}
const format = argv.includes('--json') ? 'json' : (valueOf('--format') ?? 'text')
const minGrade = valueOf('--min')?.toUpperCase() ?? (argv.includes('--min') ? 'C' : null)
const failOn = valueOf('--fail-on')?.toLowerCase() as Severity | undefined
const ignore = (valueOf('--ignore') ?? '').split(',').map((s) => s.trim()).filter(Boolean)

try {
  if (!statSync(dir).isDirectory()) throw new Error('not a directory')
} catch {
  console.error(paint(`error: ${dir} is not a directory`, C.red))
  process.exit(2)
}

const report = scan(dir, { ignore })

function printReport(): void {
  const g = paint(` ${report.grade} `, (GRADE_COLOR[report.grade] ?? '') + C.bold)
  const sc = report.severityCounts
  console.log('')
  console.log(`  ${paint('NoRE exposure report', C.bold)}  ${report.root}`)
  console.log(`  grade ${g}  score ${report.score}/100   ${paint(`${report.filesScanned} JS files, ${(report.bytesScanned / 1024).toFixed(0)} KB`, C.dim)}`)
  console.log(`  risk: ${paint(`${sc.critical} critical`, sc.critical ? C.red : C.dim)}, ${paint(`${sc.high} high`, sc.high ? C.red : C.dim)}, ${sc.medium} medium, ${sc.low} low, ${sc.info} info`)
  const vColor: Record<string, string> = { strong: C.green, partial: C.yellow, weak: C.red, none: C.red }
  console.log(`  anti-LLM deobfuscation: ${paint(report.antiLlm.verdict, vColor[report.antiLlm.verdict] ?? '')} ${paint(`(≥${report.antiLlm.transforms.length} transforms detected — heuristic estimate)`, C.dim)}`)
  console.log('')
  if (!report.findings.length) {
    console.log('  ' + paint('No findings.', C.green))
  } else {
    for (const f of report.findings) {
      const pts = f.penalty > 0 ? paint(`-${f.penalty}`, C.dim) : ''
      console.log(`  ${paint('●', SEV[f.severity])} ${paint(f.severity.toUpperCase().padEnd(8), SEV[f.severity])} ${f.title}  ${pts}`)
      console.log(`    ${paint(f.detail, C.dim)}`)
      for (const l of (f.locations ?? []).slice(0, 5)) {
        console.log(`    ${paint('↳', C.dim)} ${paint(`${l.file}:${l.line}`, C.cyan)}${l.match ? paint(`  ${l.match}`, C.dim) : ''}`)
      }
      if (f.remediation) console.log(`    ${paint('fix:', C.dim)} ${paint(f.remediation, C.dim)}`)
    }
  }
  console.log('')
}

// --badge/--endpoint can emit a bare artifact to stdout (then skip the report).
const emit = (flag: string, render: () => string, noun: string): 'stdout' | 'file' | null => {
  const i = argv.indexOf(flag)
  if (i < 0) return null
  const arg = argv[i + 1]
  const file = arg && !arg.startsWith('-') ? arg : null
  if (!file) {
    console.log(render())
    return 'stdout'
  }
  writeFileSync(file, render())
  console.error(paint(`${noun} written to ${file} (grade ${report.grade})`, C.cyan))
  return 'file'
}

const badge = emit('--badge', () => renderBadge(report), 'badge')
const endpoint = emit('--endpoint', () => endpointJson(report), 'endpoint JSON')

if (badge !== 'stdout' && endpoint !== 'stdout') {
  if (format === 'json') console.log(JSON.stringify(report, null, 2))
  else if (format === 'sarif') console.log(toSarif(report))
  else printReport()
}

// Exit gates (both can be set; either failing exits 1).
let failed = false
if (minGrade) {
  const order = ['F', 'D', 'C', 'B', 'A']
  if (order.indexOf(report.grade) < order.indexOf(minGrade)) {
    if (format === 'text') console.error(paint(`  FAIL: grade ${report.grade} is below required ${minGrade}`, C.red))
    failed = true
  }
}
if (failOn && SEVERITY_ORDER.includes(failOn)) {
  const threshold = SEVERITY_ORDER.indexOf(failOn)
  const worst = report.findings.reduce((m, f) => Math.max(m, SEVERITY_ORDER.indexOf(f.severity)), -1)
  if (worst >= threshold) {
    if (format === 'text') console.error(paint(`  FAIL: a ${SEVERITY_ORDER[worst]} finding is at/above --fail-on ${failOn}`, C.red))
    failed = true
  }
}
if (failed) process.exit(1)
