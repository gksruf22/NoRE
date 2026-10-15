#!/usr/bin/env node
import { statSync, writeFileSync } from 'node:fs'
import { scan, type Severity } from './scanner.js'
import { renderBadge, endpointJson } from './badge.js'

const C = {
  reset: '\x1b[0m', bold: '\x1b[1m', dim: '\x1b[2m',
  red: '\x1b[31m', yellow: '\x1b[33m', green: '\x1b[32m', cyan: '\x1b[36m'
}
const color = process.stdout.isTTY
const paint = (s: string, c: string) => (color ? c + s + C.reset : s)

const SEV: Record<Severity, string> = {
  critical: C.red, high: C.red, medium: C.yellow, info: C.dim
}
const GRADE_COLOR: Record<string, string> = { A: C.green, B: C.green, C: C.yellow, D: C.yellow, F: C.red }

function help(): never {
  console.log(`nore — reverse-engineering exposure scanner

Usage:
  nore scan <dir>        Grade how reverse-engineerable a built app is
  nore scan <dir> --json Machine-readable report
  nore scan <dir> --min <grade>  Exit non-zero below <grade> (for CI)
  nore scan <dir> --badge [file]    Write an SVG grade badge (stdout if no file)
  nore scan <dir> --endpoint [file] Write shields.io endpoint JSON for a live badge

Example:
  npx nore scan ./dist --min B
  npx nore scan ./dist --badge nore-badge.svg
  npx nore scan ./dist --endpoint nore-badge.json  # host it, then:
  #   https://img.shields.io/endpoint?url=<raw url of nore-badge.json>`)
  process.exit(2)
}

const argv = process.argv.slice(2)
if (argv[0] !== 'scan' || !argv[1] || argv.includes('-h') || argv.includes('--help')) help()

const dir = argv[1]
const asJson = argv.includes('--json')
const minIdx = argv.indexOf('--min')
const minGrade = minIdx >= 0 ? (argv[minIdx + 1] ?? 'C').toUpperCase() : null

try {
  if (!statSync(dir).isDirectory()) throw new Error('not a directory')
} catch {
  console.error(paint(`error: ${dir} is not a directory`, C.red))
  process.exit(2)
}

const report = scan(dir)

function printReport(): void {
  const g = paint(` ${report.grade} `, (GRADE_COLOR[report.grade] ?? '') + C.bold)
  console.log('')
  console.log(`  ${paint('NoRE exposure report', C.bold)}  ${report.root}`)
  console.log(`  grade ${g}  score ${report.score}/100   ${paint(`${report.filesScanned} JS files, ${(report.bytesScanned / 1024).toFixed(0)} KB`, C.dim)}`)
  const vColor: Record<string, string> = { strong: C.green, partial: C.yellow, weak: C.red, none: C.red }
  console.log(`  anti-LLM deobfuscation: ${paint(report.antiLlm.verdict, vColor[report.antiLlm.verdict] ?? '')} ${paint(`(≥${report.antiLlm.transforms.length} transforms detected — heuristic estimate)`, C.dim)}`)
  console.log('')
  if (!report.findings.length) {
    console.log('  ' + paint('No exposure findings. Well hardened.', C.green))
  } else {
    for (const f of report.findings) {
      const pts = f.penalty > 0 ? paint(`-${f.penalty}`, C.dim) : ''
      console.log(`  ${paint('●', SEV[f.severity])} ${paint(f.severity.toUpperCase().padEnd(8), SEV[f.severity])} ${f.title}  ${pts}`)
      console.log(`    ${paint(f.detail, C.dim)}`)
    }
  }
  console.log('')
  console.log(paint('  Harden with the nore/vite plugin, then re-scan.', C.cyan))
  console.log('')
}

// --badge [file] (SVG) / --endpoint [file] (shields endpoint JSON).
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

// Only print the human/JSON report if we didn't emit a bare artifact to stdout.
if (badge !== 'stdout' && endpoint !== 'stdout') {
  if (asJson) console.log(JSON.stringify(report, null, 2))
  else printReport()
}

if (minGrade) {
  const order = ['F', 'D', 'C', 'B', 'A']
  if (order.indexOf(report.grade) < order.indexOf(minGrade)) {
    if (!asJson) console.error(paint(`  FAIL: grade ${report.grade} is below required ${minGrade}`, C.red))
    process.exit(1)
  }
}
