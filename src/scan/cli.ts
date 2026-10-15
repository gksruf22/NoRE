#!/usr/bin/env node
import { statSync, writeFileSync, readFileSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { scan, SEVERITY_ORDER, type Severity } from './scanner.js'
import { renderBadge, endpointJson } from './badge.js'
import { toSarif } from './sarif.js'
import { loadBaseline, saveBaseline, isNewFinding } from './baseline.js'
import { takeSnapshot, diffSnapshots, type Snapshot } from './snapshot.js'
import { extractSourceMapRef, resolveMapUrl, recoverableSources } from './probe.js'

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
  --baseline <file>    Record current findings; later runs gate only on NEW ones
                       (creates the file if missing). --update-baseline rewrites it.
  --format <fmt>       text (default) | json | sarif
  --json               Shorthand for --format json
  --badge [file]       Write an SVG grade badge (stdout if no file)
  --endpoint [file]    Write shields.io endpoint JSON for a live badge

Other commands:
  nore snapshot <dir> [-o file]       Record file hashes of a build
  nore diff <dir> --against <file>    Detect unexpected changes vs a snapshot
                                      (exit 1 if anything added/removed/changed)
  nore probe <js-url>                 Scan a DEPLOYED script and check whether its
                                      source map is actually reachable over HTTP

Examples:
  npx @gksruf22/nore scan ./dist --min B
  npx @gksruf22/nore scan ./dist --fail-on critical --ignore "secret:OpenAI API key"
  npx @gksruf22/nore scan ./dist --format sarif > nore.sarif
  npx @gksruf22/nore snapshot ./dist -o deploy.json
  npx @gksruf22/nore diff ./dist --against deploy.json`)
  process.exit(2)
}

const argvEarly = process.argv.slice(2)
const flagVal = (flag: string): string | undefined => {
  const i = argvEarly.indexOf(flag)
  const v = i >= 0 ? argvEarly[i + 1] : undefined
  return v && !v.startsWith('-') ? v : undefined
}
const dirArg = argvEarly[1]
const ensureDir = (d: string) => {
  try {
    if (!statSync(d).isDirectory()) throw 0
  } catch {
    process.stderr.write(`error: ${d} is not a directory\n`)
    process.exit(2)
  }
}

// --- nore snapshot <dir> [-o file] ---
if (argvEarly[0] === 'snapshot') {
  if (!dirArg) help()
  ensureDir(dirArg)
  const snap = JSON.stringify(takeSnapshot(dirArg), null, 2)
  const out = flagVal('-o') ?? flagVal('--out')
  if (out) {
    writeFileSync(out, snap)
    process.stderr.write(`snapshot written to ${out}\n`)
  } else {
    process.stdout.write(snap + '\n')
  }
  process.exit(0)
}

// --- nore diff <dir> --against <snapshot> ---
if (argvEarly[0] === 'diff') {
  if (!dirArg) help()
  ensureDir(dirArg)
  const against = flagVal('--against')
  if (!against) {
    process.stderr.write('error: diff requires --against <snapshot.json>\n')
    process.exit(2)
  }
  let base: Snapshot
  try {
    base = JSON.parse(readFileSync(against, 'utf8'))
  } catch {
    process.stderr.write(`error: cannot read snapshot ${against}\n`)
    process.exit(2)
  }
  const d = diffSnapshots(base, takeSnapshot(dirArg))
  if (argvEarly.includes('--json')) {
    process.stdout.write(JSON.stringify(d, null, 2) + '\n')
  } else {
    const line = (label: string, arr: string[], col: string) => {
      if (!arr.length) return
      process.stdout.write(`  ${paint(label, col)} (${arr.length})\n`)
      for (const p of arr) process.stdout.write(`    ${p}\n`)
    }
    const total = d.added.length + d.removed.length + d.changed.length
    process.stdout.write('\n')
    if (!total) process.stdout.write('  ' + paint('No changes vs snapshot.', C.green) + '\n')
    else {
      line('changed', d.changed, C.yellow)
      line('added', d.added, C.red)
      line('removed', d.removed, C.red)
      process.stdout.write('\n  ' + paint(`${total} change(s) — review for unexpected/supply-chain modifications.`, C.cyan) + '\n')
    }
    process.stdout.write('\n')
  }
  process.exit(d.added.length + d.removed.length + d.changed.length ? 1 : 0)
}

// --- nore probe <js-url> : scan a deployed script + live source-map check ---
if (argvEarly[0] === 'probe') {
  const url = dirArg
  if (!url || !/^https?:\/\//.test(url)) {
    process.stderr.write('error: probe requires an http(s) URL to a deployed .js\n')
    process.exit(2)
  }
  const asJson = argvEarly.includes('--json')
  const get = async (u: string) => {
    const ctrl = new AbortController()
    const to = setTimeout(() => ctrl.abort(), 10000)
    try {
      return await fetch(u, { signal: ctrl.signal, redirect: 'follow' })
    } finally {
      clearTimeout(to)
    }
  }
  ;(async () => {
    let js: string
    try {
      const res = await get(url)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      js = await res.text()
    } catch (e) {
      process.stderr.write(`error: could not fetch ${url}: ${(e as Error).message}\n`)
      process.exit(2)
    }

    // Reuse the full scanner on the fetched content.
    const d = mkdtempSync(join(tmpdir(), 'nore-probe-'))
    writeFileSync(join(d, 'app.js'), js)
    const report = scan(d)
    rmSync(d, { recursive: true, force: true })

    // Live source-map accessibility — the real "is it exposed" check.
    const ref = extractSourceMapRef(js)
    let map: { kind: string; url?: string; accessible?: boolean; status?: number; sources?: number } = { kind: ref.kind }
    if (ref.kind === 'external' && ref.url) {
      const mapUrl = resolveMapUrl(ref.url, url)
      map.url = mapUrl
      try {
        const mres = await get(mapUrl)
        map.status = mres.status
        map.accessible = mres.ok
        if (mres.ok) map.sources = recoverableSources(await mres.text())
      } catch {
        map.accessible = false
      }
    } else if (ref.kind === 'inline') {
      map.accessible = true
      map.sources = recoverableSources(Buffer.from((js.match(/sourceMappingURL=data:[^,]*,([^\s'"]+)/) ?? [])[1] ?? '', 'base64').toString('utf8'))
    }

    if (asJson) {
      process.stdout.write(JSON.stringify({ url, scan: report, sourcemap: map }, null, 2) + '\n')
    } else {
      process.stdout.write(`\n  ${paint('NoRE probe', C.bold)}  ${url}\n`)
      process.stdout.write(`  exposure grade ${paint(report.grade, GRADE_COLOR[report.grade] ?? '')}  score ${report.score}/100\n`)
      if (map.kind === 'none') process.stdout.write('  ' + paint('source map: no reference in the script.', C.green) + '\n')
      else if (map.kind === 'inline') process.stdout.write('  ' + paint(`source map: INLINE in the script — ${map.sources} source(s) recoverable.`, C.red) + '\n')
      else if (map.accessible) process.stdout.write('  ' + paint(`source map: PUBLICLY ACCESSIBLE at ${map.url} — ${map.sources} source(s) recoverable.`, C.red) + '\n')
      else process.stdout.write('  ' + paint(`source map: referenced (${map.url}) but NOT reachable (HTTP ${map.status ?? 'error'}) — good.`, C.green) + '\n')
      process.stdout.write('\n')
    }
    // Fail if source is actually recoverable (inline, or an accessible map).
    const exposed = map.kind === 'inline' || map.accessible === true
    process.exit(exposed ? 1 : 0)
  })()
} else {

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

// --baseline: create on first use (or --update-baseline), else mark NEW findings.
const baselineFile = valueOf('--baseline')
let baseline: Set<string> | null = null
if (baselineFile) {
  if (argv.includes('--update-baseline') || !loadBaseline(baselineFile)) {
    const n = saveBaseline(baselineFile, report.findings)
    if (format === 'text') console.error(paint(`baseline ${argv.includes('--update-baseline') ? 'updated' : 'created'}: ${n} finding(s) recorded in ${baselineFile}`, C.cyan))
    process.exit(0)
  }
  baseline = loadBaseline(baselineFile)
}
const isNew = (f: (typeof report.findings)[number]) => (baseline ? isNewFinding(f, baseline) : true)
const newCount = baseline ? report.findings.filter(isNew).length : report.findings.length

function printReport(): void {
  const g = paint(` ${report.grade} `, (GRADE_COLOR[report.grade] ?? '') + C.bold)
  const sc = report.severityCounts
  console.log('')
  console.log(`  ${paint('NoRE exposure report', C.bold)}  ${report.root}`)
  console.log(`  grade ${g}  score ${report.score}/100   ${paint(`${report.filesScanned} JS files, ${(report.bytesScanned / 1024).toFixed(0)} KB`, C.dim)}`)
  console.log(`  risk: ${paint(`${sc.critical} critical`, sc.critical ? C.red : C.dim)}, ${paint(`${sc.high} high`, sc.high ? C.red : C.dim)}, ${sc.medium} medium, ${sc.low} low, ${sc.info} info`)
  const vColor: Record<string, string> = { strong: C.green, partial: C.yellow, weak: C.red, none: C.red }
  console.log(`  anti-LLM deobfuscation: ${paint(report.antiLlm.verdict, vColor[report.antiLlm.verdict] ?? '')} ${paint(`(≥${report.antiLlm.transforms.length} transforms detected — heuristic estimate)`, C.dim)}`)
  if (baseline) console.log(`  baseline: ${paint(`${newCount} new`, newCount ? C.yellow : C.green)}, ${report.findings.length - newCount} known`)
  console.log('')
  if (!report.findings.length) {
    console.log('  ' + paint('No findings.', C.green))
  } else {
    for (const f of report.findings) {
      const pts = f.penalty > 0 ? paint(`-${f.penalty}`, C.dim) : ''
      const tag = baseline ? (isNew(f) ? paint(' NEW', C.yellow) : paint(' known', C.dim)) : ''
      console.log(`  ${paint('●', SEV[f.severity])} ${paint(f.severity.toUpperCase().padEnd(8), SEV[f.severity])} ${f.title}${tag}  ${pts}`)
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
  // With a baseline, only NEW findings can fail the build.
  const considered = baseline ? report.findings.filter(isNew) : report.findings
  const worst = considered.reduce((m, f) => Math.max(m, SEVERITY_ORDER.indexOf(f.severity)), -1)
  if (worst >= threshold) {
    if (format === 'text') console.error(paint(`  FAIL: a ${baseline ? 'new ' : ''}${SEVERITY_ORDER[worst]} finding is at/above --fail-on ${failOn}`, C.red))
    failed = true
  }
}
if (failed) process.exit(1)
}
