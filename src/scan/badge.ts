// Render a scan result as a shields-style flat SVG badge, so a project can embed
// its reverse-engineering exposure grade in a README. Pure string template.
import type { ScanReport } from './scanner.js'

const GRADE_COLOR: Record<string, string> = {
  A: '#4c1', // bright green
  B: '#97ca00',
  C: '#dfb317', // yellow
  D: '#fe7d37', // orange
  F: '#e05d44' // red
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
// Approximate text width at 11px (shields uses ~7px/char for this font).
const textWidth = (s: string) => s.length * 7 + 10

export function renderBadge(report: ScanReport, label = 'RE exposure'): string {
  const msg = `${report.grade} ${report.score}/100`
  const color = GRADE_COLOR[report.grade] ?? '#9f9f9f'
  const lw = textWidth(label)
  const rw = textWidth(msg)
  const w = lw + rw
  const lx = (lw / 2) * 10
  const rx = (lw + rw / 2) * 10
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="20" role="img" aria-label="${esc(label)}: ${esc(msg)}">
  <title>${esc(label)}: ${esc(msg)}</title>
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <clipPath id="r"><rect width="${w}" height="20" rx="3" fill="#fff"/></clipPath>
  <g clip-path="url(#r)">
    <rect width="${lw}" height="20" fill="#555"/>
    <rect x="${lw}" width="${rw}" height="20" fill="${color}"/>
    <rect width="${w}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="110" text-rendering="geometricPrecision">
    <text aria-hidden="true" x="${lx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(lw - 10) * 10}">${esc(label)}</text>
    <text x="${lx}" y="140" transform="scale(.1)" textLength="${(lw - 10) * 10}">${esc(label)}</text>
    <text aria-hidden="true" x="${rx}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)" textLength="${(rw - 10) * 10}">${esc(msg)}</text>
    <text x="${rx}" y="140" transform="scale(.1)" textLength="${(rw - 10) * 10}">${esc(msg)}</text>
  </g>
</svg>`
}

// Shields.io "endpoint" schema. Host the returned JSON anywhere (a committed
// file, a CI artifact, gh-pages) and render a live badge with:
//   https://img.shields.io/endpoint?url=<raw-url-of-this-json>
const ENDPOINT_COLOR: Record<string, string> = {
  A: 'brightgreen',
  B: 'green',
  C: 'yellow',
  D: 'orange',
  F: 'red'
}

export function endpointJson(report: ScanReport, label = 'RE exposure'): string {
  return JSON.stringify({
    schemaVersion: 1,
    label,
    message: `${report.grade} ${report.score}/100`,
    color: ENDPOINT_COLOR[report.grade] ?? 'lightgrey'
  })
}
