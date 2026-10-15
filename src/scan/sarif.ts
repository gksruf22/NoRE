// Emit SARIF 2.1.0 so results show up in GitHub Code Scanning / other SARIF
// viewers. Maps NoRE severities to SARIF levels.
import type { ScanReport, Severity } from './scanner.js'

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note'
}

export function toSarif(report: ScanReport, version = '0.1.0'): string {
  const ruleIds = [...new Set(report.findings.map((f) => f.id))]
  const rules = ruleIds.map((id) => {
    const f = report.findings.find((x) => x.id === id)!
    return {
      id,
      name: id,
      shortDescription: { text: f.title },
      fullDescription: { text: f.detail },
      help: { text: f.remediation || f.detail },
      properties: { category: f.category }
    }
  })

  const results = report.findings.flatMap((f) => {
    const locs = f.locations?.length ? f.locations : [{ file: '.', line: 1 }]
    return locs.map((l) => ({
      ruleId: f.id,
      level: LEVEL[f.severity],
      message: { text: `${f.title}${l.match ? ` — ${l.match}` : ''}. ${f.remediation}`.trim() },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: l.file },
            region: { startLine: Math.max(1, l.line) }
          }
        }
      ]
    }))
  })

  return JSON.stringify(
    {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'NoRE',
              informationUri: 'https://github.com/gksruf22/NoRE',
              version,
              rules
            }
          },
          results
        }
      ]
    },
    null,
    2
  )
}
