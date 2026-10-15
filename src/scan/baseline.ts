// Baseline support: record today's findings so CI can fail only on NEW ones.
// Lets a project with existing warnings adopt NoRE without a big-bang cleanup.
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { findingKeys, type Finding } from './scanner.js'

export interface Baseline {
  version: number
  createdAt: string
  keys: string[]
}

export function loadBaseline(file: string): Set<string> | null {
  if (!existsSync(file)) return null
  try {
    const b = JSON.parse(readFileSync(file, 'utf8'))
    return new Set(Array.isArray(b.keys) ? b.keys : [])
  } catch {
    return null
  }
}

export function saveBaseline(file: string, findings: Finding[]): number {
  const keys = [...new Set(findings.flatMap(findingKeys))]
  const b: Baseline = { version: 1, createdAt: new Date().toISOString(), keys }
  writeFileSync(file, JSON.stringify(b, null, 2))
  return keys.length
}

/** A finding is new if any of its keys is absent from the baseline. */
export function isNewFinding(f: Finding, baseline: Set<string>): boolean {
  return findingKeys(f).some((k) => !baseline.has(k))
}
