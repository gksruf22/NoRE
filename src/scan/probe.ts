// Remote probe: the review's "file present vs. externally accessible" distinction.
// A .map in your build dir is one thing; a .map actually reachable on your deploy
// is the real exposure. These helpers are pure (network lives in the CLI).

export interface SourceMapRef {
  kind: 'none' | 'inline' | 'external'
  url?: string // for 'external', the raw sourceMappingURL value
}

// The effective sourceMappingURL is the LAST one in the file.
export function extractSourceMapRef(js: string): SourceMapRef {
  let last: RegExpExecArray | null = null
  const re = /\/\/[#@]\s*sourceMappingURL=(\S+)/g
  for (let m = re.exec(js); m; m = re.exec(js)) last = m
  if (!last) return { kind: 'none' }
  const val = last[1]
  if (val.startsWith('data:')) return { kind: 'inline' }
  return { kind: 'external', url: val }
}

// Resolve a (possibly relative) sourceMappingURL against the JS file's URL.
export function resolveMapUrl(ref: string, jsUrl: string): string {
  return new URL(ref, jsUrl).href
}

// Count how many original sources a fetched source map leaks.
export function recoverableSources(mapText: string): number {
  try {
    const m = JSON.parse(mapText)
    return Array.isArray(m.sourcesContent)
      ? m.sourcesContent.filter((s: unknown) => typeof s === 'string').length
      : Array.isArray(m.sources)
        ? m.sources.length
        : 0
  } catch {
    return 0
  }
}
