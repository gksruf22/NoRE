import { describe, it, expect } from 'vitest'
import { extractSourceMapRef, resolveMapUrl, recoverableSources } from '../src/scan/probe.js'

describe('extractSourceMapRef', () => {
  it('finds an external reference (last one wins)', () => {
    expect(extractSourceMapRef('a\n//# sourceMappingURL=app.js.map')).toEqual({ kind: 'external', url: 'app.js.map' })
    expect(extractSourceMapRef('//# sourceMappingURL=a.map\n//# sourceMappingURL=b.map').url).toBe('b.map')
  })
  it('detects inline data-URI maps and none', () => {
    expect(extractSourceMapRef('x\n//# sourceMappingURL=data:application/json;base64,AAAA').kind).toBe('inline')
    expect(extractSourceMapRef('const x=1').kind).toBe('none')
  })
})

describe('resolveMapUrl', () => {
  it('resolves relative and absolute against the JS url', () => {
    expect(resolveMapUrl('app.js.map', 'https://x.com/assets/app.js')).toBe('https://x.com/assets/app.js.map')
    expect(resolveMapUrl('/m/app.map', 'https://x.com/assets/app.js')).toBe('https://x.com/m/app.map')
    expect(resolveMapUrl('https://cdn.com/a.map', 'https://x.com/app.js')).toBe('https://cdn.com/a.map')
  })
})

describe('recoverableSources', () => {
  it('counts sourcesContent, falls back to sources, 0 on garbage', () => {
    expect(recoverableSources(JSON.stringify({ sourcesContent: ['a', 'b', null] }))).toBe(2)
    expect(recoverableSources(JSON.stringify({ sources: ['a.ts', 'b.ts'] }))).toBe(2)
    expect(recoverableSources('not json')).toBe(0)
  })
})
