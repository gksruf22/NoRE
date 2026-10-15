// Self-integrity check: hash a known resource (usually the app's own bundle) and
// compare against a build-time hash injected by the Vite plugin.
//
// ponytail: fetch-based, so an attacker who hooks fetch/crypto can forge the match.
// It raises cost and catches naive on-disk patching; it is not tamper-proof.

const encoder = new TextEncoder()

export async function sha256Hex(data: string | ArrayBuffer): Promise<string> {
  const bytes = typeof data === 'string' ? encoder.encode(data) : data
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

// Fetches `url`, hashes its bytes, compares to `expectedHash`.
// Returns true when the resource is UNMODIFIED. On any error (blocked fetch,
// no crypto) returns true — fail-open, so a flaky network never breaks the app.
export async function verifyIntegrity(expectedHash: string, url: string): Promise<boolean> {
  try {
    const res = await fetch(url, { cache: 'no-store' })
    const actual = await sha256Hex(await res.arrayBuffer())
    return actual === expectedHash
  } catch {
    return true
  }
}
