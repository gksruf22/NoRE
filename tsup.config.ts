import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    vite: 'src/build/vite-plugin.ts',
    electron: 'src/electron/main-guard.ts',
    cli: 'src/scan/cli.ts'
  },
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  shims: true,
  // Keep node-only / heavy deps external; the browser bundle (index) stays small.
  external: [
    'vite',
    'javascript-obfuscator',
    'acorn',
    'acorn-walk',
    'node:crypto',
    'node:inspector',
    'node:fs',
    'node:fs/promises',
    'node:path'
  ]
})
