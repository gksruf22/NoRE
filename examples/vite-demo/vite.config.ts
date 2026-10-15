import { defineConfig } from 'vite'
import { nore } from 'nore/vite'

export default defineConfig({
  plugins: [
    nore({
      obfuscate: true,
      preset: 'high',
      canaries: { collector: 'https://canary.example.com', count: 4 }
    })
  ]
})
