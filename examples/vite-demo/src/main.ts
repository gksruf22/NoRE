import { createGuard } from '@gksruf22/nore'

// A plaintext marker. After `vite build`, grep the output in dist/ — obfuscation
// means this literal is gone (base64-encoded in a string array), so REA's
// static recovery can't lift it straight out.
const SECRET = 'SUPER_SECRET_TOKEN_42'
console.log('secret length is', SECRET.length)

const status = document.getElementById('status')!

// When a debugger / CDP session / devtools is detected, say so on the page.
// In production you'd degrade behavior or beacon the event instead.
createGuard({
  devtools: true, // opt-in: demo wants the (weak) devtools-open heuristic visible
  onDetect: (e) => {
    status.textContent = `analysis tooling detected: ${e.detector}`
    status.style.color = 'red'
  }
})
