# Demonstrating NoRE against REA

[`vite-demo/`](./vite-demo) is a runnable app hardened with NoRE. Use it to
reproduce REA's two JS attack paths and watch NoRE blunt each.

## Run it

```sh
# from the repo root — build the library first
npm install && npm run build

# then the demo (links the local build via a file: dependency)
cd examples/vite-demo
npm install
npm run build        # production build: obfuscated, no sourcemaps
npm run preview      # serve dist/ to attack it
```

## 1. Static recovery — should fail

Attack with REA:

- `mcp__rea__analyze_web_bundle` / `mcp__rea__recover_javascript_sources`

**Before NoRE:** sourcemaps let REA reconstruct original filenames and readable
source. **After NoRE:** no `.map` files ship and chunks are obfuscated (control
flow flattened, every string base64-encoded), so recovery yields opaque code
instead of your source. Confirm it yourself:

```sh
grep -r SUPER_SECRET_TOKEN_42 dist/   # the plaintext marker is gone
ls dist/assets/*.map                  # no sourcemaps
```

## 2. CDP attach — should be detected

Attack with REA:

- `mcp__rea__observe_web_session` (attaches over the Chrome DevTools Protocol)

**Result:** the attach opens an inspector session. In Electron/Node contexts
`inspectorAttached` flips immediately; in the browser `debuggerTiming` /
`devtoolsOpen` catch an open inspector. The guard's `onDetect` fires — the demo
turns the status line red with the detector name.

## 3. Record the comparison

Capture the before/after for each path (recovered source vs. obfuscated output;
no-detection vs. `onDetect` firing) so the defense is measurable, not assumed.

> Reminder: this raises cost; a determined analyst who disables breakpoints and
> deobfuscates can still proceed. Keep secrets server-side.
