# NovaProtect website · vendored JS libs

Offline copies (npm → dist / esbuild IIFE). No CDN at runtime.

| File | Package | Version | Use |
|------|---------|---------|-----|
| motion.js / motion.dev.js | motion | 14.14.0 | springs, interruptible `animate()` |
| motion-dom.js | motion-dom | 14.14.0 | DOM-only motion |
| framer-motion.js / mini / dom | framer-motion | 14.14.0 | React motion, DOM animate |
| vaul.mjs + vaul.css | vaul | 1.1.2 | drawer/sheet gestures (Emil) |
| react-vaul.js | react 19.3.1 + react-dom 19.3.1 + vaul | esbuild IIFE | `window.NovaUI` = { React, createRoot, Drawer } |
| react.js / react-dom-client.js | react / react-dom | 19.3.1 | raw modules |

`motion.js` is retained as a vendored library but is not loaded by first-party pages; the website uses native Web Animations API for its current effects. `react-vaul.js` is loaded on demand for drawers.
