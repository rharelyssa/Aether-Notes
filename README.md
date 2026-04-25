# ✦ Aether Notes

> Privacy-first, local-only encrypted note taking app. No cloud. No accounts. No tracking. Just you.

[![Version](https://img.shields.io/badge/version-1.2.0-5b7cf6)](https://github.com/rharelyssa/Aether-Notes)
[![License](https://img.shields.io/badge/license-MIT-34c88a)](https://github.com/rharelyssa/Aether-Notes/blob/main/LICENSE)
[![PWA](https://img.shields.io/badge/PWA-ready-f0b429)](https://github.com/rharelyssa/Aether-Notes)
[![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-e05c7a)](https://github.com/rharelyssa/Aether-Notes)
[![Built with Claude](https://img.shields.io/badge/built%20with-Claude-7c6af7)](https://claude.ai)

## ✨ Features

- **🔐 AES-256-GCM Encryption** — Browser-native Web Crypto API. Zero external crypto libraries.
- **🔑 PBKDF2 Key Derivation** — 310,000 iterations, SHA-256, unique random salt per save.
- **🛡️ 12-Word Recovery Phrase** — Bitcoin-style seed phrase. Never stored, shown once only.
- **💾 IndexedDB Storage** — Encrypted blobs stored in IndexedDB, not localStorage. Async, no size limits.
- **🔒 Note-Level Lock** — Individual notes can have their own PIN.
- **🔐 Passphrase Mode** — Optional long passphrase instead of 4-digit PIN. Entropy meter included.
- **🪪 Biometric Unlock** — WebAuthn (Face ID / Touch ID) for quick access. Encryption unchanged.
- **🔄 Security Migration** — Switch between PIN and passphrase. Re-encrypts all data in place.
- **📌 Pinned Notes** — Pin important notes to the top of your list.
- **🔗 Wiki-Style Linking** — `[[Note Title]]` syntax. Click to navigate between notes.
- **🏷️ Tags + Smart Search** — Filter by tag, category, or full-text search.
- **📂 Custom Categories** — Create categories with custom colors and icons.
- **✍️ Markdown Preview** — XSS-safe double-layer sanitization (escape + DOMParser allowlist).
- **🎨 Note Colors** — 12-color palette per note.
- **📊 Statistics** — Word count, streaks, category breakdown.
- **⏱️ Auto-lock** — Session clears from memory after 5 minutes idle.
- **🛡️ Brute-Force Protection** — 5 wrong attempts triggers 30-second lockout.
- **📤 Export / Import** — Encrypted `.vault` backup. Useless without your secret.
- **⌘K Command Palette** — Keyboard-first navigation.
- **📱 PWA** — Installable as native app, works fully offline.
- **🌙 Dark / Light Mode** — Saved across sessions.

## 🔐 Security Model

```
Secret (PIN or Passphrase)
  ↓
PBKDF2 — 310,000 iter — SHA-256 — random 16-byte salt (per save)
  ↓
AES-256-GCM key  (never exported, never stored)
  ↓
AES-GCM encrypt — random 12-byte IV (per save)
  ↓
[V1][salt][IV][ciphertext+GCM tag] → Base64 → IndexedDB
```

### Storage Architecture

| Data | Where | Format |
|------|-------|--------|
| Encrypted notes | **IndexedDB** | AES-256-GCM blob |
| PIN/passphrase verifier | **IndexedDB** | PBKDF2-derived hash |
| Recovery blob | **IndexedDB** | AES-256-GCM blob |
| Biometric credential | **IndexedDB** | AES-256-GCM blob |
| Theme, stats, categories | localStorage | Plaintext (non-sensitive) |
| Auth mode config | localStorage | `{ authMode: "pin"\|"passphrase" }` |

**Sensitive data NEVER touches localStorage after v1.2.0.**  
On first launch, any existing localStorage vault is automatically migrated to IndexedDB with zero data loss.

### What is NEVER stored anywhere

- Raw PIN or passphrase
- Recovery phrase (shown once, then gone forever)
- Derived encryption key
- Decrypted note content

### XSS Protection — Double Layer

```
User input (Markdown)
  → Layer 1: HTML escape (& < > " encoded before any processing)
  → Layer 2: renderMarkdown() (safe pattern matching on escaped text)
  → Layer 3: sanitizeParsedHTML() (DOMParser + allowlist filter)
       allowed tags: p, strong, em, a, code, blockquote, h1-h3, ul, ol, li
       blocked: script, iframe, form, input, on* attributes
  → dangerouslySetInnerHTML
```

### Passphrase vs PIN

| | PIN | Passphrase |
|---|---|---|
| Length | 4 digits | 8+ chars (any UTF-8) |
| Entropy | ~13 bits | 60–100+ bits |
| Recommended | Quick testing | Production use |
| Crypto pipeline | **Identical** | **Identical** |

### Biometric (WebAuthn)

Biometric does **not** replace encryption:

```
Registration:
  sessionSecret → AES-256-GCM (key derived from WebAuthn credentialId) → IndexedDB

Unlock:
  WebAuthn assertion → decrypt from IndexedDB → sessionSecret → open vault
```

If the device is lost or biometric is removed, the vault still requires PIN/passphrase.

### Memory Safety

- Session secret stored in `useRef` (hidden from React DevTools)
- On lock/logout: `sessionPin.current = null`, all input states cleared
- No derived keys are exported or persisted between sessions
- Timing-safe comparison prevents timing attacks on PIN verification

### Content Security Policy

Deployed with strict CSP headers (Netlify `_headers` / Vercel `vercel.json`):

```
connect-src 'none'   → zero outbound network requests
frame-src 'none'     → no iframe embedding
object-src 'none'    → no plugins
base-uri 'self'      → no base tag injection
form-action 'none'   → no form submissions
```

## 🚀 Getting Started

```bash
git clone https://github.com/rharelyssa/Aether-Notes.git
cd Aether-Notes
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## 🏗️ Build & Deploy

```bash
npm run build
```

### Netlify

Drag & drop the `build/` folder at netlify.com — the `public/_headers` file is automatically picked up for CSP.

### Vercel

```bash
vercel deploy
```

The `vercel.json` in the root is automatically applied. No extra config needed.

### GitHub Pages

```bash
npm install --save-dev gh-pages
# Add to package.json scripts: "deploy": "gh-pages -d build"
npm run deploy
```

> ⚠️ GitHub Pages doesn't support custom response headers — CSP won't be enforced. Use Netlify or Vercel for full security.

## ⚙️ Settings

Access via the **⚙️** button in the top bar:

| Section | What you can do |
|---------|----------------|
| 🔑 Recovery Phrase | View or regenerate your 12-word backup phrase |
| 🪪 Biometric | Register / remove Face ID or fingerprint unlock |
| 🔐 Security Mode | Switch between PIN and passphrase, migrate all data |
| ⚠️ Reset Vault | Wipe all vault data (export first!) |

## 📁 Project Structure

```
aether-notes/
├── public/
│   ├── index.html       # PWA meta tags
│   ├── manifest.json    # PWA manifest
│   ├── sw.js            # Service worker (offline)
│   ├── icon.svg         # App icon
│   └── _headers         # Netlify CSP headers
├── src/
│   ├── App.jsx          # Full app (2700+ lines)
│   └── index.js         # Entry point
├── vercel.json          # Vercel security headers
├── package.json
└── README.md
```

## 🛣️ Roadmap

### ✅ Shipped

- [x] AES-256-GCM encryption via Web Crypto API
- [x] PBKDF2 key derivation (310k iterations)
- [x] 12-word recovery phrase (BIP-39 style)
- [x] Note-level PIN lock
- [x] Export / Import encrypted `.vault` backup
- [x] **IndexedDB storage** (migrated from localStorage)
- [x] **XSS double-layer sanitization** (escape + DOMParser allowlist)
- [x] **CSP headers** (Netlify + Vercel)
- [x] **Memory wipe on lock/logout**
- [x] **Passphrase mode** (optional, stronger than PIN)
- [x] **Security migration** (PIN ↔ passphrase, re-encrypts all data)
- [x] **Biometric unlock** (WebAuthn / Face ID / Touch ID)
- [x] PWA — installable, offline-ready
- [x] Note-to-note linking (`[[wiki-style]]`)
- [x] Pinned notes
- [x] Custom categories (color + icon)
- [x] Note colors (12 palette)
- [x] Command palette (⌘K)
- [x] Dark / Light mode
- [x] Tag system + smart search
- [x] Markdown preview
- [x] Statistics dashboard
- [x] Brute-force lockout + timing-safe comparison

### 🔜 Planned

- [ ] Note graph view (visualize wiki links)
- [ ] Quick capture — jot a note without unlocking
- [ ] Writing goals — daily word count targets
- [ ] Advanced search syntax (`tag:work date:today`)
- [ ] Note templates
- [ ] Configurable auto-lock timeout
- [ ] Multiple vaults
- [ ] Import from Markdown files

## 🤝 Contributing

Issues and PRs welcome. Please open an issue first for major changes.

## 📄 License

MIT

---

✨ **Built with [Claude](https://claude.ai) — Vibe Coded from scratch.** 🚀
