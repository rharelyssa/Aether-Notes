# ✦ Aether Notes

> Privacy-first, local-only encrypted note taking app. No cloud. No accounts. No tracking. Just you.

[![Version](https://img.shields.io/badge/version-1.1.0-5b7cf6)](https://github.com/rharelyssa/Aether-Notes)
[![License](https://img.shields.io/badge/license-MIT-34c88a)](https://github.com/rharelyssa/Aether-Notes/blob/main/LICENSE)
[![PWA](https://img.shields.io/badge/PWA-ready-f0b429)](https://github.com/rharelyssa/Aether-Notes)
[![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-e05c7a)](https://github.com/rharelyssa/Aether-Notes)
[![Built with Claude](https://img.shields.io/badge/built%20with-Claude-7c6af7)](https://claude.ai)

## ✨ Features

- **🔐 AES-256-GCM Encryption** — Browser-native Web Crypto API. Zero external crypto libraries.
- **🔑 PBKDF2 Key Derivation** — 310,000 iterations, SHA-256, unique random salt per save.
- **🛡️ 12-Word Recovery Phrase** — Bitcoin-style seed phrase. Never stored, shown once only.
- **🔒 Note-Level Lock** — Individual notes can have their own PIN.
- **🔐 Passphrase Mode** — Optional long passphrase instead of 4-digit PIN. Entropy meter included.
- **🪪 Biometric Unlock** — WebAuthn (Face ID / Touch ID) for quick access. Encryption unchanged.
- **🔄 Security Migration** — Switch between PIN and passphrase. Re-encrypts all data in place.
- **📌 Pinned Notes** — Pin important notes to the top of your list.
- **🔗 Wiki-Style Linking** — `[[Note Title]]` syntax. Click to navigate between notes.
- **🏷️ Tags + Smart Search** — Filter by tag, category, or full-text search.
- **📂 Custom Categories** — Create categories with custom colors and icons.
- **✍️ Markdown Preview** — Live rendered preview with XSS-safe sanitization.
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
[V1][salt][IV][ciphertext+GCM tag] → Base64 → localStorage
```

### What is stored in localStorage

| Key | Content |
|-----|---------|
| `vault_v2_pin` | PBKDF2-derived verifier hash — not the raw secret |
| `vault_v2_notes` | AES-256-GCM encrypted notes blob |
| `vault_v2_recovery_blob` | AES-256-GCM blob keyed to recovery phrase |
| `vault_v2_config` | `{ authMode: "pin" \| "passphrase" }` — no sensitive data |
| `vault_v2_stats` | Plaintext aggregate counts only |
| `vault_v2_categories` | Custom category definitions |

### What is NEVER stored

- Raw PIN or passphrase
- Recovery phrase (shown once, then gone)
- Derived encryption key
- Decrypted note content

### Passphrase vs PIN

| | PIN | Passphrase |
|---|---|---|
| Length | 4 digits | 8+ chars (any UTF-8) |
| Entropy | ~13 bits | 60–100+ bits |
| Recommended | Quick testing | Production use |
| Crypto pipeline | Identical | Identical |

The crypto pipeline is the same for both — only the input string changes.

### Biometric (WebAuthn)

Biometric does **not** replace encryption. It works like this:

```
Registration:
  sessionSecret → AES-256-GCM (keyed to WebAuthn credentialId) → SK_BIO_BLOB

Unlock:
  WebAuthn assertion → decrypt SK_BIO_BLOB → sessionSecret → open vault
```

If the device is lost or biometric is removed, the vault still requires the PIN/passphrase.

### Brute-force protection

- 5 wrong attempts → 30-second lockout
- Timing-safe comparison (constant-time) prevents timing attacks
- PBKDF2 310k iterations makes offline attacks impractical

> ⚠️ This app protects notes from casual access and device theft. It is not a replacement for a dedicated password manager.

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

Deploy the `/build` folder to any static host:

- **Netlify** — drag & drop `build/` at netlify.com
- **GitHub Pages** — push `build/` to `gh-pages` branch  
- **Vercel** — `vercel deploy`

## ⚙️ Settings

Access via the **⚙️** button in the top bar:

| Section | What you can do |
|---------|----------------|
| 🔑 Recovery Phrase | View or regenerate your 12-word backup |
| 🪪 Biometric | Register / remove Face ID or fingerprint |
| 🔐 Security Mode | Switch between PIN and passphrase, migrate all data |
| ⚠️ Reset | Wipe all vault data |

## 🛣️ Roadmap

### ✅ Shipped

- [x] AES-256-GCM encryption via Web Crypto API
- [x] PBKDF2 key derivation (310k iterations)
- [x] 12-word recovery phrase (BIP-39 style)
- [x] Note-level PIN lock
- [x] Export / Import encrypted `.vault` backup
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
- [x] Markdown preview (XSS-safe)
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
