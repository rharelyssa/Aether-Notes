# ✦ Aether Notes

> Privacy-first, local-only encrypted note taking app. No cloud. No accounts. No tracking. Just you.

![Version](https://img.shields.io/badge/version-1.0.0-5b7cf6)
![License](https://img.shields.io/badge/license-MIT-34c88a)
![PWA](https://img.shields.io/badge/PWA-ready-f0b429)
![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-e05c7a)

## ✨ Features

- **🔐 AES-256-GCM Encryption** — Browser-native Web Crypto API. No external libraries.
- **🔑 PBKDF2 Key Derivation** — 310,000 iterations, SHA-256, unique random salt per save.
- **🛡️ 12-Word Recovery Phrase** — Bitcoin-style seed phrase backup. Never stored, only shown once.
- **🔒 Note-Level Lock** — Individual notes can have their own 4-digit PIN.
- **📌 Pinned Notes** — Pin important notes to the top of your list.
- **🔗 Wiki-Style Linking** — `[[Note Title]]` syntax to link between notes.
- **🏷️ Tags + Smart Search** — Filter by tag, category, or full-text search.
- **📂 Custom Categories** — Create categories with custom colors and icons.
- **✍️ Markdown Preview** — Live rendered preview with XSS-safe HTML sanitization.
- **🎨 Note Colors** — 12-color palette per note.
- **📊 Statistics** — Word count, streaks, category breakdown.
- **⏱️ Auto-lock** — Session clears from memory after 5 minutes idle.
- **🛡️ Brute-Force Protection** — 5 wrong attempts triggers 30-second lockout.
- **📤 Export / Import** — Encrypted `.vault` backup file. Useless without your PIN.
- **⌘K Command Palette** — Keyboard-first navigation.
- **📱 PWA** — Installable as a native app, works fully offline.
- **🌙 Dark / Light Mode** — Saved across sessions.

## 🔐 Security Model

```
PIN (user input)
  ↓
PBKDF2 — 310,000 iter — SHA-256 — random 16-byte salt (per save)
  ↓
AES-256-GCM key (never exported, never stored)
  ↓
AES-GCM encrypt — random 12-byte IV (per save)
  ↓
[V1 header][salt][IV][ciphertext+tag] → Base64 → localStorage
```

**What is stored in localStorage:**
| Key | Content |
|-----|---------|
| `vault_v2_pin` | PBKDF2-derived verifier hash — not the PIN |
| `vault_v2_notes` | AES-256-GCM encrypted notes blob |
| `vault_v2_recovery_blob` | AES-256-GCM encrypted backup (keyed to recovery phrase) |
| `vault_v2_stats` | Plaintext aggregate counts only — no note content |
| `vault_v2_categories` | Custom category definitions — no note content |

**What is never stored:**
- Raw PIN
- Recovery phrase
- Decrypted note content
- Encryption key

**Brute-force protection:**
- 5 wrong attempts → 30-second lockout
- Timing-safe string comparison (constant-time) for PIN verification
- PBKDF2 with 310k iterations makes offline dictionary attacks impractical

> ⚠️ This app protects your notes from casual access and device theft. It is not a replacement for a dedicated password manager. The encryption key derives from a 4-digit PIN — a short PIN is inherently weaker than a long passphrase.

## 🚀 Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/aether-notes.git
cd aether-notes
npm install
npm start
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

## 🏗️ Build & Deploy

```bash
npm run build
# Deploy the /build folder to any static host:
# - Netlify: drag & drop build/ folder at netlify.com
# - GitHub Pages: use the included .github/workflows/deploy.yml
# - Vercel: vercel deploy
```

## 🛣️ Roadmap

### ✅ Shipped
- [x] AES-256-GCM encryption via Web Crypto API
- [x] PBKDF2 key derivation (310k iterations)
- [x] 12-word recovery phrase (BIP-39 style)
- [x] Note-level PIN lock
- [x] Export / Import encrypted `.vault` backup
- [x] PWA — installable, offline-ready
- [x] Note-to-note linking (`[[wiki-style]]`)
- [x] Pinned notes
- [x] Custom categories (color + icon)
- [x] Note colors
- [x] Command palette (⌘K)
- [x] Dark / Light mode
- [x] Tag system + smart search
- [x] Markdown preview (XSS-safe)
- [x] Statistics dashboard
- [x] Brute-force lockout
- [x] Timing-safe PIN comparison

### 🔜 Planned
- [ ] Biometric unlock (WebAuthn / Face ID / Touch ID)
- [ ] Note graph view (visualize wiki links)
- [ ] Quick capture — jot a note without unlocking vault
- [ ] Advanced search syntax (`tag:work date:today`)
- [ ] Note templates
- [ ] Configurable auto-lock timeout
- [ ] Multiple vaults
- [ ] Import from Markdown files

## 🤝 Contributing

Issues and PRs welcome. Please open an issue first for major changes.

## 📄 License

MIT

-----

✨ **Built entirely with "Vibe Coding" principles, powered by Claude.** 🚀
