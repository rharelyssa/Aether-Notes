# 🔒 Aether Notes

> Privacy-first, local-only encrypted note taking app. No cloud. No accounts. No tracking. Just you.

## ✨ Features

- **🔐 AES-256-GCM Encryption** — Browser-native Web Crypto API. No external libraries.
- **🔑 PBKDF2 Key Derivation** — 310,000 iterations, SHA-256, unique random salt per save.
- **🛡️ PIN Brute-Force Protection** — Exponential backoff after failed attempts (locked out after 5 wrong tries).
- **📵 Zero Network** — No requests, no telemetry, no analytics. Verified by CSP headers.
- **🔒 Note-Level Lock** — Individual notes can have their own PIN.
- **🏷️ Tags + Smart Search** — Filter by tag, category, or full-text.
- **✍️ Markdown Preview** — Live rendered preview with safe HTML sanitization.
- **📊 Statistics** — Word count, streaks, category breakdown.
- **⏱️ Auto-lock** — Session clears from memory after 5 minutes idle.
- **📱 Mobile-first** — Responsive, works in any browser.

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
- `vault_v2_pin` → PBKDF2-derived verifier hash (not the PIN)
- `vault_v2_notes` → AES-256-GCM encrypted blob
- `vault_v2_stats` → Plaintext aggregate counts only (no note content)

**What is never stored:**
- Raw PIN
- Decrypted note content
- Encryption key

**Brute-force protection:**
- Failed PIN attempts trigger exponential backoff: 1s → 2s → 4s → 8s → 16s
- After 5 attempts: 30-second lockout
- Timing-safe comparison for PIN verification

> ⚠️ This app protects your notes from casual access and device theft. It is not a replacement for a dedicated password manager. The encryption key derives from a 4-digit PIN — a short PIN is inherently weaker than a long passphrase.

## 🚀 Getting Started

```bash
git clone https://github.com/YOUR_USERNAME/aether-notes.git
cd aether-notes
npm install
npm start
```

## 🏗️ Build & Deploy

```bash
npm run build
# Deploy the /build folder to any static host:
# - Netlify: drag & drop build/ folder at netlify.com
# - GitHub Pages: push build/ to gh-pages branch
# - Vercel: vercel deploy
```

## 🛣️ Roadmap

- [ ] Export vault as encrypted JSON file
- [ ] Import from encrypted backup
- [ ] PWA / installable app
- [ ] Biometric unlock (WebAuthn)
- [ ] Note-to-note linking ([[wiki-style]])

## 🤝 Contributing

Issues and PRs welcome. Please open an issue first for major changes.

## 📄 License

MIT

---

✨ **Built entirely with "Vibe Coding" principles, powered by Claude.** 🚀
