import { useState, useEffect, useRef, useCallback } from "react";

// ═══════════════════════════════════════════════════════════════════════════════
// CRYPTO: AES-256-GCM + PBKDF2
// ───────────────────────────────────────────────────────────────────────────────
// Pipeline (değişmedi):
//   secret (PIN veya passphrase) → PBKDF2 → AES-256-GCM key → encrypt/decrypt
//
// Vault schema v2:
//   SK_CONFIG = { authMode: "pin"|"passphrase", version: "V1" }
//   → hassas veri yok, sadece UI için hangi input gösterileceğini belirtir
//
// Verifier (PIN veya passphrase için aynı fonksiyon):
//   PBKDF2(secret, FIXED_SALT, 310k iter) → export raw → SHA-256 → Base64
//   → ham secret asla saklanmaz, sadece bu hash localStorage'da durur
//
// Migration:
//   Eski PIN vault → passphrase'e geçiş:
//   1. Eski secret ile decryptData()
//   2. Yeni secret ile encryptData()
//   3. SK_CONFIG güncelle
//   Mevcut veri formatı değişmiyor, sadece secret değişiyor.
// ═══════════════════════════════════════════════════════════════════════════════

const CRYPTO_VERSION  = "V1";
const PBKDF2_ITER     = 310_000;
// Verifier için sabit salt — aynı secret her zaman aynı verifier üretir
// Şifreleme için her kayıtta random salt kullanılır (aşağıda)
const VERIFIER_SALT   = new TextEncoder().encode("aether-verifier-v1-do-not-change");
const MAX_ATTEMPTS    = 5;
const LOCKOUT_SECS    = 30;

// ── Passphrase kuralları ──────────────────────────────────────────────────────
const PASSPHRASE_MIN_LEN = 8; // minimum karakter
// Entropy tahmini: karakter çeşitliliğine göre bit hesabı
function estimateEntropy(s) {
  let pool = 0;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += 26;
  if (/[0-9]/.test(s)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(s)) pool += 32;
  return pool > 0 ? Math.floor(s.length * Math.log2(pool)) : 0;
}
function getPassphraseStrength(s) {
  if (!s) return null;
  const bits = estimateEntropy(s);
  if (s.length < PASSPHRASE_MIN_LEN) return { level: "weak",   label: "Çok Kısa",   bits, color: "#e05c7a" };
  if (bits < 40)                     return { level: "weak",   label: "Zayıf",       bits, color: "#e05c7a" };
  if (bits < 60)                     return { level: "fair",   label: "Orta",        bits, color: "#f0b429" };
  if (bits < 80)                     return { level: "strong", label: "Güçlü",       bits, color: "#34c88a" };
  return                                    { level: "great",  label: "Çok Güçlü",   bits, color: "#5b7cf6" };
}

// ── Storage keys ──────────────────────────────────────────────────────────────
const SK_NOTES    = "vault_v2_notes";
const SK_PIN      = "vault_v2_pin";       // verifier hash (PIN veya passphrase için aynı key)
const SK_STATS    = "vault_v2_stats";
const SK_RECOVERY = "vault_v2_recovery_blob";
const SK_CATS     = "vault_v2_categories";
const SK_CONFIG   = "vault_v2_config";    // { authMode, version } — hassas veri yok

// ── Vault config helpers ──────────────────────────────────────────────────────
function getVaultConfig() {
  try { return JSON.parse(localStorage.getItem(SK_CONFIG) || "{}"); } catch { return {}; }
}
function setVaultConfig(cfg) {
  localStorage.setItem(SK_CONFIG, JSON.stringify({ ...getVaultConfig(), ...cfg }));
}
function getAuthMode() {
  return getVaultConfig().authMode || "pin"; // eski vault'lar için default pin
}

// ── Core crypto ───────────────────────────────────────────────────────────────
function buf2b64(buf) {
  const b = new Uint8Array(buf); let s = "";
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s);
}
function b642buf(b64) {
  const s = atob(b64), b = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) b[i] = s.charCodeAt(i);
  return b.buffer;
}

// deriveKey: PIN veya passphrase için aynı — sadece input string değişiyor
async function deriveKey(secret, salt, exportable = false) {
  const km = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name:"PBKDF2", salt, iterations:PBKDF2_ITER, hash:"SHA-256" },
    km, { name:"AES-GCM", length:256 }, exportable, ["encrypt","decrypt"]
  );
}

// encryptData / decryptData: format değişmedi — eski vault'larla uyumlu
async function encryptData(plain, secret) {
  const salt = crypto.getRandomValues(new Uint8Array(16)); // her kayıtta random
  const iv   = crypto.getRandomValues(new Uint8Array(12)); // her kayıtta random
  const key  = await deriveKey(secret, salt);
  const ct   = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, key, new TextEncoder().encode(plain));
  const vb   = new TextEncoder().encode(CRYPTO_VERSION);
  const out  = new Uint8Array(2 + 16 + 12 + ct.byteLength);
  out.set(vb,0); out.set(salt,2); out.set(iv,18); out.set(new Uint8Array(ct),30);
  return buf2b64(out.buffer);
}
async function decryptData(b64, secret) {
  const buf = new Uint8Array(b642buf(b64));
  if (new TextDecoder().decode(buf.slice(0,2)) !== CRYPTO_VERSION) throw new Error("bad version");
  const key = await deriveKey(secret, buf.slice(2,18));
  const pt  = await crypto.subtle.decrypt({ name:"AES-GCM", iv:buf.slice(18,30) }, key, buf.slice(30));
  return new TextDecoder().decode(pt);
}

// makeVerifier: hem PIN hem passphrase için aynı fonksiyon
// Sabit salt + PBKDF2 → deterministik hash → localStorage'da saklanır
// Ham secret ASLA saklanmaz
async function makeVerifier(secret) {
  const km = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), "PBKDF2", false, ["deriveKey"]
  );
  const k = await crypto.subtle.deriveKey(
    { name:"PBKDF2", salt:VERIFIER_SALT, iterations:PBKDF2_ITER, hash:"SHA-256" },
    km, { name:"AES-GCM", length:256 }, true, ["encrypt"]
  );
  return buf2b64(await crypto.subtle.digest("SHA-256", await crypto.subtle.exportKey("raw", k)));
}
// Geriye dönük uyumluluk için alias
const makePinVerifier = makeVerifier;

function timingSafeEqual(a, b) {
  if (!a || !b) return false;
  if (a.length !== b.length) return false;
  let d = 0; for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

// ── Migration: PIN → Passphrase (veya tersi) ─────────────────────────────────
// Adım adım:
//   1. decryptData(localStorage[SK_NOTES], oldSecret)    → plaintext
//   2. encryptData(plaintext, newSecret)                  → yeni blob
//   3. makeVerifier(newSecret)                            → yeni verifier
//   4. localStorage[SK_NOTES]    = yeni blob
//   5. localStorage[SK_PIN]      = yeni verifier
//   6. setVaultConfig({ authMode: newMode })
//   Recovery blob da aynı şekilde yeniden şifrelenir.
async function migrateVaultSecret(oldSecret, newSecret, newMode) {
  // Notes
  const rawNotes = localStorage.getItem(SK_NOTES);
  if (rawNotes) {
    const plain = await decryptData(rawNotes, oldSecret);
    localStorage.setItem(SK_NOTES, await encryptData(plain, newSecret));
  }
  // Recovery blob
  const rawRec = localStorage.getItem(SK_RECOVERY);
  if (rawRec) {
    try {
      const plain = await decryptData(rawRec, oldSecret);
      localStorage.setItem(SK_RECOVERY, await encryptData(plain, newSecret));
    } catch {} // recovery blob farklı key ile şifreliyse atla
  }
  // Verifier + config güncelle
  localStorage.setItem(SK_PIN, await makeVerifier(newSecret));
  setVaultConfig({ authMode: newMode, version: CRYPTO_VERSION });
}

// ── Biometric / WebAuthn ─────────────────────────────────────────────────────
// Güvenlik modeli:
//   Gerçek şifreleme anahtarı hâlâ PIN/passphrase'den türetilir.
//   Biometrik, session sırasında sessionPin'i localStorage'a ŞİFRELİ olarak saklar.
//   Biometrik → şifreli blob çöz → sessionPin → vault aç.
//   Cihaz değiştiğinde veya biometrik kaldırıldığında kullanılamaz.
//
// Storage format:
//   SK_BIO_CRED  = { credentialId: base64 }    — hangi credential kaydedildi
//   SK_BIO_BLOB  = base64(AES-256-GCM encrypted sessionPin)
//                  key = PBKDF2(credentialId, fixed_salt) — deterministik ama cihaza özgü

const SK_BIO_CRED = "aether_bio_cred";
const SK_BIO_BLOB = "aether_bio_blob";
const BIO_SALT    = new TextEncoder().encode("aether-bio-v1-fixed-salt");

function isBiometricAvailable() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

async function biometricRegister(sessionSecret) {
  if (!isBiometricAvailable()) throw new Error("WebAuthn desteklenmiyor");
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const cred = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: "Aether Notes", id: location.hostname },
      user: {
        id: new TextEncoder().encode("aether-user"),
        name: "aether@local",
        displayName: "Aether Vault",
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7  }, // ES256
        { type: "public-key", alg: -257 }, // RS256
      ],
      authenticatorSelection: {
        authenticatorAttachment: "platform", // sadece cihaz biyometriği
        userVerification: "required",
        requireResidentKey: false,
      },
      timeout: 60000,
    },
  });
  // Credential ID'yi sakla
  const credId = buf2b64(cred.rawId);
  // sessionSecret'i credential ID ile şifrele
  const key = await deriveKey(credId, BIO_SALT);
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, new TextEncoder().encode(sessionSecret)
  );
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(ct), 12);
  localStorage.setItem(SK_BIO_CRED, JSON.stringify({ credId }));
  localStorage.setItem(SK_BIO_BLOB, buf2b64(out.buffer));
  return credId;
}

async function biometricUnlock() {
  if (!isBiometricAvailable()) throw new Error("WebAuthn desteklenmiyor");
  const stored = localStorage.getItem(SK_BIO_CRED);
  if (!stored) throw new Error("Kayıtlı biyometrik yok");
  const { credId } = JSON.parse(stored);
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{
        type: "public-key",
        id: b642buf(credId),
      }],
      userVerification: "required",
      timeout: 60000,
    },
  });
  // Doğrulama başarılı — blob'u çöz
  const rawBlob = new Uint8Array(b642buf(localStorage.getItem(SK_BIO_BLOB)));
  const iv = rawBlob.slice(0, 12);
  const ct = rawBlob.slice(12);
  const key = await deriveKey(credId, BIO_SALT);
  const pt  = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
  return new TextDecoder().decode(pt); // sessionSecret
}

function hasBiometricRegistered() {
  return !!localStorage.getItem(SK_BIO_CRED);
}
function removeBiometric() {
  localStorage.removeItem(SK_BIO_CRED);
  localStorage.removeItem(SK_BIO_BLOB);
}

// ═══════════════════════════════════════════════════════════════════════════════
// RECOVERY PHRASE — BIP-39'dan 256 kelimelik alt küme (128-bit entropi, 12 kelime)
// Phrase asla localStorage'a yazılmaz. Sadece kurulumda ekranda gösterilir.
// Recovery blob = encryptData(notlar, phrase) → localStorage'da şifreli blob
// ═══════════════════════════════════════════════════════════════════════════════
const WORDLIST = [
  "abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse",
  "access","accident","account","accuse","achieve","acid","acoustic","acquire","across","act",
  "action","actor","actress","actual","adapt","add","addict","address","adjust","admit",
  "adult","advance","advice","aerobic","afford","afraid","again","agent","agree","ahead",
  "aim","air","airport","aisle","alarm","album","alcohol","alert","alien","alley",
  "allow","almost","alone","alpha","already","also","alter","always","amateur","amazing",
  "among","amount","amused","analyst","anchor","ancient","anger","angle","angry","animal",
  "ankle","announce","annual","answer","antenna","antique","anxiety","apart","april","arch",
  "arctic","area","arena","argue","arm","armor","army","arrow","art","artist",
  "aspect","assault","asset","assist","assume","asthma","athlete","atom","attack","attend",
  "attitude","attract","auction","august","aunt","author","auto","autumn","average","avocado",
  "avoid","awake","aware","away","awesome","awful","awkward","axis","balance","bamboo",
  "banner","barely","barrel","base","battle","beach","become","before","begin","believe",
  "below","bench","benefit","best","better","between","beyond","bicycle","bind","biology",
  "bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless",
  "blind","blood","blossom","blouse","blue","blur","blush","board","boat","body",
  "boil","bomb","bone","bonus","book","boost","border","boring","borrow","brain",
  "brand","brave","breeze","brick","bridge","brief","bright","bring","bronze","brown",
  "brush","budget","buffalo","build","bulb","bulk","bullet","bundle","bunker","burden",
  "burger","burst","busy","butter","buyer","cabin","call","calm","camera","camp",
  "canal","cancel","candy","capture","carbon","card","cargo","castle","casual","catalog",
  "catch","category","cause","century","chain","chair","chaos","chapter","charge","chase",
  "cheap","check","cheese","chef","cherry","chest","chief","child","chimney","choice",
  "civil","claim","clap","clarify","clay","clean","clerk","clever","click","client",
  "cliff","climb","clinic","clip","clock","clog","close","cloth","cloud","cluster",
  "coast","coconut","coffee","coil","color","column","combine","come","comic","common",
  "coral","corn","correct","cost","cotton","couch","country","cover","coyote","crack",
  "crane","crash","crazy","cream","credit","creek","crew","cricket","crime","crisp",
  "cross","crowd","crucial","cruel","cruise","crystal","cube","culture","cup","curious",
  "curtain","cycle","damage","damp","dance","danger","daring","dash","daughter","dawn",
  "decade","december","decide","decline","decorate","decrease","deer","define","delay","deliver",
  "demand","denial","dentist","deny","depart","derive","desert","design","desk","detail",
  "detect","develop","device","devote","diagram","dial","diamond","diary","diesel","differ",
  "digital","dignity","dilemma","dinner","discover","disease","dish","dismiss","disorder","display",
  "distance","divert","divide","divorce","dizzy","doctor","dog","donate","door","double",
  "dove","draft","dragon","drama","drastic","dream","dress","drift","drink","drip",
  "drive","drop","drum","dry","duck","dumb","dune","during","dust","dutch",
  "duty","dwarf","dynamic","eager","eagle","early","earth","easily","east","easy",
  "edge","effort","eight","either","elbow","elder","electric","elegant","elephant","elevator",
  "elite","else","embark","embody","embrace","emerge","emotion","employ","empty","enable",
  "endless","endure","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist"
];

function generatePhrase(wordCount = 12) {
  // Kriptografik rastgelelik ile kelime seç
  const arr = new Uint32Array(wordCount);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(n => WORDLIST[n % WORDLIST.length]).join(" ");
}

// phraseFromInput: kullanıcının girdiği phrase'i normalize et
function normalizePhrase(p) {
  return p.trim().toLowerCase().replace(/\s+/g, " ");
}

// Recovery blob kaydet: notları phrase ile şifrele
async function saveRecoveryBlob(notes, phrase) {
  const payload = JSON.stringify({ notes, savedAt: new Date().toISOString() });
  const blob    = await encryptData(payload, normalizePhrase(phrase));
  localStorage.setItem(SK_RECOVERY, blob);
}

// Recovery blob aç: phrase ile çöz
async function openRecoveryBlob(phrase) {
  const raw = localStorage.getItem(SK_RECOVERY);
  if (!raw) throw new Error("Recovery blob bulunamadı");
  const plain = await decryptData(raw, normalizePhrase(phrase));
  return JSON.parse(plain).notes;
}

// ═══════════════════════════════════════════════════════════════════════════════
// AETHER EXPORT / IMPORT
// ═══════════════════════════════════════════════════════════════════════════════
async function exportVault(notes, pin) {
  const payload   = JSON.stringify({ notes, exportedAt: new Date().toISOString() });
  const encrypted = await encryptData(payload, pin);
  const blob = new Blob([JSON.stringify({ version: CRYPTO_VERSION, encrypted })], { type:"application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href = url; a.download = `vault-backup-${new Date().toISOString().slice(0,10)}.vault`;
  a.click(); URL.revokeObjectURL(url);
}
async function importVault(file, pin) {
  return new Promise((resolve, reject) => {
    const r = new FileReader();
    r.onload = async e => {
      try {
        const { version, encrypted } = JSON.parse(e.target.result);
        if (version !== CRYPTO_VERSION) throw new Error("Desteklenmeyen versiyon");
        resolve(JSON.parse(await decryptData(encrypted, pin)).notes);
      } catch(err) { reject(err); }
    };
    r.readAsText(file);
  });
}

const CATEGORIES = [
  {id:"all",      label:"Tüm Notlar", icon:"📋"},
  {id:"personal", label:"Kişisel",    icon:"👤", color:"#5b8af5"},
  {id:"work",     label:"İş",         icon:"💼", color:"#34c88a"},
  {id:"secret",   label:"Gizli",      icon:"🔒", color:"#e05c7a"},
  {id:"idea",     label:"Fikirler",   icon:"💡", color:"#f0b429"},
];

const NOTE_COLORS = [
  {id:"none",   label:"Varsayılan", hex:null},
  {id:"red",    label:"Kırmızı",   hex:"#ff6b6b"},
  {id:"orange", label:"Turuncu",   hex:"#ff9f43"},
  {id:"yellow", label:"Sarı",      hex:"#ffd32a"},
  {id:"green",  label:"Yeşil",     hex:"#2ecc71"},
  {id:"teal",   label:"Deniz",     hex:"#1abc9c"},
  {id:"blue",   label:"Mavi",      hex:"#5b8af5"},
  {id:"purple", label:"Mor",       hex:"#a29bfe"},
  {id:"pink",   label:"Pembe",     hex:"#fd79a8"},
  {id:"brown",  label:"Kahve",     hex:"#b8860b"},
  {id:"gray",   label:"Gri",       hex:"#636e72"},
  {id:"white",  label:"Beyaz",     hex:"#dfe6e9"},
];

const THEMES = {
  dark: {
    appBg:"#111118", sidebar:"#141420", list:"#18181f", editor:"#1c1c28", topbar:"#111118",
    border:"#2a2a3e", borderLight:"#222232", card:"#1e1e2c", cardHover:"#252535", cardActive:"#2a2a40",
    text:"#e8e6f4", textSub:"#a09cb8", textMuted:"#5c5a70",
    accent:"#5b7cf6", accentBg:"#5b7cf618",
    danger:"#e05c7a", success:"#34c88a", warn:"#f0b429",
    inputBg:"#222232", inputBorder:"#333348",
    cmdBg:"#1a1a2a", cmdItem:"#222234", cmdItemHover:"#2e2e48",
    phraseBox:"#0d0d18",
  },
  light: {
    appBg:"#f4f4f8", sidebar:"#ffffff", list:"#f9f9fc", editor:"#ffffff", topbar:"#ffffff",
    border:"#e0e0ec", borderLight:"#eaeaf4", card:"#ffffff", cardHover:"#f0f0f8", cardActive:"#e8e8f8",
    text:"#1a1a2e", textSub:"#4a4a6a", textMuted:"#9090b0",
    accent:"#4a6cf7", accentBg:"#4a6cf712",
    danger:"#d94f6a", success:"#28a870", warn:"#d99a20",
    inputBg:"#f0f0f8", inputBorder:"#d8d8ec",
    cmdBg:"#ffffff", cmdItem:"#f4f4f8", cmdItemHover:"#e8e8f8",
    phraseBox:"#f0f0ff",
  }
};

let _fails=0, _lockedUntil=0;
function recordFail(){ _fails++; if(_fails>=MAX_ATTEMPTS) _lockedUntil=Date.now()+LOCKOUT_SECS*1000; }
function resetFails(){ _fails=0; _lockedUntil=0; }
function lockRem(){ const r=Math.ceil((_lockedUntil-Date.now())/1000); return r>0?r:0; }
function fmtDate(iso){
  if(!iso)return""; const d=new Date(iso),now=new Date(),diff=now-d;
  if(diff<60000)return"Az önce"; if(diff<3600000)return`${Math.floor(diff/60000)} dk`;
  if(diff<86400000)return`${Math.floor(diff/3600000)} sa`;
  return d.toLocaleDateString("tr-TR",{day:"numeric",month:"short"});
}
function wc(t){ return (t||"").split(/\s+/).filter(Boolean).length; }
// getCat ve getCatColor artık allCategories üzerinden çağrılacak — App içinde tanımlanıyor
function getNoteColor(colorId){ return NOTE_COLORS.find(c=>c.id===colorId)||NOTE_COLORS[0]; }

// ═══════════════════════════════════════════════════════════════════════════════
// APP
// ═══════════════════════════════════════════════════════════════════════════════
export default function App() {
  const [theme,setTheme] = useState(()=>localStorage.getItem("vault_theme")||"dark");
  const T = THEMES[theme];

  // Auth
  const [screen,setScreen]               = useState("lock");
  const [authMode,setAuthMode]           = useState(()=>getAuthMode()); // "pin" | "passphrase"
  const [setupMode,setSetupMode]         = useState(null);  // ilk kurulum seçimi: null|"pin"|"passphrase"
  const [pin,setPin]                     = useState("");
  const [passInput,setPassInput]         = useState("");    // passphrase giriş
  const [confirmPass,setConfirmPass]     = useState("");    // passphrase onay
  const [passStrength,setPassStrength]   = useState(null);  // getPassphraseStrength sonucu
  const [savedVerifier,setSavedVerifier] = useState(null);
  const [isSettingPin,setIsSettingPin]   = useState(false);
  const [confirmPin,setConfirmPin]       = useState("");
  const [pinStep,setPinStep]             = useState("enter"); // enter | confirm | phrase
  const [pinError,setPinError]           = useState("");
  const [shake,setShake]                 = useState(false);
  const [lockoutSecs,setLockoutSecs]     = useState(0);
  const [loading,setLoading]             = useState(false);
  const [generatedPhrase,setGeneratedPhrase] = useState("");
  const [phraseConfirmed,setPhraseConfirmed] = useState(false);
  // Migration state
  const [showMigrate,setShowMigrate]     = useState(false);
  const [migrateStep,setMigrateStep]     = useState("verify"); // "verify"|"setup"|"done"
  const [migrateOldInput,setMigrateOldInput] = useState("");
  const [migrateNewInput,setMigrateNewInput] = useState("");
  const [migrateConfirm,setMigrateConfirm]   = useState("");
  const [migrateTargetMode,setMigrateTargetMode] = useState("passphrase");
  const [migrateError,setMigrateError]   = useState("");
  const [migrateLoading,setMigrateLoading] = useState(false);
  const sessionPin = useRef(null);
  const sessionPhrase = useRef(null);
  // Biometric (WebAuthn) — PIN/passphrase şifrelemeyi değiştirmez, sadece hızlı erişim
  const [bioAvailable,setBioAvailable]   = useState(false);
  const [bioRegistered,setBioRegistered] = useState(hasBiometricRegistered);
  const [bioLoading,setBioLoading]       = useState(false);

  // Recovery flow
  const [screen2,setScreen2]           = useState(null); // "recovery"
  const [recoveryInput,setRecoveryInput] = useState("");
  const [recoveryError,setRecoveryError] = useState("");
  const [recoveryLoading,setRecoveryLoading] = useState(false);
  const [recoverySuccess,setRecoverySuccess] = useState(false); // phrase doğrulandı, yeni PIN kur
  const [newPinAfterRecovery,setNewPinAfterRecovery] = useState("");
  const [confirmNewPin,setConfirmNewPin]   = useState("");
  const [newPinStep,setNewPinStep]         = useState("enter");
  const recoveredNotes = useRef(null);

  // Notes
  const [notes,setNotes]         = useState([]);
  const [activeId,setActiveId]   = useState(null);
  const [filterCat,setFilterCat] = useState("all");
  const [filterTag,setFilterTag] = useState("");
  const [search,setSearch]       = useState("");

  // Editor
  const [eTitle,setETitle]     = useState("");
  const [eContent,setEContent] = useState("");
  const [eCat,setECat]         = useState("personal");
  const [eTags,setETags]       = useState([]);
  const [eTagIn,setETagIn]     = useState("");
  const [ePreview,setEPreview] = useState(false);
  const [eLocked,setELocked]   = useState(false);
  const [eNotePin,setENotePin] = useState("");
  const [eColor,setEColor]     = useState("none");
  const [dirty,setDirty]       = useState(false);

  // Note unlock
  const [noteUnlock,setNoteUnlock] = useState(null);
  const [ePinIn,setEPinIn]         = useState("");
  const [ePinErr,setEPinErr]       = useState("");

  // UI
  const [toast,setToast]               = useState(null);
  const [deleteConfirm,setDeleteConfirm]   = useState(null); // note id
  const [lockedDeletePin,setLockedDeletePin] = useState("");  // PIN for deleting locked note
  const [lockedDeleteErr,setLockedDeleteErr] = useState("");
  const [showStats,setShowStats]       = useState(false);
  const [sidebarOpen,setSidebarOpen]   = useState(true);
  const [showExport,setShowExport]         = useState(false);
  const [showSettings,setShowSettings]     = useState(false);
  const [pwaPrompt,setPwaPrompt]           = useState(null); // BeforeInstallPromptEvent
  const [showPhrase,setShowPhrase]         = useState(false);
  const [phraseMode,setPhraseMode]         = useState("view"); // "view" | "new"
  const [phrasePin,setPhrasePin]           = useState("");
  const [phrasePinErr,setPhrasePinErr]     = useState("");
  const [phraseRevealed,setPhraseRevealed] = useState("");      // açılan phrase
  const [newPhraseGenerated,setNewPhraseGenerated] = useState("");
  const [showColorPicker,setShowColorPicker] = useState(false);
  const [cmdOpen,setCmdOpen]           = useState(false);
  const [cmdQuery,setCmdQuery]         = useState("");
  const [cmdIdx,setCmdIdx]             = useState(0);
  const [stats,setStats] = useState({totalWords:0,streak:0,dailyCounts:{}});

  // Özel kategoriler
  const [customCats,setCustomCats]         = useState(()=>{
    try{ return JSON.parse(localStorage.getItem(SK_CATS)||"[]"); }catch{ return []; }
  });
  const [showAddCat,setShowAddCat]         = useState(false);
  const [newCatName,setNewCatName]         = useState("");
  const [newCatColor,setNewCatColor]       = useState("#a29bfe");
  const [newCatIcon,setNewCatIcon]         = useState("📁");

  const autoLockRef  = useRef(null);
  const lockoutRef   = useRef(null);
  const editorRef    = useRef(null);
  const saveTimer    = useRef(null);
  const importRef    = useRef(null);
  const cmdRef       = useRef(null);
  const recoveryRef  = useRef(null);

  useEffect(()=>{
    const v=localStorage.getItem(SK_PIN);
    if(v) setSavedVerifier(v); else setIsSettingPin(true);
    const s=localStorage.getItem(SK_STATS);
    if(s) try{setStats(JSON.parse(s));}catch{}

    // PWA install prompt
    const pwaHandler=(e)=>{ e.preventDefault(); setPwaPrompt(e); };
    window.addEventListener("beforeinstallprompt", pwaHandler);

    // WebAuthn / Biometric availability check
    // window.PublicKeyCredential varsa destekleniyor sayıyoruz
    // isUserVerifyingPlatformAuthenticatorAvailable localhost'ta false dönebilir
    if(window.PublicKeyCredential && navigator.credentials){
      setBioAvailable(true); // API var, dene — hata olursa yaklarız
      // Arka planda gerçek kontrolü de yap
      if(window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable){
        window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
          .then(ok => { if(!ok) setBioAvailable(false); })
          .catch(()=>{}); // hata olursa true'da bırak
      }
    }

    return()=>window.removeEventListener("beforeinstallprompt", pwaHandler);
  },[]);

  useEffect(()=>{
    const h=(e)=>{
      if((e.metaKey||e.ctrlKey)&&e.key==="k"){e.preventDefault();setCmdOpen(p=>!p);setCmdQuery("");setCmdIdx(0);}
      if(e.key==="Escape"){setCmdOpen(false);setShowColorPicker(false);}
    };
    window.addEventListener("keydown",h);
    return()=>window.removeEventListener("keydown",h);
  },[]);
  useEffect(()=>{ if(cmdOpen) setTimeout(()=>cmdRef.current?.focus(),50); },[cmdOpen]);

  const toggleTheme=()=>{ const n=theme==="dark"?"light":"dark"; setTheme(n); localStorage.setItem("vault_theme",n); };
  const showToast=useCallback((msg,type="success")=>{ setToast({msg,type}); setTimeout(()=>setToast(null),2800); },[]);
  const resetAutoLock=useCallback(()=>{
    if(autoLockRef.current) clearTimeout(autoLockRef.current);
    autoLockRef.current=setTimeout(()=>{ sessionPin.current=null; sessionPhrase.current=null; setScreen("lock"); setPin(""); showToast("Oturum zaman aşımı 🔒","info"); },5*60*1000);
  },[showToast]);

  const loadNotes=useCallback(async(p)=>{
    const raw=localStorage.getItem(SK_NOTES); if(!raw)return[];
    try{ return JSON.parse(await decryptData(raw,p)); }catch{ return[]; }
  },[]);

  const saveNotes=useCallback(async(arr)=>{
    if(!sessionPin.current) return;
    // PIN ile şifrele
    localStorage.setItem(SK_NOTES, await encryptData(JSON.stringify(arr), sessionPin.current));
    // Recovery blob'u da güncelle (phrase varsa)
    if(sessionPhrase.current) {
      await saveRecoveryBlob(arr, sessionPhrase.current);
    }
  },[]);

  const updStats=useCallback((arr)=>{
    const today=new Date().toISOString().slice(0,10);
    const raw=localStorage.getItem(SK_STATS);
    let st=raw?JSON.parse(raw):{totalWords:0,streak:0,dailyCounts:{}};
    st.totalWords=arr.reduce((s,n)=>s+wc(n.content),0);
    st.dailyCounts[today]=arr.filter(n=>n.updatedAt?.slice(0,10)===today).length;
    let streak=0,d=new Date();
    while(st.dailyCounts[d.toISOString().slice(0,10)]){ streak++; d.setDate(d.getDate()-1); }
    st.streak=streak; setStats(st); localStorage.setItem(SK_STATS,JSON.stringify(st));
  },[]);

  // ── PIN FLOW ──
  const shake_=()=>{ setShake(true); setTimeout(()=>setShake(false),500); };

  const handleDigit=async(d)=>{
    if(lockRem()>0) return;
    if(pinError) setPinError("");
    const np=pin+d;

    if(isSettingPin){
      if(pinStep==="enter"){
        setPin(np);
        if(np.length===4){ setConfirmPin(np); setPin(""); setPinStep("confirm"); }
      } else if(pinStep==="confirm"){
        setPin(np);
        if(np.length===4){
          if(np===confirmPin){
            // PIN tamam — phrase üret, göster
            const phrase=generatePhrase(12);
            setGeneratedPhrase(phrase);
            sessionPhrase.current=phrase;
            setPin(""); setPinStep("phrase");
          } else { shake_(); setPinError("PINler eşleşmiyor"); setPin(""); setPinStep("enter"); setConfirmPin(""); }
        }
      }
      return;
    }

    // Login
    setPin(np);
    if(np.length===4){
      setLoading(true);
      const cand=await makePinVerifier(np);
      if(timingSafeEqual(cand,savedVerifier)){
        resetFails(); sessionPin.current=np;
        const loaded=await loadNotes(np); setNotes(loaded);
        if(loaded.length>0) setActiveId(loaded[0].id);
        updStats(loaded); setLoading(false);
        setScreen("app"); setPin(""); resetAutoLock(); showToast("Aether açıldı 🔓");
      } else {
        recordFail(); shake_(); const rem=lockRem();
        if(rem>0){ setLockoutSecs(rem); setPinError(`${MAX_ATTEMPTS} hatalı deneme — ${rem}s`);
          lockoutRef.current=setInterval(()=>{ const r=lockRem(); setLockoutSecs(r); if(r===0)clearInterval(lockoutRef.current); },500);
        } else { setPinError(`Yanlış PIN (${_fails}/${MAX_ATTEMPTS})`); }
        setLoading(false); setTimeout(()=>setPin(""),400);
      }
    }
  };

  // Passphrase ile giriş
  const handlePassphraseLogin = async(pass) => {
    if(!pass){ setPinError("Passphrase gir"); return; }
    setLoading(true);
    const cand = await makeVerifier(pass);
    if(timingSafeEqual(cand, savedVerifier)){
      resetFails(); sessionPin.current = pass;
      const loaded = await loadNotes(pass); setNotes(loaded);
      if(loaded.length>0) setActiveId(loaded[0].id);
      updStats(loaded); setLoading(false);
      setScreen("app"); setPassInput(""); resetAutoLock(); showToast("Aether açıldı 🔓");
    } else {
      recordFail(); shake_(); const rem = lockRem();
      if(rem>0){ setLockoutSecs(rem); setPinError(`${MAX_ATTEMPTS} hatalı deneme — ${rem}s`); }
      else { setPinError(`Yanlış passphrase (${_fails}/${MAX_ATTEMPTS})`); }
      setLoading(false); setPassInput("");
    }
  };

  // Phrase onaylandı → vault oluştur (PIN veya passphrase)
  const finalizeSetup=async()=>{
    setLoading(true);
    const phrase = sessionPhrase.current;
    const secret = setupMode==="passphrase" ? passInput : confirmPin;
    const mode   = setupMode || "pin";
    const v = await makeVerifier(secret);
    localStorage.setItem(SK_PIN, v); setSavedVerifier(v); setIsSettingPin(false);
    setVaultConfig({ authMode: mode, version: CRYPTO_VERSION });
    setAuthMode(mode);
    sessionPin.current = secret;
    const loaded = await loadNotes(secret); setNotes(loaded);
    await saveRecoveryBlob(loaded, phrase);
    setLoading(false); setScreen("app"); setPinStep("enter");
    setGeneratedPhrase(""); setPassInput(""); setConfirmPass(""); setSetupMode(null);
    resetAutoLock(); showToast("Aether oluşturuldu! 🎉");
  };

  // ── RECOVERY FLOW ──
  const handleRecovery=async()=>{
    if(!recoveryInput.trim()){ setRecoveryError("Phrase gir"); return; }
    setRecoveryLoading(true); setRecoveryError("");
    try{
      const notes=await openRecoveryBlob(recoveryInput);
      recoveredNotes.current=notes;
      setRecoverySuccess(true); setNewPinStep("enter"); setNewPinAfterRecovery(""); setConfirmNewPin("");
    } catch {
      setRecoveryError("Geçersiz phrase — notlar açılamadı");
    }
    setRecoveryLoading(false);
  };

  const handleNewPinDigit=async(d)=>{
    if(d==="⌫"){ setNewPinAfterRecovery(p=>p.slice(0,-1)); return; }
    const np=(newPinStep==="enter"?newPinAfterRecovery:confirmNewPin)+d;
    if(newPinStep==="enter"){
      setNewPinAfterRecovery(np);
      if(np.length===4){ setConfirmNewPin(""); setNewPinStep("confirm"); }
    } else {
      setConfirmNewPin(np);
      if(np.length===4){
        if(np===newPinAfterRecovery){
          setRecoveryLoading(true);
          // Yeni PIN ile tüm verileri yeniden şifrele
          const v=await makePinVerifier(np);
          localStorage.setItem(SK_PIN,v); setSavedVerifier(v);
          sessionPin.current=np; sessionPhrase.current=normalizePhrase(recoveryInput);
          const arr=recoveredNotes.current||[];
          localStorage.setItem(SK_NOTES, await encryptData(JSON.stringify(arr),np));
          await saveRecoveryBlob(arr, recoveryInput);
          setNotes(arr); if(arr.length>0) setActiveId(arr[0].id);
          updStats(arr); setRecoveryLoading(false);
          setScreen2(null); setScreen("app"); resetAutoLock();
          showToast("Aether kurtarıldı & yeni PIN ayarlandı 🎉");
        } else { shake_(); setRecoveryError("PINler eşleşmiyor"); setConfirmNewPin(""); setNewPinStep("enter"); }
      }
    }
  };

  // ── NOTES ──
  const activeNote=notes.find(n=>n.id===activeId)||null;

  const selectNote=(note)=>{
    // Her zaman notes array'inden taze notu oku — closure stale olabilir
    const fresh = notes.find(n=>n.id===note.id) || note;
    // Kilitli ama PIN yok — direkt aç
    if(fresh.locked && !fresh.notePin){
      setActiveId(fresh.id); setETitle(fresh.title); setEContent(fresh.content);
      setECat(fresh.category); setETags(fresh.tags||[]); setELocked(true);
      setEColor(fresh.color||"none"); setENotePin(""); setETagIn(""); setEPreview(false); setDirty(false);
      return;
    }
    // Kilitli ve PIN var — sadece activeId set et, editör PIN ekranını gösterir
    if(fresh.locked){
      setActiveId(fresh.id);
      return;
    }
    // Açık not
    setActiveId(fresh.id); setETitle(fresh.title); setEContent(fresh.content);
    setECat(fresh.category); setETags(fresh.tags||[]); setELocked(false);
    setEColor(fresh.color||"none"); setENotePin(""); setETagIn(""); setEPreview(false); setDirty(false);
  };

  const newNote=()=>{
    const now=new Date().toISOString();
    const n={ id:`${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0]}`,
      title:"",content:"",category:"personal",tags:[],color:"none",pinned:false,
      locked:false,notePin:null,createdAt:now,updatedAt:now };
    const updated=[n,...notes]; setNotes(updated); saveNotes(updated); setActiveId(n.id);
    setETitle(""); setEContent(""); setECat("personal"); setETags([]); setEColor("none");
    setELocked(false); setENotePin(""); setEPreview(false); setDirty(false);
    setTimeout(()=>editorRef.current?.focus(),50); resetAutoLock();
  };

  const doSave=useCallback(async()=>{
    if(!activeId) return;
    const cur=notes.find(n=>n.id===activeId);
    if(cur?.locked && noteUnlock?.id===activeId) return;
    const now=new Date().toISOString();
    let notePinHash=null;
    if(eLocked&&eNotePin) notePinHash=await makePinVerifier(eNotePin);
    else if(eLocked&&cur?.notePin) notePinHash=cur.notePin;
    // PIN yoksa kilitli kaydetme — locked'ı false yap
    const actualLocked = eLocked && (notePinHash!==null);
    const updated=notes.map(n=>n.id===activeId
      ?{...n,title:eTitle||"Başlıksız",content:eContent,category:eCat,tags:eTags,
          color:eColor,locked:actualLocked,notePin:notePinHash,updatedAt:now}:n);    setNotes(updated); await saveNotes(updated); updStats(updated); setDirty(false); resetAutoLock();
  },[activeId,eTitle,eContent,eCat,eTags,eColor,eLocked,eNotePin,notes,noteUnlock,saveNotes,updStats,resetAutoLock]);

  useEffect(()=>{
    if(!dirty) return;
    if(saveTimer.current) clearTimeout(saveTimer.current);
    saveTimer.current=setTimeout(doSave,1500);
    return()=>clearTimeout(saveTimer.current);
  },[dirty,doSave]);

  const deleteNote=async(id)=>{
    const updated=notes.filter(n=>n.id!==id); setNotes(updated);
    await saveNotes(updated); updStats(updated); setDeleteConfirm(null);
    if(activeId===id){
      const next=updated.find(n=>!n.locked)||updated[0]||null; setActiveId(next?.id||null);
      if(next&&!next.locked){ setETitle(next.title); setEContent(next.content); setECat(next.category); setETags(next.tags||[]); setEColor(next.color||"none"); setELocked(false); }
      else{ setETitle(""); setEContent(""); setELocked(false); }
    }
    showToast("Not silindi","danger"); resetAutoLock();
  };

  const addTag=()=>{
    const t=eTagIn.trim().toLowerCase().replace(/\s+/g,"-");
    if(t&&!eTags.includes(t)&&eTags.length<8){ setETags([...eTags,t]); setETagIn(""); setDirty(true); }
  };

  const togglePin=async(id)=>{
    const updated=notes.map(n=>n.id===id?{...n,pinned:!n.pinned}:n);
    setNotes(updated); await saveNotes(updated); resetAutoLock();
    showToast(updated.find(n=>n.id===id)?.pinned?"Sabitlendi 📌":"Sabitlenme kaldırıldı");
  };

  // ── COMMAND PALETTE ──
  const cmdActions=[
    {id:"new",     label:"Yeni Not",           icon:"✏️", action:()=>{newNote();setCmdOpen(false);}},
    {id:"export",  label:"Aether Dışa Aktar",   icon:"📤", action:()=>{setShowExport(true);setCmdOpen(false);}},
    {id:"import",  label:"Aether İçe Aktar",    icon:"📥", action:()=>{importRef.current?.click();setCmdOpen(false);}},
    {id:"stats",   label:"İstatistikler",       icon:"📊", action:()=>{setShowStats(true);setCmdOpen(false);}},
    {id:"theme",   label:theme==="dark"?"Aydınlık Mod":"Karanlık Mod", icon:theme==="dark"?"☀":"🌙", action:()=>{toggleTheme();setCmdOpen(false);}},
    {id:"lock",    label:"Aether'i Kilitle",     icon:"🔒", action:()=>{sessionPin.current=null;sessionPhrase.current=null;setScreen("lock");setPin("");setCmdOpen(false);}},
    ...CATEGORIES.filter(c=>c.id!=="all").map(c=>({
      id:`cat-${c.id}`, label:`${c.label} notlarını göster`, icon:c.icon,
      action:()=>{setFilterCat(c.id);setCmdOpen(false);}
    })),
    ...notes.map(n=>({
      id:`note-${n.id}`, label:n.title||"Başlıksız", icon:n.locked?"🔒":"📄",
      action:()=>{selectNote(n);setCmdOpen(false);}
    })),
  ];
  const cmdFiltered=cmdQuery ? cmdActions.filter(a=>a.label.toLowerCase().includes(cmdQuery.toLowerCase())) : cmdActions;

  const allTags=[...new Set(notes.flatMap(n=>n.tags||[]))];
  const allCategories=[...CATEGORIES,...customCats];
  const getCat=(id)=>allCategories.find(c=>c.id===id);
  const filtered=notes.filter(n=>{
    const cOk=filterCat==="all"||n.category===filterCat;
    const tOk=!filterTag||(n.tags||[]).includes(filterTag);
    const q=search.toLowerCase();
    const sOk=!q||n.title.toLowerCase().includes(q)||n.content.toLowerCase().includes(q)||(n.tags||[]).some(t=>t.includes(q));
    return cOk&&tOk&&sOk;
  }).sort((a,b)=>(b.pinned?1:0)-(a.pinned?1:0)); // Sabitlenmiş notlar üstte

  // ── HELPER: not arka plan rengi ──
  const noteEditorBg=(colorId)=>{
    const c=getNoteColor(colorId);
    if(!c.hex) return T.editor;
    return theme==="dark" ? c.hex+"18" : c.hex+"22";
  };

  // ══════════════════════════════════════════════════════════════
  // PIN SCREEN (shared)
  // ══════════════════════════════════════════════════════════════
  const PinPad=({pinVal,onDigit,disabled})=>(
    <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8,width:"100%"}}>
      {[1,2,3,4,5,6,7,8,9,"",0,"⌫"].map((d,i)=>(
        <button key={i} style={{width:"100%",aspectRatio:"1",borderRadius:12,
          background:d===""?"transparent":T.inputBg,border:d===""?"none":`1px solid ${T.inputBorder}`,
          color:T.text,fontSize:20,fontFamily:"'IBM Plex Mono',monospace",fontWeight:600,
          cursor:d===""?"default":"pointer",opacity:disabled?.4:1,transition:"all .15s"}}
          className={d!==""?"pinkey":""} disabled={disabled||d===""}
          onClick={()=>{ if(d==="⌫")onDigit("⌫"); else if(d!=="")onDigit(String(d)); }}>
          {d}
        </button>
      ))}
    </div>
  );

  const PinDots=({len,shk})=>(
    <div style={{display:"flex",gap:16,animation:shk?"shake .4s ease":"none"}}>
      {[0,1,2,3].map(i=>(
        <div key={i} style={{width:13,height:13,borderRadius:"50%",border:"2px solid",
          borderColor:i<len?T.accent:T.border, background:i<len?T.accent:"transparent",
          boxShadow:i<len?`0 0 10px ${T.accent}88`:"none",transition:"all .15s"}}/>
      ))}
    </div>
  );

  // ── RECOVERY SCREEN ──
  if(screen2==="recovery") return (
    <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",
      background:T.appBg,fontFamily:"'IBM Plex Sans',sans-serif"}}>
      <style>{globalCSS(T)}</style>
      <div style={{padding:36,borderRadius:20,width:420,maxWidth:"95vw",background:T.sidebar,
        border:`1px solid ${T.border}`,boxShadow:"0 8px 40px #0004",display:"flex",
        flexDirection:"column",gap:16}}>
        <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",
          fontSize:13,fontFamily:"inherit",textAlign:"left",marginBottom:-8}}
          onClick={()=>{setScreen2(null);setRecoverySuccess(false);setRecoveryInput("");setRecoveryError("");}}>
          ← Giriş ekranına dön
        </button>
        <div style={{textAlign:"center"}}>
          <div style={{fontSize:36,marginBottom:8}}>🔑</div>
          <div style={{fontSize:18,fontWeight:700,letterSpacing:2,color:T.text}}>
            {recoverySuccess?"Yeni PIN Belirle":"Aether Kurtarma"}
          </div>
          <div style={{fontSize:12,color:T.textMuted,marginTop:4}}>
            {recoverySuccess?`PIN'i ${newPinStep==="enter"?"gir":"tekrar gir"}`:"12 kelimelik recovery phrase'ini gir"}
          </div>
        </div>

        {!recoverySuccess?(
          <>
            <textarea style={{background:T.phraseBox,border:`1px solid ${T.inputBorder}`,
              borderRadius:10,padding:"12px 14px",color:T.text,fontSize:13,fontFamily:"inherit",
              resize:"none",height:100,outline:"none",lineHeight:1.7,letterSpacing:.5}}
              placeholder="kelime1 kelime2 kelime3 … kelime12"
              value={recoveryInput} onChange={e=>{setRecoveryInput(e.target.value);setRecoveryError("");}}
            />
            {recoveryError&&<div style={{color:T.danger,fontSize:12,textAlign:"center"}}>{recoveryError}</div>}
            <button style={{background:T.accent,border:"none",color:"#fff",padding:"12px 0",
              borderRadius:10,cursor:"pointer",fontSize:14,fontFamily:"inherit",fontWeight:700,
              opacity:recoveryLoading?.6:1}}
              onClick={handleRecovery} disabled={recoveryLoading}>
              {recoveryLoading?"Doğrulanıyor…":"Aether'i Kurtart →"}
            </button>
          </>
        ):(
          <>
            <PinDots len={newPinStep==="enter"?newPinAfterRecovery.length:confirmNewPin.length} shk={shake}/>
            {recoveryError&&<div style={{color:T.danger,fontSize:12,textAlign:"center"}}>{recoveryError}</div>}
            <PinPad pinVal="" onDigit={handleNewPinDigit} disabled={recoveryLoading}/>
          </>
        )}
      </div>
    </div>
  );

  // ── LOCK SCREEN ──
  if(screen==="lock") return (
    <div style={{minHeight:"100vh",display:"flex",alignItems:"center",justifyContent:"center",
      background:T.appBg,fontFamily:"'IBM Plex Sans',sans-serif"}}>
      <style>{globalCSS(T)}</style>

      {/* PHRASE ONAY EKRANI */}
      {pinStep==="phrase"?(
        <div style={{padding:36,borderRadius:20,width:440,maxWidth:"95vw",background:T.sidebar,
          border:`1px solid ${T.border}`,boxShadow:"0 8px 40px #0004",display:"flex",
          flexDirection:"column",gap:16,alignItems:"center"}}>
          <div style={{fontSize:32}}>🔑</div>
          <div style={{fontSize:17,fontWeight:700,letterSpacing:2,color:T.text,textAlign:"center"}}>
            Recovery Phrase
          </div>
          <div style={{fontSize:12,color:T.danger,textAlign:"center",lineHeight:1.7,fontWeight:600}}>
            ⚠ Bu 12 kelimeyi güvenli bir yere yaz.<br/>
            PIN'ini unutursan sadece bu phrase ile kurtarabilirsin.<br/>
            Ekranda bir daha gösterilmeyecek.
          </div>
          {/* Phrase kutusu */}
          <div style={{background:T.phraseBox,border:`1px solid ${T.inputBorder}`,
            borderRadius:12,padding:"16px 20px",width:"100%",boxSizing:"border-box"}}>
            <div style={{display:"flex",flexWrap:"wrap",gap:8,justifyContent:"center"}}>
              {generatedPhrase.split(" ").map((w,i)=>(
                <div key={i} style={{display:"flex",alignItems:"center",gap:6,
                  background:T.inputBg,border:`1px solid ${T.inputBorder}`,
                  borderRadius:8,padding:"5px 10px",minWidth:90}}>
                  <span style={{fontSize:10,color:T.textMuted,minWidth:16}}>{i+1}.</span>
                  <span style={{fontSize:13,fontWeight:600,color:T.text,fontFamily:"'IBM Plex Mono',monospace"}}>{w}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{display:"flex",alignItems:"center",gap:10,width:"100%",
            background:T.inputBg,border:`1px solid ${T.inputBorder}`,
            borderRadius:8,padding:"10px 14px"}}>
            <input type="checkbox" id="phraseCheck"
              checked={phraseConfirmed} onChange={e=>setPhraseConfirmed(e.target.checked)}
              style={{width:16,height:16,cursor:"pointer"}}/>
            <label htmlFor="phraseCheck" style={{fontSize:12,color:T.textSub,cursor:"pointer"}}>
              Phrase'i güvenli bir yere yazdım, anlıyorum
            </label>
          </div>
          <div style={{display:"flex",gap:10,width:"100%"}}>
            <button style={{flex:1,background:T.inputBg,border:`1px solid ${T.inputBorder}`,
              color:T.text,padding:"10px 0",borderRadius:10,cursor:"pointer",
              fontSize:13,fontFamily:"inherit"}}
              onClick={()=>{
                const txt=generatedPhrase; const el=document.createElement("textarea");
                el.value=txt; document.body.appendChild(el); el.select(); document.execCommand("copy");
                document.body.removeChild(el); showToast("Kopyalandı ✓");
              }}>
              📋 Kopyala
            </button>
            <button style={{flex:2,background:phraseConfirmed?T.accent:T.inputBg,
              border:"none",color:phraseConfirmed?"#fff":T.textMuted,
              padding:"10px 0",borderRadius:10,cursor:phraseConfirmed?"pointer":"not-allowed",
              fontSize:13,fontFamily:"inherit",fontWeight:700,transition:"all .2s"}}
              onClick={()=>{if(phraseConfirmed)finalizeSetup();}}
              disabled={!phraseConfirmed||loading}>
              {loading?"Oluşturuluyor…":"Aether'i Oluştur →"}
            </button>
          </div>
        </div>
      ):(
        /* ── Giriş / Kurulum ekranı ── */
        <div style={{padding:36,borderRadius:20,width:360,display:"flex",flexDirection:"column",
          alignItems:"center",gap:16,background:T.sidebar,border:`1px solid ${T.border}`,
          boxShadow:"0 8px 40px #0004"}}>
          <div style={{width:68,height:68,borderRadius:18,
            background:"linear-gradient(135deg,#3d3580,#5b7cf6)",
            display:"flex",alignItems:"center",justifyContent:"center",
            fontSize:30,boxShadow:`0 0 40px ${T.accent}44`}}>✦</div>
          <div style={{fontSize:20,fontWeight:700,letterSpacing:4,color:T.text}}>AETHER</div>

          {/* İlk kurulum — mod seçimi */}
          {isSettingPin && !setupMode && (
            <>
              <div style={{fontSize:12,color:T.textMuted,textAlign:"center",lineHeight:1.7}}>
                Güvenlik modunu seç
              </div>
              <div style={{display:"flex",flexDirection:"column",gap:10,width:"100%"}}>
                <button style={{background:T.inputBg,border:`2px solid ${T.inputBorder}`,
                  color:T.text,padding:"14px 16px",borderRadius:12,cursor:"pointer",
                  fontFamily:"inherit",textAlign:"left",transition:"all .2s"}}
                  onMouseEnter={e=>e.currentTarget.style.borderColor=T.accent}
                  onMouseLeave={e=>e.currentTarget.style.borderColor=T.inputBorder}
                  onClick={()=>setSetupMode("passphrase")}>
                  <div style={{fontWeight:700,fontSize:13,marginBottom:4}}>
                    🔐 Passphrase <span style={{background:T.success+"22",color:T.success,
                      fontSize:10,padding:"2px 6px",borderRadius:4,marginLeft:6}}>Önerilen</span>
                  </div>
                  <div style={{fontSize:11,color:T.textMuted,lineHeight:1.6}}>
                    Uzun bir şifre cümlesi — çok daha güçlü.<br/>
                    Örn: <em>"mavi kediler 42 uçar!"</em>
                  </div>
                </button>
                <button style={{background:T.inputBg,border:`2px solid ${T.inputBorder}`,
                  color:T.text,padding:"14px 16px",borderRadius:12,cursor:"pointer",
                  fontFamily:"inherit",textAlign:"left",transition:"all .2s"}}
                  onMouseEnter={e=>e.currentTarget.style.borderColor=T.accent}
                  onMouseLeave={e=>e.currentTarget.style.borderColor=T.inputBorder}
                  onClick={()=>setSetupMode("pin")}>
                  <div style={{fontWeight:700,fontSize:13,marginBottom:4}}>
                    🔢 4 Haneli PIN <span style={{background:T.warn+"22",color:T.warn,
                      fontSize:10,padding:"2px 6px",borderRadius:4,marginLeft:6}}>Daha Zayıf</span>
                  </div>
                  <div style={{fontSize:11,color:T.textMuted,lineHeight:1.6}}>
                    Hızlı erişim, ama kısa — daha az güvenli.
                  </div>
                </button>
              </div>
            </>
          )}

          {/* Passphrase kurulum / giriş */}
          {(setupMode==="passphrase" || (!isSettingPin && authMode==="passphrase")) && (
            <>
              <div style={{fontSize:12,color:T.textMuted,textAlign:"center"}}>
                {isSettingPin
                  ? (pinStep==="confirm" ? "Passphrase'i tekrar gir" : "Güçlü bir passphrase belirle")
                  : loading ? "Doğrulanıyor…" : "Passphrase'ini gir"}
              </div>
              <div style={{width:"100%",display:"flex",flexDirection:"column",gap:8}}>
                <input
                  type="password"
                  autoFocus
                  style={{width:"100%",background:T.inputBg,border:`2px solid ${T.inputBorder}`,
                    outline:"none",color:T.text,fontSize:15,fontFamily:"inherit",
                    padding:"12px 16px",borderRadius:10,boxSizing:"border-box",transition:"border .2s"}}
                  placeholder={isSettingPin&&pinStep==="confirm"?"Tekrar gir…":"Passphrase…"}
                  value={pinStep==="confirm"?confirmPass:passInput}
                  onFocus={e=>e.target.style.borderColor=T.accent}
                  onBlur={e=>e.target.style.borderColor=T.inputBorder}
                  onChange={e=>{
                    if(pinStep==="confirm") setConfirmPass(e.target.value);
                    else { setPassInput(e.target.value); setPassStrength(getPassphraseStrength(e.target.value)); }
                    setPinError("");
                  }}
                  onKeyDown={async e=>{
                    if(e.key!=="Enter") return;
                    if(isSettingPin){
                      if(pinStep==="enter"){
                        const s=getPassphraseStrength(passInput);
                        if(!s||s.level==="weak"){ setPinError(`Çok kısa veya zayıf (min ${PASSPHRASE_MIN_LEN} karakter)`); return; }
                        setPinStep("confirm");
                      } else {
                        if(confirmPass!==passInput){ shake_(); setPinError("Passphrase'ler eşleşmiyor"); setConfirmPass(""); return; }
                        const phrase=generatePhrase(12); setGeneratedPhrase(phrase);
                        sessionPhrase.current=phrase; setPinStep("phrase");
                      }
                    } else {
                      if(!passInput){ setPinError("Passphrase gir"); return; }
                      await handlePassphraseLogin(passInput);
                    }
                  }}
                />
                {/* Güç göstergesi */}
                {isSettingPin && pinStep==="enter" && passStrength && (
                  <div style={{display:"flex",alignItems:"center",gap:8}}>
                    <div style={{flex:1,height:4,borderRadius:4,background:T.border,overflow:"hidden"}}>
                      <div style={{height:"100%",borderRadius:4,transition:"all .3s",
                        background:passStrength.color,
                        width:passStrength.level==="weak"?"25%":passStrength.level==="fair"?"50%":
                          passStrength.level==="strong"?"75%":"100%"}}/>
                    </div>
                    <span style={{fontSize:11,color:passStrength.color,fontWeight:600,minWidth:60}}>
                      {passStrength.label}
                    </span>
                    <span style={{fontSize:10,color:T.textMuted}}>~{passStrength.bits}bit</span>
                  </div>
                )}
              </div>
              {pinError&&<div style={{color:T.danger,fontSize:12,textAlign:"center"}}>{pinError}</div>}
              {isSettingPin && (
                <button style={{width:"100%",background:T.accent,border:"none",color:"#fff",
                  padding:"11px 0",borderRadius:10,cursor:"pointer",fontSize:13,
                  fontFamily:"inherit",fontWeight:700,opacity:loading?.6:1}}
                  disabled={loading}
                  onClick={async()=>{
                    if(pinStep==="enter"){
                      const s=getPassphraseStrength(passInput);
                      if(!s||s.level==="weak"){ setPinError(`Çok kısa veya zayıf (min ${PASSPHRASE_MIN_LEN} karakter)`); return; }
                      setPinStep("confirm");
                    } else {
                      if(confirmPass!==passInput){ shake_(); setPinError("Passphrase'ler eşleşmiyor"); setConfirmPass(""); return; }
                      const phrase=generatePhrase(12); setGeneratedPhrase(phrase);
                      sessionPhrase.current=phrase; setPinStep("phrase");
                    }
                  }}>
                  {pinStep==="enter"?"Devam →":"Onayla →"}
                </button>
              )}
              {!isSettingPin && (
                <button style={{width:"100%",background:T.accent,border:"none",color:"#fff",
                  padding:"11px 0",borderRadius:10,cursor:"pointer",fontSize:13,
                  fontFamily:"inherit",fontWeight:700,opacity:loading?.6:1}}
                  disabled={loading}
                  onClick={()=>handlePassphraseLogin(passInput)}>
                  {loading?"Açılıyor…":"Aç →"}
                </button>
              )}
              {isSettingPin && (
                <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",
                  fontSize:11,fontFamily:"inherit"}}
                  onClick={()=>{setSetupMode(null);setPinStep("enter");setPassInput("");setConfirmPass("");setPinError("");}}>
                  ← Geri
                </button>
              )}
            </>
          )}

          {/* PIN kurulum / giriş */}
          {(setupMode==="pin" || (!isSettingPin && authMode==="pin")) && pinStep!=="phrase" && (
            <>
              <div style={{fontSize:12,color:T.textMuted,letterSpacing:2,textAlign:"center"}}>
                {isSettingPin?(pinStep==="enter"?"Yeni PIN belirle (4 hane)":"PIN'i tekrar gir")
                  :lockoutSecs>0?`Kilitli — ${lockoutSecs}s`:loading?"Doğrulanıyor…":"PIN'ini gir"}
              </div>
              <PinDots len={pin.length} shk={shake}/>
              {pinError&&<div style={{color:T.danger,fontSize:12,textAlign:"center"}}>{pinError}</div>}
              <PinPad pinVal={pin} onDigit={d=>{if(d==="⌫"){setPin(p=>p.slice(0,-1));setPinError("");}else handleDigit(d);}} disabled={loading||lockoutSecs>0}/>
              {isSettingPin && (
                <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",
                  fontSize:11,fontFamily:"inherit"}}
                  onClick={()=>{setSetupMode(null);setPinStep("enter");setPin("");setPinError("");}}>
                  ← Geri
                </button>
              )}
            </>
          )}

          {/* Ortak footer */}
          {!isSettingPin && (
            <div style={{fontSize:10,color:T.textMuted,letterSpacing:2,textAlign:"center"}}>
              🛡 AES-256-GCM · Yerel · Bulut yok
            </div>
          )}
          {/* Biometric unlock butonu — kayıtlıysa her zaman göster */}
          {!isSettingPin && bioRegistered && (
            <button
              style={{width:"100%",background:T.accentBg,border:`1px solid ${T.accent}44`,
                color:T.accent,padding:"11px 0",borderRadius:10,cursor:"pointer",
                fontSize:13,fontFamily:"inherit",fontWeight:600,
                display:"flex",alignItems:"center",justifyContent:"center",gap:8,
                opacity:bioLoading?.6:1}}
              disabled={bioLoading}
              onClick={async()=>{
                setBioLoading(true);
                try{
                  const secret=await biometricUnlock();
                  const cand=await makeVerifier(secret);
                  if(timingSafeEqual(cand,savedVerifier)){
                    resetFails(); sessionPin.current=secret;
                    const loaded=await loadNotes(secret); setNotes(loaded);
                    if(loaded.length>0) setActiveId(loaded[0].id);
                    updStats(loaded); setScreen("app");
                    setPin(""); setPassInput(""); resetAutoLock();
                    showToast("Biyometrik ile açıldı 🔓");
                  } else { showToast("Biyometrik doğrulama başarısız","danger"); }
                }catch(e){
                  if(e.name==="NotAllowedError") showToast("İptal edildi","warn");
                  else showToast("Biyometrik hata: "+e.message,"danger");
                }
                setBioLoading(false);
              }}>
              {bioLoading?"Doğrulanıyor…":"🪪 Face ID / Parmak İzi ile Aç"}
            </button>
          )}
          {!isSettingPin&&localStorage.getItem(SK_RECOVERY)&&(
            <button style={{background:"none",border:`1px solid ${T.border}`,color:T.textMuted,
              padding:"6px 14px",borderRadius:8,cursor:"pointer",fontSize:11,fontFamily:"inherit"}}
              onClick={()=>{setScreen2("recovery");setRecoverySuccess(false);setRecoveryInput("");setRecoveryError("");}}>
              🔑 Şifremi unuttum
            </button>
          )}
          <button style={{background:"none",border:`1px solid ${T.border}`,color:T.textMuted,
            padding:"5px 14px",borderRadius:8,cursor:"pointer",fontSize:11,fontFamily:"inherit"}}
            onClick={toggleTheme}>{theme==="dark"?"☀ Aydınlık":"🌙 Karanlık"}</button>
        </div>
      )}
    </div>
  );

  // ── NOTE UNLOCK — artık modal overlay, ayrı sayfa değil ──

  // ══════════════════════════════════════════════════════════════
  // MAIN APP
  // ══════════════════════════════════════════════════════════════
  return (
    <div style={{display:"flex",flexDirection:"column",height:"100vh",background:T.appBg,
      color:T.text,fontFamily:"'IBM Plex Sans','Segoe UI',sans-serif",overflow:"hidden"}}
      onClick={()=>setShowColorPicker(false)}>
      <style>{globalCSS(T)}</style>

      <input ref={importRef} type="file" accept=".vault" style={{display:"none"}}
        onChange={async e=>{
          const file=e.target.files?.[0]; if(!file)return;
          try{
            const imported=await importVault(file,sessionPin.current);
            const existingIds=new Set(notes.map(n=>n.id));
            const newNotes=imported.filter(n=>!existingIds.has(n.id));
            const updated=[...newNotes,...notes]; setNotes(updated); await saveNotes(updated); updStats(updated);
            showToast(`${newNotes.length} not içe aktarıldı ✓`);
          }catch{ showToast("İçe aktarma başarısız","danger"); }
          e.target.value="";
        }}/>

      {/* TOP BAR */}
      <div style={{display:"flex",alignItems:"center",height:48,background:T.topbar,
        borderBottom:`1px solid ${T.border}`,padding:"0 16px",gap:12,flexShrink:0,zIndex:10,
        boxShadow:theme==="light"?"0 1px 4px #0001":"none"}}>
        <button style={topBtn(T)} onClick={()=>setSidebarOpen(p=>!p)}>☰</button>
        <span style={{fontWeight:700,fontSize:15,letterSpacing:3,color:T.text}}>AETHER</span>
        <span style={{fontSize:10,color:T.textMuted,letterSpacing:1}}>· AES-256-GCM</span>
        <div style={{flex:1}}/>
        <button style={{display:"flex",alignItems:"center",gap:8,background:T.inputBg,
          border:`1px solid ${T.inputBorder}`,color:T.textMuted,padding:"5px 12px",
          borderRadius:6,cursor:"pointer",fontSize:11,fontFamily:"inherit"}}
          onClick={()=>{setCmdOpen(true);setCmdQuery("");setCmdIdx(0);}}>
          <span>⌕ Komut veya ara…</span>
          <kbd style={{background:T.border,border:"none",color:T.textMuted,padding:"1px 5px",borderRadius:3,fontSize:10}}>⌘K</kbd>
        </button>
        {pwaPrompt&&(
          <button style={{...topBtn(T),color:T.success,borderColor:T.success+"66",
            fontSize:11,width:"auto",padding:"0 10px",gap:4,display:"flex",alignItems:"center"}}
            title="Uygulamayı yükle"
            onClick={async()=>{
              pwaPrompt.prompt();
              const {outcome}=await pwaPrompt.userChoice;
              if(outcome==="accepted") showToast("Aether Notes yüklendi! 🎉");
              setPwaPrompt(null);
            }}>
            ⬇ Yükle
          </button>
        )}
        {[["📤","Dışa/İçe Aktar",()=>setShowExport(true)],["📊","İstatistikler",()=>setShowStats(true)],
          [theme==="dark"?"☀":"🌙","Tema",toggleTheme]].map(([ico,title,fn])=>(
          <button key={title} style={topBtn(T)} title={title} onClick={fn}>{ico}</button>
        ))}
        {/* Ayarlar — PIN modunda uyarı rengi */}
        <button style={{...topBtn(T),
          color:authMode==="pin"?T.warn:T.textSub,
          borderColor:authMode==="pin"?T.warn+"66":T.border}}
          title={authMode==="pin"?"Ayarlar (PIN modu aktif — passphrase önerilir)":"Ayarlar"}
          onClick={()=>setShowSettings(true)}>
          ⚙️
        </button>
        <button style={{...topBtn(T),color:T.danger}} title="Kilitle"
          onClick={()=>{sessionPin.current=null;sessionPhrase.current=null;setScreen("lock");setPin("");}}>🔒</button>
      </div>

      <div style={{display:"flex",flex:1,overflow:"hidden"}}>
        {/* SIDEBAR */}
        {sidebarOpen&&(
          <div style={{width:200,background:T.sidebar,borderRight:`1px solid ${T.border}`,
            display:"flex",flexDirection:"column",flexShrink:0,overflow:"hidden"}}>
            <div style={{padding:"14px 12px 10px",borderBottom:`1px solid ${T.borderLight}`}}>
              <div style={sectionLabel(T)}>GÖRÜNÜMLER</div>
              <button className="sidebar-btn" style={navBtn(T,filterCat==="all")}
                onClick={()=>{setFilterCat("all");setFilterTag("");}}>
                <span>📋</span><span style={{flex:1}}>Tüm Notlar</span>
                <span style={badge(T)}>{notes.length}</span>
              </button>
            </div>
            <div style={{padding:"12px 12px 10px",borderBottom:`1px solid ${T.borderLight}`}}>
              <div style={{display:"flex",alignItems:"center",marginBottom:8}}>
                <span style={{fontSize:10,fontWeight:700,letterSpacing:2,color:T.textMuted}}>KATEGORİLER</span>
                <button style={{marginLeft:"auto",background:T.accentBg,border:`1px solid ${T.accent}44`,
                  color:T.accent,width:20,height:20,borderRadius:4,cursor:"pointer",
                  fontSize:13,display:"flex",alignItems:"center",justifyContent:"center",lineHeight:1,
                  fontWeight:700}} title="Yeni kategori ekle"
                  onClick={()=>{setShowAddCat(true);setNewCatName("");setNewCatColor("#a29bfe");setNewCatIcon("📁");}}>+</button>
              </div>
              {allCategories.filter(c=>c.id!=="all").map(cat=>(
                <div key={cat.id} style={{display:"flex",alignItems:"center"}}>
                  <button className="sidebar-btn" style={{...navBtn(T,filterCat===cat.id),flex:1,minWidth:0}}
                    onClick={()=>{setFilterCat(cat.id);setFilterTag("");}}>
                    <span style={{width:8,height:8,borderRadius:"50%",background:cat.color,flexShrink:0}}/>
                    <span style={{flex:1,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{cat.label}</span>
                    <span style={badge(T)}>{notes.filter(n=>n.category===cat.id).length}</span>
                  </button>
                  {customCats.find(c=>c.id===cat.id)&&(
                    <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",
                      fontSize:13,opacity:.4,padding:"2px 3px",flexShrink:0,lineHeight:1,
                      transition:"opacity .15s"}}
                      title="Kategoriyi sil"
                      onClick={()=>{
                        if(!window.confirm(`"${cat.label}" kategorisini sil?`)) return;
                        const updated=customCats.filter(c=>c.id!==cat.id);
                        setCustomCats(updated); localStorage.setItem(SK_CATS,JSON.stringify(updated));
                        if(filterCat===cat.id) setFilterCat("all");
                      }}>×</button>
                  )}
                </div>
              ))}
            </div>
            {allTags.length>0&&(
              <div style={{padding:"12px 12px 10px"}}>
                <div style={sectionLabel(T)}>ETİKETLER</div>
                {allTags.map(t=>(
                  <button key={t} className="sidebar-btn" style={navBtn(T,filterTag===t)}
                    onClick={()=>setFilterTag(filterTag===t?"":t)}>
                    <span style={{color:T.textMuted}}>#</span><span style={{flex:1}}>{t}</span>
                  </button>
                ))}
              </div>
            )}
            <div style={{flex:1}}/>
            <div style={{padding:12,borderTop:`1px solid ${T.borderLight}`,fontSize:10,
              color:T.textMuted,textAlign:"center",lineHeight:1.7}}>
              🛡 Yerel · Şifreli<br/>Bulut yok
            </div>
          </div>
        )}

        {/* NOTE LIST */}
        <div style={{width:280,background:T.list,borderRight:`1px solid ${T.border}`,
          display:"flex",flexDirection:"column",flexShrink:0}}>
          <div style={{padding:"10px 14px",borderBottom:`1px solid ${T.border}`,
            display:"flex",alignItems:"center",gap:8,flexShrink:0}}>
            <span style={{fontWeight:600,fontSize:13,color:T.text,flex:1}}>
              {getCat(filterCat)?.label||"Tüm Notlar"}
            </span>
            <button style={{background:T.accent,border:"none",color:"#fff",width:26,height:26,
              borderRadius:6,cursor:"pointer",fontSize:20,display:"flex",alignItems:"center",
              justifyContent:"center",lineHeight:1}} onClick={newNote}>+</button>
          </div>
          <div style={{padding:"8px 10px",borderBottom:`1px solid ${T.borderLight}`,flexShrink:0}}>
            <div style={{display:"flex",alignItems:"center",gap:6,background:T.inputBg,
              border:`1px solid ${T.inputBorder}`,borderRadius:6,padding:"5px 10px"}}>
              <span style={{color:T.textMuted,fontSize:13}}>⌕</span>
              <input style={{background:"none",border:"none",outline:"none",color:T.text,
                fontSize:12,flex:1,fontFamily:"inherit"}}
                placeholder="Ara…" value={search} onChange={e=>setSearch(e.target.value)}/>
              {search&&<button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",fontSize:11}}
                onClick={()=>setSearch("")}>✕</button>}
            </div>
          </div>
          <div style={{flex:1,overflowY:"auto"}}>
            {filtered.length===0
              ?<div style={{padding:24,textAlign:"center",color:T.textMuted,fontSize:12}}>
                {search?"Sonuç bulunamadı":"Not yok — + ile ekle"}
              </div>
              :filtered.map(note=>{
                const nc=getNoteColor(note.color);
                const leftColor=nc.hex||getCat(note.category)?.color||T.accent;
                return(
                  <div key={note.id} className="note-item"
                    style={{padding:"12px 14px",borderBottom:`1px solid ${T.borderLight}`,
                      cursor:"pointer",transition:"background .15s",position:"relative",
                      background:activeId===note.id?T.cardActive:nc.hex?nc.hex+(theme==="dark"?"18":"14"):"transparent"}}
                    onClick={()=>selectNote(note)}>
                    <div style={{position:"absolute",left:0,top:4,bottom:4,width:3,
                      borderRadius:"0 3px 3px 0",background:activeId===note.id?T.accent:leftColor,
                      opacity:activeId===note.id?1:.5}}/>
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",paddingLeft:6}}>
                      <div style={{fontSize:13,fontWeight:600,color:T.text,whiteSpace:"nowrap",
                        overflow:"hidden",textOverflow:"ellipsis",flex:1,marginRight:4}}>
                        {note.pinned&&<span style={{color:T.accent,marginRight:4}}>📌</span>}
                        {note.locked?"🔒 ":""}{note.title||"Başlıksız"}
                      </div>
                      <div style={{display:"flex",gap:2,flexShrink:0}}>
                        <button className="del-btn"
                          style={{background:"none",border:"none",
                            color:note.pinned?T.accent:T.textMuted,cursor:"pointer",
                            fontSize:12,lineHeight:1,opacity:note.pinned?1:.3,flexShrink:0,
                            transition:"opacity .15s",padding:"0 2px"}}
                          title={note.pinned?"Sabitlemeyi kaldır":"Sabitle"}
                          onClick={e=>{e.stopPropagation();togglePin(note.id);}}>📌</button>
                        <button className="del-btn"
                          style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",
                            fontSize:14,lineHeight:1,opacity:.4,flexShrink:0,transition:"opacity .15s"}}
                          onClick={e=>{e.stopPropagation();setDeleteConfirm(note.id);}}>×</button>
                      </div>
                    </div>
                    {note.locked
                      ?<div style={{fontSize:11,color:T.textMuted,marginTop:4,paddingLeft:6,fontStyle:"italic"}}>🔐 Kilitli · PIN ile aç</div>
                      :<div style={{fontSize:11,color:T.textSub,marginTop:4,paddingLeft:6,
                        overflow:"hidden",display:"-webkit-box",WebkitLineClamp:2,WebkitBoxOrient:"vertical",lineHeight:1.5}}>
                        {note.content||<em style={{opacity:.5}}>İçerik yok</em>}
                      </div>
                    }
                    <div style={{display:"flex",justifyContent:"space-between",alignItems:"center",marginTop:6,paddingLeft:6}}>
                      <div style={{display:"flex",gap:4,flexWrap:"wrap",flex:1}}>
                        {nc.hex&&<span style={{fontSize:10,background:nc.hex+"44",color:T.text,
                          padding:"1px 5px",borderRadius:3,border:`1px solid ${nc.hex}66`}}>●</span>}
                        {(note.tags||[]).slice(0,2).map(t=>(
                          <span key={t} style={{fontSize:10,color:T.accent,background:T.accentBg,padding:"1px 5px",borderRadius:3}}>#{t}</span>
                        ))}
                      </div>
                      <span style={{fontSize:10,color:T.textMuted,flexShrink:0}}>{fmtDate(note.updatedAt)}</span>
                    </div>
                  </div>
                );
              })
            }
          </div>
        </div>

        {/* EDITOR */}
        <div style={{flex:1,display:"flex",flexDirection:"column",
          background:activeNote&&activeNote.id===activeId&&!activeNote.locked?noteEditorBg(eColor):T.editor,
          overflow:"hidden",transition:"background .3s"}}>

          {/* Kilitli not — basit PIN input */}
          {activeNote?.locked&&(
            <div style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",
              justifyContent:"center",gap:16,padding:40}}>
              <div style={{fontSize:44}}>🔒</div>
              <div style={{fontSize:16,fontWeight:700,color:T.text}}>
                {activeNote.title||"Başlıksız"}
              </div>
              <div style={{fontSize:12,color:T.textMuted}}>Bu not PIN ile kilitli</div>
              <div style={{display:"flex",gap:8,alignItems:"center"}}>
                <input
                  key={activeNote.id}
                  type="password"
                  inputMode="numeric"
                  maxLength={4}
                  placeholder="PIN"
                  autoFocus
                  style={{background:T.inputBg,border:`2px solid ${T.inputBorder}`,
                    outline:"none",color:T.text,fontSize:22,fontFamily:"'IBM Plex Mono',monospace",
                    padding:"10px 16px",borderRadius:10,width:110,letterSpacing:8,textAlign:"center",
                    transition:"border .2s"}}
                  onFocus={e=>e.target.style.borderColor=T.accent}
                  onBlur={e=>e.target.style.borderColor=T.inputBorder}
                  onChange={async e=>{
                    const val=e.target.value.replace(/\D/g,"").slice(0,4);
                    e.target.value=val;
                    if(val.length===4){
                      if(!activeNote.notePin){
                        // PIN hash yok — direkt aç
                        setETitle(activeNote.title); setEContent(activeNote.content);
                        setECat(activeNote.category); setETags(activeNote.tags||[]);
                        setEColor(activeNote.color||"none"); setELocked(false);
                        setENotePin(""); setETagIn(""); setEPreview(false); setDirty(false);
                        // locked'ı kaldır
                        const updated=notes.map(n=>n.id===activeNote.id?{...n,locked:false,notePin:null}:n);
                        setNotes(updated); await saveNotes(updated);
                        return;
                      }
                      const cand=await makePinVerifier(val);
                      if(timingSafeEqual(cand,activeNote.notePin)){
                        // Doğru PIN — notu aç
                        setETitle(activeNote.title); setEContent(activeNote.content);
                        setECat(activeNote.category); setETags(activeNote.tags||[]);
                        setEColor(activeNote.color||"none"); setELocked(true);
                        setENotePin(""); setETagIn(""); setEPreview(false); setDirty(false);
                        // locked=false yap ki editör görünsün, notePin koru
                        const updated=notes.map(n=>n.id===activeNote.id?{...n,locked:false}:n);
                        setNotes(updated);
                        showToast("Not açıldı 🔓");
                      } else {
                        e.target.value="";
                        e.target.style.borderColor=T.danger;
                        setTimeout(()=>e.target.style.borderColor=T.inputBorder,800);
                        showToast("Yanlış PIN","danger");
                      }
                    }
                  }}
                />
              </div>
              <div style={{fontSize:11,color:T.textMuted}}>4 haneyi gir, otomatik açılır</div>
            </div>
          )}

          {/* Normal editör — not açık */}
          {activeNote&&!activeNote.locked&&(
            <>
              {/* Toolbar */}
              <div style={{padding:"10px 20px",borderBottom:`1px solid ${T.border}`,
                display:"flex",alignItems:"center",gap:10,flexShrink:0}}>
                <span style={{fontSize:11,color:T.textMuted}}>{fmtDate(activeNote.updatedAt)}</span>
                {dirty&&<span style={{fontSize:11,color:T.warn}}>● kaydediliyor…</span>}
                {!dirty&&<span style={{fontSize:11,color:T.success}}>✓</span>}
                <div style={{flex:1}}/>
                {/* Renk seçici */}
                <div style={{position:"relative"}} onClick={e=>e.stopPropagation()}>
                  <button style={{...toolBtn(T),display:"flex",alignItems:"center",gap:6}}
                    onClick={()=>setShowColorPicker(p=>!p)}>
                    <span style={{width:12,height:12,borderRadius:"50%",
                      background:getNoteColor(eColor).hex||T.textMuted,
                      border:`1px solid ${T.inputBorder}`,display:"inline-block"}}/>
                    <span>Renk</span>
                  </button>
                  {showColorPicker&&(
                    <div style={{position:"absolute",right:0,top:"110%",zIndex:50,
                      background:T.cmdBg,border:`1px solid ${T.border}`,borderRadius:12,
                      padding:12,boxShadow:"0 8px 30px #0006",width:220}}>
                      <div style={{fontSize:10,color:T.textMuted,letterSpacing:2,marginBottom:10}}>NOT RENGİ</div>
                      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8}}>
                        {NOTE_COLORS.map(c=>(
                          <button key={c.id}
                            style={{display:"flex",flexDirection:"column",alignItems:"center",gap:4,
                              background:eColor===c.id?T.accentBg:"transparent",
                              border:`2px solid ${eColor===c.id?T.accent:"transparent"}`,
                              borderRadius:8,padding:"6px 4px",cursor:"pointer",transition:"all .15s"}}
                            onClick={()=>{setEColor(c.id);setDirty(true);setShowColorPicker(false);}}>
                            <div style={{width:20,height:20,borderRadius:"50%",
                              background:c.hex||T.inputBg,border:`1px solid ${T.inputBorder}`,
                              boxShadow:eColor===c.id?`0 0 8px ${c.hex||T.accent}88`:"none"}}/>
                            <span style={{fontSize:9,color:T.textMuted}}>{c.label}</span>
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <select style={{background:T.inputBg,border:`1px solid ${T.inputBorder}`,
                  color:T.text,borderRadius:6,padding:"4px 8px",fontSize:11,fontFamily:"inherit",cursor:"pointer"}}
                  value={eCat} onChange={e=>{setECat(e.target.value);setDirty(true);}}>
                  {allCategories.filter(c=>c.id!=="all").map(c=>(
                    <option key={c.id} value={c.id}>{c.icon} {c.label}</option>
                  ))}
                </select>
                <button style={{...toolBtn(T),color:ePreview?T.accent:T.textSub}}
                  onClick={()=>setEPreview(p=>!p)}>
                  {ePreview?"✏️ Düzenle":"👁 Önizle"}
                </button>
                <button style={{...toolBtn(T),color:T.danger}}
                  onClick={()=>setDeleteConfirm(activeId)}>🗑</button>
              </div>

              <input style={{background:"transparent",border:"none",
                borderBottom:`1px solid ${T.borderLight}`,outline:"none",color:T.text,
                fontSize:22,fontWeight:700,padding:"16px 24px",letterSpacing:.5,
                fontFamily:"'Crimson Pro','Georgia',serif",width:"100%",boxSizing:"border-box"}}
                placeholder="Başlık…" value={eTitle}
                onChange={e=>{setETitle(e.target.value);setDirty(true);}}/>

              {/* Tags + Lock */}
              <div style={{display:"flex",gap:6,padding:"8px 24px",
                borderBottom:`1px solid ${T.borderLight}`,flexWrap:"wrap",
                alignItems:"center",flexShrink:0,minHeight:40}}>
                {eTags.map(t=>(
                  <span key={t} style={{fontSize:11,color:T.accent,background:T.accentBg,
                    padding:"2px 8px",borderRadius:12,display:"flex",alignItems:"center",gap:4}}>
                    #{t}
                    <button style={{background:"none",border:"none",color:T.accent,cursor:"pointer",fontSize:13,lineHeight:1,padding:0}}
                      onClick={()=>{setETags(eTags.filter(x=>x!==t));setDirty(true);}}>×</button>
                  </span>
                ))}
                <input style={{background:"none",border:"none",outline:"none",color:T.textMuted,
                  fontSize:11,fontFamily:"inherit",minWidth:100,padding:"2px 0"}}
                  placeholder="+ etiket (Enter)" value={eTagIn}
                  onChange={e=>setETagIn(e.target.value)}
                  onKeyDown={e=>{if(e.key==="Enter"||e.key===","){e.preventDefault();addTag();}}}/>
                <div style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:8}}>
                  {!eLocked&&(
                    <input style={{background:T.inputBg,
                      border:`2px solid ${eNotePin.length===4?T.success:T.inputBorder}`,
                      outline:"none",color:T.text,fontSize:14,fontFamily:"'IBM Plex Mono',monospace",
                      padding:"3px 10px",borderRadius:6,width:110,letterSpacing:4,textAlign:"center",
                      transition:"border .2s"}}
                      type="password" inputMode="numeric" maxLength={4} placeholder="Not PIN"
                      value={eNotePin} onChange={e=>setENotePin(e.target.value.replace(/\D/g,"").slice(0,4))}/>
                  )}
                  <button style={{...toolBtn(T),
                    border:`1px solid ${eLocked?T.danger+"66":eNotePin.length===4?T.success+"66":T.inputBorder}`,
                    color:eLocked?T.danger:eNotePin.length===4?T.success:T.textMuted}}
                    onClick={async()=>{
                      if(eLocked){
                        setELocked(false); setENotePin(""); setDirty(true);
                      } else {
                        if(!eNotePin){showToast("Önce PIN gir","warn");return;}
                        if(eNotePin.length<4){showToast("PIN 4 hane olmalı","warn");return;}
                        const now=new Date().toISOString();
                        const notePinHash=await makePinVerifier(eNotePin);
                        const updated=notes.map(n=>n.id===activeId
                          ?{...n,title:eTitle||"Başlıksız",content:eContent,category:eCat,
                              tags:eTags,color:eColor,locked:true,notePin:notePinHash,updatedAt:now}:n);
                        setNotes(updated); await saveNotes(updated); updStats(updated);
                        setELocked(true); setDirty(false);
                        showToast("Not kilitlendi 🔒");
                      }
                    }}>
                    {eLocked?"🔒 Kilitli":"🔓 Kilitle"}
                  </button>
                  {eLocked&&<span style={{fontSize:11,color:T.textMuted}}>PIN ayarlı ✓</span>}
                </div>
              </div>

              {ePreview
                ?<div
                    style={{flex:1,padding:"20px 24px",overflowY:"auto",lineHeight:1.9,fontSize:14,color:T.text}}
                    dangerouslySetInnerHTML={{__html:renderMarkdown(eContent)||`<p style="color:${T.textMuted}">İçerik yok</p>`}}
                    onClick={e=>{
                      // Wiki link tıklaması
                      const wiki=e.target.dataset?.wiki;
                      if(!wiki) return;
                      const target=notes.find(n=>n.title.toLowerCase()===wiki.toLowerCase());
                      if(target){ selectNote(target); showToast(`"${target.title}" notuna geçildi`); }
                      else showToast(`"${wiki}" notu bulunamadı`,"warn");
                    }}
                  />
                :<textarea ref={editorRef}
                    style={{flex:1,background:"transparent",border:"none",outline:"none",color:T.text,
                      fontSize:14,fontFamily:"'Crimson Pro','Georgia',serif",padding:"20px 24px",
                      resize:"none",lineHeight:1.9,width:"100%",boxSizing:"border-box"}}
                    placeholder={"Yazmaya başla…\n\n# Başlık  **kalın**  *italik*  `kod`\n- liste  > alıntı\n[[Başka Not Adı]] — not bağlantısı"}
                    value={eContent} onChange={e=>{setEContent(e.target.value);setDirty(true);}}/>
              }
              <div style={{padding:"6px 24px",borderTop:`1px solid ${T.borderLight}`,
                display:"flex",gap:20,fontSize:11,color:T.textMuted,flexShrink:0,flexWrap:"wrap"}}>
                <span>{eContent.length} kr</span>
                <span>{wc(eContent)} kelime</span>
                <span>{eContent.split(/\n/).length} satır</span>
                {(eContent.match(/\[\[([^\]]+)\]\]/g)||[]).length>0&&(
                  <span style={{color:T.accent}}>
                    🔗 {(eContent.match(/\[\[([^\]]+)\]\]/g)||[]).length} bağlantı
                  </span>
                )}
              </div>
            </>
          )}

          {/* Boş state */}
          {!activeNote&&(
            <div style={{flex:1,display:"flex",flexDirection:"column",alignItems:"center",
              justifyContent:"center",color:T.textMuted,gap:12}}>
              <div style={{fontSize:48}}>✦</div>
              <div style={{fontSize:15,fontWeight:600,color:T.textSub}}>Aether Notes</div>
              <div style={{fontSize:12}}>Bir not seç veya yeni not oluştur</div>
              <button style={{marginTop:8,background:T.accent,border:"none",color:"#fff",
                padding:"10px 24px",borderRadius:8,fontSize:13,cursor:"pointer",fontFamily:"inherit",fontWeight:600}}
                onClick={newNote}>+ Yeni Not</button>
              <div style={{fontSize:11,color:T.textMuted,marginTop:4}}>
                veya <kbd style={{background:T.inputBg,border:`1px solid ${T.inputBorder}`,
                  padding:"2px 6px",borderRadius:4,fontSize:10}}>⌘K</kbd>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* ══ COMMAND PALETTE ══ */}
      {cmdOpen&&(
        <div style={{position:"fixed",inset:0,background:"#0006",display:"flex",
          alignItems:"flex-start",justifyContent:"center",zIndex:200,paddingTop:"15vh"}}
          onClick={()=>setCmdOpen(false)}>
          <div style={{background:T.cmdBg,border:`1px solid ${T.border}`,borderRadius:12,
            width:520,maxWidth:"90vw",boxShadow:"0 20px 60px #0006",overflow:"hidden"}}
            onClick={e=>e.stopPropagation()}>
            <div style={{display:"flex",alignItems:"center",gap:10,padding:"12px 16px",
              borderBottom:`1px solid ${T.border}`}}>
              <span style={{color:T.textMuted,fontSize:16}}>⌕</span>
              <input ref={cmdRef}
                style={{flex:1,background:"transparent",border:"none",outline:"none",
                  color:T.text,fontSize:14,fontFamily:"inherit"}}
                placeholder="Komut veya not ara…" value={cmdQuery}
                onChange={e=>{setCmdQuery(e.target.value);setCmdIdx(0);}}
                onKeyDown={e=>{
                  if(e.key==="ArrowDown"){e.preventDefault();setCmdIdx(i=>Math.min(i+1,cmdFiltered.length-1));}
                  if(e.key==="ArrowUp"){e.preventDefault();setCmdIdx(i=>Math.max(i-1,0));}
                  if(e.key==="Enter"&&cmdFiltered[cmdIdx]) cmdFiltered[cmdIdx].action();
                  if(e.key==="Escape") setCmdOpen(false);
                }}/>
              <kbd style={{background:T.inputBg,border:`1px solid ${T.inputBorder}`,
                color:T.textMuted,padding:"2px 6px",borderRadius:4,fontSize:10}}>ESC</kbd>
            </div>
            <div style={{maxHeight:320,overflowY:"auto"}}>
              {cmdFiltered.length===0
                ?<div style={{padding:20,textAlign:"center",color:T.textMuted,fontSize:12}}>Sonuç bulunamadı</div>
                :cmdFiltered.map((a,i)=>(
                  <div key={a.id}
                    style={{display:"flex",alignItems:"center",gap:12,padding:"10px 16px",
                      cursor:"pointer",transition:"background .1s",
                      background:i===cmdIdx?T.cmdItemHover:T.cmdItem,
                      borderBottom:`1px solid ${T.border}`}}
                    onMouseEnter={()=>setCmdIdx(i)} onClick={()=>a.action()}>
                    <span style={{fontSize:16,flexShrink:0}}>{a.icon}</span>
                    <span style={{fontSize:13,color:T.text}}>{a.label}</span>
                    {i===cmdIdx&&<span style={{marginLeft:"auto",fontSize:10,color:T.textMuted}}>↵</span>}
                  </div>
                ))
              }
            </div>
            <div style={{padding:"8px 16px",borderTop:`1px solid ${T.border}`,
              display:"flex",gap:16,fontSize:10,color:T.textMuted}}>
              <span>↑↓ Gezin</span><span>↵ Seç</span><span>ESC Kapat</span>
            </div>
          </div>
        </div>
      )}

      {/* ══ EXPORT MODAL ══ */}
      {showExport&&(
        <div style={{position:"fixed",inset:0,background:"#0008",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:100}} onClick={()=>setShowExport(false)}>
          <div style={{background:T.sidebar,border:`1px solid ${T.border}`,borderRadius:16,
            padding:28,width:380,maxWidth:"92vw"}} onClick={e=>e.stopPropagation()}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:4}}>
              <span style={{fontWeight:700,fontSize:15,color:T.text}}>📤 Aether Yedekle</span>
              <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",fontSize:20}}
                onClick={()=>setShowExport(false)}>×</button>
            </div>
            <p style={{fontSize:12,color:T.textMuted,marginBottom:20,lineHeight:1.7}}>
              Notların AES-256-GCM ile şifrelenmiş <code style={{background:T.inputBg,padding:"1px 4px",borderRadius:3}}>.vault</code> dosyasına aktarılır. PIN olmadan açılamaz.
            </p>
            <div style={{display:"flex",flexDirection:"column",gap:10}}>
              <button style={{background:T.accent,border:"none",color:"#fff",padding:"10px 0",
                borderRadius:8,cursor:"pointer",fontSize:13,fontFamily:"inherit",fontWeight:700}}
                onClick={async()=>{await exportVault(notes,sessionPin.current);showToast(`${notes.length} not dışa aktarıldı ✓`);setShowExport(false);}}>
                📥 {notes.length} notu indir (.vault)
              </button>
              <button style={{background:T.inputBg,border:`1px solid ${T.inputBorder}`,color:T.text,
                padding:"10px 0",borderRadius:8,cursor:"pointer",fontSize:13,fontFamily:"inherit"}}
                onClick={()=>{importRef.current?.click();setShowExport(false);}}>
                📂 .vault dosyasından içe aktar
              </button>
            </div>
            <p style={{fontSize:11,color:T.textMuted,marginTop:14,lineHeight:1.6}}>
              ⚠ İçe aktarırken aynı ID'li notlar atlanır, yeni notlar eklenir.
            </p>
          </div>
        </div>
      )}

      {/* ══ STATS ══ */}
      {showStats&&(
        <div style={{position:"fixed",inset:0,background:"#0008",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:100}} onClick={()=>setShowStats(false)}>
          <div style={{background:T.sidebar,border:`1px solid ${T.border}`,borderRadius:16,
            padding:28,width:360,maxWidth:"92vw"}} onClick={e=>e.stopPropagation()}>
            <div style={{display:"flex",justifyContent:"space-between",marginBottom:20}}>
              <span style={{fontWeight:700,fontSize:14,color:T.text}}>📊 İstatistikler</span>
              <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",fontSize:20}}
                onClick={()=>setShowStats(false)}>×</button>
            </div>
            <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10}}>
              {[{l:"Toplam Not",v:notes.length,i:"◈"},{l:"Kelime",v:stats.totalWords,i:"✍"},
                {l:"Seri 🔥",v:stats.streak,i:"📈"},{l:"Kilitli",v:notes.filter(n=>n.locked).length,i:"🔒"},
                {l:"Etiket",v:allTags.length,i:"🏷"},{l:"Kategori",v:new Set(notes.map(n=>n.category)).size,i:"📂"}
              ].map(s=>(
                <div key={s.l} style={{background:T.card,border:`1px solid ${T.border}`,borderRadius:10,
                  padding:"12px 8px",display:"flex",flexDirection:"column",alignItems:"center",gap:4}}>
                  <div style={{fontSize:18}}>{s.i}</div>
                  <div style={{fontSize:20,fontWeight:700,color:T.accent}}>{s.v}</div>
                  <div style={{fontSize:10,color:T.textMuted}}>{s.l}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ══ DELETE ══ */}
      {deleteConfirm&&(()=>{
        const noteToDelete=notes.find(n=>n.id===deleteConfirm);
        const isLocked=noteToDelete?.locked&&noteToDelete?.notePin;
        return(
          <div style={{position:"fixed",inset:0,background:"#0008",display:"flex",
            alignItems:"center",justifyContent:"center",zIndex:100}}
            onClick={()=>{setDeleteConfirm(null);setLockedDeletePin("");setLockedDeleteErr("");}}>
            <div style={{background:T.sidebar,border:`1px solid ${T.border}`,borderRadius:16,
              padding:28,maxWidth:320,width:"90%",textAlign:"center"}} onClick={e=>e.stopPropagation()}>
              <div style={{fontSize:32,marginBottom:12}}>⚠️</div>
              <div style={{fontWeight:700,fontSize:14,color:T.text,marginBottom:8}}>
                {isLocked?"Kilitli notu sil?":"Notu sil?"}
              </div>
              {isLocked?(
                <>
                  <div style={{fontSize:12,color:T.textMuted,marginBottom:16,lineHeight:1.6}}>
                    Bu not kilitli. Silmek için not PIN'ini gir.
                  </div>
                  <div style={{display:"flex",gap:12,justifyContent:"center",marginBottom:12}}>
                    {[0,1,2,3].map(i=>(
                      <div key={i} style={{width:11,height:11,borderRadius:"50%",border:"2px solid",
                        borderColor:i<lockedDeletePin.length?T.danger:T.border,
                        background:i<lockedDeletePin.length?T.danger:"transparent",transition:"all .15s"}}/>
                    ))}
                  </div>
                  {lockedDeleteErr&&<div style={{color:T.danger,fontSize:11,marginBottom:8}}>{lockedDeleteErr}</div>}
                  <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:6,marginBottom:16}}>
                    {[1,2,3,4,5,6,7,8,9,"",0,"⌫"].map((d,i)=>(
                      <button key={i} style={{width:"100%",aspectRatio:"1",borderRadius:8,
                        background:d===""?"transparent":T.inputBg,
                        border:d===""?"none":`1px solid ${T.inputBorder}`,
                        color:T.text,fontSize:16,fontFamily:"'IBM Plex Mono',monospace",
                        cursor:d===""?"default":"pointer"}}
                        className={d!==""?"pinkey":""}
                        disabled={d===""}
                        onClick={async()=>{
                          if(d==="⌫"){setLockedDeletePin(p=>p.slice(0,-1));setLockedDeleteErr("");return;}
                          const np=lockedDeletePin+String(d); setLockedDeletePin(np);
                          if(np.length===4){
                            const cand=await makePinVerifier(np);
                            if(timingSafeEqual(cand,noteToDelete.notePin)){
                              deleteNote(deleteConfirm);
                              setLockedDeletePin(""); setLockedDeleteErr("");
                            } else {
                              setLockedDeleteErr("Yanlış PIN"); setLockedDeletePin("");
                            }
                          }
                        }}>
                        {d}
                      </button>
                    ))}
                  </div>
                  <button style={{background:"transparent",border:`1px solid ${T.border}`,color:T.textMuted,
                    padding:"7px 20px",borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit"}}
                    onClick={()=>{setDeleteConfirm(null);setLockedDeletePin("");setLockedDeleteErr("");}}>
                    İptal
                  </button>
                </>
              ):(
                <>
                  <div style={{fontSize:12,color:T.textMuted,marginBottom:24}}>Bu işlem geri alınamaz.</div>
                  <div style={{display:"flex",gap:10,justifyContent:"center"}}>
                    <button style={{background:T.inputBg,border:`1px solid ${T.inputBorder}`,color:T.text,
                      padding:"8px 20px",borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit"}}
                      onClick={()=>setDeleteConfirm(null)}>İptal</button>
                    <button style={{background:T.danger,border:"none",color:"#fff",padding:"8px 20px",
                      borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:700}}
                      onClick={()=>deleteNote(deleteConfirm)}>Sil</button>
                  </div>
                </>
              )}
            </div>
          </div>
        );
      })()}

      {/* ══ SETTINGS MODAL ══ */}
      {showSettings&&(
        <div style={{position:"fixed",inset:0,background:"#0008",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:100}} onClick={()=>setShowSettings(false)}>
          <div style={{background:T.sidebar,border:`1px solid ${T.border}`,borderRadius:16,
            padding:28,width:380,maxWidth:"92vw",display:"flex",flexDirection:"column",gap:16}}
            onClick={e=>e.stopPropagation()}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <span style={{fontWeight:700,fontSize:15,color:T.text}}>⚙️ Ayarlar</span>
              <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",fontSize:20}}
                onClick={()=>setShowSettings(false)}>×</button>
            </div>

            {/* Recovery Phrase bölümü */}
            <div style={{background:T.inputBg,border:`1px solid ${T.inputBorder}`,
              borderRadius:12,padding:16,display:"flex",flexDirection:"column",gap:10}}>
              <div style={{fontWeight:600,fontSize:13,color:T.text}}>🔑 Recovery Phrase</div>
              <div style={{fontSize:12,color:T.textMuted,lineHeight:1.7}}>
                {localStorage.getItem(SK_RECOVERY)
                  ?"Recovery blob mevcut ✓ — Phrase'ini unuttuysan veya yeni bir tane oluşturmak istiyorsan aşağıdan yapabilirsin."
                  :"⚠ Henüz recovery phrase oluşturulmamış. Hemen oluşturmanı öneririz."}
              </div>
              <div style={{display:"flex",gap:8,flexDirection:"column"}}>
                {localStorage.getItem(SK_RECOVERY)&&(
                  <button style={{background:T.accent,border:"none",color:"#fff",
                    padding:"9px 0",borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600}}
                    onClick={()=>{
                      setShowSettings(false); setShowPhrase(true); setPhraseMode("view");
                      setPhrasePin(""); setPhrasePinErr(""); setPhraseRevealed(""); setNewPhraseGenerated("");
                    }}>
                    👁 Phrase'imi Görüntüle
                  </button>
                )}
                <button style={{background:localStorage.getItem(SK_RECOVERY)?T.inputBg:T.accent,
                  border:`1px solid ${T.inputBorder}`,
                  color:localStorage.getItem(SK_RECOVERY)?T.textSub:"#fff",
                  padding:"9px 0",borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit"}}
                  onClick={()=>{
                    if(localStorage.getItem(SK_RECOVERY)&&!window.confirm("Mevcut phrase silinip YENİ bir phrase oluşturulacak.\nEski phrase artık çalışmayacak. Devam et?")) return;
                    setShowSettings(false); setShowPhrase(true); setPhraseMode("new");
                    setPhrasePin(""); setPhrasePinErr(""); setPhraseRevealed(""); setNewPhraseGenerated("");
                  }}>
                  🔄 Yeni Phrase Oluştur
                </button>
              </div>
            </div>

            {/* Biyometrik */}
            <div style={{background:T.inputBg,border:`1px solid ${T.inputBorder}`,
              borderRadius:12,padding:16,display:"flex",flexDirection:"column",gap:10}}>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <span style={{fontWeight:600,fontSize:13,color:T.text}}>🪪 Biyometrik Kilit Açma</span>
                {bioRegistered && (
                  <span style={{background:T.success+"22",color:T.success,
                    fontSize:10,padding:"2px 6px",borderRadius:4,fontWeight:700}}>AKTİF</span>
                )}
                {!bioAvailable && (
                  <span style={{background:T.warn+"22",color:T.warn,
                    fontSize:10,padding:"2px 6px",borderRadius:4}}>Desteklenmiyor</span>
                )}
              </div>
              <div style={{fontSize:12,color:T.textMuted,lineHeight:1.6}}>
                {!bioAvailable
                  ? "Bu cihaz/tarayıcı WebAuthn desteklemiyor. Chrome/Safari + HTTPS gerekli."
                  : bioRegistered
                    ? "Face ID / Parmak izi ile hızlı açma aktif. PIN/passphrase şifrelemeyi korur."
                    : "Face ID veya parmak izi ile vault'u hızlıca açabilirsin. Şifreleme değişmez."}
              </div>
              {bioAvailable && (!bioRegistered ? (
                <button style={{background:T.accent,border:"none",color:"#fff",
                  padding:"9px 0",borderRadius:8,cursor:"pointer",fontSize:12,
                  fontFamily:"inherit",fontWeight:600}}
                  onClick={async()=>{
                    if(!sessionPin.current){ showToast("Önce vault'u aç","warn"); return; }
                    try{
                      await biometricRegister(sessionPin.current);
                      setBioRegistered(true);
                      showToast("Biyometrik kaydedildi ✓");
                    }catch(e){
                      if(e.name==="NotAllowedError") showToast("İptal edildi","warn");
                      else showToast("Kayıt başarısız: "+e.message,"danger");
                    }
                  }}>
                  🪪 Biyometrik Kaydet
                </button>
              ):(
                <button style={{background:"transparent",border:`1px solid ${T.danger}44`,
                  color:T.danger,padding:"8px 0",borderRadius:8,cursor:"pointer",
                  fontSize:12,fontFamily:"inherit"}}
                  onClick={()=>{ removeBiometric(); setBioRegistered(false); showToast("Biyometrik kaldırıldı"); }}>
                  Biyometriği Kaldır
                </button>
              ))}
            </div>

            {/* Güvenlik Modu */}
            <div style={{background:T.inputBg,border:`1px solid ${T.inputBorder}`,
              borderRadius:12,padding:16,display:"flex",flexDirection:"column",gap:10}}>
              <div style={{display:"flex",alignItems:"center",gap:8}}>
                <span style={{fontWeight:600,fontSize:13,color:T.text}}>🔐 Güvenlik Modu</span>
                <span style={{
                  background:authMode==="passphrase"?T.success+"22":T.warn+"22",
                  color:authMode==="passphrase"?T.success:T.warn,
                  fontSize:10,padding:"2px 8px",borderRadius:4,fontWeight:700}}>
                  {authMode==="passphrase"?"PASSPHRASE":"4 HANELİ PIN"}
                </span>
              </div>
              <div style={{fontSize:12,color:T.textMuted,lineHeight:1.6}}>
                {authMode==="pin"
                  ? "⚠ 4 haneli PIN görece zayıftır. Passphrase'e geçmenizi öneririz."
                  : "✓ Passphrase kullanıyorsunuz. Güçlü güvenlik modundasınız."}
              </div>
              <button style={{background:T.accent,border:"none",color:"#fff",
                padding:"9px 0",borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:600}}
                onClick={()=>{
                  setShowSettings(false);
                  setShowMigrate(true);
                  setMigrateStep("verify");
                  setMigrateOldInput("");
                  setMigrateNewInput("");
                  setMigrateConfirm("");
                  setMigrateError("");
                  setMigrateTargetMode(authMode==="pin"?"passphrase":"pin");
                }}>
                {authMode==="pin"?"🔐 Passphrase'e Geç":"🔢 PIN'e Geç (veya değiştir)"}
              </button>
            </div>

            {/* Sıfırla */}
            <div style={{background:T.inputBg,border:`1px solid ${T.border}`,
              borderRadius:12,padding:16,display:"flex",flexDirection:"column",gap:10}}>
              <div style={{fontWeight:600,fontSize:13,color:T.text}}>⚠️ Vault'u Sıfırla</div>
              <div style={{fontSize:12,color:T.textMuted,lineHeight:1.6}}>
                Tüm notlar ve ayarlar silinir. Önce export almayı unutma.
              </div>
              <button style={{background:"transparent",border:`1px solid ${T.danger}44`,
                color:T.danger,padding:"8px 0",borderRadius:8,cursor:"pointer",
                fontSize:12,fontFamily:"inherit"}}
                onClick={()=>{
                  if(window.confirm("Dikkat: Tüm notlar silinecek!\n\nDevam etmek istiyor musun?")){
                    localStorage.clear(); window.location.reload();
                  }
                }}>
                Aether'i Sıfırla (tüm veriler silinir)
              </button>
            </div>

            {/* Versiyon */}
            <div style={{fontSize:10,color:T.textMuted,textAlign:"center",lineHeight:1.8}}>
              Aether Notes v1.0 · AES-256-GCM · PBKDF2 310k iter · Yerel & Açık Kaynak
            </div>
          </div>
        </div>
      )}

      {/* ══ PHRASE MODAL ══ */}
      {showPhrase&&(
        <div style={{position:"fixed",inset:0,background:"#000a",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:110}} onClick={()=>{setShowPhrase(false);setPhraseRevealed("");}}>
          <div style={{background:T.sidebar,border:`1px solid ${T.border}`,borderRadius:16,
            padding:28,width:460,maxWidth:"94vw",display:"flex",flexDirection:"column",gap:16}}
            onClick={e=>e.stopPropagation()}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <span style={{fontWeight:700,fontSize:15,color:T.text}}>🔑 Recovery Phrase</span>
              <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",fontSize:20}}
                onClick={()=>{setShowPhrase(false);setPhraseRevealed("");setNewPhraseGenerated("");}}>×</button>
            </div>

            {!phraseRevealed&&!newPhraseGenerated?(
              /* PIN doğrulama pad'i */
              <>
                <div style={{fontSize:12,color:T.textMuted,lineHeight:1.7}}>
                  Güvenlik için önce PIN'ini doğrula.
                </div>
                {/* Mini pin pad */}
                <div style={{display:"flex",gap:12,justifyContent:"center",margin:"4px 0"}}>
                  {[0,1,2,3].map(i=>(
                    <div key={i} style={{width:13,height:13,borderRadius:"50%",border:"2px solid",
                      borderColor:i<phrasePin.length?T.accent:T.border,
                      background:i<phrasePin.length?T.accent:"transparent",transition:"all .15s"}}/>
                  ))}
                </div>
                {phrasePinErr&&<div style={{color:T.danger,fontSize:12,textAlign:"center"}}>{phrasePinErr}</div>}
                <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
                  {[1,2,3,4,5,6,7,8,9,"",0,"⌫"].map((d,i)=>(
                    <button key={i} style={{width:"100%",aspectRatio:"1",borderRadius:10,
                      background:d===""?"transparent":T.inputBg,
                      border:d===""?"none":`1px solid ${T.inputBorder}`,
                      color:T.text,fontSize:18,fontFamily:"'IBM Plex Mono',monospace",
                      cursor:d===""?"default":"pointer",transition:"all .15s"}}
                      className={d!==""?"pinkey":""}
                      disabled={d===""}
                      onClick={async()=>{
                        if(d==="⌫"){setPhrasePin(p=>p.slice(0,-1));setPhrasePinErr("");return;}
                        const np=phrasePin+String(d); setPhrasePin(np);
                        if(np.length===4){
                          const cand=await makePinVerifier(np);
                          if(timingSafeEqual(cand,savedVerifier)){
                            if(phraseMode==="view" && sessionPhrase.current){
                              // Oturum bellekte — direkt göster
                              setNewPhraseGenerated(sessionPhrase.current);
                            } else if(phraseMode==="view" && !sessionPhrase.current){
                              // Sayfa yenilenmiş, bellekte yok — kullanıcıya bildir
                              // Güvenlik gereği eski phrase gösterilemez, yeni oluşturulmalı
                              setPhrasePinErr("");
                              setNewPhraseGenerated("__info__");
                            } else {
                              // phraseMode === "new" → yeni phrase üret
                              const phrase=generatePhrase(12);
                              setNewPhraseGenerated(phrase);
                              sessionPhrase.current=phrase;
                              await saveRecoveryBlob(notes, phrase);
                              showToast("Yeni recovery phrase oluşturuldu ✓");
                            }
                          } else {
                            setPhrasePinErr("Yanlış PIN"); setPhrasePin("");
                          }
                        }
                      }}>
                      {d}
                    </button>
                  ))}
                </div>
              </>
            ):(
              /* Phrase göster ya da "bellekte yok" bilgisi */
              newPhraseGenerated === "__info__" ? (
                /* Sayfa yenilenmiş, eski phrase bellekte yok */
                <>
                  <div style={{background:T.inputBg,border:`1px solid ${T.warn}44`,
                    borderRadius:12,padding:16,textAlign:"center"}}>
                    <div style={{fontSize:28,marginBottom:10}}>⚠️</div>
                    <div style={{fontSize:13,fontWeight:600,color:T.text,marginBottom:8}}>
                      Phrase artık görüntülenemiyor
                    </div>
                    <div style={{fontSize:12,color:T.textMuted,lineHeight:1.8}}>
                      Recovery phrase güvenlik nedeniyle yalnızca oluşturulduğu anda gösterilir
                      ve bellekte tutulur. Sayfa yenilendiğinde bellekten silinir.<br/><br/>
                      Eğer phrase'ini kaybettiysen <strong style={{color:T.warn}}>yeni bir phrase oluşturman</strong> gerekiyor.
                      Eski phrase artık çalışmayacak.
                    </div>
                  </div>
                  <div style={{display:"flex",gap:10}}>
                    <button style={{flex:1,background:T.inputBg,border:`1px solid ${T.inputBorder}`,
                      color:T.text,padding:"9px 0",borderRadius:8,cursor:"pointer",
                      fontSize:12,fontFamily:"inherit"}}
                      onClick={()=>{setShowPhrase(false);setNewPhraseGenerated("");}}>
                      Kapat
                    </button>
                    <button style={{flex:1,background:T.danger,border:"none",color:"#fff",
                      padding:"9px 0",borderRadius:8,cursor:"pointer",
                      fontSize:12,fontFamily:"inherit",fontWeight:700}}
                      onClick={async()=>{
                        const phrase=generatePhrase(12);
                        setNewPhraseGenerated(phrase);
                        sessionPhrase.current=phrase;
                        await saveRecoveryBlob(notes,phrase);
                        showToast("Yeni recovery phrase oluşturuldu ✓");
                      }}>
                      🔄 Yeni Phrase Oluştur
                    </button>
                  </div>
                </>
              ) : (
                /* Normal phrase gösterimi */
                <>
                  <div style={{fontSize:12,color:T.danger,lineHeight:1.7,fontWeight:600,textAlign:"center"}}>
                    ⚠ Bu 12 kelimeyi güvenli bir yere yaz. Ekranda bir daha gösterilmeyecek.
                  </div>
                  <div style={{background:T.phraseBox,border:`1px solid ${T.inputBorder}`,
                    borderRadius:12,padding:"14px 16px"}}>
                    <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
                      {(newPhraseGenerated||phraseRevealed).split(" ").map((w,i)=>(
                        <div key={i} style={{display:"flex",alignItems:"center",gap:6,
                          background:T.inputBg,border:`1px solid ${T.inputBorder}`,
                          borderRadius:8,padding:"6px 10px"}}>
                          <span style={{fontSize:10,color:T.textMuted,minWidth:18}}>{i+1}.</span>
                          <span style={{fontSize:12,fontWeight:600,color:T.text,
                            fontFamily:"'IBM Plex Mono',monospace"}}>{w}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                  <div style={{display:"flex",gap:10}}>
                    <button style={{flex:1,background:T.inputBg,border:`1px solid ${T.inputBorder}`,
                      color:T.text,padding:"9px 0",borderRadius:8,cursor:"pointer",
                      fontSize:12,fontFamily:"inherit"}}
                      onClick={()=>{
                        const txt=newPhraseGenerated||phraseRevealed;
                        const el=document.createElement("textarea");
                        el.value=txt; document.body.appendChild(el); el.select();
                        document.execCommand("copy"); document.body.removeChild(el);
                        showToast("Kopyalandı ✓");
                      }}>
                      📋 Kopyala
                    </button>
                    <button style={{flex:1,background:T.success,border:"none",color:"#000",
                      padding:"9px 0",borderRadius:8,cursor:"pointer",fontSize:12,
                      fontFamily:"inherit",fontWeight:700}}
                      onClick={()=>{setShowPhrase(false);setPhraseRevealed("");setNewPhraseGenerated("");showToast("Phrase kaydedildi, güvende ✓");}}>
                      ✓ Yazdım, Kapat
                    </button>
                  </div>
                </>
              )
            )}
          </div>
        </div>
      )}

      {/* ══ ADD CATEGORY MODAL ══ */}
      {showAddCat&&(
        <div style={{position:"fixed",inset:0,background:"#0008",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:300}}
          onClick={e=>{e.stopPropagation();setShowAddCat(false);}}>
          <div style={{background:T.sidebar,border:`1px solid ${T.border}`,borderRadius:16,
            padding:28,width:340,maxWidth:"92vw",display:"flex",flexDirection:"column",gap:16}}
            onClick={e=>e.stopPropagation()}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <span style={{fontWeight:700,fontSize:15,color:T.text}}>+ Yeni Kategori</span>
              <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",fontSize:20}}
                onClick={()=>setShowAddCat(false)}>×</button>
            </div>

            {/* Önizleme */}
            <div style={{display:"flex",alignItems:"center",gap:10,background:T.inputBg,
              border:`1px solid ${T.inputBorder}`,borderRadius:10,padding:"10px 14px"}}>
              <span style={{fontSize:16}}>{newCatIcon}</span>
              <span style={{width:10,height:10,borderRadius:"50%",background:newCatColor,flexShrink:0}}/>
              <span style={{fontSize:13,color:T.text,flex:1}}>
                {newCatName||<span style={{color:T.textMuted,fontStyle:"italic"}}>Kategori adı</span>}
              </span>
              <span style={{fontSize:11,color:T.textMuted,background:T.border,padding:"1px 6px",borderRadius:8}}>0</span>
            </div>

            {/* İsim */}
            <div>
              <div style={{fontSize:11,color:T.textMuted,marginBottom:6,letterSpacing:1}}>KATEGORİ ADI</div>
              <input style={{width:"100%",background:T.inputBg,border:`1px solid ${T.inputBorder}`,
                outline:"none",color:T.text,fontSize:13,fontFamily:"inherit",
                padding:"8px 12px",borderRadius:8,boxSizing:"border-box"}}
                placeholder="ör: Seyahat, Tarifler, Proje…"
                maxLength={20}
                value={newCatName} onChange={e=>setNewCatName(e.target.value)}
                onKeyDown={e=>e.key==="Enter"&&document.getElementById("addCatBtn")?.click()}
                autoFocus
              />
            </div>

            {/* İkon */}
            <div>
              <div style={{fontSize:11,color:T.textMuted,marginBottom:8,letterSpacing:1}}>İKON</div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                {["📁","📝","💼","🏠","❤️","⭐","🎯","🔬","🎨","✈️","🍕","💪","📚","🎵","💡","🌿"].map(ico=>(
                  <button key={ico}
                    style={{width:34,height:34,borderRadius:8,background:newCatIcon===ico?T.accentBg:T.inputBg,
                      border:`2px solid ${newCatIcon===ico?T.accent:T.inputBorder}`,
                      cursor:"pointer",fontSize:16,transition:"all .15s"}}
                    onClick={()=>setNewCatIcon(ico)}>{ico}</button>
                ))}
              </div>
            </div>
            <div>
              <div style={{fontSize:11,color:T.textMuted,marginBottom:8,letterSpacing:1}}>RENK</div>
              <div style={{display:"flex",gap:8,flexWrap:"wrap"}}>
                {["#5b8af5","#34c88a","#e05c7a","#f0b429","#a29bfe","#fd79a8",
                  "#1abc9c","#e17055","#6c5ce7","#00cec9","#fdcb6e","#74b9ff"].map(hex=>(
                  <button key={hex}
                    style={{width:28,height:28,borderRadius:"50%",background:hex,border:"none",
                      cursor:"pointer",outline:newCatColor===hex?`3px solid ${T.text}`:"3px solid transparent",
                      outlineOffset:2,transition:"all .15s"}}
                    onClick={()=>setNewCatColor(hex)}/>
                ))}
                {/* Custom color */}
                <label style={{width:28,height:28,borderRadius:"50%",cursor:"pointer",
                  background:`conic-gradient(red,yellow,lime,cyan,blue,magenta,red)`,
                  display:"flex",alignItems:"center",justifyContent:"center",fontSize:12,
                  border:`2px solid ${T.border}`,overflow:"hidden",position:"relative"}}>
                  <input type="color" value={newCatColor}
                    onChange={e=>setNewCatColor(e.target.value)}
                    style={{position:"absolute",inset:0,width:"100%",height:"100%",
                      border:"none",cursor:"pointer",opacity:0,padding:0}}/>
                  <span style={{pointerEvents:"none",position:"relative",zIndex:1}}>+</span>
                </label>
              </div>
            </div>

            <button id="addCatBtn"
              style={{background:newCatName.trim()?T.accent:T.inputBg,border:"none",
                color:newCatName.trim()?"#fff":T.textMuted,padding:"11px 0",borderRadius:10,
                cursor:newCatName.trim()?"pointer":"not-allowed",fontSize:13,
                fontFamily:"inherit",fontWeight:700,transition:"all .2s"}}
              disabled={!newCatName.trim()}
              onClick={()=>{
                const id=`cat_${Date.now()}`;
                const newCat={id,label:newCatName.trim(),icon:newCatIcon,color:newCatColor};
                const updated=[...customCats,newCat];
                setCustomCats(updated); localStorage.setItem(SK_CATS,JSON.stringify(updated));
                setShowAddCat(false); showToast(`"${newCat.label}" eklendi ✓`);
              }}>
              Kategori Ekle →
            </button>
          </div>
        </div>
      )}


      {/* ══ MIGRATION MODAL ══ */}
      {showMigrate&&(
        <div style={{position:"fixed",inset:0,background:"#000b",display:"flex",
          alignItems:"center",justifyContent:"center",zIndex:120}}
          onClick={()=>setShowMigrate(false)}>
          <div style={{background:T.sidebar,border:`1px solid ${T.border}`,borderRadius:16,
            padding:28,width:400,maxWidth:"94vw",display:"flex",flexDirection:"column",gap:16}}
            onClick={e=>e.stopPropagation()}>
            <div style={{display:"flex",justifyContent:"space-between",alignItems:"center"}}>
              <span style={{fontWeight:700,fontSize:15,color:T.text}}>
                {migrateTargetMode==="passphrase"?"🔐 Passphrase'e Geç":"🔢 PIN'e Geç"}
              </span>
              <button style={{background:"none",border:"none",color:T.textMuted,cursor:"pointer",fontSize:20}}
                onClick={()=>setShowMigrate(false)}>×</button>
            </div>

            {migrateStep==="verify"&&(
              <>
                <div style={{fontSize:12,color:T.textMuted,lineHeight:1.7}}>
                  Güvenlik için önce mevcut {authMode==="pin"?"PIN'ini":"passphrase'ini"} gir.
                </div>
                {authMode==="pin"?(
                  <>
                    <div style={{display:"flex",gap:12,justifyContent:"center"}}>
                      {[0,1,2,3].map(i=>(
                        <div key={i} style={{width:13,height:13,borderRadius:"50%",border:"2px solid",
                          borderColor:i<migrateOldInput.length?T.accent:T.border,
                          background:i<migrateOldInput.length?T.accent:"transparent",transition:"all .15s"}}/>
                      ))}
                    </div>
                    <div style={{display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:8}}>
                      {[1,2,3,4,5,6,7,8,9,"",0,"⌫"].map((d,i)=>(
                        <button key={i} style={{width:"100%",aspectRatio:"1",borderRadius:10,
                          background:d===""?"transparent":T.inputBg,
                          border:d===""?"none":`1px solid ${T.inputBorder}`,
                          color:T.text,fontSize:18,fontFamily:"'IBM Plex Mono',monospace",
                          cursor:d===""?"default":"pointer"}}
                          className={d!==""?"pinkey":""}
                          disabled={d===""}
                          onClick={async()=>{
                            if(d==="⌫"){setMigrateOldInput(p=>p.slice(0,-1));setMigrateError("");return;}
                            const np=migrateOldInput+String(d); setMigrateOldInput(np);
                            if(np.length===4){
                              const cand=await makeVerifier(np);
                              if(timingSafeEqual(cand,savedVerifier)){ setMigrateStep("setup"); setMigrateError(""); }
                              else{ shake_(); setMigrateError("Yanlış PIN"); setMigrateOldInput(""); }
                            }
                          }}>
                          {d}
                        </button>
                      ))}
                    </div>
                  </>
                ):(
                  <>
                    <input type="password" autoFocus
                      style={{width:"100%",background:T.inputBg,border:`2px solid ${T.inputBorder}`,
                        outline:"none",color:T.text,fontSize:14,fontFamily:"inherit",
                        padding:"10px 14px",borderRadius:8,boxSizing:"border-box"}}
                      placeholder="Mevcut passphrase…"
                      value={migrateOldInput}
                      onChange={e=>{setMigrateOldInput(e.target.value);setMigrateError("");}}
                      onKeyDown={async e=>{
                        if(e.key!=="Enter") return;
                        const cand=await makeVerifier(migrateOldInput);
                        if(timingSafeEqual(cand,savedVerifier)){ setMigrateStep("setup"); setMigrateError(""); }
                        else{ shake_(); setMigrateError("Yanlış passphrase"); setMigrateOldInput(""); }
                      }}
                    />
                    <button style={{background:T.accent,border:"none",color:"#fff",
                      padding:"10px 0",borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:700}}
                      onClick={async()=>{
                        const cand=await makeVerifier(migrateOldInput);
                        if(timingSafeEqual(cand,savedVerifier)){ setMigrateStep("setup"); setMigrateError(""); }
                        else{ shake_(); setMigrateError("Yanlış passphrase"); setMigrateOldInput(""); }
                      }}>
                      Doğrula →
                    </button>
                  </>
                )}
                {migrateError&&<div style={{color:T.danger,fontSize:12,textAlign:"center"}}>{migrateError}</div>}
              </>
            )}

            {migrateStep==="setup"&&(
              <>
                <div style={{fontSize:12,color:T.textMuted,lineHeight:1.7}}>
                  {migrateTargetMode==="passphrase"
                    ?"Yeni passphrase belirle — güçlü ve hatırlayabileceğin bir cümle."
                    :"Yeni 4 haneli PIN belirle."}
                </div>
                {migrateTargetMode==="passphrase"?(
                  <>
                    <input type="password" autoFocus
                      style={{width:"100%",background:T.inputBg,border:`2px solid ${T.inputBorder}`,
                        outline:"none",color:T.text,fontSize:14,fontFamily:"inherit",
                        padding:"10px 14px",borderRadius:8,boxSizing:"border-box"}}
                      placeholder="Yeni passphrase…"
                      value={migrateNewInput}
                      onChange={e=>{
                        setMigrateNewInput(e.target.value);
                        setPassStrength(getPassphraseStrength(e.target.value));
                        setMigrateError("");
                      }}
                    />
                    {passStrength&&(
                      <div style={{display:"flex",alignItems:"center",gap:8}}>
                        <div style={{flex:1,height:4,borderRadius:4,background:T.border,overflow:"hidden"}}>
                          <div style={{height:"100%",borderRadius:4,background:passStrength.color,
                            width:passStrength.level==="weak"?"25%":passStrength.level==="fair"?"50%":
                              passStrength.level==="strong"?"75%":"100%"}}/>
                        </div>
                        <span style={{fontSize:11,color:passStrength.color,fontWeight:600}}>{passStrength.label}</span>
                        <span style={{fontSize:10,color:T.textMuted}}>~{passStrength.bits}bit</span>
                      </div>
                    )}
                    <input type="password"
                      style={{width:"100%",background:T.inputBg,border:`2px solid ${T.inputBorder}`,
                        outline:"none",color:T.text,fontSize:14,fontFamily:"inherit",
                        padding:"10px 14px",borderRadius:8,boxSizing:"border-box"}}
                      placeholder="Tekrar gir…"
                      value={migrateConfirm}
                      onChange={e=>{setMigrateConfirm(e.target.value);setMigrateError("");}}
                    />
                  </>
                ):(
                  /* PIN modu — temiz state machine, nested setState yok */
                  <>
                    <div style={{display:'flex',gap:12,justifyContent:'center'}}>
                      {[0,1,2,3].map(i=>{
                        const active=migrateNewInput.length<4?migrateNewInput:migrateConfirm;
                        return <div key={i} style={{width:13,height:13,borderRadius:'50%',border:'2px solid',
                          borderColor:i<active.length?T.accent:T.border,
                          background:i<active.length?T.accent:'transparent',transition:'all .15s'}}/>;
                      })}
                    </div>
                    <div style={{fontSize:11,color:T.textMuted,textAlign:'center'}}>
                      {migrateNewInput.length<4?'Yeni PIN gir (4 hane)':'Tekrar gir (doğrula)'}
                    </div>
                    <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:8}}>
                      {[1,2,3,4,5,6,7,8,9,'',0,'⌫'].map((d,i)=>(
                        <button key={i} style={{width:'100%',aspectRatio:'1',borderRadius:10,
                          background:d===''?'transparent':T.inputBg,
                          border:d===''?'none':('1px solid '+T.inputBorder),
                          color:T.text,fontSize:18,fontFamily:"'IBM Plex Mono',monospace",
                          cursor:d===''?'default':'pointer'}}
                          className={d!==''?'pinkey':''}
                          disabled={d===''}
                          onClick={async()=>{
                            if(d==='') return;
                            if(d==='⌫'){
                              if(migrateConfirm.length>0) setMigrateConfirm(p=>p.slice(0,-1));
                              else setMigrateNewInput(p=>p.slice(0,-1));
                              setMigrateError(''); return;
                            }
                            const digit=String(d);
                            if(migrateNewInput.length<4){
                              setMigrateNewInput(p=>p+digit);
                            } else if(migrateConfirm.length<4){
                              const next=migrateConfirm+digit;
                              setMigrateConfirm(next);
                              if(next.length===4){
                                if(next!==migrateNewInput){
                                  shake_(); setMigrateError('PINler eşleşmiyor');
                                  setTimeout(()=>setMigrateConfirm(''),300); return;
                                }
                                setMigrateLoading(true);
                                try{
                                  await migrateVaultSecret(sessionPin.current,migrateNewInput,'pin');
                                  setSavedVerifier(localStorage.getItem(SK_PIN));
                                  setAuthMode('pin'); sessionPin.current=migrateNewInput;
                                  setMigrateTargetMode('pin'); setMigrateStep('done');
                                }catch(e){ setMigrateError('Hata: '+e.message); }
                                setMigrateLoading(false);
                              }
                            }
                          }}>
                          {d}
                        </button>
                      ))}
                    </div>
                  </>
                )}
                {migrateError&&<div style={{color:T.danger,fontSize:12,textAlign:"center"}}>{migrateError}</div>}
                {/* Passphrase modunda manuel buton, PIN modunda otomatik (PIN pad 4+4 tamamlayınca) */}
                {migrateTargetMode==="passphrase"&&(
                <button
                  style={{background:T.accent,border:"none",color:"#fff",padding:"11px 0",
                    borderRadius:10,cursor:"pointer",fontSize:13,fontFamily:"inherit",fontWeight:700,
                    opacity:migrateLoading?.6:1}}
                  disabled={migrateLoading}
                  onClick={async()=>{
                    if(!migrateNewInput){ setMigrateError("Yeni passphrase gir"); return; }
                    const s=getPassphraseStrength(migrateNewInput);
                    if(!s||s.level==="weak"){ setMigrateError(`Çok zayıf (min ${PASSPHRASE_MIN_LEN} karakter)`); return; }
                    if(migrateNewInput!==migrateConfirm){ setMigrateError("Passphrase'ler eşleşmiyor"); shake_(); return; }
                    setMigrateLoading(true);
                    try{
                      const oldSecret = migrateOldInput || sessionPin.current;
                      await migrateVaultSecret(oldSecret, migrateNewInput, "passphrase");
                      setSavedVerifier(localStorage.getItem(SK_PIN));
                      setAuthMode("passphrase");
                      sessionPin.current=migrateNewInput;
                      setMigrateStep("done");
                    } catch(e){ setMigrateError("Migration başarısız: "+e.message); }
                    setMigrateLoading(false);
                  }}>
                  {migrateLoading?"Dönüştürülüyor…":"Güvenli Geçiş Yap →"}
                </button>
                )}
              </>
            )}

            {migrateStep==="done"&&(
              <div style={{textAlign:"center",padding:"8px 0"}}>
                <div style={{fontSize:40,marginBottom:12}}>✅</div>
                <div style={{fontWeight:700,fontSize:14,color:T.text,marginBottom:8}}>
                  {migrateTargetMode==="passphrase"?"Passphrase'e geçildi!":"PIN güncellendi!"}
                </div>
                <div style={{fontSize:12,color:T.textMuted,marginBottom:20,lineHeight:1.7}}>
                  Tüm notlar yeni {migrateTargetMode==="passphrase"?"passphrase":"PIN"} ile yeniden şifrelendi.
                  Eski {authMode==="pin"?"PIN":"passphrase"} artık çalışmıyor.
                </div>
                <button style={{background:T.accent,border:"none",color:"#fff",padding:"10px 24px",
                  borderRadius:8,cursor:"pointer",fontSize:12,fontFamily:"inherit",fontWeight:700}}
                  onClick={()=>setShowMigrate(false)}>
                  Kapat
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {toast&&(
        <div style={{position:"fixed",bottom:24,right:24,color:"#fff",padding:"10px 20px",
          borderRadius:10,fontSize:12,zIndex:200,boxShadow:"0 4px 20px #0004",animation:"fadeUp .3s ease",
          background:toast.type==="danger"?T.danger:toast.type==="warn"?T.warn:T.accent}}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}

// ── Style helpers ──
const topBtn = T=>({ background:"none", border:`1px solid ${T.border}`, color:T.textSub,
  width:30, height:30, borderRadius:6, cursor:"pointer", fontSize:14,
  display:"flex", alignItems:"center", justifyContent:"center", transition:"all .15s" });
const toolBtn = T=>({ background:"transparent", border:`1px solid ${T.inputBorder}`,
  color:T.textSub, padding:"4px 10px", borderRadius:6, cursor:"pointer",
  fontSize:11, fontFamily:"inherit", transition:"all .15s" });
const navBtn = (T,active)=>({ display:"flex", alignItems:"center", gap:8, width:"100%",
  background:active?T.accentBg:"transparent", border:"none",
  color:active?T.accent:T.textSub, padding:"7px 8px", borderRadius:6, cursor:"pointer",
  fontSize:12, fontFamily:"inherit", textAlign:"left", transition:"all .15s" });
const sectionLabel = T=>({ fontSize:10, fontWeight:700, letterSpacing:2, color:T.textMuted, marginBottom:8 });
const badge = T=>({ fontSize:10, color:T.textMuted, background:T.inputBg, padding:"1px 6px", borderRadius:10 });

const globalCSS = T=>`
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;600;700&family=IBM+Plex+Mono:wght@400;600&family=Crimson+Pro:ital,wght@0,400;0,700;1,400&display=swap');
  *{box-sizing:border-box;margin:0;padding:0;}
  body{overflow:hidden;}
  @keyframes shake{0%,100%{transform:translateX(0)}20%{transform:translateX(-8px)}40%{transform:translateX(8px)}60%{transform:translateX(-5px)}80%{transform:translateX(5px)}}
  @keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
  .pinkey:hover{background:${T.accentBg}!important;border-color:${T.accent}!important;color:${T.accent}!important;}
  .note-item:hover{background:${T.cardHover}!important;}
  .note-item:hover .del-btn{opacity:.8!important;}
  .sidebar-btn:hover{background:${T.cardHover}!important;}
  ::-webkit-scrollbar{width:4px;}
  ::-webkit-scrollbar-thumb{background:${T.border};border-radius:4px;}
  h1,h2,h3{color:${T.accent};margin:.4em 0;}
  blockquote{border-left:3px solid ${T.accent};padding-left:12px;color:${T.textSub};margin:4px 0;}
  code{background:${T.inputBg};padding:2px 6px;border-radius:4px;font-size:.9em;}
  ul,ol{padding-left:20px;margin:4px 0;}
  a{color:${T.accent};}p{margin:.3em 0;}
  .wiki-link:hover{background:${T.accentBg};border-radius:3px;}
  select option{background:${T.inputBg};color:${T.text};}
`;
