/* Aether Notes — Service Worker v1.0 */
const CACHE = "aether-v1";

// Cache edilecek dosyalar (build sonrası React bunları üretir)
const PRECACHE = [
  "/",
  "/index.html",
  "/static/js/main.chunk.js",
  "/static/js/bundle.js",
  "/static/css/main.chunk.css",
  "/manifest.json"
];

// Install: kritik dosyaları cache'e al
self.addEventListener("install", e => {
  e.waitUntil(
    caches.open(CACHE).then(cache =>
      cache.addAll(PRECACHE).catch(() => {}) // hata olursa sessizce geç
    ).then(() => self.skipWaiting())
  );
});

// Activate: eski cache'leri temizle
self.addEventListener("activate", e => {
  e.waitUntil(
    caches.keys().then(keys =>
      Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

// Fetch: önce cache'e bak, yoksa ağdan al ve cache'e ekle
// Network-first for HTML (always fresh), Cache-first for assets
self.addEventListener("fetch", e => {
  const { request } = e;
  const url = new URL(request.url);

  // Sadece same-origin istekleri handle et
  if (url.origin !== location.origin) return;

  // HTML → Network first (sayfa güncel kalsın)
  if (request.mode === "navigate") {
    e.respondWith(
      fetch(request)
        .then(res => {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(request, clone));
          return res;
        })
        .catch(() => caches.match("/index.html"))
    );
    return;
  }

  // JS/CSS/fonts → Cache first
  e.respondWith(
    caches.match(request).then(cached => {
      if (cached) return cached;
      return fetch(request).then(res => {
        if (!res || res.status !== 200 || res.type !== "basic") return res;
        const clone = res.clone();
        caches.open(CACHE).then(c => c.put(request, clone));
        return res;
      });
    })
  );
});
