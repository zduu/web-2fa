const CACHE = '2fa-cache-v13';
const ASSETS = [
  '/',
  '/index.html',
  '/styles.css',
  '/app.js',
  '/runtime-config.js',
  '/theme-bootstrap.js',
  '/shared.html',
  '/shared.js',
  '/manifest.webmanifest',
  '/assets/icons/apple-touch-icon.png',
  '/assets/icons/icon-192.png',
  '/assets/icons/icon-512.png',
  '/assets/icons/icon-maskable-192.png',
  '/assets/icons/icon-maskable-512.png',
  '/assets/icons/icon.svg',
  '/assets/icons/icon-maskable.svg',

  // src/core
  '/src/core/totp.js',
  '/src/core/crypto.js',
  '/src/core/storage.js',
  '/src/core/version.js',
  '/src/core/idle.js',
  '/src/core/runtime.js',
  '/src/core/password-strength.js',
  '/src/core/imports.js',
  '/src/core/migration-formats.js',
  '/src/core/passkey.js',
  '/src/core/qrdecode.js',
  '/src/core/qrdecode-vendor.js',
  '/src/core/qrgen.js',
  '/src/core/qrgen-vendor.js',
  '/src/core/share-password.js',

  // src/sync
  '/src/sync/sync.js',
  '/src/sync/projects.js',
  '/src/sync/vault.js',
  '/src/sync/cloud.js',

  // src/share
  '/src/share/share.js',

  // src/ui
  '/src/ui/home.js',
  '/src/ui/add.js',
  '/src/ui/scanner.js',
  '/src/ui/drawer.js',
  '/src/ui/modal.js',
  '/src/ui/toast.js',
  '/src/ui/ring.js',
  '/src/ui/avatar.js',
  '/src/ui/import-export.js',
  '/src/ui/prefs.js',
  '/src/ui/theme.js',

  // src/admin
  '/src/admin/unlock.js',
];

self.addEventListener('install', (e) => {
  e.waitUntil((async () => {
    const c = await caches.open(CACHE);
    // best-effort: don't fail install if some optional asset is missing
    await Promise.all(ASSETS.map(a => c.add(a).catch(() => {})));
    // 8.1：不再 skipWaiting；让前端决定何时切换到新版本
  })());
});

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)));
    self.clients.claim();
  })());
});

self.addEventListener('message', (e) => {
  if (e.data === 'SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin === location.origin) {
    if (url.pathname.startsWith('/api/')) return;
    if (req.mode === 'navigate') {
      e.respondWith((async () => {
        const cache = await caches.open(CACHE);
        const res = await fetch(req).catch(() => cache.match('/index.html'));
        return res || cache.match('/index.html');
      })());
      return;
    }
    e.respondWith((async () => {
      const cache = await caches.open(CACHE);
      const cached = await cache.match(req);
      if (cached) return cached;
      const res = await fetch(req);
      if (res && res.ok) cache.put(req, res.clone());
      return res;
    })());
  }
});
