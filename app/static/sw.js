// Dudu service worker: makes the site installable and shows emergency numbers offline.
// Privacy rule: only the app shell (styles, script, icons, offline page) is cached.
// Pages with personal data, the chat API and evidence files are NEVER stored on the phone.
const CACHE = "dudu-shell-v2";
const SHELL = [
  "/offline",
  "/static/style.css",
  "/static/app.js",
  "/static/logo.png",
  "/static/favicon-32.png",
  "/static/icon-192.png",
  "/static/icon-512.png",
];

self.addEventListener("install", (event) => {
  event.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Pages: always from the network. Offline, show the offline page (never a cached private page).
  if (req.mode === "navigate") {
    event.respondWith(fetch(req).catch(() => caches.match("/offline")));
    return;
  }
  // App shell: cache first, refreshed in the background.
  if (SHELL.includes(url.pathname)) {
    event.respondWith(
      caches.match(req).then((hit) => {
        const fresh = fetch(req).then((res) => {
          if (res.ok) caches.open(CACHE).then((c) => c.put(req, res.clone()));
          return res;
        }).catch(() => hit);
        return hit || fresh;
      })
    );
  }
  // Everything else (API, evidence files, exports) goes straight to the network, uncached.
});
