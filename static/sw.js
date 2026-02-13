/* Minimal service worker to make the app installable (PWA) on Android.
   This caches the app shell (GET requests only). Scans still require network. */

const CACHE_NAME = "safescan-v5";
const APP_SHELL = [
  "/",
  "/download",
  "/static/style.css",
  "/static/hero-security.svg",
  "/static/manifest.webmanifest",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png",
  "/static/icons/maskable-192.png",
  "/static/icons/maskable-512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches
      .open(CACHE_NAME)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches
      .keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  if (event.request.method !== "GET") return;

  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin) return;

  const path = url.pathname;
  const isStatic = path.startsWith("/static/");
  const isPage = event.request.mode === "navigate" && (path === "/" || path === "/download");
  if (!isStatic && !isPage) return;

  // Network-first so updates ship immediately after a deploy.
  // Cache is used as fallback for offline/spotty connections.
  event.respondWith(
    fetch(event.request)
      .then((resp) => {
        if (resp && resp.ok) {
          const copy = resp.clone();
          caches.open(CACHE_NAME).then((cache) => cache.put(event.request, copy));
        }
        return resp;
      })
      .catch(() =>
        caches.match(event.request).then((cached) => {
          if (cached) return cached;
          if (isPage) {
            return caches.match("/").then((shell) => shell || Response.error());
          }
          return Response.error();
        })
      )
  );
});
