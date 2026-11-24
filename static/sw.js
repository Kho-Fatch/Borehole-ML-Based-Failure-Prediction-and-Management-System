const CACHE = 'borehole-v1';
self.addEventListener('install', function (event) {
    event.waitUntil(caches.open(CACHE).then(function (cache) { return cache.add('/offline'); }));
    self.skipWaiting();
});
self.addEventListener('activate', function (event) { event.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function (event) {
    if (event.request.mode === 'navigate') {
        event.respondWith(fetch(event.request).catch(function () { return caches.match('/offline'); }));
    }
});
