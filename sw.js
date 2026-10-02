/* IE Billing — Service Worker (offline support)
   Online: hamesha network se taaza file (cache bhi update hota hai).
   Offline: cache se khulta hai. Supabase/API calls kabhi cache nahi hoti. */
var VER = 'ie-v1';
var CORE = ['loader.html', 'billing.html'];
var LIBS = [
  'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2',
  'https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js',
  'https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap'
];
var SKIP = /admin-panel|\.supabase\.co|razorpay|googleapis\.com\/(?!css)|firebase|generativelanguage/i;

/* ?v=... hataao aur .html hataao, taaki /billing aur billing.html?v=123 ek hi cache key bane */
function keyOf(u) {
  var x = new URL(u, self.location.href);
  if (x.origin !== self.location.origin) return x.href;
  return x.origin + x.pathname.replace(/\.html$/, '');
}
function clean(res) {            /* redirect wala response navigation ke liye allowed nahi — naya bana do */
  if (!res.redirected) return Promise.resolve(res);
  return res.clone().blob().then(function (b) {
    return new Response(b, { status: 200, statusText: 'OK', headers: res.headers });
  });
}
function put(key, res) {
  if (!res || !(res.ok || res.type === 'opaque')) return Promise.resolve();
  return clean(res.clone()).then(function (r) {
    return caches.open(VER).then(function (c) { return c.put(key, r); });
  }).catch(function () {});
}

self.addEventListener('install', function (e) {
  e.waitUntil(
    caches.open(VER).then(function (c) {
      var jobs = CORE.map(function (p) {
        return fetch(p, { cache: 'reload' }).then(function (r) { return put(keyOf(p), r); }).catch(function () {});
      }).concat(LIBS.map(function (u) {
        return fetch(u, { mode: 'no-cors' }).then(function (r) { return put(u, r); }).catch(function () {});
      }));
      return Promise.all(jobs);
    }).then(function () { return self.skipWaiting(); })
  );
});

self.addEventListener('activate', function (e) {
  e.waitUntil(
    caches.keys().then(function (ks) {
      return Promise.all(ks.filter(function (k) { return k !== VER; }).map(function (k) { return caches.delete(k); }));
    }).then(function () { return self.clients.claim(); })
  );
});

self.addEventListener('fetch', function (e) {
  var req = e.request;
  if (req.method !== 'GET' || SKIP.test(req.url)) return;
  var url = new URL(req.url);
  var same = url.origin === self.location.origin;
  var key = keyOf(req.url);

  /* App ki apni files: network pehle (taaza), fail ya 5s se der ho to cache */
  if (same) {
    e.respondWith(
      new Promise(function (resolve) {
        var done = false;
        function fromCache() {
          return caches.open(VER).then(function (c) { return c.match(key); });
        }
        var t = setTimeout(function () {
          fromCache().then(function (m) { if (m && !done) { done = true; resolve(m); } });
        }, 5000);
        fetch(req).then(function (res) {
          clearTimeout(t);
          if (done) { put(key, res); return; }
          done = true;
          if (res.redirected || res.type === 'opaqueredirect' || !res.ok) { resolve(res); return; }
          put(key, res.clone());
          resolve(res);
        }).catch(function () {
          clearTimeout(t);
          if (done) return;
          fromCache().then(function (m) {
            done = true;
            resolve(m || new Response('Offline — pehli baar app net ke saath kholo.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }));
          });
        });
      })
    );
    return;
  }

  /* Bahar ki libraries / fonts: cache pehle, peeche se update */
  e.respondWith(
    caches.open(VER).then(function (c) {
      return c.match(key).then(function (m) {
        var net = fetch(req).then(function (res) { put(key, res.clone()); return res; }).catch(function () { return m; });
        return m || net;
      });
    })
  );
});
