/* IE Billing — Service Worker (offline support)
   Online: hamesha network se taaza file (cache bhi update hota hai).
   Offline: cache se khulta hai. Supabase/API calls kabhi cache nahi hoti.
   APK / /app/ folder: service worker ke raaste se nahi jaata, seedha server se aata hai.
   ie-v5: purana ie-v4 cache delete hoga, aur slow net pe bhi taaza file milegi —
   5s timeout wala purana cache ab nahi diya jayega, sirf net fail hone pe cache milega. */
var VER = 'ie-v5';
var CORE = ['loader.html', 'billing.html'];
var LIBS = [
  'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2',
  'https://unpkg.com/html5-qrcode@2.3.8/html5-qrcode.min.js',
  'https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&display=swap'
];
var SKIP = /admin-panel|\.apk|\/app\/|\.supabase\.co|razorpay|googleapis\.com\/(?!css)|firebase|generativelanguage/i;

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

  /* App ki apni files: network pehle (taaza), sirf net fail hone pe cache.
     Pehle 5s timeout pe purana cache de diya jata tha — isiliye slow net pe
     APK purana billing.html dikhata tha. Ab timeout nahi hai. */
  if (same) {
    e.respondWith(
      fetch(req).then(function (res) {
        if (res.redirected || res.type === 'opaqueredirect' || !res.ok) { return res; }
        put(key, res.clone());
        return res;
      }).catch(function () {
        return caches.open(VER).then(function (c) { return c.match(key); }).then(function (m) {
          return m || new Response('Offline — pehli baar app net ke saath kholo.', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
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
