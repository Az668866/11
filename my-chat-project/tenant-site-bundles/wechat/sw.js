'use strict';

const STATIC_CACHE = 'tuojie-static-v2.4.8';
const PRECACHE = [
  './manifest.webmanifest',
  './icons/icon-192.png',
  './icons/icon-512.png',
];

self.addEventListener('install', (event) => {
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then((cache) => cache.addAll(PRECACHE))
      .then(() => self.skipWaiting()),
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    const names = await caches.keys();
    await Promise.all(
      names
        .filter((name) => name.startsWith('tuojie-static-') && name !== STATIC_CACHE)
        .map((name) => caches.delete(name)),
    );
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (event) => {
  const request = event.request;
  if (request.method !== 'GET') return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith('/api/')) return;

  if (url.pathname.endsWith('/manifest.webmanifest')) {
    const tenant = String(url.searchParams.get('tenant') || '').trim();
    if (/^site_[A-Za-z0-9_-]{6,80}$/.test(tenant)) {
      const displayName = String(url.searchParams.get('name') || '在线客服')
        .replace(/[\u0000-\u001f\u007f]/g, '')
        .slice(0, 40) || '在线客服';
      const startUrl = `./?tenant=${encodeURIComponent(tenant)}`;
      event.respondWith(new Response(JSON.stringify({
        name: displayName,
        short_name: displayName.slice(0, 12),
        description: '安全的实时在线客服与消息提醒',
        lang: 'zh-CN',
        id: startUrl,
        start_url: startUrl,
        scope: './',
        display: 'standalone',
        display_override: ['window-controls-overlay', 'standalone', 'minimal-ui'],
        background_color: '#f5f7fb',
        theme_color: '#2f7ee6',
        icons: [
          { src: './icons/icon-192.png', sizes: '192x192', type: 'image/png', purpose: 'any maskable' },
          { src: './icons/icon-512.png', sizes: '512x512', type: 'image/png', purpose: 'any maskable' },
        ],
      }), {
        headers: {
          'Content-Type': 'application/manifest+json; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      }));
      return;
    }
  }

  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request).catch(() => new Response(
        '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>暂时离线</title><style>body{font-family:system-ui;margin:0;display:grid;place-items:center;min-height:100vh;background:#f4f7fb;color:#25364d}.c{max-width:320px;padding:28px;text-align:center;background:#fff;border-radius:20px;box-shadow:0 16px 50px #1c355322}button{border:0;border-radius:12px;padding:12px 20px;background:#247df0;color:#fff;font-weight:700}</style><div class="c"><h2>当前网络不可用</h2><p>聊天内容不会在离线页中传输。恢复网络后点击重试。</p><button onclick="location.reload()">重新连接</button></div>',
        { headers: { 'Content-Type': 'text/html; charset=utf-8' } },
      )),
    );
    return;
  }

  if (!['script', 'style', 'image', 'font', 'manifest'].includes(request.destination)) {
    return;
  }
  event.respondWith((async () => {
    const cached = await caches.match(request);
    if (cached) return cached;
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(STATIC_CACHE);
      await cache.put(request, response.clone());
    }
    return response;
  })());
});

self.addEventListener('push', (event) => {
  event.waitUntil((async () => {
    let payload = {};
    try {
      payload = event.data?.json?.() || {};
    } catch {
      payload = { title: '客服新通知', body: event.data?.text?.() || '' };
    }
    const windows = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true,
    });
    const visibleWindow = windows.find(
      (client) => client.visibilityState === 'visible',
    );
    if (visibleWindow) {
      visibleWindow.postMessage(payload);
      return;
    }
    await self.registration.showNotification(payload.title || '客服新通知', {
      body: payload.body || '',
      icon: payload.icon || './icons/icon-192.png',
      badge: payload.badge || './icons/icon-192.png',
      tag: payload.tag || 'tuojie-notification',
      renotify: true,
      requireInteraction: payload.type === 'incoming-call',
      data: payload.data || {},
    });
  })());
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  event.waitUntil((async () => {
    const scope = new URL(self.registration.scope);
    const requested = new URL(event.notification.data?.url || './', scope);
    const target = requested.origin === scope.origin ? requested.href : scope.href;
    const windows = await self.clients.matchAll({
      type: 'window',
      includeUncontrolled: true,
    });
    const existing = windows.find(
      (client) => new URL(client.url).origin === scope.origin,
    );
    if (existing) {
      await existing.navigate(target).catch(() => {});
      return existing.focus();
    }
    return self.clients.openWindow(target);
  })());
});
