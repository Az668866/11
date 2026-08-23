const RESOLVER_CACHE_MS = 30_000;
const NEGATIVE_CACHE_MS = 5_000;
const resolverCache = new Map();

function normalizeBaseUrl(value) {
  try {
    const parsed = new URL(String(value || '').trim());
    if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
      return '';
    }
    parsed.search = '';
    parsed.hash = '';
    return parsed.toString();
  } catch {
    return '';
  }
}

function shouldBypass(hostname, env) {
  const reserved = String(
    env.RESERVED_HOSTS || 'api.ykf000.com,go.ykf000.com,www.ykf000.com,ykf000.com',
  )
    .split(',')
    .map((item) => item.trim().toLowerCase())
    .filter(Boolean);
  return reserved.includes(hostname);
}

function unavailableResponse() {
  return new Response(`<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>客服入口暂不可用</title>
  <style>
    body{margin:0;background:#f5f7fa;color:#1f2937;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}
    main{min-height:100vh;display:grid;place-items:center;padding:24px;box-sizing:border-box}
    section{max-width:420px;background:#fff;border-radius:16px;padding:32px 28px;text-align:center;box-shadow:0 12px 35px rgba(15,23,42,.08)}
    h1{font-size:20px;margin:0 0 12px}p{font-size:14px;line-height:1.7;color:#64748b;margin:0}
  </style>
</head>
<body><main><section><h1>专属客服入口暂不可用</h1><p>请稍后重试，或联系商家重新获取客服入口。</p></section></main></body>
</html>`, {
    status: 503,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  });
}

async function resolveUpstream(hostname, env) {
  const now = Date.now();
  const cached = resolverCache.get(hostname);
  if (cached && cached.expiresAt > now) return cached.value;

  const backendBaseUrl = normalizeBaseUrl(
    env.BACKEND_API_BASE || env.BACKEND_BASE_URL,
  );
  const secret = String(env.TENANT_ENTRY_GATEWAY_SECRET || '');
  if (!backendBaseUrl || secret.length < 32) {
    console.error(JSON.stringify({
      event: 'tenant_entry_gateway_config_invalid',
      backendConfigured: Boolean(backendBaseUrl),
      secretConfigured: secret.length >= 32,
      secretLength: secret.length,
    }));
    return '';
  }

  const resolverUrl = new URL('/api/public/tenant-entry/resolve', backendBaseUrl);
  resolverUrl.searchParams.set('host', hostname);
  let upstreamBaseUrl = '';
  try {
    const response = await fetch(resolverUrl, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
        'X-Tenant-Entry-Gateway-Secret': secret,
      },
      redirect: 'manual',
    });
    if (response.ok) {
      const result = await response.json();
      upstreamBaseUrl = normalizeBaseUrl(result?.upstreamBaseUrl);
    } else {
      console.error(JSON.stringify({
        event: 'tenant_entry_resolver_rejected',
        hostname,
        status: response.status,
      }));
    }
  } catch (error) {
    console.error(JSON.stringify({
      event: 'tenant_entry_resolver_fetch_failed',
      hostname,
      message: String(error?.message || error || 'unknown').slice(0, 200),
    }));
    upstreamBaseUrl = '';
  }
  resolverCache.set(hostname, {
    value: upstreamBaseUrl,
    expiresAt: now + (upstreamBaseUrl ? RESOLVER_CACHE_MS : NEGATIVE_CACHE_MS),
  });
  return upstreamBaseUrl;
}

function upstreamRequest(request, upstreamBaseUrl) {
  const incomingUrl = new URL(request.url);
  const targetUrl = new URL(upstreamBaseUrl);
  const basePath = targetUrl.pathname.replace(/\/+$/, '');
  targetUrl.pathname = `${basePath}${incomingUrl.pathname}` || '/';
  targetUrl.search = incomingUrl.search;
  targetUrl.hash = '';

  const headers = new Headers(request.headers);
  headers.delete('Authorization');
  headers.delete('Cookie');
  headers.delete('Host');
  headers.delete('X-Tenant-Entry-Gateway-Secret');
  for (const name of [...headers.keys()]) {
    if (name.toLowerCase().startsWith('cf-')) headers.delete(name);
  }

  return new Request(targetUrl, {
    method: request.method,
    headers,
    body: ['GET', 'HEAD'].includes(request.method) ? undefined : request.body,
    redirect: 'manual',
  });
}

function rewriteResponse(response, upstreamBaseUrl, publicOrigin) {
  const headers = new Headers(response.headers);
  const location = headers.get('Location');
  if (location) {
    try {
      const upstreamOrigin = new URL(upstreamBaseUrl).origin;
      const redirectUrl = new URL(location, upstreamOrigin);
      if (redirectUrl.origin === upstreamOrigin) {
        headers.set(
          'Location',
          `${publicOrigin}${redirectUrl.pathname}${redirectUrl.search}${redirectUrl.hash}`,
        );
      }
    } catch {
      headers.delete('Location');
    }
  }
  headers.set('Strict-Transport-Security', 'max-age=31536000');
  headers.set('X-Content-Type-Options', 'nosniff');
  headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

export default {
  async fetch(request, env) {
    const incomingUrl = new URL(request.url);
    const hostname = incomingUrl.hostname.toLowerCase();
    if (shouldBypass(hostname, env)) return fetch(request);

    const upstreamBaseUrl = await resolveUpstream(hostname, env);
    if (!upstreamBaseUrl) return unavailableResponse();

    try {
      const response = await fetch(upstreamRequest(request, upstreamBaseUrl));
      return rewriteResponse(response, upstreamBaseUrl, incomingUrl.origin);
    } catch (error) {
      console.error(JSON.stringify({
        event: 'tenant_entry_upstream_fetch_failed',
        hostname,
        message: String(error?.message || error || 'unknown').slice(0, 200),
      }));
      return unavailableResponse();
    }
  },
};
