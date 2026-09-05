const RESOLVER_CACHE_MS = 5_000;
const NEGATIVE_CACHE_MS = 1_000;
const MAX_RESOLVER_CACHE_ENTRIES = 400;
const resolverCache = new Map();
const FILE_UPLOAD_PROXY_PATH = '/__file-upload-proxy';
const FILE_UPLOAD_R2_HOST =
  'tuojie-chat-media.4409400db909788c7b8e9e157c9c1b3f.r2.cloudflarestorage.com';
const FILE_UPLOAD_ORIGINS = new Set([
  'https://ykf000.com',
  'https://www.ykf000.com',
]);
const MAX_FILE_UPLOAD_BYTES = 100 * 1024 * 1024;

function fileUploadCorsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'PUT, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Cache-Control',
    'Access-Control-Max-Age': '3600',
    'Cache-Control': 'no-store',
    'Vary': 'Origin',
    'X-Content-Type-Options': 'nosniff',
  };
}

function fileUploadError(status, message, origin = '') {
  return new Response(JSON.stringify({ ok: false, error: message }), {
    status,
    headers: {
      ...(origin ? fileUploadCorsHeaders(origin) : { 'Cache-Control': 'no-store' }),
      'Content-Type': 'application/json; charset=utf-8',
    },
  });
}

async function proxyFileUpload(request, incomingUrl) {
  const origin = String(request.headers.get('Origin') || '');
  if (!FILE_UPLOAD_ORIGINS.has(origin)) {
    return fileUploadError(403, '上传来源无效。');
  }
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: fileUploadCorsHeaders(origin),
    });
  }
  if (request.method !== 'PUT') {
    return fileUploadError(405, '请求方式无效。', origin);
  }
  const suppliedSize = Number(request.headers.get('Content-Length'));
  if (
    !Number.isSafeInteger(suppliedSize) ||
    suppliedSize <= 0 ||
    suppliedSize > MAX_FILE_UPLOAD_BYTES
  ) {
    return fileUploadError(413, '文件大小无效。', origin);
  }
  let target;
  try {
    target = new URL(incomingUrl.searchParams.get('target') || '');
  } catch {
    return fileUploadError(400, '上传地址无效。', origin);
  }
  if (
    target.protocol !== 'https:' ||
    target.hostname !== FILE_UPLOAD_R2_HOST ||
    target.username ||
    target.password ||
    target.port ||
    !target.pathname.startsWith('/chat-files/') ||
    !target.searchParams.has('X-Amz-Signature') ||
    !target.searchParams.has('X-Amz-Expires')
  ) {
    return fileUploadError(400, '上传地址无效。', origin);
  }
  const headers = new Headers();
  headers.set(
    'Content-Type',
    String(request.headers.get('Content-Type') || 'application/octet-stream'),
  );
  headers.set('Cache-Control', 'private, no-store');
  try {
    const response = await fetch(target, {
      method: 'PUT',
      headers,
      body: request.body,
      redirect: 'manual',
    });
    if (!response.ok) {
      return fileUploadError(502, `R2 上传失败（${response.status}）。`, origin);
    }
    return new Response(null, {
      status: 204,
      headers: fileUploadCorsHeaders(origin),
    });
  } catch {
    return fileUploadError(502, 'Cloudflare 无法连接文件存储。', origin);
  }
}

function makeResolverCacheRoom(now) {
  for (const [key, item] of resolverCache) {
    if (!item || item.expiresAt <= now) resolverCache.delete(key);
  }
  while (resolverCache.size >= MAX_RESOLVER_CACHE_ENTRIES) {
    const oldestKey = resolverCache.keys().next().value;
    if (oldestKey === undefined) break;
    resolverCache.delete(oldestKey);
  }
}

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
    return null;
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
  let resolution = null;
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
      const upstreamBaseUrl = normalizeBaseUrl(result?.upstreamBaseUrl);
      if (upstreamBaseUrl) {
        resolution = {
          upstreamBaseUrl,
          tenantCode: String(result?.tenantCode || '').trim(),
        };
      }
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
    resolution = null;
  }
  makeResolverCacheRoom(now);
  resolverCache.set(hostname, {
    value: resolution,
    expiresAt: now + (resolution ? RESOLVER_CACHE_MS : NEGATIVE_CACHE_MS),
  });
  return resolution;
}

function upstreamRequest(request, resolution) {
  const incomingUrl = new URL(request.url);
  const targetUrl = new URL(resolution.upstreamBaseUrl);
  const basePath = targetUrl.pathname.replace(/\/+$/, '');
  targetUrl.pathname = `${basePath}${incomingUrl.pathname}` || '/';
  targetUrl.search = incomingUrl.search;
  if (resolution.tenantCode && !targetUrl.searchParams.has('tenant')) {
    targetUrl.searchParams.set('tenant', resolution.tenantCode);
  }
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

function rewriteResponse(response, resolution, publicOrigin) {
  const headers = new Headers(response.headers);
  const location = headers.get('Location');
  if (location) {
    try {
      const upstreamOrigin = new URL(resolution.upstreamBaseUrl).origin;
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
  if (
    resolution.tenantCode &&
    String(headers.get('Content-Type') || '').toLowerCase().includes('text/html')
  ) {
    headers.append(
      'Set-Cookie',
      `tuojie_tenant=${encodeURIComponent(resolution.tenantCode)}; Path=/; Secure; SameSite=Lax`,
    );
  }
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
    if (incomingUrl.pathname === FILE_UPLOAD_PROXY_PATH) {
      return proxyFileUpload(request, incomingUrl);
    }
    if (shouldBypass(hostname, env)) return fetch(request);

    const resolution = await resolveUpstream(hostname, env);
    if (!resolution) return unavailableResponse();

    try {
      const response = await fetch(upstreamRequest(request, resolution));
      return rewriteResponse(response, resolution, incomingUrl.origin);
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
