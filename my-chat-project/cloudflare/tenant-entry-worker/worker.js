const JSON_HEADERS = {
  Accept: 'application/json',
};

function cleanBase(value) {
  return String(value || '').trim().replace(/\/+$/, '');
}

function htmlError(status, message) {
  return new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>入口不可用</title><style>body{font-family:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;margin:0;display:grid;place-items:center;min-height:100vh;background:#f6f7fb;color:#273047}.box{max-width:560px;margin:24px;padding:32px;border-radius:18px;background:#fff;box-shadow:0 16px 50px #26324a18;text-align:center}h1{font-size:22px}p{line-height:1.8;color:#667085}</style><div class="box"><h1>专属客服入口暂不可用</h1><p>${String(message || '请联系商家获取新的客服链接或二维码。')}</p></div>`,
    {
      status,
      headers: {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'private, no-store',
        'X-Robots-Tag': 'noindex, nofollow, noarchive',
        'X-Content-Type-Options': 'nosniff',
      },
    },
  );
}

function reservedHosts(env) {
  return new Set(
    String(env.RESERVED_HOSTS || 'api.ykf000.com,go.ykf000.com,www.ykf000.com,ykf000.com')
      .split(',')
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean),
  );
}

async function resolveEndpoint(hostname, env, { fresh = false } = {}) {
  const backend = cleanBase(env.BACKEND_API_BASE);
  if (!/^https:\/\//i.test(backend)) {
    throw new Error('Worker 尚未配置 BACKEND_API_BASE。');
  }
  if (!env.TENANT_ENTRY_GATEWAY_SECRET) {
    throw new Error('Worker 尚未配置 TENANT_ENTRY_GATEWAY_SECRET。');
  }
  const cacheKey = new Request(
    `https://tenant-entry-cache.invalid/${encodeURIComponent(hostname)}`,
  );
  let cached = null;
  if (!fresh) {
    try {
      cached = await caches.default.match(cacheKey);
    } catch (error) {
      console.warn('tenant-entry-cache-read-failed', String(error?.message || error));
    }
  }
  if (cached) return cached.json();
  const response = await fetch(
    `${backend}/api/public/tenant-entry/resolve?hostname=${encodeURIComponent(hostname)}`,
    {
      headers: {
        ...JSON_HEADERS,
        'X-Tenant-Entry-Gateway': env.TENANT_ENTRY_GATEWAY_SECRET,
      },
      cf: { cacheTtl: 0, cacheEverything: false },
    },
  );
  const result = await response.json().catch(() => null);
  if (!response.ok || !result?.templateBaseUrl) {
    throw Object.assign(
      new Error(result?.error || `入口解析失败 (${response.status})`),
      { status: response.status },
    );
  }
  const ttl = Math.max(5, Math.min(300, Number(env.RESOLVE_CACHE_SECONDS || 30)));
  const cacheResponse = new Response(JSON.stringify(result), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': `public, max-age=${ttl}`,
    },
  });
  try {
    await caches.default.put(cacheKey, cacheResponse);
  } catch (error) {
    console.warn('tenant-entry-cache-write-failed', String(error?.message || error));
  }
  return result;
}

function upstreamUrl(requestUrl, templateBaseUrl) {
  const incoming = new URL(requestUrl);
  const base = new URL(templateBaseUrl);
  if (base.protocol !== 'https:') throw new Error('用户端模板必须使用 HTTPS。');
  const basePath = base.pathname.replace(/\/+$/, '');
  base.pathname = `${basePath}${incoming.pathname.startsWith('/') ? '' : '/'}${incoming.pathname}`;
  base.search = incoming.search;
  base.hash = '';
  return base;
}

function navigationNeedsIdentity(request, url, resolved) {
  const acceptsHtml = String(request.headers.get('accept') || '').includes('text/html');
  if (!acceptsHtml) return false;
  return url.searchParams.get('tenant') !== resolved.tenantCode ||
    url.searchParams.get('entry') !== resolved.entryToken;
}

function legacyNavigationTarget(request, url, resolved) {
  const acceptsHtml = String(request.headers.get('accept') || '').includes('text/html');
  const currentHostname = String(resolved.currentHostname || '').toLowerCase();
  if (
    !acceptsHtml ||
    resolved.domainStatus !== 'legacy' ||
    !currentHostname ||
    currentHostname === url.hostname.toLowerCase()
  ) return '';
  const target = new URL(url);
  target.protocol = 'https:';
  target.hostname = currentHostname;
  target.port = '';
  target.searchParams.set('tenant', resolved.tenantCode);
  target.searchParams.set(
    'entry',
    resolved.currentEntryToken || resolved.entryToken,
  );
  return target.toString();
}

function rewriteLocation(location, upstreamOrigin, publicOrigin) {
  if (!location) return '';
  try {
    const target = new URL(location, upstreamOrigin);
    if (target.origin !== upstreamOrigin) return target.toString();
    return `${publicOrigin}${target.pathname}${target.search}${target.hash}`;
  } catch {
    return location;
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const hostname = url.hostname.toLowerCase();
    if (reservedHosts(env).has(hostname)) return fetch(request);
    if (!['GET', 'HEAD'].includes(request.method)) {
      return new Response('Method Not Allowed', { status: 405 });
    }
    try {
      // 页面导航始终查询最新记录，确保租户点击“二维码异常”后旧域名
      // 能立即跳到新域名；静态资源仍使用短缓存，降低后端读取量。
      const resolved = await resolveEndpoint(hostname, env, {
        fresh: String(request.headers.get('accept') || '').includes('text/html'),
      });
      const legacyTarget = legacyNavigationTarget(request, url, resolved);
      if (legacyTarget) return Response.redirect(legacyTarget, 302);
      if (navigationNeedsIdentity(request, url, resolved)) {
        url.protocol = 'https:';
        url.searchParams.set('tenant', resolved.tenantCode);
        url.searchParams.set('entry', resolved.entryToken);
        return Response.redirect(url.toString(), 302);
      }
      const target = upstreamUrl(request.url, resolved.templateBaseUrl);
      const headers = new Headers(request.headers);
      headers.delete('host');
      headers.delete('cookie');
      const upstreamResponse = await fetch(
        new Request(target.toString(), {
          method: request.method,
          headers,
          redirect: 'manual',
        }),
      );
      const responseHeaders = new Headers(upstreamResponse.headers);
      responseHeaders.delete('set-cookie');
      responseHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
      responseHeaders.set('X-Content-Type-Options', 'nosniff');
      responseHeaders.set('Referrer-Policy', 'strict-origin-when-cross-origin');
      responseHeaders.set('X-Robots-Tag', 'noindex, nofollow, noarchive');
      const rewrittenLocation = rewriteLocation(
        responseHeaders.get('location'),
        new URL(resolved.templateBaseUrl).origin,
        url.origin,
      );
      if (rewrittenLocation) responseHeaders.set('Location', rewrittenLocation);
      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      const status = Number(error?.status);
      console.error('tenant-entry-gateway-failed', {
        hostname,
        status: Number.isFinite(status) ? status : null,
        message: String(error?.message || error || 'unknown').slice(0, 500),
      });
      return htmlError(
        [404, 410].includes(status) ? status : 502,
        [404, 410].includes(status)
          ? '该入口不存在、已经停用或对应租户服务已到期，请联系商家获取新的二维码。'
          : '入口网关暂时无法连接，请稍后重试。',
      );
    }
  },
};
