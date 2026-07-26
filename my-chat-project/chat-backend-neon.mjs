/**
 * Render + Neon 客服聊天后端
 * Node.js 20+ / PostgreSQL (Neon)
 *
 * 持久化策略：
 *   - 会话、消息、图片、快捷语、自动回复和设置全部存入 Neon PostgreSQL
 *   - 不创建本地数据目录，不读写 Render 磁盘
 *   - JavaScript 全局变量不保存聊天记录；仅保留 SSE 连接和限流计数等瞬时运行状态
 *   - 消息和图片最多保留 24 小时
 *
 * 必填环境变量：
 *   DATABASE_URL     Neon 的 pooled PostgreSQL 连接串
 *   ALLOWED_ORIGINS  用户端和客户后台域名，英文逗号分隔
 *   TOKEN_SECRET     至少32个字符的随机密钥
 *
 * Telegram 私聊发卡（启用时三项都必须设置）：
 *   TELEGRAM_BOT_TOKEN
 *   TELEGRAM_WEBHOOK_SECRET
 *   TELEGRAM_ALLOWED_PRIVATE_USER_IDS 允许私聊发卡的 Telegram 数字用户 ID，英文逗号分隔
 *
 * 可选环境变量：
 *   PORT=10000
 *   HOST=0.0.0.0
 *   CHAT_RETENTION_HOURS=24（强制不超过24小时）
 *   TOKEN_TTL_HOURS=24
 *   MAX_IMAGE_MB=8
 *   MAX_CONVERSATIONS=1000
 *   DB_POOL_MAX=5
 */

import http from 'node:http';
import {
  createHmac,
  randomBytes,
  randomUUID,
  timingSafeEqual,
} from 'node:crypto';
import pg from 'pg';

const { Pool } = pg;

const PORT = Number(process.env.PORT || 10000);
const HOST = process.env.HOST || '0.0.0.0';
const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();
const TOKEN_SECRET_TEXT = process.env.TOKEN_SECRET || '';
const TELEGRAM_BOT_TOKEN = String(process.env.TELEGRAM_BOT_TOKEN || '').trim();
const TELEGRAM_WEBHOOK_SECRET = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
const TELEGRAM_ALLOWED_PRIVATE_USER_IDS = new Set(
  String(process.env.TELEGRAM_ALLOWED_PRIVATE_USER_IDS || '')
    .split(',')
    .map((item) => item.trim())
    .filter((item) => /^\d+$/.test(item)),
);
const TELEGRAM_ENABLED = Boolean(TELEGRAM_BOT_TOKEN);
const MAX_IMAGE_BYTES =
  Math.max(1, Number(process.env.MAX_IMAGE_MB || 8)) * 1024 * 1024;
const MAX_CONVERSATIONS = Math.max(
  10,
  Number(process.env.MAX_CONVERSATIONS || 1000),
);
const RETENTION_HOURS = Math.min(
  24,
  Math.max(1, Number(process.env.CHAT_RETENTION_HOURS || 24)),
);
const TOKEN_TTL_SECONDS = Math.min(
  RETENTION_HOURS * 3600,
  Math.max(1, Number(process.env.TOKEN_TTL_HOURS || 24)) * 3600,
);
const DB_POOL_MAX = Math.min(
  20,
  Math.max(1, Number(process.env.DB_POOL_MAX || 5)),
);

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((item) => item.trim().replace(/\/$/, ''))
  .filter(Boolean);

if (!DATABASE_URL || !/^postgres(?:ql)?:\/\//i.test(DATABASE_URL)) {
  throw new Error('DATABASE_URL 必须设置为 Neon PostgreSQL 连接串。');
}


if (!ALLOWED_ORIGINS.length) {
  throw new Error(
    'ALLOWED_ORIGINS 必须设置，例如：https://user.example.com,https://admin.example.com',
  );
}

if (TOKEN_SECRET_TEXT.length < 32) {
  throw new Error('TOKEN_SECRET 必须设置，且至少32个字符。');
}
if (TELEGRAM_ENABLED) {
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(TELEGRAM_WEBHOOK_SECRET)) {
    throw new Error('TELEGRAM_WEBHOOK_SECRET 必须为16-256位字母、数字、下划线或短横线。');
  }
  if (!TELEGRAM_ALLOWED_PRIVATE_USER_IDS.size) {
    throw new Error(
      '启用 Telegram 时必须设置 TELEGRAM_ALLOWED_PRIVATE_USER_IDS 私聊操作员白名单。',
    );
  }
}

const TOKEN_SECRET = Buffer.from(TOKEN_SECRET_TEXT, 'utf8');
const ALLOWED_IMAGE_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
]);

const pool = new Pool({
  connectionString: DATABASE_URL,
  max: DB_POOL_MAX,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 12_000,
  allowExitOnIdle: false,
});

pool.on('error', (error) => {
  console.error('Neon 连接池错误：', error);
});

// 这里只保存实时连接和限流计数，不保存聊天内容。
const sseClients = new Set();
const rateBuckets = new Map();
let lastCleanupAt = 0;
let cleanupPromise = null;

function nowIso() {
  return new Date().toISOString();
}

function defaultConfig() {
  return {
    cannedReplies: [
      {
        id: '4c0f8612-6be5-4a61-9fbe-b9be746bcd6d',
        title: '您好',
        text: '您好，请问有什么可以帮您？',
      },
      {
        id: 'b58f8da7-a505-43a4-97ce-48434934066a',
        title: '稍等',
        text: '好的，请稍等，我现在为您核实。',
      },
      {
        id: 'ea08dfd7-94a1-4436-aac6-18a00ecb8ff8',
        title: '已收到',
        text: '您的信息已收到，我们会尽快处理。',
      },
    ],
    autoReplies: [
      {
        id: '276e1703-c1b3-47b1-a3f6-0a40d9d18015',
        name: '价格咨询',
        enabled: true,
        keywords: ['价格', '多少钱', '报价'],
        replyText:
          '您好，价格会根据具体需求确定。请留下您的需求、数量或预算，客服会尽快回复。',
      },
      {
        id: '020108c9-e639-4f24-9841-623019eb668e',
        name: '人工客服',
        enabled: true,
        keywords: ['人工', '客服', '转人工'],
        replyText: '已记录人工客服请求，请稍等，客服上线后会优先回复。',
      },
    ],
    settings: {
      siteName: '在线客服',
      welcomeText: '您好，欢迎咨询。您可以发送文字或图片，我们会尽快回复。',
      autoReplyEnabled: true,
      defaultAutoReplyEnabled: true,
      defaultAutoReply: '消息已收到，客服看到后会尽快回复。',
      autoReplyCooldownSeconds: 20,
      userSiteUrl: '',
    },
  };
}

async function initDatabase() {
  const defaults = defaultConfig();
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    await client.query(`
      CREATE TABLE IF NOT EXISTS app_config (
        id SMALLINT PRIMARY KEY CHECK (id = 1),
        canned_replies JSONB NOT NULL,
        auto_replies JSONB NOT NULL,
        settings JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tenants (
        id UUID PRIMARY KEY,
        public_code TEXT NOT NULL UNIQUE,
        status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended')),
        access_expires_at TIMESTAMPTZ NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS license_keys (
        id UUID PRIMARY KEY,
        tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
        key_hash TEXT NOT NULL UNIQUE,
        key_prefix TEXT NOT NULL,
        key_suffix TEXT NOT NULL,
        duration_code TEXT NOT NULL CHECK (duration_code IN ('1d','7d','30d','180d','365d')),
        duration_days INTEGER NOT NULL CHECK (duration_days > 0),
        status TEXT NOT NULL DEFAULT 'unused' CHECK (status IN ('unused','active','superseded','revoked')),
        telegram_chat_id TEXT,
        telegram_user_id TEXT,
        activated_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ,
        last_used_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_config (
        tenant_id UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
        canned_replies JSONB NOT NULL,
        auto_replies JSONB NOT NULL,
        settings JSONB NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS telegram_updates (
        update_id BIGINT PRIMARY KEY,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS conversations (
        id UUID PRIMARY KEY,
        visitor_key_hash TEXT NOT NULL,
        visitor_name TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed')),
        unread_admin INTEGER NOT NULL DEFAULT 0 CHECK (unread_admin >= 0),
        unread_user INTEGER NOT NULL DEFAULT 0 CHECK (unread_user >= 0),
        last_auto_reply_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS visitor_note TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS ip_address TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS ip_location TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS ip_isp TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS device_type TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS device_label TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS entry_source TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS user_agent TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS referrer_url TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS attachments (
        id UUID PRIMARY KEY,
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        filename TEXT NOT NULL,
        mime TEXT NOT NULL CHECK (mime IN ('image/jpeg','image/png','image/webp','image/gif')),
        size INTEGER NOT NULL CHECK (size > 0),
        uploader TEXT NOT NULL CHECK (uploader IN ('user','admin')),
        data BYTEA NOT NULL,
        linked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY,
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN ('user','admin')),
        source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','auto')),
        type TEXT NOT NULL CHECK (type IN ('text','image')),
        text TEXT NOT NULL DEFAULT '',
        attachment_id UUID UNIQUE REFERENCES attachments(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (
          (type = 'text' AND attachment_id IS NULL AND length(text) > 0)
          OR
          (type = 'image' AND attachment_id IS NOT NULL)
        )
      )
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS conversations_updated_at_idx
      ON conversations (updated_at DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS conversations_tenant_updated_idx
      ON conversations (tenant_id, updated_at DESC)
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS conversations_tenant_visitor_unique_idx
      ON conversations (tenant_id, visitor_key_hash)
      WHERE tenant_id IS NOT NULL
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS license_keys_tenant_idx ON license_keys (tenant_id, created_at DESC)`);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_conversation_created_idx
      ON messages (conversation_id, created_at ASC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_created_at_idx
      ON messages (created_at)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS attachments_created_at_idx
      ON attachments (created_at)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS attachments_conversation_idx
      ON attachments (conversation_id)
    `);

    await client.query(
      `
        INSERT INTO app_config (id, canned_replies, auto_replies, settings)
        VALUES (1, $1::jsonb, $2::jsonb, $3::jsonb)
        ON CONFLICT (id) DO NOTHING
      `,
      [
        JSON.stringify(defaults.cannedReplies),
        JSON.stringify(defaults.autoReplies),
        JSON.stringify(defaults.settings),
      ],
    );

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }

  await cleanupExpiredData();
}

async function cleanupExpiredData() {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const messages = await client.query(
      `
        DELETE FROM messages
        WHERE created_at < NOW() - ($1::text || ' hours')::interval
      `,
      [RETENTION_HOURS],
    );

    const attachments = await client.query(
      `
        DELETE FROM attachments a
        WHERE
          COALESCE(a.linked_at, a.created_at)
            < NOW() - ($1::text || ' hours')::interval
          OR (
            a.created_at < NOW() - INTERVAL '10 minutes'
            AND (
              a.linked_at IS NULL
              OR NOT EXISTS (
                SELECT 1 FROM messages m WHERE m.attachment_id = a.id
              )
            )
          )
      `,
      [RETENTION_HOURS],
    );

    const conversations = await client.query(
      `
        DELETE FROM conversations c
        WHERE
          c.created_at < NOW() - ($1::text || ' hours')::interval
          AND NOT EXISTS (
            SELECT 1 FROM messages m WHERE m.conversation_id = c.id
          )
      `,
      [RETENTION_HOURS],
    );

    await client.query(`DELETE FROM telegram_updates WHERE created_at < NOW() - INTERVAL '30 days'`);

    await client.query('COMMIT');
    lastCleanupAt = Date.now();

    return {
      messages: messages.rowCount,
      attachments: attachments.rowCount,
      conversations: conversations.rowCount,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

function maybeCleanupExpiredData() {
  if (Date.now() - lastCleanupAt < 10 * 60 * 1000) return;
  if (cleanupPromise) return;

  cleanupPromise = cleanupExpiredData()
    .catch((error) => console.error('清理过期聊天失败：', error))
    .finally(() => {
      cleanupPromise = null;
    });
}

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function signToken(payload, ttlSeconds = TOKEN_TTL_SECONDS) {
  const currentSeconds = Math.floor(Date.now() / 1000);
  const body = {
    ...payload,
    iat: currentSeconds,
    exp: currentSeconds + ttlSeconds,
  };
  const encoded = base64url(JSON.stringify(body));
  const signature = createHmac('sha256', TOKEN_SECRET)
    .update(encoded)
    .digest('base64url');
  return `${encoded}.${signature}`;
}

function signTokenUntil(payload, expiresAt) {
  const target = Math.floor(new Date(expiresAt).getTime() / 1000);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(target) || target <= now) return '';
  return signToken(payload, target - now);
}

function verifyToken(token) {
  if (!token || typeof token !== 'string') return null;
  const [encoded, signature, extra] = token.split('.');
  if (!encoded || !signature || extra) return null;

  const expected = createHmac('sha256', TOKEN_SECRET).update(encoded).digest();
  let supplied;
  try {
    supplied = Buffer.from(signature, 'base64url');
  } catch {
    return null;
  }

  if (
    supplied.length !== expected.length ||
    !timingSafeEqual(supplied, expected)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      Buffer.from(encoded, 'base64url').toString('utf8'),
    );
    if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

function hashVisitorKey(visitorKey) {
  return createHmac('sha256', TOKEN_SECRET)
    .update(String(visitorKey || ''))
    .digest('base64url');
}

function normalizeLicenseKey(value) {
  return String(value || '').trim().toUpperCase().replace(/[\s_]+/g, '-').replace(/-+/g, '-');
}
function hashLicenseKey(value) {
  return createHmac('sha256', TOKEN_SECRET)
    .update(`license:${normalizeLicenseKey(value)}`)
    .digest('base64url');
}
const LICENSE_DURATIONS = Object.freeze({
  '1d': { label: '一日卡', days: 1 },
  '7d': { label: '周卡', days: 7 },
  '30d': { label: '月卡', days: 30 },
  '180d': { label: '半年卡', days: 180 },
  '365d': { label: '年卡', days: 365 },
});
function generateLicenseKey() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(20);
  let raw = '';
  for (let i = 0; i < 20; i += 1) raw += alphabet[bytes[i] % alphabet.length];
  return `VIP-${raw.match(/.{1,5}/g).join('-')}`;
}
function generateTenantCode() {
  return `site_${randomBytes(12).toString('base64url')}`;
}
function licenseHint(row) {
  return row ? `${row.key_prefix || 'VIP'}-••••-••••-${row.key_suffix || '????'}` : '';
}


function getBearer(req) {
  const value = req.headers.authorization || '';
  return value.startsWith('Bearer ') ? value.slice(7) : '';
}

function authenticate(req, kind) {
  const payload = verifyToken(getBearer(req));
  if (!payload || (kind && payload.kind !== kind)) return null;
  return payload;
}

function normalizeOrigin(origin) {
  return String(origin || '').trim().replace(/\/$/, '');
}

function originAllowed(origin) {
  if (!origin) return true;
  const normalized = normalizeOrigin(origin);
  return ALLOWED_ORIGINS.includes('*') || ALLOWED_ORIGINS.includes(normalized);
}

function setCommonHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && originAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Authorization,Content-Type,X-File-Name',
  );
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=()',
  );
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
}

function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
}

function sendError(res, status, message, code = 'ERROR') {
  return sendJson(res, status, {
    ok: false,
    error: message,
    code,
  });
}

async function readBody(req, maxBytes) {
  const chunks = [];
  let total = 0;

  for await (const chunk of req) {
    total += chunk.length;
    if (total > maxBytes) {
      const error = new Error('请求内容过大。');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }

  return Buffer.concat(chunks);
}

async function readJson(req, maxBytes = 256 * 1024) {
  const body = await readBody(req, maxBytes);
  if (!body.length) return {};
  try {
    return JSON.parse(body.toString('utf8'));
  } catch {
    const error = new Error('JSON格式无效。');
    error.statusCode = 400;
    throw error;
  }
}

function cleanText(value, max = 4000) {
  return String(value ?? '')
    .replace(/\u0000/g, '')
    .trim()
    .slice(0, max);
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(String(value || ''));
  } catch {
    return String(value || '');
  }
}

function isUuid(value) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    String(value || ''),
  );
}

function safeFilename(value) {
  return (
    cleanText(safeDecodeURIComponent(value || 'image'), 120).replace(
      /[\\/<>:"|?*\x00-\x1F]/g,
      '_',
    ) || 'image'
  );
}

function requestIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '')
    .split(',')[0]
    .trim();
  return forwarded || req.socket.remoteAddress || 'unknown';
}

function rateLimit(req, res, name, max, windowMs) {
  const key = `${name}:${requestIp(req)}`;
  const now = Date.now();
  const current = rateBuckets.get(key);

  if (!current || current.resetAt <= now) {
    rateBuckets.set(key, { count: 1, resetAt: now + windowMs });
    return true;
  }

  current.count += 1;
  if (current.count > max) {
    res.setHeader(
      'Retry-After',
      String(Math.ceil((current.resetAt - now) / 1000)),
    );
    sendError(res, 429, '操作过于频繁，请稍后再试。', 'RATE_LIMIT');
    return false;
  }

  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [key, value] of rateBuckets) {
    if (value.resetAt < now) rateBuckets.delete(key);
  }
}, 10 * 60 * 1000).unref();

function imageContentMatchesMime(data, mime) {
  if (!Buffer.isBuffer(data)) return false;

  if (mime === 'image/jpeg') {
    return data.length >= 3 && data[0] === 0xff && data[1] === 0xd8 && data[2] === 0xff;
  }

  if (mime === 'image/png') {
    return (
      data.length >= 8 &&
      data.subarray(0, 8).equals(
        Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
      )
    );
  }

  if (mime === 'image/gif') {
    const signature = data.subarray(0, 6).toString('ascii');
    return signature === 'GIF87a' || signature === 'GIF89a';
  }

  if (mime === 'image/webp') {
    return (
      data.length >= 12 &&
      data.subarray(0, 4).toString('ascii') === 'RIFF' &&
      data.subarray(8, 12).toString('ascii') === 'WEBP'
    );
  }

  return false;
}

function publicMessage(row) {
  return {
    id: row.id,
    role: row.role,
    source: row.source || 'manual',
    type: row.type,
    text: row.text || '',
    attachmentId: row.attachment_id || null,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

function publicAttachment(row) {
  return {
    id: row.id,
    conversationId: row.conversation_id,
    filename: row.filename,
    mime: row.mime,
    size: Number(row.size),
    createdAt: new Date(row.created_at).toISOString(),
    uploader: row.uploader,
  };
}

function conversationBase(row) {
  const lastSeenAt = row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null;
  return {
    id: row.id,
    tenantId: row.tenant_id || null,
    visitorName: row.visitor_name,
    visitorNote: row.visitor_note || '',
    status: row.status,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    lastSeenAt,
    online: Boolean(lastSeenAt && Date.now() - new Date(lastSeenAt).getTime() < 75_000),
    unreadAdmin: Number(row.unread_admin || 0),
    unreadUser: Number(row.unread_user || 0),
    ipAddress: row.ip_address || '',
    ipLocation: row.ip_location || '',
    ipIsp: row.ip_isp || '',
    deviceType: row.device_type || '',
    deviceLabel: row.device_label || '',
    entrySource: row.entry_source || '',
  };
}

function conversationSummary(row) {
  const result = conversationBase(row);
  result.latestMessage = row.latest_id
    ? {
        type: row.latest_type,
        text:
          row.latest_type === 'image'
            ? row.latest_text || '[图片]'
            : row.latest_text || '',
        role: row.latest_role,
        createdAt: new Date(row.latest_created_at).toISOString(),
      }
    : null;
  return result;
}

async function createTenantConfig(tenantId, client = pool) {
  const defaults = defaultConfig();
  await client.query(
    `
      INSERT INTO tenant_config (tenant_id, canned_replies, auto_replies, settings)
      VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb)
      ON CONFLICT (tenant_id) DO NOTHING
    `,
    [tenantId, JSON.stringify(defaults.cannedReplies), JSON.stringify(defaults.autoReplies), JSON.stringify(defaults.settings)],
  );
}

async function getConfig(tenantId, client = pool) {
  if (!tenantId) throw new Error('缺少租户标识。');
  const result = await client.query(
    `SELECT canned_replies, auto_replies, settings FROM tenant_config WHERE tenant_id = $1`,
    [tenantId],
  );
  if (!result.rows[0]) {
    await createTenantConfig(tenantId, client);
    return getConfig(tenantId, client);
  }
  return {
    cannedReplies: result.rows[0].canned_replies || [],
    autoReplies: result.rows[0].auto_replies || [],
    settings: result.rows[0].settings || {},
  };
}

async function getConversationRow(id, client = pool, forUpdate = false, tenantId = null) {
  const result = await client.query(
    `
      SELECT * FROM conversations
      WHERE id = $1 AND ($2::uuid IS NULL OR tenant_id = $2)
      ${forUpdate ? 'FOR UPDATE' : ''}
    `,
    [id, tenantId],
  );
  return result.rows[0] || null;
}

async function getPublicConversation(id, client = pool, tenantId = null) {
  const conversationResult = await client.query(
    `SELECT * FROM conversations WHERE id = $1 AND ($2::uuid IS NULL OR tenant_id = $2)`,
    [id, tenantId],
  );
  const conversation = conversationResult.rows[0];
  if (!conversation) return null;

  const messagesResult = await client.query(
    `
      SELECT * FROM messages
      WHERE conversation_id = $1
      ORDER BY created_at ASC, id ASC
    `,
    [id],
  );

  return {
    ...conversationBase(conversation),
    messages: messagesResult.rows.map(publicMessage),
  };
}

async function getAllSummaries(tenantId) {
  const result = await pool.query(`
    SELECT
      c.*,
      latest.id AS latest_id,
      latest.type AS latest_type,
      latest.text AS latest_text,
      latest.role AS latest_role,
      latest.created_at AS latest_created_at
    FROM conversations c
    LEFT JOIN LATERAL (
      SELECT m.id, m.type, m.text, m.role, m.created_at
      FROM messages m
      WHERE m.conversation_id = c.id
      ORDER BY m.created_at DESC, m.id DESC
      LIMIT 1
    ) latest ON TRUE
    WHERE c.tenant_id = $1
    ORDER BY c.updated_at DESC
  `, [tenantId]);
  return result.rows.map(conversationSummary);
}

function authorizeConversation(payload, conversation) {
  if (
    payload?.kind === 'tenant_admin' &&
    payload.tenantId &&
    timingSafeTextEqual(payload.tenantId, conversation.tenant_id)
  ) return true;
  return Boolean(
    payload?.kind === 'user' &&
      payload.tenantId &&
      timingSafeTextEqual(payload.tenantId, conversation.tenant_id) &&
      payload.conversationId === conversation.id &&
      payload.visitorKey &&
      timingSafeTextEqual(hashVisitorKey(payload.visitorKey), conversation.visitor_key_hash),
  );
}

function timingSafeTextEqual(a, b) {
  const left = Buffer.from(String(a || ''), 'utf8');
  const right = Buffer.from(String(b || ''), 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

function matchAutoReply(config, text) {
  if (!config.settings?.autoReplyEnabled) return '';
  const normalized = String(text || '').toLowerCase();

  for (const rule of Array.isArray(config.autoReplies) ? config.autoReplies : []) {
    if (!rule?.enabled || !rule.replyText) continue;
    const keywords = Array.isArray(rule.keywords) ? rule.keywords : [];
    if (
      keywords.some((keyword) =>
        normalized.includes(String(keyword || '').toLowerCase()),
      )
    ) {
      return cleanText(rule.replyText, 4000);
    }
  }

  if (config.settings?.defaultAutoReplyEnabled) {
    return cleanText(config.settings.defaultAutoReply, 4000);
  }

  return '';
}

function validateAdminSettings(body, current) {
  const cannedReplies = Array.isArray(body.cannedReplies)
    ? body.cannedReplies
        .slice(0, 100)
        .map((item) => ({
          id: cleanText(item?.id, 80) || randomUUID(),
          title: cleanText(item?.title, 40) || '快捷语',
          text: cleanText(item?.text, 2000),
        }))
        .filter((item) => item.text)
    : current.cannedReplies;

  const autoReplies = Array.isArray(body.autoReplies)
    ? body.autoReplies
        .slice(0, 100)
        .map((item) => ({
          id: cleanText(item?.id, 80) || randomUUID(),
          name: cleanText(item?.name, 40) || '自动回复',
          enabled: Boolean(item?.enabled),
          keywords: Array.isArray(item?.keywords)
            ? item.keywords
                .map((keyword) => cleanText(keyword, 40))
                .filter(Boolean)
                .slice(0, 30)
            : [],
          replyText: cleanText(item?.replyText, 2000),
        }))
        .filter((item) => item.replyText)
    : current.autoReplies;

  const input =
    body.settings && typeof body.settings === 'object' ? body.settings : {};

  const cooldownRaw = Number(
    input.autoReplyCooldownSeconds ??
      current.settings.autoReplyCooldownSeconds ??
      20,
  );

  const settings = {
    ...current.settings,
    siteName:
      input.siteName !== undefined
        ? cleanText(input.siteName, 80) || '在线客服'
        : current.settings.siteName,
    welcomeText:
      input.welcomeText !== undefined
        ? cleanText(input.welcomeText, 2000)
        : current.settings.welcomeText,
    autoReplyEnabled:
      input.autoReplyEnabled !== undefined
        ? Boolean(input.autoReplyEnabled)
        : Boolean(current.settings.autoReplyEnabled),
    defaultAutoReplyEnabled:
      input.defaultAutoReplyEnabled !== undefined
        ? Boolean(input.defaultAutoReplyEnabled)
        : Boolean(current.settings.defaultAutoReplyEnabled),
    defaultAutoReply:
      input.defaultAutoReply !== undefined
        ? cleanText(input.defaultAutoReply, 2000)
        : current.settings.defaultAutoReply,
    autoReplyCooldownSeconds: Number.isFinite(cooldownRaw)
      ? Math.min(3600, Math.max(0, cooldownRaw))
      : 20,
    userSiteUrl:
      input.userSiteUrl !== undefined
        ? cleanText(input.userSiteUrl, 500)
        : current.settings.userSiteUrl,
    announcementEnabled:
      input.announcementEnabled !== undefined
        ? Boolean(input.announcementEnabled)
        : Boolean(current.settings.announcementEnabled),
    announcementText:
      input.announcementText !== undefined
        ? cleanText(input.announcementText, 1000)
        : cleanText(current.settings.announcementText, 1000),
  };

  return { cannedReplies, autoReplies, settings };
}

function sendSse(res, payload) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function broadcast(payload, conversationId = null, tenantId = null) {
  for (const client of sseClients) {
    if (client.kind === 'user' && client.conversationId !== conversationId) continue;
    if (client.kind === 'tenant_admin' && tenantId && client.tenantId !== tenantId) continue;
    try {
      sendSse(client.res, payload);
    } catch {
      sseClients.delete(client);
    }
  }
}

setInterval(() => {
  for (const client of sseClients) {
    try {
      if (client.accessExpiresAt && client.accessExpiresAt <= Date.now()) {
        sendSse(client.res, { type: 'tenant-expired', at: nowIso() });
        client.res.end();
        sseClients.delete(client);
        continue;
      }
      client.res.write(': heartbeat\n\n');
    } catch {
      sseClients.delete(client);
    }
  }
}, 20_000).unref();

async function handleUpload(req, res, payload, conversation) {
  if (conversation.status === 'closed') {
    return sendError(res, 409, '此会话已结束。', 'CLOSED');
  }

  if (!rateLimit(req, res, 'upload', 12, 60_000)) return;

  const mime = String(req.headers['content-type'] || '')
    .split(';')[0]
    .trim()
    .toLowerCase();

  if (!ALLOWED_IMAGE_TYPES.has(mime)) {
    return sendError(
      res,
      415,
      '仅支持 JPG、PNG、WEBP、GIF 图片。',
      'IMAGE_TYPE',
    );
  }

  const data = await readBody(req, MAX_IMAGE_BYTES);
  if (!data.length) {
    return sendError(res, 400, '图片内容为空。', 'EMPTY_IMAGE');
  }

  if (!imageContentMatchesMime(data, mime)) {
    return sendError(
      res,
      415,
      '图片内容与文件类型不匹配。',
      'IMAGE_SIGNATURE',
    );
  }

  const attachmentId = randomUUID();
  const filename = safeFilename(
    req.headers['x-file-name'] || `image-${attachmentId}`,
  );

  const result = await pool.query(
    `
      INSERT INTO attachments (
        id, conversation_id, filename, mime, size, uploader, data
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, conversation_id, filename, mime, size, uploader, created_at
    `,
    [
      attachmentId,
      conversation.id,
      filename,
      mime,
      data.length,
      payload.kind === 'tenant_admin' ? 'admin' : 'user',
      data,
    ],
  );

  return sendJson(res, 201, {
    ok: true,
    attachment: publicAttachment(result.rows[0]),
  });
}

async function createUserMessage(conversationId, body, tenantId) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const conversation = await getConversationRow(conversationId, client, true, tenantId);
    if (!conversation) {
      const error = new Error('访客会话不存在。');
      error.statusCode = 401;
      error.code = 'AUTH';
      throw error;
    }
    if (conversation.status === 'closed') {
      const error = new Error('此会话已结束。');
      error.statusCode = 409;
      error.code = 'CLOSED';
      throw error;
    }

    const type = body.type === 'image' ? 'image' : 'text';
    const text = cleanText(body.text, 4000);
    const attachmentId = cleanText(body.attachmentId, 80);

    if (type === 'text' && !text) {
      const error = new Error('消息不能为空。');
      error.statusCode = 400;
      error.code = 'EMPTY_MESSAGE';
      throw error;
    }

    if (type === 'image') {
      if (!isUuid(attachmentId)) {
        const error = new Error('图片附件无效。');
        error.statusCode = 400;
        error.code = 'INVALID_ATTACHMENT';
        throw error;
      }
      const attachmentResult = await client.query(
        `
          SELECT id FROM attachments
          WHERE id = $1 AND conversation_id = $2 AND linked_at IS NULL
          FOR UPDATE
        `,
        [attachmentId, conversationId],
      );
      if (!attachmentResult.rows[0]) {
        const error = new Error('图片附件无效或已经使用。');
        error.statusCode = 400;
        error.code = 'INVALID_ATTACHMENT';
        throw error;
      }
    }

    const messageId = randomUUID();
    const messageResult = await client.query(
      `
        INSERT INTO messages (
          id, conversation_id, role, source, type, text, attachment_id
        )
        VALUES ($1, $2, 'user', 'manual', $3, $4, $5)
        RETURNING *
      `,
      [
        messageId,
        conversationId,
        type,
        text,
        type === 'image' ? attachmentId : null,
      ],
    );

    if (type === 'image') {
      await client.query(
        `UPDATE attachments SET linked_at = NOW() WHERE id = $1`,
        [attachmentId],
      );
    }

    await client.query(
      `
        UPDATE conversations
        SET unread_admin = unread_admin + 1, updated_at = NOW()
        WHERE id = $1
      `,
      [conversationId],
    );

    let autoReplyRow = null;
    if (type === 'text') {
      const config = await getConfig(conversation.tenant_id, client);
      const cooldownSeconds = Math.min(
        3600,
        Math.max(0, Number(config.settings.autoReplyCooldownSeconds ?? 20)),
      );
      const lastAutoReplyAt = conversation.last_auto_reply_at
        ? new Date(conversation.last_auto_reply_at).getTime()
        : 0;
      const cooldownPassed =
        !lastAutoReplyAt || Date.now() - lastAutoReplyAt >= cooldownSeconds * 1000;
      const replyText = cooldownPassed ? matchAutoReply(config, text) : '';

      if (replyText) {
        const autoResult = await client.query(
          `
            INSERT INTO messages (
              id, conversation_id, role, source, type, text
            )
            VALUES ($1, $2, 'admin', 'auto', 'text', $3)
            RETURNING *
          `,
          [randomUUID(), conversationId, replyText],
        );
        autoReplyRow = autoResult.rows[0];
        await client.query(
          `
            UPDATE conversations
            SET
              unread_user = unread_user + 1,
              last_auto_reply_at = NOW(),
              updated_at = NOW()
            WHERE id = $1
          `,
          [conversationId],
        );
      }
    }

    await client.query('COMMIT');
    const publicConversation = await getPublicConversation(conversationId, pool, conversation.tenant_id);

    return {
      message: publicMessage(messageResult.rows[0]),
      autoReply: autoReplyRow ? publicMessage(autoReplyRow) : null,
      conversation: publicConversation,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function createAdminMessage(conversationId, body, tenantId) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const conversation = await getConversationRow(conversationId, client, true, tenantId);
    if (!conversation) {
      const error = new Error('会话不存在。');
      error.statusCode = 404;
      error.code = 'NOT_FOUND';
      throw error;
    }
    if (conversation.status === 'closed') {
      const error = new Error('此会话已结束。');
      error.statusCode = 409;
      error.code = 'CLOSED';
      throw error;
    }

    const type = body.type === 'image' ? 'image' : 'text';
    const text = cleanText(body.text, 4000);
    const attachmentId = cleanText(body.attachmentId, 80);

    if (type === 'text' && !text) {
      const error = new Error('消息不能为空。');
      error.statusCode = 400;
      error.code = 'EMPTY_MESSAGE';
      throw error;
    }

    if (type === 'image') {
      if (!isUuid(attachmentId)) {
        const error = new Error('图片附件无效。');
        error.statusCode = 400;
        error.code = 'INVALID_ATTACHMENT';
        throw error;
      }
      const attachmentResult = await client.query(
        `
          SELECT id FROM attachments
          WHERE id = $1 AND conversation_id = $2 AND linked_at IS NULL
          FOR UPDATE
        `,
        [attachmentId, conversationId],
      );
      if (!attachmentResult.rows[0]) {
        const error = new Error('图片附件无效或已经使用。');
        error.statusCode = 400;
        error.code = 'INVALID_ATTACHMENT';
        throw error;
      }
    }

    const messageResult = await client.query(
      `
        INSERT INTO messages (
          id, conversation_id, role, source, type, text, attachment_id
        )
        VALUES ($1, $2, 'admin', 'manual', $3, $4, $5)
        RETURNING *
      `,
      [
        randomUUID(),
        conversationId,
        type,
        text,
        type === 'image' ? attachmentId : null,
      ],
    );

    if (type === 'image') {
      await client.query(`UPDATE attachments SET linked_at = NOW() WHERE id = $1`, [
        attachmentId,
      ]);
    }

    await client.query(
      `
        UPDATE conversations
        SET unread_user = unread_user + 1, updated_at = NOW()
        WHERE id = $1
      `,
      [conversationId],
    );

    await client.query('COMMIT');
    const publicConversation = await getPublicConversation(conversationId, pool, conversation.tenant_id);

    return {
      message: publicMessage(messageResult.rows[0]),
      conversation: publicConversation,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}


async function getTenantById(tenantId, client = pool, forUpdate = false) {
  if (!isUuid(tenantId)) return null;
  const result = await client.query(
    `SELECT * FROM tenants WHERE id = $1 ${forUpdate ? 'FOR UPDATE' : ''}`,
    [tenantId],
  );
  return result.rows[0] || null;
}

async function getTenantByCode(publicCode, client = pool) {
  const code = cleanText(publicCode, 100);
  if (!code) return null;
  const result = await client.query(`SELECT * FROM tenants WHERE public_code = $1`, [code]);
  return result.rows[0] || null;
}

function tenantExpired(tenant) {
  return !tenant || tenant.status !== 'active' || new Date(tenant.access_expires_at).getTime() <= Date.now();
}

function publicTenant(tenant) {
  return {
    id: tenant.id,
    publicCode: tenant.public_code,
    status: tenant.status,
    accessExpiresAt: new Date(tenant.access_expires_at).toISOString(),
    createdAt: new Date(tenant.created_at).toISOString(),
  };
}

async function touchConversation(conversationId, body = {}, req = null, tenantId = null) {
  await pool.query(
    `
      UPDATE conversations SET
        last_seen_at = NOW(),
        ip_address = CASE WHEN $2 <> '' THEN $2 ELSE ip_address END,
        device_type = CASE WHEN $3 <> '' THEN $3 ELSE device_type END,
        device_label = CASE WHEN $4 <> '' THEN $4 ELSE device_label END,
        entry_source = CASE WHEN $5 <> '' THEN $5 ELSE entry_source END,
        user_agent = CASE WHEN $6 <> '' THEN $6 ELSE user_agent END,
        referrer_url = CASE WHEN $7 <> '' THEN $7 ELSE referrer_url END
      WHERE id = $1 AND ($8::uuid IS NULL OR tenant_id = $8)
    `,
    [
      conversationId,
      req ? cleanText(requestIp(req), 100) : '',
      cleanText(body.deviceType, 30), cleanText(body.deviceLabel, 100),
      cleanText(body.entrySource, 30), cleanText(body.userAgent, 500),
      cleanText(body.referrerUrl, 500), tenantId,
    ],
  );
}

async function createLicenseRecord(durationCode, metadata = {}) {
  const duration = LICENSE_DURATIONS[durationCode];
  if (!duration) throw new Error('卡密时长无效。');
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const licenseKey = generateLicenseKey();
    try {
      const result = await pool.query(
        `
          INSERT INTO license_keys (
            id, key_hash, key_prefix, key_suffix, duration_code, duration_days,
            telegram_chat_id, telegram_user_id
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
          RETURNING *
        `,
        [randomUUID(), hashLicenseKey(licenseKey), 'VIP', licenseKey.slice(-5),
         durationCode, duration.days, cleanText(metadata.telegramChatId, 50), cleanText(metadata.telegramUserId, 50)],
      );
      return { licenseKey, row: result.rows[0], duration };
    } catch (error) {
      if (error?.code !== '23505' || attempt === 4) throw error;
    }
  }
  throw new Error('生成卡密失败。');
}

async function handleTenantLogin(req, res) {
  if (!rateLimit(req, res, 'tenant-login', 15, 10 * 60_000)) return;
  const body = await readJson(req, 64 * 1024);
  const key = normalizeLicenseKey(body.licenseKey);
  if (!/^VIP-[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}$/.test(key)) {
    return sendError(res, 401, '卡密格式不正确。', 'LICENSE_INVALID');
  }
  const client = await pool.connect();
  let tenant;
  let license;
  try {
    await client.query('BEGIN');
    const result = await client.query(`SELECT * FROM license_keys WHERE key_hash = $1 FOR UPDATE`, [hashLicenseKey(key)]);
    license = result.rows[0];
    if (!license) {
      const error = new Error('卡密不存在或输入错误。'); error.statusCode = 401; error.code = 'LICENSE_INVALID'; throw error;
    }
    if (license.status === 'revoked') {
      const error = new Error('此卡密已被停用，请联系平台。'); error.statusCode = 403; error.code = 'LICENSE_REVOKED'; throw error;
    }
    if (license.status === 'superseded') {
      const error = new Error('此卡密已被续费卡替换，请使用最新卡密。'); error.statusCode = 403; error.code = 'LICENSE_REPLACED'; throw error;
    }
    if (license.status === 'unused') {
      const tenantId = randomUUID();
      const expiry = new Date(Date.now() + Number(license.duration_days) * 86_400_000);
      const tenantResult = await client.query(
        `INSERT INTO tenants (id, public_code, access_expires_at) VALUES ($1,$2,$3) RETURNING *`,
        [tenantId, generateTenantCode(), expiry.toISOString()],
      );
      tenant = tenantResult.rows[0];
      await createTenantConfig(tenantId, client);
      await client.query(
        `UPDATE license_keys SET tenant_id=$2,status='active',activated_at=NOW(),expires_at=$3,last_used_at=NOW(),updated_at=NOW() WHERE id=$1`,
        [license.id, tenantId, expiry.toISOString()],
      );
      license = { ...license, tenant_id: tenantId, status: 'active', expires_at: expiry };
    } else {
      tenant = await getTenantById(license.tenant_id, client, true);
      if (!tenant) {
        const error = new Error('租户账户不存在，请联系平台。'); error.statusCode = 409; error.code = 'LICENSE_STATE'; throw error;
      }
      if (tenantExpired(tenant)) {
        const error = new Error('卡密已到期，请购买新卡密续费。'); error.statusCode = 403; error.code = 'TENANT_EXPIRED'; error.expiresAt = new Date(tenant.access_expires_at).toISOString(); throw error;
      }
      await client.query(`UPDATE license_keys SET last_used_at=NOW(),updated_at=NOW() WHERE id=$1`, [license.id]);
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    if (error.code === 'TENANT_EXPIRED') {
      return sendJson(res, error.statusCode, { ok:false,error:error.message,code:error.code,expiresAt:error.expiresAt });
    }
    throw error;
  } finally { client.release(); }
  const config = await getConfig(tenant.id);
  return sendJson(res, 200, {
    ok: true,
    token: signTokenUntil({ kind:'tenant_admin', tenantId:tenant.id, licenseId:license.id }, tenant.access_expires_at),
    tenant: publicTenant(tenant),
    settings: config.settings,
  });
}

async function handleTenantRenew(req, res) {
  if (!rateLimit(req, res, 'tenant-renew', 10, 10 * 60_000)) return;
  const body = await readJson(req, 64 * 1024);
  const currentKey = normalizeLicenseKey(body.currentLicenseKey);
  const newKey = normalizeLicenseKey(body.newLicenseKey);
  if (!currentKey || !newKey || currentKey === newKey) {
    return sendError(res, 400, '请输入当前卡密和新的续费卡密。', 'LICENSE_RENEW_INPUT');
  }
  const client = await pool.connect();
  let tenant, newLicense, newExpiry;
  try {
    await client.query('BEGIN');
    const currentResult = await client.query(`SELECT * FROM license_keys WHERE key_hash=$1 FOR UPDATE`, [hashLicenseKey(currentKey)]);
    const current = currentResult.rows[0];
    if (!current || current.status !== 'active' || !current.tenant_id) {
      const error = new Error('当前卡密无效，必须使用最近一次有效卡密续费。'); error.statusCode=403; error.code='LICENSE_CURRENT_INVALID'; throw error;
    }
    const newResult = await client.query(`SELECT * FROM license_keys WHERE key_hash=$1 FOR UPDATE`, [hashLicenseKey(newKey)]);
    newLicense = newResult.rows[0];
    if (!newLicense || newLicense.status !== 'unused' || newLicense.tenant_id) {
      const error = new Error('新卡密不存在、已使用或已停用。'); error.statusCode=403; error.code='LICENSE_NEW_INVALID'; throw error;
    }
    tenant = await getTenantById(current.tenant_id, client, true);
    if (!tenant) { const error=new Error('租户不存在。'); error.statusCode=409; error.code='LICENSE_STATE'; throw error; }
    const base = Math.max(Date.now(), new Date(tenant.access_expires_at).getTime());
    newExpiry = new Date(base + Number(newLicense.duration_days) * 86_400_000);
    const tenantResult = await client.query(
      `UPDATE tenants SET status='active',access_expires_at=$2,updated_at=NOW() WHERE id=$1 RETURNING *`,
      [tenant.id, newExpiry.toISOString()],
    );
    tenant = tenantResult.rows[0];
    await client.query(`UPDATE license_keys SET status='superseded',updated_at=NOW() WHERE tenant_id=$1 AND status='active'`, [tenant.id]);
    await client.query(
      `UPDATE license_keys SET tenant_id=$2,status='active',activated_at=NOW(),expires_at=$3,last_used_at=NOW(),updated_at=NOW() WHERE id=$1`,
      [newLicense.id, tenant.id, newExpiry.toISOString()],
    );
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
  return sendJson(res, 200, {
    ok:true,
    token: signTokenUntil({ kind:'tenant_admin', tenantId:tenant.id, licenseId:newLicense.id }, newExpiry),
    tenant: publicTenant(tenant),
  });
}

function telegramPrivateAllowed(chat, userId) {
  return Boolean(
    chat?.type === 'private' &&
      userId != null &&
      TELEGRAM_ALLOWED_PRIVATE_USER_IDS.has(String(userId)),
  );
}

async function telegramApi(method, payload) {
  const response = await fetch(
    `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/${method}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(12_000),
    },
  );
  const result = await response.json().catch(() => null);
  if (!response.ok || !result?.ok) {
    throw new Error(result?.description || `Telegram ${method} 失败。`);
  }
  return result.result;
}

function telegramGenerateKeyboard() {
  return {
    inline_keyboard: [
      [
        { text: '一日卡', callback_data: 'license:1d' },
        { text: '周卡', callback_data: 'license:7d' },
      ],
      [
        { text: '月卡', callback_data: 'license:30d' },
        { text: '半年卡', callback_data: 'license:180d' },
      ],
      [{ text: '年卡', callback_data: 'license:365d' }],
    ],
  };
}

async function processTelegramUpdate(update) {
  const message = update?.message;
  const callback = update?.callback_query;

  if (message?.text) {
    const chat = message.chat;
    const chatId = chat?.id;
    const userId = message.from?.id;
    const raw = String(message.text || '').trim();
    const command = raw.split('@')[0].toLowerCase();

    // 本机器人只允许私聊发卡。群组、超级群和频道消息全部忽略。
    if (chat?.type !== 'private') return;

    if (!telegramPrivateAllowed(chat, userId)) {
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text: '⛔ 你不在私聊发卡白名单中，无法使用此机器人。',
      });
      return;
    }

    if (['/start', '/help'].includes(command)) {
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text: [
          '✅ 私聊发卡机器人已启用。',
          '',
          '发送“生成密钥”或 /key 选择卡密时长。',
          '停用卡密：/revoke 卡密',
        ].join('\n'),
      });
      return;
    }

    if (
      ['生成密钥', '生成卡密', '/key', '/card', '/generate'].includes(command)
    ) {
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text: '请点击下方按键选择，请注意：请确认钱包收款成功后，再把密钥发给客户！',
        reply_markup: telegramGenerateKeyboard(),
      });
      return;
    }

    const revokeMatch = raw.match(/^(?:\/revoke|禁用卡密)\s+(.+)$/i);
    if (revokeMatch) {
      const key = normalizeLicenseKey(revokeMatch[1]);
      const client = await pool.connect();
      let text = '卡密不存在。';
      try {
        await client.query('BEGIN');
        const result = await client.query(
          `SELECT * FROM license_keys WHERE key_hash=$1 FOR UPDATE`,
          [hashLicenseKey(key)],
        );
        const row = result.rows[0];
        if (row) {
          await client.query(
            `UPDATE license_keys
             SET status='revoked',updated_at=NOW()
             WHERE id=$1`,
            [row.id],
          );
          if (row.tenant_id && row.status === 'active') {
            await client.query(
              `UPDATE tenants
               SET status='suspended',access_expires_at=NOW(),updated_at=NOW()
               WHERE id=$1`,
              [row.tenant_id],
            );
          }
          text = `已停用卡密：${licenseHint(row)}`;
        }
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      await telegramApi('sendMessage', { chat_id: chatId, text });
      return;
    }
  }

  if (callback?.data?.startsWith('license:')) {
    const chat = callback.message?.chat;
    const chatId = chat?.id;
    const userId = callback.from?.id;
    const code = callback.data.slice(8);

    // 防止把私聊按钮转发到群后被利用，也防止非白名单用户点击。
    if (!telegramPrivateAllowed(chat, userId)) {
      await telegramApi('answerCallbackQuery', {
        callback_query_id: callback.id,
        text:
          chat?.type === 'private'
            ? '你不在私聊发卡白名单中。'
            : '只能在机器人私聊中生成卡密。',
        show_alert: true,
      });
      return;
    }

    if (!LICENSE_DURATIONS[code]) {
      await telegramApi('answerCallbackQuery', {
        callback_query_id: callback.id,
        text: '卡密时长无效。',
        show_alert: true,
      });
      return;
    }

    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '正在生成卡密…',
    });

    const created = await createLicenseRecord(code, {
      telegramChatId: chatId,
      telegramUserId: userId,
    });

    await telegramApi('sendMessage', {
      chat_id: chatId,
      text: [
        `✅ ${created.duration.label}已生成`,
        '',
        `卡密：${created.licenseKey}`,
        `有效时长：首次登录后台后 ${created.duration.days} 天`,
        '',
        '请确认钱包收款成功后，再把卡密发给客户。',
        '客户用此卡密登录后台；系统会自动创建独立租户和专属用户端入口。',
      ].join('\n'),
    });
  }
}

async function router(req, res) {
  maybeCleanupExpiredData();
  setCommonHeaders(req, res);

  const origin = req.headers.origin;
  if (origin && !originAllowed(origin)) {
    return sendError(res, 403, '来源域名未被允许。', 'ORIGIN');
  }

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname.replace(/\/+$/, '') || '/';

  if (req.method === 'GET' && pathname === '/health') {
    const dbResult = await pool.query('SELECT NOW() AS now');
    return sendJson(res, 200, {
      ok: true,
      service: 'neon-chat',
      storage: 'neon-postgresql',
      retentionHours: RETENTION_HOURS,
      telegramBotEnabled: TELEGRAM_ENABLED,
      databaseTime: new Date(dbResult.rows[0].now).toISOString(),
    });
  }

  if (req.method === 'POST' && pathname === '/api/telegram/webhook') {
    if (!TELEGRAM_ENABLED) return sendError(res,404,'Telegram 机器人未启用。','NOT_FOUND');
    const secret=String(req.headers['x-telegram-bot-api-secret-token']||'');
    if (!timingSafeTextEqual(secret,TELEGRAM_WEBHOOK_SECRET)) return sendError(res,403,'Webhook 校验失败。','TELEGRAM_SECRET');
    const update=await readJson(req,512*1024);
    const updateId=Number(update.update_id);
    let updateClaimed = false;
    if (Number.isSafeInteger(updateId)) {
      const claimed=await pool.query(`INSERT INTO telegram_updates(update_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING update_id`,[updateId]);
      if (!claimed.rows[0]) return sendJson(res,200,{ok:true});
      updateClaimed = true;
    }
    try {
      await processTelegramUpdate(update);
    } catch(error) {
      console.error('Telegram 更新处理失败：',error);
      if (updateClaimed) await pool.query(`DELETE FROM telegram_updates WHERE update_id=$1`,[updateId]).catch(()=>{});
      return sendError(res,500,'Telegram 更新处理失败，请让 Telegram 重试。','TELEGRAM_PROCESSING');
    }
    return sendJson(res,200,{ok:true});
  }

  if (req.method === 'POST' && pathname === '/api/admin/login') {
    return handleTenantLogin(req, res);
  }
  if (req.method === 'POST' && pathname === '/api/admin/renew') {
    return handleTenantRenew(req, res);
  }

  if (req.method === 'POST' && pathname === '/api/user/session') {
    if (!rateLimit(req,res,'new-session',20,60_000)) return;
    const body=await readJson(req,64*1024);
    const tenant=await getTenantByCode(body.tenantCode);
    if (!tenant) return sendError(res,404,'用户端入口无效。','TENANT_NOT_FOUND');
    if (tenantExpired(tenant)) return sendError(res,403,'该客服服务已到期，请联系商家续费。','TENANT_EXPIRED');
    const config=await getConfig(tenant.id);
    let conversationId=null;
    let visitorKey=cleanText(body.visitorKey,200);
    if (visitorKey && !body.forceNew) {
      const existing=await pool.query(`SELECT id FROM conversations WHERE tenant_id=$1 AND visitor_key_hash=$2`,[tenant.id,hashVisitorKey(visitorKey)]);
      conversationId=existing.rows[0]?.id||null;
    }
    let created=false;
    if (!conversationId) {
      const countResult=await pool.query(`SELECT COUNT(*)::int AS count FROM conversations WHERE tenant_id=$1`,[tenant.id]);
      if (countResult.rows[0].count>=MAX_CONVERSATIONS) return sendError(res,503,'当前会话过多，请稍后再试。','CONVERSATION_LIMIT');
      conversationId=randomUUID(); visitorKey=randomBytes(24).toString('base64url'); created=true;
      const visitorName=cleanText(body.name,40)||`访客 ${conversationId.slice(0,6)}`;
      const client=await pool.connect();
      try {
        await client.query('BEGIN');
        await client.query(`
          INSERT INTO conversations(
            id,tenant_id,visitor_key_hash,visitor_name,ip_address,device_type,device_label,
            entry_source,user_agent,referrer_url,last_seen_at
          ) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())
        `,[conversationId,tenant.id,hashVisitorKey(visitorKey),visitorName,cleanText(requestIp(req),100),cleanText(body.deviceType,30),cleanText(body.deviceLabel,100),cleanText(body.entrySource,30),cleanText(body.userAgent,500),cleanText(body.referrerUrl,500)]);
        if (config.settings?.welcomeText) {
          await client.query(`INSERT INTO messages(id,conversation_id,role,source,type,text) VALUES($1,$2,'admin','auto','text',$3)`,[randomUUID(),conversationId,cleanText(config.settings.welcomeText,2000)]);
          await client.query(`UPDATE conversations SET updated_at=NOW() WHERE id=$1`,[conversationId]);
        }
        await client.query('COMMIT');
      } catch(error){await client.query('ROLLBACK');throw error;} finally{client.release();}
    } else {
      await touchConversation(conversationId,body,req,tenant.id);
    }
    const conversation=await getPublicConversation(conversationId,pool,tenant.id);
    if (created) broadcast({type:'conversation-created',conversation:conversationSummary({
      id:conversation.id,tenant_id:tenant.id,visitor_name:conversation.visitorName,visitor_note:'',status:conversation.status,
      created_at:conversation.createdAt,updated_at:conversation.updatedAt,last_seen_at:conversation.lastSeenAt,
      unread_admin:conversation.unreadAdmin,unread_user:conversation.unreadUser,
      latest_id:conversation.messages.at(-1)?.id||null,latest_type:conversation.messages.at(-1)?.type,
      latest_text:conversation.messages.at(-1)?.text,latest_role:conversation.messages.at(-1)?.role,
      latest_created_at:conversation.messages.at(-1)?.createdAt,
    })},conversationId,tenant.id);
    return sendJson(res,201,{
      ok:true,
      tenant:{publicCode:tenant.public_code,accessExpiresAt:new Date(tenant.access_expires_at).toISOString()},
      visitorKey,
      token:signTokenUntil({kind:'user',tenantId:tenant.id,conversationId,visitorKey},tenant.access_expires_at),
      conversation,
      settings:config.settings,
    });
  }

  if (req.method === 'GET' && pathname === '/api/events') {
    const payload = authenticate(req);
    if (!payload || !['user', 'tenant_admin'].includes(payload.kind)) {
      return sendError(res, 401, '登录已失效。', 'AUTH');
    }

    const tenant = await getTenantById(payload.tenantId);
    if (!tenant || tenantExpired(tenant)) return sendError(res,403,'服务已到期，请续费。','TENANT_EXPIRED');
    if (payload.kind === 'user') {
      const conversation = await getConversationRow(payload.conversationId, pool, false, payload.tenantId);
      if (!conversation || !authorizeConversation(payload, conversation)) return sendError(res,401,'会话已失效。','AUTH');
      await touchConversation(conversation.id,{},req,payload.tenantId);
    }

    res.statusCode = 200;
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders?.();

    const client = {
      res,
      kind: payload.kind,
      tenantId: payload.tenantId,
      conversationId: payload.conversationId || null,
      accessExpiresAt: new Date(tenant.access_expires_at).getTime(),
    };
    sseClients.add(client);
    sendSse(res, { type: 'connected', at: nowIso() });
    req.on('close', () => sseClients.delete(client));
    return;
  }

  if (pathname.startsWith('/api/user/')) {
    const payload = authenticate(req, 'user');
    if (!payload) {
      return sendError(
        res,
        401,
        '访客会话已失效，请刷新页面重新进入。',
        'AUTH',
      );
    }

    const tenant = await getTenantById(payload.tenantId);
    if (!tenant || tenantExpired(tenant)) return sendError(res,403,'该客服服务已到期，请联系商家续费。','TENANT_EXPIRED');
    const conversation = await getConversationRow(payload.conversationId, pool, false, payload.tenantId);
    if (!conversation || !authorizeConversation(payload, conversation)) return sendError(res,401,'访客会话不存在。','AUTH');
    await touchConversation(conversation.id,{},req,payload.tenantId);

    if (req.method === 'GET' && pathname === '/api/user/conversation') {
      await pool.query(
        `UPDATE conversations SET unread_user = 0 WHERE id = $1 AND tenant_id = $2`,
        [conversation.id, payload.tenantId],
      );
      const [publicConversation, config] = await Promise.all([
        getPublicConversation(conversation.id, pool, payload.tenantId),
        getConfig(payload.tenantId),
      ]);
      return sendJson(res, 200, {
        ok: true,
        conversation: publicConversation,
        settings: config.settings,
      });
    }

    if (req.method === 'POST' && pathname === '/api/user/uploads') {
      return handleUpload(req, res, payload, conversation);
    }

    if (req.method === 'POST' && pathname === '/api/user/messages') {
      if (!rateLimit(req, res, 'user-message', 40, 60_000)) return;
      const body = await readJson(req);
      const result = await createUserMessage(conversation.id, body, payload.tenantId);
      broadcast(
        {
          type: 'conversation-updated',
          trigger: 'user-message',
          conversation: result.conversation,
        },
        conversation.id,
        payload.tenantId,
      );
      return sendJson(res, 201, {
        ok: true,
        message: result.message,
        autoReply: result.autoReply,
      });
    }
  }

  if (pathname.startsWith('/api/admin/')) {
    const payload = authenticate(req, 'tenant_admin');
    if (!payload) {
      return sendError(res, 401, '后台登录已失效。', 'AUTH');
    }
    const activeTenant = await getTenantById(payload.tenantId);
    if (!activeTenant || tenantExpired(activeTenant)) {
      return sendError(res,403,'卡密已到期或已被停用，请续费。','TENANT_EXPIRED');
    }

    if (req.method === 'GET' && pathname === '/api/admin/bootstrap') {
      const tenant = activeTenant;
      const [conversations, config] = await Promise.all([
        getAllSummaries(payload.tenantId),
        getConfig(payload.tenantId),
      ]);
      return sendJson(res, 200, {
        ok: true,
        tenant: publicTenant(tenant),
        conversations,
        cannedReplies: config.cannedReplies,
        autoReplies: config.autoReplies,
        settings: config.settings,
      });
    }

    if (req.method === 'PUT' && pathname === '/api/admin/settings') {
      const body = await readJson(req, 512 * 1024);
      const tenant = activeTenant;
      const current = await getConfig(payload.tenantId);
      const validated = validateAdminSettings(body, current);
      await pool.query(
        `
          UPDATE tenant_config
          SET canned_replies = $1::jsonb,
              auto_replies = $2::jsonb,
              settings = $3::jsonb,
              updated_at = NOW()
          WHERE tenant_id = $4
        `,
        [
          JSON.stringify(validated.cannedReplies),
          JSON.stringify(validated.autoReplies),
          JSON.stringify(validated.settings),
          payload.tenantId,
        ],
      );
      broadcast({ type: 'settings-updated' }, null, payload.tenantId);
      return sendJson(res, 200, { ok: true, ...validated });
    }

    const match = pathname.match(
      /^\/api\/admin\/conversations\/([^/]+)(?:\/(messages|uploads))?$/,
    );

    if (match) {
      const conversationId = safeDecodeURIComponent(match[1]);
      const action = match[2] || '';
      if (!isUuid(conversationId)) {
        return sendError(res, 404, '会话不存在。', 'NOT_FOUND');
      }
      const conversation = await getConversationRow(conversationId, pool, false, payload.tenantId);

      if (!conversation || !authorizeConversation(payload, conversation)) {
        return sendError(res, 404, '会话不存在。', 'NOT_FOUND');
      }

      if (req.method === 'GET' && !action) {
        await pool.query(
          `UPDATE conversations SET unread_admin = 0 WHERE id = $1 AND tenant_id = $2`,
          [conversationId, payload.tenantId],
        );
        const publicConversation = await getPublicConversation(conversationId, pool, payload.tenantId);
        broadcast(
          {
            type: 'summary-updated',
            conversation: {
              ...conversationBase({
                ...conversation,
                unread_admin: 0,
              }),
              latestMessage: publicConversation.messages.at(-1)
                ? {
                    type: publicConversation.messages.at(-1).type,
                    text:
                      publicConversation.messages.at(-1).type === 'image'
                        ? publicConversation.messages.at(-1).text || '[图片]'
                        : publicConversation.messages.at(-1).text,
                    role: publicConversation.messages.at(-1).role,
                    createdAt: publicConversation.messages.at(-1).createdAt,
                  }
                : null,
            },
          },
          conversationId,
          payload.tenantId,
        );
        return sendJson(res, 200, {
          ok: true,
          conversation: publicConversation,
        });
      }

      if (req.method === 'PATCH' && !action) {
        const body = await readJson(req, 64 * 1024);
        const status =
          body.status !== undefined
            ? body.status === 'closed'
              ? 'closed'
              : 'open'
            : conversation.status;
        const visitorName =
          body.visitorName !== undefined
            ? cleanText(body.visitorName, 40) || conversation.visitor_name
            : conversation.visitor_name;
        const visitorNote = body.visitorNote !== undefined ? cleanText(body.visitorNote,80) : conversation.visitor_note || '';

        await pool.query(
          `
            UPDATE conversations
            SET status = $2, visitor_name = $3, visitor_note = $4, updated_at = NOW()
            WHERE id = $1 AND tenant_id = $5
          `,
          [conversationId, status, visitorName, visitorNote, payload.tenantId],
        );

        const publicConversation = await getPublicConversation(conversationId, pool, payload.tenantId);
        broadcast(
          { type: 'conversation-updated', conversation: publicConversation },
          conversationId,
          payload.tenantId,
        );
        return sendJson(res, 200, {
          ok: true,
          conversation: publicConversation,
        });
      }

      if (req.method === 'DELETE' && !action) {
        await pool.query(`DELETE FROM conversations WHERE id = $1 AND tenant_id = $2`, [conversationId, payload.tenantId]);
        broadcast(
          { type: 'conversation-deleted', conversationId },
          conversationId,
          payload.tenantId,
        );
        return sendJson(res, 200, { ok: true });
      }

      if (req.method === 'POST' && action === 'uploads') {
        return handleUpload(req, res, payload, conversation);
      }

      if (req.method === 'POST' && action === 'messages') {
        if (!rateLimit(req, res, 'admin-message', 100, 60_000)) return;
        const body = await readJson(req);
        const result = await createAdminMessage(conversationId, body, payload.tenantId);
        broadcast(
          { type: 'conversation-updated', conversation: result.conversation },
          conversationId,
          payload.tenantId,
        );
        return sendJson(res, 201, { ok: true, message: result.message });
      }
    }
  }

  if (req.method === 'GET' && pathname.startsWith('/api/media/')) {
    const payload = authenticate(req);
    if (!payload) {
      return sendError(res, 401, '没有权限读取图片。', 'AUTH');
    }

    const attachmentId = safeDecodeURIComponent(
      pathname.slice('/api/media/'.length),
    );
    if (!isUuid(attachmentId)) {
      return sendError(res, 404, '图片不存在。', 'NOT_FOUND');
    }
    const result = await pool.query(
      `
        SELECT
          a.*,
          c.visitor_key_hash,
          c.tenant_id,
          c.visitor_name,
          c.status,
          c.unread_admin,
          c.unread_user,
          c.created_at AS conversation_created_at,
          c.updated_at AS conversation_updated_at
        FROM attachments a
        JOIN conversations c ON c.id = a.conversation_id
        WHERE a.id = $1
      `,
      [attachmentId],
    );
    const row = result.rows[0];
    if (!row) return sendError(res, 404, '图片不存在。', 'NOT_FOUND');

    const conversationForAuth = {
      id: row.conversation_id,
      tenant_id: row.tenant_id,
      visitor_key_hash: row.visitor_key_hash,
    };
    if (!authorizeConversation(payload, conversationForAuth)) {
      return sendError(res, 403, '没有权限读取图片。', 'FORBIDDEN');
    }
    const tenant = await getTenantById(row.tenant_id);
    if (!tenant || tenantExpired(tenant)) return sendError(res,403,'服务已到期，请续费。','TENANT_EXPIRED');

    const data = row.data;
    if (!Buffer.isBuffer(data)) {
      return sendError(res, 404, '图片不存在。', 'NOT_FOUND');
    }

    res.statusCode = 200;
    res.setHeader('Content-Type', row.mime);
    res.setHeader('Content-Length', String(data.length));
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Content-Disposition', `inline; filename="image"`);
    return res.end(data);
  }

  return sendError(res, 404, '接口不存在。', 'NOT_FOUND');
}

const server = http.createServer((req, res) => {
  router(req, res).catch((error) => {
    console.error('请求处理失败：', error);
    if (res.headersSent) {
      res.destroy();
      return;
    }
    sendError(
      res,
      Number(error.statusCode || 500),
      error.statusCode ? error.message : '服务器内部错误。',
      error.code || 'SERVER_ERROR',
    );
  });
});

server.requestTimeout = 30_000;
server.headersTimeout = 35_000;
server.keepAliveTimeout = 65_000;

async function shutdown(signal) {
  console.log(`${signal}：正在关闭服务。`);
  server.close(async () => {
    try {
      await pool.end();
    } finally {
      process.exit(0);
    }
  });

  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

await initDatabase();

server.listen(PORT, HOST, () => {
  console.log(`Neon 聊天后端已启动：http://${HOST}:${PORT}`);
  console.log(`聊天保留时间：${RETENTION_HOURS} 小时`);
  console.log(`Telegram 发卡机器人：${TELEGRAM_ENABLED ? '已启用' : '未启用'}`);
});
