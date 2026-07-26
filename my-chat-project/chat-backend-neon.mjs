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
 *   ADMIN_PASSWORD   客服后台密码（至少10个字符）
 *   ALLOWED_ORIGINS  前端域名，英文逗号分隔
 *   TOKEN_SECRET     至少32个字符的随机密钥
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
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const TOKEN_SECRET_TEXT = process.env.TOKEN_SECRET || '';
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

if (!ADMIN_PASSWORD || ADMIN_PASSWORD.length < 10) {
  throw new Error('ADMIN_PASSWORD 必须设置，且至少10个字符。');
}

if (!ALLOWED_ORIGINS.length) {
  throw new Error(
    'ALLOWED_ORIGINS 必须设置，例如：https://user.example.com,https://admin.example.com',
  );
}

if (TOKEN_SECRET_TEXT.length < 32) {
  throw new Error('TOKEN_SECRET 必须设置，且至少32个字符。');
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

function passwordMatches(input) {
  const supplied = createHmac('sha256', TOKEN_SECRET)
    .update(String(input || ''))
    .digest();
  const expected = createHmac('sha256', TOKEN_SECRET)
    .update(ADMIN_PASSWORD)
    .digest();
  return timingSafeEqual(supplied, expected);
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
  return {
    id: row.id,
    visitorName: row.visitor_name,
    status: row.status,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    unreadAdmin: Number(row.unread_admin || 0),
    unreadUser: Number(row.unread_user || 0),
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

async function getConfig(client = pool) {
  const result = await client.query(
    `SELECT canned_replies, auto_replies, settings FROM app_config WHERE id = 1`,
  );
  if (!result.rows[0]) throw new Error('系统设置不存在。');
  return {
    cannedReplies: result.rows[0].canned_replies || [],
    autoReplies: result.rows[0].auto_replies || [],
    settings: result.rows[0].settings || {},
  };
}

async function getConversationRow(id, client = pool, forUpdate = false) {
  const result = await client.query(
    `
      SELECT * FROM conversations
      WHERE id = $1
      ${forUpdate ? 'FOR UPDATE' : ''}
    `,
    [id],
  );
  return result.rows[0] || null;
}

async function getPublicConversation(id, client = pool) {
  const conversationResult = await client.query(
    `SELECT * FROM conversations WHERE id = $1`,
    [id],
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

async function getAllSummaries() {
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
    ORDER BY c.updated_at DESC
  `);
  return result.rows.map(conversationSummary);
}

function authorizeConversation(payload, conversation) {
  if (payload?.kind === 'admin') return true;
  return Boolean(
    payload?.kind === 'user' &&
      payload.conversationId === conversation.id &&
      payload.visitorKey &&
      timingSafeTextEqual(
        hashVisitorKey(payload.visitorKey),
        conversation.visitor_key_hash,
      ),
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
  };

  return { cannedReplies, autoReplies, settings };
}

function sendSse(res, payload) {
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function broadcast(payload, conversationId = null) {
  for (const client of sseClients) {
    if (
      client.kind === 'user' &&
      client.conversationId !== conversationId
    ) {
      continue;
    }

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
      payload.kind,
      data,
    ],
  );

  return sendJson(res, 201, {
    ok: true,
    attachment: publicAttachment(result.rows[0]),
  });
}

async function createUserMessage(conversationId, body) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const conversation = await getConversationRow(conversationId, client, true);
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
      const config = await getConfig(client);
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
    const publicConversation = await getPublicConversation(conversationId);

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

async function createAdminMessage(conversationId, body) {
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const conversation = await getConversationRow(conversationId, client, true);
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
    const publicConversation = await getPublicConversation(conversationId);

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
      databaseTime: new Date(dbResult.rows[0].now).toISOString(),
    });
  }

  if (req.method === 'POST' && pathname === '/api/admin/login') {
    if (!rateLimit(req, res, 'login', 8, 15 * 60_000)) return;
    const body = await readJson(req, 32 * 1024);
    if (!passwordMatches(body.password)) {
      return sendError(res, 401, '密码错误。', 'LOGIN_FAILED');
    }
    return sendJson(res, 200, {
      ok: true,
      token: signToken({ kind: 'admin' }, 12 * 3600),
    });
  }

  if (req.method === 'POST' && pathname === '/api/user/session') {
    if (!rateLimit(req, res, 'new-session', 12, 60_000)) return;
    const body = await readJson(req, 32 * 1024);
    await cleanupExpiredData();

    const countResult = await pool.query(`SELECT COUNT(*)::int AS count FROM conversations`);
    if (countResult.rows[0].count >= MAX_CONVERSATIONS) {
      return sendError(
        res,
        503,
        '当前会话过多，请稍后再试。',
        'CONVERSATION_LIMIT',
      );
    }

    const config = await getConfig();
    const conversationId = randomUUID();
    const visitorKey = randomBytes(24).toString('base64url');
    const visitorName =
      cleanText(body.name, 40) || `访客 ${conversationId.slice(0, 6)}`;
    const client = await pool.connect();

    try {
      await client.query('BEGIN');
      await client.query(
        `
          INSERT INTO conversations (
            id, visitor_key_hash, visitor_name
          )
          VALUES ($1, $2, $3)
        `,
        [conversationId, hashVisitorKey(visitorKey), visitorName],
      );

      if (config.settings?.welcomeText) {
        await client.query(
          `
            INSERT INTO messages (
              id, conversation_id, role, source, type, text
            )
            VALUES ($1, $2, 'admin', 'auto', 'text', $3)
          `,
          [randomUUID(), conversationId, cleanText(config.settings.welcomeText, 2000)],
        );
        await client.query(
          `UPDATE conversations SET updated_at = NOW() WHERE id = $1`,
          [conversationId],
        );
      }

      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }

    const conversation = await getPublicConversation(conversationId);
    broadcast(
      {
        type: 'conversation-created',
        conversation: conversationSummary({
          id: conversation.id,
          visitor_name: conversation.visitorName,
          status: conversation.status,
          created_at: conversation.createdAt,
          updated_at: conversation.updatedAt,
          unread_admin: conversation.unreadAdmin,
          unread_user: conversation.unreadUser,
          latest_id: conversation.messages.at(-1)?.id || null,
          latest_type: conversation.messages.at(-1)?.type,
          latest_text: conversation.messages.at(-1)?.text,
          latest_role: conversation.messages.at(-1)?.role,
          latest_created_at: conversation.messages.at(-1)?.createdAt,
        }),
      },
      conversationId,
    );

    return sendJson(res, 201, {
      ok: true,
      token: signToken({
        kind: 'user',
        conversationId,
        visitorKey,
      }),
      conversation,
      settings: { siteName: config.settings?.siteName || '在线客服' },
    });
  }

  if (req.method === 'GET' && pathname === '/api/events') {
    const payload = authenticate(req);
    if (!payload || !['user', 'admin'].includes(payload.kind)) {
      return sendError(res, 401, '登录已失效。', 'AUTH');
    }

    if (payload.kind === 'user') {
      const conversation = await getConversationRow(payload.conversationId);
      if (!conversation || !authorizeConversation(payload, conversation)) {
        return sendError(res, 401, '会话已失效。', 'AUTH');
      }
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
      conversationId: payload.conversationId || null,
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

    const conversation = await getConversationRow(payload.conversationId);
    if (!conversation || !authorizeConversation(payload, conversation)) {
      return sendError(res, 401, '访客会话不存在。', 'AUTH');
    }

    if (req.method === 'GET' && pathname === '/api/user/conversation') {
      await pool.query(
        `UPDATE conversations SET unread_user = 0 WHERE id = $1`,
        [conversation.id],
      );
      const [publicConversation, config] = await Promise.all([
        getPublicConversation(conversation.id),
        getConfig(),
      ]);
      return sendJson(res, 200, {
        ok: true,
        conversation: publicConversation,
        settings: { siteName: config.settings?.siteName || '在线客服' },
      });
    }

    if (req.method === 'POST' && pathname === '/api/user/uploads') {
      return handleUpload(req, res, payload, conversation);
    }

    if (req.method === 'POST' && pathname === '/api/user/messages') {
      if (!rateLimit(req, res, 'user-message', 40, 60_000)) return;
      const body = await readJson(req);
      const result = await createUserMessage(conversation.id, body);
      broadcast(
        {
          type: 'conversation-updated',
          trigger: 'user-message',
          conversation: result.conversation,
        },
        conversation.id,
      );
      return sendJson(res, 201, {
        ok: true,
        message: result.message,
        autoReply: result.autoReply,
      });
    }
  }

  if (pathname.startsWith('/api/admin/')) {
    const payload = authenticate(req, 'admin');
    if (!payload) {
      return sendError(res, 401, '后台登录已失效。', 'AUTH');
    }

    if (req.method === 'GET' && pathname === '/api/admin/bootstrap') {
      const [conversations, config] = await Promise.all([
        getAllSummaries(),
        getConfig(),
      ]);
      return sendJson(res, 200, {
        ok: true,
        conversations,
        cannedReplies: config.cannedReplies,
        autoReplies: config.autoReplies,
        settings: config.settings,
      });
    }

    if (req.method === 'PUT' && pathname === '/api/admin/settings') {
      const body = await readJson(req, 512 * 1024);
      const current = await getConfig();
      const validated = validateAdminSettings(body, current);
      await pool.query(
        `
          UPDATE app_config
          SET canned_replies = $1::jsonb,
              auto_replies = $2::jsonb,
              settings = $3::jsonb,
              updated_at = NOW()
          WHERE id = 1
        `,
        [
          JSON.stringify(validated.cannedReplies),
          JSON.stringify(validated.autoReplies),
          JSON.stringify(validated.settings),
        ],
      );
      broadcast({ type: 'settings-updated' });
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
      const conversation = await getConversationRow(conversationId);

      if (!conversation) {
        return sendError(res, 404, '会话不存在。', 'NOT_FOUND');
      }

      if (req.method === 'GET' && !action) {
        await pool.query(
          `UPDATE conversations SET unread_admin = 0 WHERE id = $1`,
          [conversationId],
        );
        const publicConversation = await getPublicConversation(conversationId);
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

        await pool.query(
          `
            UPDATE conversations
            SET status = $2, visitor_name = $3, updated_at = NOW()
            WHERE id = $1
          `,
          [conversationId, status, visitorName],
        );

        const publicConversation = await getPublicConversation(conversationId);
        broadcast(
          { type: 'conversation-updated', conversation: publicConversation },
          conversationId,
        );
        return sendJson(res, 200, {
          ok: true,
          conversation: publicConversation,
        });
      }

      if (req.method === 'DELETE' && !action) {
        await pool.query(`DELETE FROM conversations WHERE id = $1`, [conversationId]);
        broadcast(
          { type: 'conversation-deleted', conversationId },
          conversationId,
        );
        return sendJson(res, 200, { ok: true });
      }

      if (req.method === 'POST' && action === 'uploads') {
        return handleUpload(req, res, payload, conversation);
      }

      if (req.method === 'POST' && action === 'messages') {
        if (!rateLimit(req, res, 'admin-message', 100, 60_000)) return;
        const body = await readJson(req);
        const result = await createAdminMessage(conversationId, body);
        broadcast(
          { type: 'conversation-updated', conversation: result.conversation },
          conversationId,
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
      visitor_key_hash: row.visitor_key_hash,
    };
    if (!authorizeConversation(payload, conversationForAuth)) {
      return sendError(res, 403, '没有权限读取图片。', 'FORBIDDEN');
    }

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
});
