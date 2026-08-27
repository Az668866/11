import http from 'node:http';
import https from 'node:https';
import { AsyncLocalStorage } from 'node:async_hooks';
import { lookup as dnsLookup } from 'node:dns';
import { BlockList, isIP } from 'node:net';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
  scrypt,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import {
  DeleteObjectCommand,
  GetObjectCommand,
  PutObjectCommand,
  S3Client,
} from '@aws-sdk/client-s3';
import pg from 'pg';
import QRCode from 'qrcode';
import sharp from 'sharp';
import webpush from 'web-push';

const { Pool } = pg;

const PORT = Number(process.env.PORT || 10000);
const HOST = process.env.HOST || '0.0.0.0';
const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();
const TOKEN_SECRET_TEXT = process.env.TOKEN_SECRET || '';
// 数据保护密钥与令牌签名密钥分离后，可以轮换 TOKEN_SECRET 使全部
// 现有令牌立即失效，而不会让历史卡密、TOTP 和加密语音无法读取。
// 未显式配置时沿用旧版 TOKEN_SECRET，保证原数据库可无损升级。
const DATA_PROTECTION_SECRET_TEXT =
  process.env.DATA_PROTECTION_SECRET || TOKEN_SECRET_TEXT;
const DATA_PROTECTION_SECRET_CONFIGURED = Boolean(
  process.env.DATA_PROTECTION_SECRET,
);
const PUBLIC_API_BASE = String(
  process.env.PUBLIC_API_BASE || 'https://api.ykf000.com',
).replace(/\/+$/, '');
const APP_VERSION = String(process.env.APP_VERSION || '2.4.8').trim();
const SUPPORT_TELEGRAM = String(
  process.env.SUPPORT_TELEGRAM || '@YingYingUu',
).trim();
const CUSTOMER_SERVICE_TELEGRAM = String(
  process.env.CUSTOMER_SERVICE_TELEGRAM || '@kjwh8',
).trim();
const SUPER_ADMIN_USERNAME = String(
  process.env.SUPER_ADMIN_USERNAME || '',
).trim();
const SUPER_ADMIN_PASSWORD = String(
  process.env.SUPER_ADMIN_PASSWORD || '',
);
const SUPER_ADMIN_TOTP_SECRET = String(
  process.env.SUPER_ADMIN_TOTP_SECRET || '',
)
  .replace(/\s+/g, '')
  .toUpperCase();
const SUPER_ADMIN_USERNAME_2 = String(
  process.env.SUPER_ADMIN_USERNAME_2 || '',
).trim();
const SUPER_ADMIN_PASSWORD_2 = String(
  process.env.SUPER_ADMIN_PASSWORD_2 || '',
);
const SUPER_ADMIN_TOTP_SECRET_2 = String(
  process.env.SUPER_ADMIN_TOTP_SECRET_2 || '',
)
  .replace(/\s+/g, '')
  .toUpperCase();
const ENV_SUPER_ADMINS = [
  {
    username: SUPER_ADMIN_USERNAME.toLowerCase(),
    password: SUPER_ADMIN_PASSWORD,
    totpSecret: SUPER_ADMIN_TOTP_SECRET,
  },
  {
    username: SUPER_ADMIN_USERNAME_2.toLowerCase(),
    password: SUPER_ADMIN_PASSWORD_2,
    totpSecret: SUPER_ADMIN_TOTP_SECRET_2,
  },
].filter((item) => item.username && item.password);
const COOKIE_DOMAIN = String(process.env.COOKIE_DOMAIN || '').trim();
const COOKIE_SECURE = process.env.COOKIE_SECURE !== 'false';
const REQUIRE_CLOUDFLARE = process.env.REQUIRE_CLOUDFLARE === 'true';
const REQUIRE_SUPER_ADMIN_TOTP =
  process.env.REQUIRE_SUPER_ADMIN_TOTP !== 'false';
const STRICT_CLIENT_ORIGIN =
  process.env.STRICT_CLIENT_ORIGIN !== 'false';
const REQUIRE_CLIENT_TEMPLATE_ID =
  process.env.REQUIRE_CLIENT_TEMPLATE_ID !== 'false';
const CLOUDFLARE_ORIGIN_SECRET = String(
  process.env.CLOUDFLARE_ORIGIN_SECRET || '',
);
const RENDER_API_KEY = String(process.env.RENDER_API_KEY || '').trim();
const RENDER_SERVICE_ID = String(process.env.RENDER_SERVICE_ID || '').trim();
const NEON_API_KEY = String(process.env.NEON_API_KEY || '').trim();
const NEON_PROJECT_ID = String(process.env.NEON_PROJECT_ID || '').trim();
const NEON_ORG_ID = String(process.env.NEON_ORG_ID || '').trim();
const NETLIFY_AUTH_TOKEN = String(
  process.env.NETLIFY_AUTH_TOKEN || '',
).trim();
const TENANT_ENTRY_ENABLED = process.env.TENANT_ENTRY_ENABLED === 'true';
// 客户级短域名必须在 Worker、DNS 和 HTTPS 全部验收后显式启用。
// 默认关闭，避免仅部署后端时立即替换现有租户入口和域名前缀。
const TENANT_TEMPLATE_DOMAINS_ENABLED =
  process.env.TENANT_TEMPLATE_DOMAINS_ENABLED === 'true';
const TENANT_ENTRY_DOMAIN_SUFFIXES = [...new Set(
  String(process.env.TENANT_ENTRY_DOMAIN_SUFFIXES || '')
    .split(',')
    .map((item) => normalizeTenantDomainSuffix(item))
    .filter(Boolean),
)];
const TENANT_ENTRY_DOMAIN_POOL = [...new Set(
  String(process.env.TENANT_ENTRY_DOMAIN_POOL || '')
    .split(',')
    .map((item) => normalizeTenantDomainSuffix(item))
    .filter(Boolean),
)];
const TENANT_ENTRY_GATEWAY_SECRET = String(
  process.env.TENANT_ENTRY_GATEWAY_SECRET || '',
);
const CLOUDFLARE_API_TOKEN = String(
  process.env.CLOUDFLARE_API_TOKEN || '',
).trim();
const CLOUDFLARE_TENANT_ENTRY_WORKER_SCRIPT = cleanText(
  process.env.CLOUDFLARE_TENANT_ENTRY_WORKER_SCRIPT ||
    'tuojie-tenant-entry',
  120,
);
const CLOUDFLARE_TENANT_ENTRY_DNS_IPV4 = String(
  process.env.CLOUDFLARE_TENANT_ENTRY_DNS_IPV4 || '192.0.2.1',
).trim();
const INSTANCE_MEMORY_MB = envNumber(
  'INSTANCE_MEMORY_MB',
  2048,
  128,
  524288,
);
const INSTANCE_CPU_CORES = envNumber('INSTANCE_CPU_CORES', 1, 0.1, 256);
const TELEGRAM_BOT_TOKEN = String(process.env.TELEGRAM_BOT_TOKEN || '').trim();
const TELEGRAM_WEBHOOK_SECRET = String(process.env.TELEGRAM_WEBHOOK_SECRET || '').trim();
const TELEGRAM_ALLOWED_USER_IDS = new Set(
  [
    process.env.TELEGRAM_ALLOWED_USER_IDS,
    process.env.TELEGRAM_ALLOWED_PRIVATE_USER_IDS,
  ]
    .filter(Boolean)
    .join(',')
    .split(',')
    .map((item) => item.trim())
    .filter((item) => /^\d+$/.test(item)),
);
const TELEGRAM_ALLOWED_GROUP_IDS = new Set(
  String(process.env.TELEGRAM_ALLOWED_GROUP_IDS || '')
    .split(',')
    .map((item) => item.trim())
    .filter((item) => /^-?\d+$/.test(item)),
);
const TELEGRAM_ENABLED = Boolean(TELEGRAM_BOT_TOKEN);
function envNumber(name, fallback, min, max) {
  const parsed = Number(process.env[name] ?? fallback);
  return Number.isFinite(parsed)
    ? Math.min(max, Math.max(min, parsed))
    : fallback;
}
const LEGACY_API_ENABLED = process.env.LEGACY_API_ENABLED === 'true';
const API_PAGE_DEFAULT = Math.trunc(
  envNumber('API_PAGE_DEFAULT', 50, 20, 100),
);
const API_PAGE_MAX = Math.trunc(envNumber('API_PAGE_MAX', 100, 50, 200));
const CONFIG_CACHE_MS = envNumber(
  'CONFIG_CACHE_SECONDS',
  300,
  30,
  3600,
) * 1000;
const MONITOR_CACHE_MS = envNumber(
  'MONITOR_CACHE_MINUTES',
  10,
  5,
  60,
) * 60_000;
const ACTIVE_MONITOR_INTERVAL_MS = envNumber(
  'ACTIVE_MONITOR_MINUTES',
  15,
  5,
  60,
) * 60_000;
const ACTIVE_CLEANUP_INTERVAL_MS = envNumber(
  'ACTIVE_CLEANUP_MINUTES',
  30,
  10,
  180,
) * 60_000;
const READINESS_CACHE_MS = envNumber(
  'READINESS_CACHE_SECONDS',
  15,
  5,
  60,
) * 1000;
const BLOCKLIST_CACHE_MS = envNumber(
  'BLOCKLIST_CACHE_SECONDS',
  300,
  30,
  3600,
) * 1000;
const SECURITY_IP_BLOCK_HOURS = envNumber(
  'SECURITY_IP_BLOCK_HOURS',
  24,
  1,
  24 * 365,
);
const SECURITY_ALERT_COOLDOWN_MS = envNumber(
  'SECURITY_ALERT_COOLDOWN_MINUTES',
  10,
  1,
  1440,
) * 60_000;
const SLOW_API_MS = envNumber('SLOW_API_MS', 1000, 100, 60_000);
const SLOW_QUERY_MS = envNumber('SLOW_QUERY_MS', 500, 50, 60_000);
const LICENSE_GENERATION_REPLAY_MS = 15 * 60_000;
const AUDIT_RETENTION_DAYS = Math.trunc(
  envNumber('AUDIT_RETENTION_DAYS', 90, 7, 3650),
);
const ANOMALY_WINDOW_MS = 10 * 60_000;
const ANOMALY_VISITOR_IP_LIMIT = Math.trunc(
  envNumber('ANOMALY_VISITOR_IP_10M', 12, 3, 10_000),
);
const ANOMALY_VISITOR_TENANT_LIMIT = Math.trunc(
  envNumber('ANOMALY_VISITOR_TENANT_10M', 120, 10, 100_000),
);
const ANOMALY_MESSAGE_CONVERSATION_LIMIT = Math.trunc(
  envNumber('ANOMALY_MESSAGES_CONVERSATION_10M', 80, 10, 100_000),
);
const ANOMALY_MESSAGE_TENANT_LIMIT = Math.trunc(
  envNumber('ANOMALY_MESSAGES_TENANT_10M', 600, 50, 1_000_000),
);
// 未登录的模板来源不一致必须连续出现才通知管理员；带有效签名令牌的
// 跨来源复用会结合租户当前批准来源单独作高置信判定并立即告警。
const ANOMALY_ORIGIN_MISMATCH_LIMIT = Math.trunc(
  envNumber('ANOMALY_ORIGIN_MISMATCH_10M', 3, 2, 1000),
);
const QR_INCIDENT_WINDOW_MINUTES = Math.trunc(
  envNumber('QR_INCIDENT_WINDOW_MINUTES', 10, 1, 1440),
);
const QR_INCIDENT_REVIEW_THRESHOLD = Math.trunc(
  envNumber('QR_INCIDENT_REVIEW_THRESHOLD', 3, 2, 1000),
);
const MAX_IMAGE_BYTES =
  envNumber('MAX_IMAGE_MB', 8, 1, 16) * 1024 * 1024;
const MAX_VIDEO_BYTES =
  envNumber('MAX_VIDEO_MB', 25, 1, 50) * 1024 * 1024;
const MAX_AUDIO_BYTES =
  envNumber('MAX_AUDIO_MB', 12, 1, 30) * 1024 * 1024;
const MAX_AVATAR_BYTES = 2 * 1024 * 1024;
const MAX_QR_LOGO_BYTES = 3 * 1024 * 1024;
const MAX_COVER_BYTES = 5 * 1024 * 1024;
const LEGACY_QR_BOTTOM_TEXT =
  '支持微信、支付宝、QQ和浏览器进入\n此二维码为活码，模板域名更换后仍可继续使用';
const DEFAULT_QR_BOTTOM_TEXT =
  '支持微信、支付宝、QQ和浏览器进入\n二维码已绑定当前模板和商家专属识别码';
const MAX_ALBUM_IMAGES = 9;
const MAX_CONCURRENT_UPLOADS = Math.trunc(
  envNumber('MAX_CONCURRENT_UPLOADS', 4, 1, 8),
);
const MAX_CONVERSATIONS = Math.trunc(
  envNumber('MAX_CONVERSATIONS', 1000, 10, 10_000),
);
const MAX_MESSAGES_PER_CONVERSATION = Math.trunc(
  envNumber('MAX_MESSAGES_PER_CONVERSATION', 100, 50, 500),
);
const MAX_SSE_CONNECTIONS = Math.trunc(
  envNumber('MAX_SSE_CONNECTIONS', 500, 50, 2000),
);
const RETENTION_HOURS = envNumber('CHAT_RETENTION_HOURS', 24, 1, 24);
const TOKEN_TTL_SECONDS = Math.min(
  RETENTION_HOURS * 3600,
  envNumber('TOKEN_TTL_HOURS', 24, 1, 24) * 3600,
);
const DB_POOL_MAX = Math.trunc(
  envNumber('DB_POOL_MAX', 5, 1, 20),
);
const WEB_PUSH_VAPID_PUBLIC_KEY = String(
  process.env.WEB_PUSH_VAPID_PUBLIC_KEY || '',
).trim();
const WEB_PUSH_VAPID_PRIVATE_KEY = String(
  process.env.WEB_PUSH_VAPID_PRIVATE_KEY || '',
).trim();
const WEB_PUSH_SUBJECT = String(
  process.env.WEB_PUSH_SUBJECT || 'mailto:security@example.com',
).trim();
const DEFAULT_WEB_PUSH_HOSTS = [
  'fcm.googleapis.com',
  'updates.push.services.mozilla.com',
  'push.services.mozilla.com',
  'web.push.apple.com',
  '.notify.windows.com',
];
const WEB_PUSH_ALLOWED_HOSTS = new Set(
  [
    ...DEFAULT_WEB_PUSH_HOSTS,
    ...String(process.env.WEB_PUSH_ALLOWED_HOSTS || '').split(','),
  ]
    .map((item) => item.trim().toLowerCase())
    .filter((item) =>
      /^\.?[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(item) &&
      (!item.startsWith('.') || item.slice(1).includes('.')),
    ),
);
const WEB_PUSH_ENABLED = Boolean(
  WEB_PUSH_VAPID_PUBLIC_KEY && WEB_PUSH_VAPID_PRIVATE_KEY,
);
if (WEB_PUSH_ENABLED) {
  webpush.setVapidDetails(
    WEB_PUSH_SUBJECT,
    WEB_PUSH_VAPID_PUBLIC_KEY,
    WEB_PUSH_VAPID_PRIVATE_KEY,
  );
}
const WEBRTC_STUN_URLS = String(
  process.env.WEBRTC_STUN_URLS || 'stun:stun.cloudflare.com:3478',
)
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);
const WEBRTC_TURN_URLS = String(process.env.WEBRTC_TURN_URLS || '')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);
const WEBRTC_TURN_USERNAME = String(
  process.env.WEBRTC_TURN_USERNAME || '',
).trim();
const WEBRTC_TURN_CREDENTIAL = String(
  process.env.WEBRTC_TURN_CREDENTIAL || '',
);
const CLOUDFLARE_TURN_KEY_ID = String(
  process.env.CLOUDFLARE_TURN_KEY_ID || '',
).trim();
const CLOUDFLARE_TURN_KEY_API_TOKEN = String(
  process.env.CLOUDFLARE_TURN_KEY_API_TOKEN || '',
).trim();
const CLOUDFLARE_TURN_TTL_SECONDS = Math.trunc(
  envNumber('CLOUDFLARE_TURN_TTL_SECONDS', 86_400, 3_600, 172_800),
);
const CLOUDFLARE_TURN_ENABLED = Boolean(
  CLOUDFLARE_TURN_KEY_ID && CLOUDFLARE_TURN_KEY_API_TOKEN,
);
const CLOUDFLARE_ACCOUNT_ID = String(
  process.env.CLOUDFLARE_ACCOUNT_ID || '',
).trim();
const CLOUDFLARE_ANALYTICS_API_TOKEN = String(
  process.env.CLOUDFLARE_ANALYTICS_API_TOKEN ||
    process.env.CLOUDFLARE_TURN_ANALYTICS_API_TOKEN ||
    '',
).trim();
const CLOUDFLARE_REALTIME_MONTHLY_QUOTA_GB = envNumber(
  'CLOUDFLARE_REALTIME_MONTHLY_QUOTA_GB',
  1000,
  1,
  10_000_000,
);
const CLOUDFLARE_ANALYTICS_CACHE_MS = envNumber(
  'CLOUDFLARE_ANALYTICS_CACHE_MINUTES',
  15,
  5,
  60,
) * 60_000;
const LICENSE_DESKTOP_DEVICE_DEFAULT = Math.trunc(
  envNumber('LICENSE_DESKTOP_DEVICE_DEFAULT', 3, 1, 50),
);
const LICENSE_MOBILE_DEVICE_DEFAULT = Math.trunc(
  envNumber('LICENSE_MOBILE_DEVICE_DEFAULT', 3, 1, 50),
);
const EXPIRED_TENANT_GRACE_DAYS = Math.trunc(
  envNumber('EXPIRED_TENANT_GRACE_DAYS', 3, 1, 30),
);
const ACTIVE_CHAT_WINDOW_MS = envNumber(
  'ACTIVE_CHAT_WINDOW_MINUTES',
  10,
  2,
  60,
) * 60_000;
const CALL_RING_TIMEOUT_SECONDS = Math.trunc(
  envNumber('CALL_RING_TIMEOUT_SECONDS', 45, 20, 120),
);
const CALL_ACTIVE_TIMEOUT_SECONDS = Math.trunc(
  envNumber('CALL_ACTIVE_TIMEOUT_SECONDS', 43_200, 300, 86_400),
);
const cloudflareTurnCredentialCache = new Map();
const cloudflareTurnCredentialRequests = new Map();
let lastCloudflareTurnErrorAt = 0;
let cloudflareTurnFailureUntil = 0;

const STATIC_ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
  .split(',')
  .map((item) => item.trim().replace(/\/$/, ''))
  .filter(Boolean);
const R2_ACCOUNT_ID = String(process.env.R2_ACCOUNT_ID || '').trim();
const R2_ACCESS_KEY_ID = String(process.env.R2_ACCESS_KEY_ID || '').trim();
const R2_SECRET_ACCESS_KEY = String(
  process.env.R2_SECRET_ACCESS_KEY || '',
).trim();
const R2_BUCKET = String(process.env.R2_BUCKET || '').trim();
const R2_ENABLED = Boolean(
  R2_ACCOUNT_ID &&
    R2_ACCESS_KEY_ID &&
    R2_SECRET_ACCESS_KEY &&
    R2_BUCKET,
);

if (!DATABASE_URL || !/^postgres(?:ql)?:\/\//i.test(DATABASE_URL)) {
  throw new Error('DATABASE_URL 必须设置为 Neon PostgreSQL 连接串。');
}

for (const [name, value] of [['PUBLIC_API_BASE', PUBLIC_API_BASE]]) {
  try {
    const parsed = new URL(value);
    if (
      parsed.protocol !== 'https:' ||
      parsed.username ||
      parsed.password ||
      parsed.search ||
      parsed.hash
    ) throw new Error();
  } catch {
    throw new Error(`${name} 必须是标准 HTTPS 地址。`);
  }
}

if (!STATIC_ALLOWED_ORIGINS.length) {
  throw new Error(
    'ALLOWED_ORIGINS 必须设置，例如：https://user.example.com,https://admin.example.com',
  );
}

if (TOKEN_SECRET_TEXT.length < 32) {
  throw new Error('TOKEN_SECRET 必须设置，且至少32个字符。');
}

if (TENANT_ENTRY_ENABLED && !TENANT_ENTRY_DOMAIN_SUFFIXES.length) {
  throw new Error(
    '启用模板自有域名入口时必须设置 TENANT_ENTRY_DOMAIN_SUFFIXES。',
  );
}
if (TENANT_ENTRY_ENABLED && TENANT_ENTRY_GATEWAY_SECRET.length < 32) {
  throw new Error(
    '启用模板自有域名入口时，TENANT_ENTRY_GATEWAY_SECRET 必须至少32个字符。',
  );
}
if (DATA_PROTECTION_SECRET_TEXT.length < 32) {
  throw new Error('DATA_PROTECTION_SECRET 必须至少32个字符。');
}
if (!DATA_PROTECTION_SECRET_CONFIGURED) {
  console.warn(JSON.stringify({
    event: 'data_protection_secret_fallback',
    message:
      'DATA_PROTECTION_SECRET 未显式配置，当前兼容使用 TOKEN_SECRET；轮换 TOKEN_SECRET 前必须先固定数据保护密钥。',
  }));
}
if (Boolean(SUPER_ADMIN_USERNAME) !== Boolean(SUPER_ADMIN_PASSWORD)) {
  throw new Error(
    'SUPER_ADMIN_USERNAME 和 SUPER_ADMIN_PASSWORD 必须同时设置。',
  );
}
if (Boolean(SUPER_ADMIN_USERNAME_2) !== Boolean(SUPER_ADMIN_PASSWORD_2)) {
  throw new Error(
    'SUPER_ADMIN_USERNAME_2 和 SUPER_ADMIN_PASSWORD_2 必须同时设置。',
  );
}
if (SUPER_ADMIN_PASSWORD && SUPER_ADMIN_PASSWORD.length < 8) {
  throw new Error('SUPER_ADMIN_PASSWORD 必须至少8位。');
}
if (SUPER_ADMIN_PASSWORD_2 && SUPER_ADMIN_PASSWORD_2.length < 8) {
  throw new Error('SUPER_ADMIN_PASSWORD_2 必须至少8位。');
}
if (
  SUPER_ADMIN_USERNAME_2 &&
  SUPER_ADMIN_USERNAME.toLowerCase() === SUPER_ADMIN_USERNAME_2.toLowerCase()
) {
  throw new Error('两个超级管理员账号不能相同。');
}
if (
  SUPER_ADMIN_TOTP_SECRET &&
  !/^[A-Z2-7]{16,128}$/.test(SUPER_ADMIN_TOTP_SECRET)
) {
  throw new Error('SUPER_ADMIN_TOTP_SECRET 必须是有效的 Base32 密钥。');
}
if (
  SUPER_ADMIN_TOTP_SECRET_2 &&
  !/^[A-Z2-7]{16,128}$/.test(SUPER_ADMIN_TOTP_SECRET_2)
) {
  throw new Error('SUPER_ADMIN_TOTP_SECRET_2 必须是有效的 Base32 密钥。');
}
if (
  REQUIRE_SUPER_ADMIN_TOTP &&
  ENV_SUPER_ADMINS.some((admin) => !admin.totpSecret)
) {
  throw new Error(
    'REQUIRE_SUPER_ADMIN_TOTP=true 时，每个超级管理员都必须配置 TOTP 密钥。',
  );
}
if (REQUIRE_CLOUDFLARE && CLOUDFLARE_ORIGIN_SECRET.length < 24) {
  throw new Error(
    'REQUIRE_CLOUDFLARE=true 时，CLOUDFLARE_ORIGIN_SECRET 必须至少24位。',
  );
}
if (TELEGRAM_ENABLED) {
  if (!/^[A-Za-z0-9_-]{16,256}$/.test(TELEGRAM_WEBHOOK_SECRET)) {
    throw new Error('TELEGRAM_WEBHOOK_SECRET 必须为16-256位字母、数字、下划线或短横线。');
  }
  if (!TELEGRAM_ALLOWED_USER_IDS.size) {
    throw new Error(
      '启用 Telegram 时必须设置 TELEGRAM_ALLOWED_USER_IDS 操作员白名单（旧变量 TELEGRAM_ALLOWED_PRIVATE_USER_IDS 仍兼容）。',
    );
  }
}

const TOKEN_SECRET = Buffer.from(TOKEN_SECRET_TEXT, 'utf8');
const DATA_PROTECTION_SECRET = Buffer.from(
  DATA_PROTECTION_SECRET_TEXT,
  'utf8',
);
const LICENSE_ENCRYPTION_KEY = createHash('sha256')
  .update(DATA_PROTECTION_SECRET)
  .digest();
const AUDIO_ENCRYPTION_KEY = createHmac('sha256', DATA_PROTECTION_SECRET)
  .update('chat-audio-media-v1')
  .digest();
const AUDIO_ENCRYPTION_MAGIC = Buffer.from('TKAE1', 'ascii');
const SESSION_COOKIE = 'tuojie_super_session';
const ALLOWED_IMAGE_TYPES = new Set([
  'image/jpeg',
  'image/png',
  'image/webp',
  'image/gif',
]);
const ALLOWED_VIDEO_TYPES = new Set([
  'video/mp4',
  'video/webm',
  'video/quicktime',
]);
const ALLOWED_AUDIO_TYPES = new Set([
  'audio/webm',
  'audio/ogg',
  'audio/mp4',
  'audio/mpeg',
  'audio/wav',
]);
const DEFAULT_USER_SITE_URL = 'https://zxkf.netlify.app/';
const DEFAULT_TEMPLATE_ID = '11111111-1111-4111-8111-111111111111';
const RETENTION_OPTIONS = new Set([1, 6, 12, 24, 72, 168, 240, 360]);
const SUPPORTED_FEATURE_FLAGS = new Set([
  'media_album',
  'auto_reply',
  'frontend_templates',
  'message_actions',
  'tenant_branding',
]);

const r2 = R2_ENABLED
  ? new S3Client({
      region: 'auto',
      endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
      credentials: {
        accessKeyId: R2_ACCESS_KEY_ID,
        secretAccessKey: R2_SECRET_ACCESS_KEY,
      },
    })
  : null;

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

const sseClients = new Set();
const rateBuckets = new Map();
let nextRateBucketCleanupAt = 0;
const behaviorBuckets = new Map();
const recentChatActivity = new Map();
const onlineVisitorCountCache = { expiresAt: 0, counts: new Map() };
const securityAlertClaims = new Map();
const MAX_RATE_BUCKETS = 20_000;
const MAX_BEHAVIOR_BUCKETS = 5_000;
const MAX_SECURITY_ALERT_CLAIMS = 2_000;
const blockedIpCache = new Map();
const telegramBlockedUserCache = new Map();
let blockedIpCacheExpiresAt = 0;
let blockedIpCachePromise = null;
const eventHistory = [];
const distributorPresenceTimers = new Map();
const requestLatencies = [];
const routeCounters = new Map();
const minuteCounters = {
  requests: 0,
  errors: 0,
  messages: 0,
  uploads: 0,
  uploadFailures: 0,
  licenseFailures: 0,
  telegramWebhookFailures: 0,
  legacyRequests: 0,
  fullHistoryReads: 0,
  fullHistoryMessages: 0,
  databaseMediaReads: 0,
  databaseMediaBytes: 0,
};
const metricSamples = [];
const alertState = new Map();
const tenantConfigCache = new Map();
const tenantFeatureCache = new Map();
const tenantQrImageCache = new Map();
const tenantEntryResolutionCache = new Map();
const tenantEntryRootDomains = new Set(TENANT_ENTRY_DOMAIN_SUFFIXES);
let activeTenantEntryRootDomain = TENANT_ENTRY_DOMAIN_SUFFIXES[0] || '';
const pushSubscriptionCache = new Map();
const PUSH_SUBSCRIPTION_CACHE_MS = 60_000;
const MAX_PUSH_SUBSCRIPTION_CACHE = 2_000;
const MAX_PUSH_SUBSCRIPTIONS_PER_CONVERSATION = 8;
const TENANT_QR_CACHE_MS = 5 * 60_000;
const MAX_TENANT_QR_CACHE = 100;
const TENANT_ENTRY_RESOLUTION_CACHE_MS = 60_000;
const TENANT_ENTRY_NEGATIVE_CACHE_MS = 5_000;
const MAX_TENANT_ENTRY_RESOLUTION_CACHE = 500;
const TENANT_ENTRY_DOMAIN_STATUS_CACHE_MS = 5 * 60_000;
let tenantEntryDomainStatusCache = {
  expiresAt: 0,
  rows: [],
};
let approvedOriginCache = new Set(STATIC_ALLOWED_ORIGINS);
let approvedOriginCacheExpiresAt = 0;
let nextEventId = 1;
let lastCleanupAt = 0;
let cleanupPromise = null;
let cleanupFailureCount = 0;
let nextCleanupRetryAt = 0;
let activeUploads = 0;
let activeImageTransforms = 0;
let reportTimer = null;
let expiryReminderTimer = null;
let expiryReminderRescheduleTimer = null;
let expiredTenantPurgeTimer = null;
let expiredTenantPurgeRescheduleTimer = null;
let legacySuperKeyBackfillTimer = null;
let activeMonitorPromise = null;
let lastPersistedMonitorAt = 0;
let lastMonitorCounterResetAt = Date.now();
let activeMaintenancePromise = null;
let lastCpuUsage = process.cpuUsage();
let lastCpuSampleAt = process.hrtime.bigint();
let lastMonitorSnapshot = null;
let lastPlatformSettings = null;
let platformSettingsCacheExpiresAt = 0;
let monitorFailureCount = 0;
let nextMonitorRetryAt = 0;
let startedAt = Date.now();
let providerMetricsCache = {
  expiresAt: 0,
  render: null,
  neon: null,
  cloudflareTurn: null,
};
let providerMetricsPromise = null;
let cloudflareTurnAnalyticsCache = {
  expiresAt: 0,
  value: null,
  promise: null,
};
let readinessCache = {
  expiresAt: 0,
  value: null,
  promise: null,
};
let superDashboardCache = { expiresAt: 0, value: null, promise: null };
const telegramGenerationClaims = new Map();

function nowIso() {
  return new Date().toISOString();
}

function normalizeApiPath(pathname) {
  if (!pathname.startsWith('/api/v2/')) {
    return { apiVersion: 1, pathname };
  }
  return {
    apiVersion: 2,
    pathname: pathname.replace(/^\/api\/v2(?=\/)/, '/api'),
  };
}

function monitoredRouteKey(method, pathname) {
  const normalized = normalizeApiPath(pathname).pathname
    .replace(
      /\/[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}(?=\/|$)/gi,
      '/:id',
    )
    .replace(/\/\d+(?=\/|$)/g, '/:number')
    .slice(0, 180);
  return `${String(method || 'GET').toUpperCase()} ${normalized}`;
}

function requireLegacyApi(res, apiVersion) {
  if (apiVersion >= 2 || LEGACY_API_ENABLED) return true;
  sendError(
    res,
    410,
    '旧版接口已关闭，请更新客户端模板。',
    'LEGACY_API_DISABLED',
  );
  return false;
}

function pageLimit(url, fallback = API_PAGE_DEFAULT) {
  const parsed = Number(url.searchParams.get('limit') || fallback);
  return Math.min(
    API_PAGE_MAX,
    Math.max(1, Number.isFinite(parsed) ? Math.trunc(parsed) : fallback),
  );
}

function encodeCursor(value) {
  return Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');
}

function decodeCursor(value) {
  if (!value) return null;
  try {
    const parsed = JSON.parse(
      Buffer.from(String(value), 'base64url').toString('utf8'),
    );
    if (!parsed || typeof parsed !== 'object') return null;
    const at = new Date(parsed.at);
    if (!Number.isFinite(at.getTime()) || !isUuid(parsed.id)) return null;
    return { at: at.toISOString(), id: parsed.id };
  } catch {
    return null;
  }
}

function cacheGet(cache, key) {
  const item = cache.get(key);
  if (!item || item.expiresAt <= Date.now()) {
    if (item) cache.delete(key);
    return null;
  }
  return item.value;
}

function cacheSet(cache, key, value, ttl = CONFIG_CACHE_MS) {
  cache.set(key, { value, expiresAt: Date.now() + ttl });
  return value;
}

function parseRequestUrl(value) {
  try {
    const parsed = new URL(String(value || '/'), 'http://localhost');
    return ['http:', 'https:'].includes(parsed.protocol) ? parsed : null;
  } catch {
    return null;
  }
}

function requestTraceId(req) {
  const traceparent = String(req?.headers?.traceparent || '').trim();
  const match = traceparent.match(
    /^[\da-f]{2}-([\da-f]{32})-[\da-f]{16}-[\da-f]{2}$/i,
  );
  return match?.[1]?.toLowerCase() || randomBytes(16).toString('hex');
}

function makeRoomInExpiringMap(cache, maxEntries, now, expiresAtOf) {
  if (cache.size < maxEntries) return;
  for (const [key, value] of cache) {
    if (expiresAtOf(value) <= now) cache.delete(key);
  }
  while (cache.size >= maxEntries) {
    const oldestKey = cache.keys().next().value;
    if (oldestKey === undefined) break;
    cache.delete(oldestKey);
  }
}

function invalidateTenantCaches(tenantId = '') {
  if (tenantId) {
    tenantConfigCache.delete(tenantId);
    tenantFeatureCache.delete(tenantId);
    for (const key of tenantQrImageCache.keys()) {
      if (key.startsWith(`${tenantId}:`)) tenantQrImageCache.delete(key);
    }
    return;
  }
  tenantConfigCache.clear();
  tenantFeatureCache.clear();
  tenantQrImageCache.clear();
}

function invalidateTenantEntryCaches() {
  tenantEntryResolutionCache.clear();
  tenantEntryDomainStatusCache = { expiresAt: 0, rows: [] };
}

function cacheTenantEntryResolution(hostname, value, ttl) {
  makeRoomInExpiringMap(
    tenantEntryResolutionCache,
    MAX_TENANT_ENTRY_RESOLUTION_CACHE,
    Date.now(),
    (item) => item.expiresAt,
  );
  return cacheSet(tenantEntryResolutionCache, hostname, value, ttl);
}

function invalidatePlatformCache() {
  platformSettingsCacheExpiresAt = 0;
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
      avatarAssetId: '',
      qrTopText: '',
      qrBottomText: DEFAULT_QR_BOTTOM_TEXT,
      qrLogoAssetId: '',
      welcomeText: '您好，欢迎咨询。您可以发送文字、图片或视频，我们会尽快回复。',
      onlineStatusText: '客服在线',
      pageTitle: '在线客服',
      quickReplyDirectSend: true,
      autoReplyEnabled: true,
      defaultAutoReplyEnabled: true,
      defaultAutoReply: '消息已收到，客服看到后会尽快回复。',
      defaultAutoReplyImageAssetId: '',
      autoReplyCooldownSeconds: 20,
      frontendTemplateId: DEFAULT_TEMPLATE_ID,
      retentionHours: 24,
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
        key_ciphertext TEXT,
        key_prefix TEXT NOT NULL,
        key_suffix TEXT NOT NULL,
        duration_code TEXT NOT NULL CHECK (duration_code IN ('1h','1d','7d','30d','180d','365d')),
        duration_days INTEGER NOT NULL CHECK (duration_days > 0),
        status TEXT NOT NULL DEFAULT 'unused' CHECK (status IN ('unused','active','superseded','revoked')),
        telegram_chat_id TEXT,
        telegram_user_id TEXT,
        telegram_username TEXT,
        telegram_display_name TEXT,
        telegram_update_id BIGINT,
        activated_at TIMESTAMPTZ,
        expires_at TIMESTAMPTZ,
        revoked_at TIMESTAMPTZ,
        disable_mode TEXT NOT NULL DEFAULT 'notice'
          CHECK (disable_mode IN ('notice','busy')),
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

    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS name TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS note TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS distributor_note TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1`);
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS last_admin_online_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS expiry_reminder_sent_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS generated_by_admin_id UUID`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS super_key_hash TEXT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS super_key_ciphertext TEXT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS super_key_suffix TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS max_desktop_devices INTEGER NOT NULL DEFAULT ${LICENSE_DESKTOP_DEVICE_DEFAULT}`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS max_mobile_devices INTEGER NOT NULL DEFAULT ${LICENSE_MOBILE_DEVICE_DEFAULT}`);
    await client.query(`
      ALTER TABLE license_keys
      ADD COLUMN IF NOT EXISTS disable_mode TEXT NOT NULL DEFAULT 'notice'
    `);
    await client.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid='license_keys'::regclass
            AND conname='license_keys_disable_mode_check'
        ) THEN
          ALTER TABLE license_keys
          ADD CONSTRAINT license_keys_disable_mode_check
          CHECK (disable_mode IN ('notice','busy'));
        END IF;
      END $$
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS license_keys_super_hash_unique_idx
      ON license_keys (super_key_hash)
      WHERE super_key_hash IS NOT NULL
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS license_devices (
        id UUID PRIMARY KEY,
        license_id UUID NOT NULL REFERENCES license_keys(id) ON DELETE CASCADE,
        access_kind TEXT NOT NULL DEFAULT 'normal'
          CHECK (access_kind IN ('normal','super')),
        device_hash TEXT NOT NULL,
        device_type TEXT NOT NULL
          CHECK (device_type IN ('desktop','mobile')),
        device_label TEXT NOT NULL DEFAULT '',
        first_ip TEXT NOT NULL DEFAULT '',
        last_ip TEXT NOT NULL DEFAULT '',
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        revoked_at TIMESTAMPTZ,
        UNIQUE (license_id, access_kind, device_hash)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS license_generation_requests (
        id UUID PRIMARY KEY,
        actor_kind TEXT NOT NULL
          CHECK (actor_kind IN ('super_admin','distributor')),
        actor_id UUID NOT NULL,
        idempotency_key TEXT NOT NULL
          CHECK (char_length(idempotency_key) BETWEEN 16 AND 128),
        request_hash TEXT NOT NULL,
        license_ids UUID[] NOT NULL DEFAULT '{}'::uuid[],
        completed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (actor_kind, actor_id, idempotency_key)
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS license_generation_requests_created_idx
      ON license_generation_requests (created_at)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS license_devices_active_count_idx
      ON license_devices (license_id,access_kind,device_type)
      WHERE revoked_at IS NULL
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS assets (
        id UUID PRIMARY KEY,
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('brand_avatar','template_cover','qr_logo','reply_image')),
        filename TEXT NOT NULL,
        mime TEXT NOT NULL,
        size INTEGER NOT NULL CHECK (size > 0),
        storage TEXT NOT NULL DEFAULT 'r2' CHECK (storage IN ('r2','database')),
        object_key TEXT,
        data BYTEA,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (
          (storage = 'r2' AND object_key IS NOT NULL)
          OR (storage = 'database' AND data IS NOT NULL)
        )
      )
    `);
    await client.query(`
      ALTER TABLE assets DROP CONSTRAINT IF EXISTS assets_kind_check
    `);
    await client.query(`
      ALTER TABLE assets
      ADD CONSTRAINT assets_kind_check
      CHECK (kind IN ('brand_avatar','template_cover','qr_logo','reply_image'))
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS frontend_templates (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        base_url TEXT NOT NULL,
        origin TEXT NOT NULL,
        netlify_site_id TEXT NOT NULL DEFAULT '',
        entry_host TEXT NOT NULL DEFAULT '',
        cover_asset_id UUID REFERENCES assets(id) ON DELETE SET NULL,
        client_version TEXT NOT NULL DEFAULT '1.8.1',
        min_backend_version TEXT NOT NULL DEFAULT '1.8.1',
        status TEXT NOT NULL DEFAULT 'testing'
          CHECK (status IN ('testing','enabled','disabled')),
        selection_closed BOOLEAN NOT NULL DEFAULT FALSE,
        sort_order INTEGER NOT NULL DEFAULT 0,
        recommended BOOLEAN NOT NULL DEFAULT FALSE,
        is_default BOOLEAN NOT NULL DEFAULT FALSE,
        test_tenant_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      ALTER TABLE frontend_templates
      ADD COLUMN IF NOT EXISTS test_tenant_ids JSONB NOT NULL DEFAULT '[]'::jsonb
    `);
    await client.query(`
      ALTER TABLE frontend_templates
      ADD COLUMN IF NOT EXISTS selection_closed BOOLEAN NOT NULL DEFAULT FALSE
    `);
    await client.query(`
      ALTER TABLE frontend_templates
      ADD COLUMN IF NOT EXISTS netlify_site_id TEXT NOT NULL DEFAULT ''
    `);
    await client.query(`
      ALTER TABLE frontend_templates
      ADD COLUMN IF NOT EXISTS entry_host TEXT NOT NULL DEFAULT ''
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_entry_root_domains (
        domain TEXT PRIMARY KEY CHECK (domain=LOWER(domain)),
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending','available','current','historical','error')),
        cloudflare_zone_id TEXT NOT NULL DEFAULT '',
        dns_record_id TEXT NOT NULL DEFAULT '',
        worker_route_id TEXT NOT NULL DEFAULT '',
        last_error TEXT NOT NULL DEFAULT '',
        last_checked_at TIMESTAMPTZ,
        activated_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS tenant_entry_root_domains_current_idx
      ON tenant_entry_root_domains ((status='current'))
      WHERE status='current'
    `);
    for (const domain of [
      ...TENANT_ENTRY_DOMAIN_SUFFIXES,
      ...TENANT_ENTRY_DOMAIN_POOL,
    ]) {
      await client.query(
        `INSERT INTO tenant_entry_root_domains (domain,status)
         VALUES ($1,'pending')
         ON CONFLICT (domain) DO NOTHING`,
        [domain],
      );
    }
    if (TENANT_ENTRY_DOMAIN_SUFFIXES[0]) {
      await client.query(
        `UPDATE tenant_entry_root_domains
         SET status='current',activated_at=COALESCE(activated_at,NOW()),
             updated_at=NOW()
         WHERE domain=$1
           AND NOT EXISTS (
             SELECT 1 FROM tenant_entry_root_domains WHERE status='current'
           )`,
        [TENANT_ENTRY_DOMAIN_SUFFIXES[0]],
      );
    }
    const rootDomainRegistry = await client.query(
      `SELECT domain,status FROM tenant_entry_root_domains`,
    );
    for (const row of rootDomainRegistry.rows) {
      const domain = normalizeTenantDomainSuffix(row.domain);
      if (domain) tenantEntryRootDomains.add(domain);
      if (domain && row.status === 'current') {
        activeTenantEntryRootDomain = domain;
      }
    }
    await client.query(`
      CREATE TABLE IF NOT EXISTS frontend_template_entry_aliases (
        hostname TEXT PRIMARY KEY CHECK (hostname=LOWER(hostname)),
        template_id UUID NOT NULL REFERENCES frontend_templates(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS frontend_template_entry_aliases_template_idx
      ON frontend_template_entry_aliases (template_id)
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_template_domains (
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        template_id UUID NOT NULL REFERENCES frontend_templates(id) ON DELETE CASCADE,
        hostname TEXT NOT NULL CHECK (hostname=LOWER(hostname)),
        label TEXT NOT NULL,
        root_domain TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (tenant_id,template_id)
      )
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS tenant_template_domains_hostname_idx
      ON tenant_template_domains (LOWER(hostname))
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenant_template_domains_template_idx
      ON tenant_template_domains (template_id,tenant_id)
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_template_domain_aliases (
        hostname TEXT PRIMARY KEY CHECK (hostname=LOWER(hostname)),
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        template_id UUID NOT NULL REFERENCES frontend_templates(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenant_template_domain_aliases_owner_idx
      ON tenant_template_domain_aliases (tenant_id,template_id)
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_entry_domain_switch_requests (
        id UUID PRIMARY KEY,
        domain TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending'
          CHECK (status IN ('pending','processing','completed','cancelled','failed')),
        telegram_chat_id TEXT NOT NULL,
        telegram_message_id BIGINT,
        requested_by_telegram_user_id TEXT NOT NULL,
        confirmed_by_telegram_user_id TEXT NOT NULL DEFAULT '',
        previous_domain TEXT NOT NULL DEFAULT '',
        error TEXT NOT NULL DEFAULT '',
        expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '15 minutes',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenant_entry_domain_switch_requests_status_idx
      ON tenant_entry_domain_switch_requests (status,expires_at)
    `);
    if (TENANT_ENTRY_ENABLED) {
      const entryBackfill = await client.query(`
        SELECT id,base_url,entry_host
        FROM frontend_templates
      `);
      for (const row of entryBackfill.rows) {
        const entryHost = tenantEntryHostFromNetlifyUrl(row.base_url);
        if (!entryHost) continue;
        const currentEntryHost = String(row.entry_host || '')
          .trim()
          .toLowerCase();
        if (currentEntryHost === entryHost) continue;
        if (
          currentEntryHost &&
          !isManagedTenantEntryHost(currentEntryHost, row.base_url)
        ) continue;
        await client.query(
          `UPDATE frontend_templates SET entry_host=$2 WHERE id=$1 AND entry_host=$3`,
          [row.id, entryHost, row.entry_host || ''],
        );
      }
    }
    await client.query(`DROP INDEX IF EXISTS frontend_templates_origin_unique_idx`);
    await client.query(`
      CREATE INDEX IF NOT EXISTS frontend_templates_origin_idx
      ON frontend_templates (origin)
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS frontend_templates_base_url_unique_idx
      ON frontend_templates (base_url)
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS frontend_templates_entry_host_unique_idx
      ON frontend_templates (LOWER(entry_host))
      WHERE entry_host <> ''
    `);
    await client.query(`
      INSERT INTO frontend_templates (
        id, name, base_url, origin, entry_host,
        client_version, min_backend_version,
        status, sort_order, recommended, is_default
      ) VALUES ($1, '拓界经典版', $2, $3, $4, $5, $5, 'enabled', 10, TRUE, TRUE)
      ON CONFLICT (id) DO NOTHING
    `, [
      DEFAULT_TEMPLATE_ID,
      DEFAULT_USER_SITE_URL,
      new URL(DEFAULT_USER_SITE_URL).origin,
      tenantEntryHostFromNetlifyUrl(DEFAULT_USER_SITE_URL),
      APP_VERSION,
    ]);
    await client.query(`
      WITH ranked AS (
        SELECT id, ROW_NUMBER() OVER (
          ORDER BY is_default DESC, updated_at DESC, created_at DESC
        ) AS position
        FROM frontend_templates
        WHERE is_default = TRUE
      )
      UPDATE frontend_templates
      SET is_default = FALSE
      WHERE id IN (SELECT id FROM ranked WHERE position > 1)
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS frontend_templates_one_default_idx
      ON frontend_templates (is_default)
      WHERE is_default = TRUE
    `);
    await client.query(`
      ALTER TABLE tenant_config
      ADD COLUMN IF NOT EXISTS frontend_template_id UUID
      REFERENCES frontend_templates(id) ON DELETE SET NULL
    `);
    await client.query(`
      ALTER TABLE tenant_config
      ADD COLUMN IF NOT EXISTS retention_hours INTEGER NOT NULL DEFAULT 24
    `);
    await client.query(`
      UPDATE tenant_config
      SET frontend_template_id = $1
      WHERE frontend_template_id IS NULL
    `, [DEFAULT_TEMPLATE_ID]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS tenant_frontend_templates (
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        template_id UUID NOT NULL REFERENCES frontend_templates(id) ON DELETE CASCADE,
        first_selected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_selected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (tenant_id, template_id)
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenant_frontend_templates_template_idx
      ON tenant_frontend_templates (template_id, tenant_id)
    `);
    // Existing databases only know the currently selected template. Seed that
    // trusted selection first; every later switch is retained automatically.
    await client.query(`
      INSERT INTO tenant_frontend_templates (tenant_id, template_id)
      SELECT tenant_id, frontend_template_id
      FROM tenant_config
      WHERE frontend_template_id IS NOT NULL
      ON CONFLICT (tenant_id, template_id) DO NOTHING
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS platform_settings (
        id SMALLINT PRIMARY KEY CHECK (id = 1),
        brand_name TEXT NOT NULL DEFAULT '拓界云客服',
        current_version TEXT NOT NULL DEFAULT '1.8.1',
        support_telegram TEXT NOT NULL DEFAULT '@YingYingUu',
        customer_service_telegram TEXT NOT NULL DEFAULT '@kjwh8',
        telegram_group_id TEXT NOT NULL DEFAULT '',
        report_time TEXT NOT NULL DEFAULT '09:00',
        report_timezone TEXT NOT NULL DEFAULT 'Asia/Shanghai',
        daily_report_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        weekly_report_enabled BOOLEAN NOT NULL DEFAULT FALSE,
        alert_settings JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      ALTER TABLE platform_settings
      ADD COLUMN IF NOT EXISTS customer_service_telegram TEXT NOT NULL DEFAULT '@kjwh8'
    `);
    await client.query(`
      INSERT INTO platform_settings (
        id, current_version, support_telegram, customer_service_telegram
      ) VALUES (1, $1, $2, $3)
      ON CONFLICT (id) DO NOTHING
    `, [
      APP_VERSION,
      publicTelegramHandle(SUPPORT_TELEGRAM, '@YingYingUu'),
      publicTelegramHandle(CUSTOMER_SERVICE_TELEGRAM),
    ]);
    const storedPlatformVersion = await client.query(
      `SELECT current_version FROM platform_settings WHERE id=1`,
    );
    if (
      compareVersions(
        storedPlatformVersion.rows[0]?.current_version,
        APP_VERSION,
      ) < 0
    ) {
      await client.query(
        `UPDATE platform_settings SET current_version=$1,updated_at=NOW() WHERE id=1`,
        [APP_VERSION],
      );
    }

    await client.query(`
      CREATE TABLE IF NOT EXISTS super_admins (
        id UUID PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK (role IN ('owner','manager','operations','support','readonly')),
        totp_secret_ciphertext TEXT,
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        session_version INTEGER NOT NULL DEFAULT 1,
        last_login_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS distributors (
        id UUID PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        display_name TEXT NOT NULL DEFAULT '',
        password_hash TEXT NOT NULL,
        telegram_username TEXT NOT NULL DEFAULT '',
        enabled BOOLEAN NOT NULL DEFAULT TRUE,
        can_generate BOOLEAN NOT NULL DEFAULT FALSE,
        allowed_duration_codes JSONB NOT NULL DEFAULT '[]'::jsonb,
        session_version INTEGER NOT NULL DEFAULT 1,
        last_login_at TIMESTAMPTZ,
        created_by_admin_id UUID REFERENCES super_admins(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      ALTER TABLE license_keys
      ADD COLUMN IF NOT EXISTS generated_by_distributor_id UUID
        REFERENCES distributors(id) ON DELETE SET NULL
    `);
    await client.query(`
      ALTER TABLE tenants
      ADD COLUMN IF NOT EXISTS owner_distributor_id UUID
        REFERENCES distributors(id) ON DELETE SET NULL
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS distributor_license_quotas (
        distributor_id UUID NOT NULL REFERENCES distributors(id) ON DELETE CASCADE,
        duration_code TEXT NOT NULL
          CHECK (duration_code IN ('1h','1d','7d','30d','180d','365d')),
        remaining_count INTEGER NOT NULL DEFAULT 0 CHECK (remaining_count >= 0),
        generated_count BIGINT NOT NULL DEFAULT 0 CHECK (generated_count >= 0),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (distributor_id, duration_code)
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS distributor_quota_logs (
        id BIGSERIAL PRIMARY KEY,
        distributor_id UUID NOT NULL REFERENCES distributors(id) ON DELETE CASCADE,
        duration_code TEXT NOT NULL
          CHECK (duration_code IN ('1h','1d','7d','30d','180d','365d')),
        action TEXT NOT NULL,
        change_amount INTEGER NOT NULL,
        balance_before INTEGER NOT NULL CHECK (balance_before >= 0),
        balance_after INTEGER NOT NULL CHECK (balance_after >= 0),
        actor_admin_id UUID REFERENCES super_admins(id) ON DELETE SET NULL,
        actor_distributor_id UUID REFERENCES distributors(id) ON DELETE SET NULL,
        reason TEXT NOT NULL DEFAULT '',
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id BIGSERIAL PRIMARY KEY,
        actor_admin_id UUID REFERENCES super_admins(id) ON DELETE SET NULL,
        action TEXT NOT NULL,
        target_type TEXT NOT NULL DEFAULT '',
        target_id TEXT NOT NULL DEFAULT '',
        ip_address TEXT NOT NULL DEFAULT '',
        result TEXT NOT NULL DEFAULT 'success',
        metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      ALTER TABLE audit_logs
      ADD COLUMN IF NOT EXISTS actor_distributor_id UUID
        REFERENCES distributors(id) ON DELETE SET NULL
    `);
    await client.query(`
      ALTER TABLE audit_logs
      ADD COLUMN IF NOT EXISTS actor_tenant_id UUID
        REFERENCES tenants(id) ON DELETE SET NULL
    `);
    await client.query(`
      ALTER TABLE audit_logs
      ADD COLUMN IF NOT EXISTS actor_license_id UUID
        REFERENCES license_keys(id) ON DELETE SET NULL
    `);
    await client.query(`
      ALTER TABLE audit_logs
      ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'high'
    `);
    await client.query(`
      ALTER TABLE audit_logs
      ADD COLUMN IF NOT EXISTS summary TEXT NOT NULL DEFAULT ''
    `);
    // Recover authenticated tenant-side template choices still present in the
    // audit window before low-risk audit cleanup runs. Rejected Origin events
    // are deliberately excluded so an attacker can never self-approve a site.
    await client.query(`
      WITH candidates AS (
        SELECT DISTINCT
          CASE
            WHEN target_id ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            THEN target_id::uuid
          END AS tenant_id,
          CASE
            WHEN COALESCE(metadata->>'frontendTemplateId','')
              ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
            THEN (metadata->>'frontendTemplateId')::uuid
          END AS template_id
        FROM audit_logs
        WHERE action='tenant.config.update'
      )
      INSERT INTO tenant_frontend_templates (tenant_id, template_id)
      SELECT candidates.tenant_id, candidates.template_id
      FROM candidates
      JOIN tenants t ON t.id=candidates.tenant_id
      JOIN frontend_templates ft ON ft.id=candidates.template_id
      WHERE candidates.tenant_id IS NOT NULL
        AND candidates.template_id IS NOT NULL
      ON CONFLICT (tenant_id, template_id) DO NOTHING
    `);
    await client.query(
      `
        DELETE FROM audit_logs
        WHERE actor_tenant_id IS NOT NULL
          AND result='success'
          AND NOT (action=ANY($1::text[]))
      `,
      [[...TENANT_HIGH_RISK_AUDIT_ACTIONS]],
    );
    await client.query(`
      UPDATE audit_logs
      SET risk_level='critical'
      WHERE result='failed' OR action LIKE 'security.%'
    `);
    await client.query(
      `
        UPDATE audit_logs AS audit
        SET summary=descriptions.summary
        FROM jsonb_each_text($1::jsonb)
          AS descriptions(action,summary)
        WHERE audit.action=descriptions.action
          AND audit.summary=''
      `,
      [JSON.stringify(AUDIT_SUMMARIES)],
    );
    await client.query(`
      CREATE INDEX IF NOT EXISTS audit_logs_created_idx
      ON audit_logs (created_at DESC)
    `);
    await client.query(`
      DROP INDEX IF EXISTS audit_logs_created_at_idx
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS license_keys_distributor_created_idx
      ON license_keys (generated_by_distributor_id, created_at DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS license_keys_distributor_page_idx
      ON license_keys (generated_by_distributor_id, created_at DESC, id DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenants_distributor_created_idx
      ON tenants (owner_distributor_id, created_at DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenants_distributor_page_idx
      ON tenants (owner_distributor_id, updated_at DESC, id DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS distributor_quota_logs_created_idx
      ON distributor_quota_logs (distributor_id, created_at DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS distributor_quota_logs_page_idx
      ON distributor_quota_logs (distributor_id, id DESC)
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS announcements (
        id UUID PRIMARY KEY,
        type TEXT NOT NULL CHECK (
          type IN ('normal','important','maintenance','version','incident')
        ),
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        scope TEXT NOT NULL DEFAULT 'all' CHECK (scope IN ('all','selected')),
        tenant_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        starts_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        ends_at TIMESTAMPTZ,
        display_mode TEXT NOT NULL DEFAULT 'banner'
          CHECK (display_mode IN ('banner','modal','both')),
        force_modal BOOLEAN NOT NULL DEFAULT FALSE,
        active BOOLEAN NOT NULL DEFAULT TRUE,
        retracted_at TIMESTAMPTZ,
        created_by UUID REFERENCES super_admins(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS announcement_reads (
        announcement_id UUID REFERENCES announcements(id) ON DELETE CASCADE,
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (announcement_id, tenant_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS releases (
        id UUID PRIMARY KEY,
        version TEXT NOT NULL UNIQUE,
        title TEXT NOT NULL,
        new_features TEXT NOT NULL DEFAULT '',
        improvements TEXT NOT NULL DEFAULT '',
        fixes TEXT NOT NULL DEFAULT '',
        known_issues TEXT NOT NULL DEFAULT '',
        scope TEXT NOT NULL DEFAULT 'all' CHECK (scope IN ('all','selected')),
        tenant_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        force_modal BOOLEAN NOT NULL DEFAULT FALSE,
        published_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        created_by UUID REFERENCES super_admins(id) ON DELETE SET NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS release_reads (
        release_id UUID REFERENCES releases(id) ON DELETE CASCADE,
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        read_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (release_id, tenant_id)
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS feature_catalog (
        id UUID PRIMARY KEY,
        code TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT '基础功能',
        icon TEXT NOT NULL DEFAULT 'sparkles',
        public_visible BOOLEAN NOT NULL DEFAULT TRUE,
        status TEXT NOT NULL DEFAULT 'normal'
          CHECK (status IN ('normal','testing','maintenance','coming')),
        entitlements JSONB NOT NULL DEFAULT '{"scope":"all"}'::jsonb,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS feature_flags (
        code TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        enabled BOOLEAN NOT NULL DEFAULT FALSE,
        scope TEXT NOT NULL DEFAULT 'super'
          CHECK (scope IN ('super','selected','all')),
        tenant_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
        starts_at TIMESTAMPTZ,
        ends_at TIMESTAMPTZ,
        updated_by UUID REFERENCES super_admins(id) ON DELETE SET NULL,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS r2_delete_queue (
        id BIGSERIAL PRIMARY KEY,
        object_key TEXT NOT NULL UNIQUE,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_error TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS system_metric_samples (
        id BIGSERIAL PRIMARY KEY,
        metrics JSONB NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS system_metric_samples_created_idx
      ON system_metric_samples (created_at DESC)
    `);
    await client.query(`
      DROP INDEX IF EXISTS system_metric_samples_created_at_idx
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS daily_reports (
        report_date DATE PRIMARY KEY,
        status TEXT NOT NULL CHECK (status IN ('pending','sent','failed')),
        summary JSONB NOT NULL DEFAULT '{}'::jsonb,
        sent_at TIMESTAMPTZ,
        error TEXT NOT NULL DEFAULT '',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS weekly_reports (
        week_start DATE PRIMARY KEY,
        week_end DATE NOT NULL,
        status TEXT NOT NULL CHECK (status IN ('pending','sent','failed')),
        summary JSONB NOT NULL DEFAULT '{}'::jsonb,
        sent_at TIMESTAMPTZ,
        error TEXT NOT NULL DEFAULT '',
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
      CREATE TABLE IF NOT EXISTS qr_incidents (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        template_id UUID NOT NULL REFERENCES frontend_templates(id) ON DELETE CASCADE,
        status TEXT NOT NULL DEFAULT 'open'
          CHECK (status IN ('open','processing','resolved','failed')),
        reported_base_url TEXT NOT NULL,
        requested_base_url TEXT NOT NULL DEFAULT '',
        telegram_chat_id TEXT,
        telegram_message_id BIGINT,
        resolved_by_telegram_user_id TEXT,
        error TEXT NOT NULL DEFAULT '',
        reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        processing_started_at TIMESTAMPTZ,
        resolved_at TIMESTAMPTZ,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS qr_incidents_active_unique_idx
      ON qr_incidents (tenant_id, template_id)
      WHERE status IN ('open','processing')
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS qr_incidents_telegram_message_idx
      ON qr_incidents (telegram_chat_id, telegram_message_id)
      WHERE telegram_message_id IS NOT NULL
    `);
    await client.query(`ALTER TABLE qr_incidents ADD COLUMN IF NOT EXISTS reporter_license_id UUID REFERENCES license_keys(id) ON DELETE SET NULL`);
    await client.query(`ALTER TABLE qr_incidents ADD COLUMN IF NOT EXISTS click_count_30m INTEGER NOT NULL DEFAULT 1`);
    await client.query(`ALTER TABLE qr_incidents ADD COLUMN IF NOT EXISTS click_count_10m INTEGER NOT NULL DEFAULT 1`);
    await client.query(`ALTER TABLE qr_incidents ADD COLUMN IF NOT EXISTS requires_admin_review BOOLEAN NOT NULL DEFAULT FALSE`);
    await client.query(`
      CREATE TABLE IF NOT EXISTS qr_incident_reports (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        template_id UUID NOT NULL REFERENCES frontend_templates(id) ON DELETE CASCADE,
        reporter_license_id UUID REFERENCES license_keys(id) ON DELETE SET NULL,
        reported_domain TEXT NOT NULL,
        reported_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS qr_incident_reports_tenant_time_idx
      ON qr_incident_reports (tenant_id, reported_at DESC)
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS visitor_groups (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 40),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS auth_sessions (
        id UUID PRIMARY KEY,
        kind TEXT NOT NULL
          CHECK (kind IN ('super_admin','distributor','tenant_admin')),
        subject_id UUID NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL,
        revoked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS auth_sessions_subject_active_idx
      ON auth_sessions (kind,subject_id,expires_at)
      WHERE revoked_at IS NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS auth_sessions_expiry_idx
      ON auth_sessions (expires_at)
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS auth_attempt_limits (
        key_hash TEXT PRIMARY KEY,
        scope TEXT NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 1 CHECK (attempts > 0),
        window_started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS auth_attempt_limits_expiry_idx
      ON auth_attempt_limits (expires_at)
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS data_protection_state (
        id SMALLINT PRIMARY KEY CHECK (id = 1),
        verification_tag TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS visitor_groups_tenant_name_unique_idx
      ON visitor_groups (tenant_id, lower(name))
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS visitor_groups_tenant_updated_idx
      ON visitor_groups (tenant_id, updated_at DESC)
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
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS network_type TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS network_effective_type TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS downlink_mbps NUMERIC(8,2)`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS rtt_ms INTEGER`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS save_data BOOLEAN`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS client_template_id UUID`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS client_version TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE conversations ADD COLUMN IF NOT EXISTS visitor_group_id UUID REFERENCES visitor_groups(id) ON DELETE SET NULL`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS telegram_username TEXT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS telegram_display_name TEXT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS key_ciphertext TEXT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS telegram_update_id BIGINT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        endpoint TEXT NOT NULL,
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        p256dh TEXT NOT NULL,
        auth TEXT NOT NULL,
        user_agent TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (endpoint,tenant_id,conversation_id)
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS push_subscriptions_conversation_idx
      ON push_subscriptions (tenant_id, conversation_id)
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS call_sessions (
        id UUID PRIMARY KEY,
        tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        mode TEXT NOT NULL DEFAULT 'audio' CHECK (mode IN ('audio','video')),
        offer JSONB NOT NULL,
        caller_kind TEXT NOT NULL DEFAULT 'admin'
          CHECK (caller_kind IN ('user','admin')),
        caller_name TEXT NOT NULL DEFAULT '',
        caller_device_id TEXT NOT NULL DEFAULT '',
        status TEXT NOT NULL DEFAULT 'ringing'
          CHECK (status IN (
            'ringing','answered','connected','completed','rejected',
            'busy','missed','cancelled','failed'
          )),
        claimed_by TEXT,
        claimed_at TIMESTAMPTZ,
        answered_at TIMESTAMPTZ,
        connected_at TIMESTAMPTZ,
        ended_at TIMESTAMPTZ,
        duration_seconds INTEGER NOT NULL DEFAULT 0 CHECK (duration_seconds >= 0),
        end_reason TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at TIMESTAMPTZ NOT NULL DEFAULT NOW() + INTERVAL '45 seconds'
      )
    `);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS caller_kind TEXT NOT NULL DEFAULT 'admin'`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS caller_name TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS caller_device_id TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS claimed_by TEXT`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS claimed_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS answered_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS connected_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS ended_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS duration_seconds INTEGER NOT NULL DEFAULT 0`);
    await client.query(`ALTER TABLE call_sessions ADD COLUMN IF NOT EXISTS end_reason TEXT NOT NULL DEFAULT ''`);
    await client.query(`ALTER TABLE call_sessions DROP CONSTRAINT IF EXISTS call_sessions_status_check`);
    await client.query(`UPDATE call_sessions SET status='completed',end_reason=COALESCE(NULLIF(end_reason,''),'completed'),ended_at=COALESCE(ended_at,updated_at) WHERE status='ended'`);
    await client.query(`
      ALTER TABLE call_sessions
      ADD CONSTRAINT call_sessions_status_check CHECK (status IN (
        'ringing','answered','connected','completed','rejected',
        'busy','missed','cancelled','failed'
      ))
    `);
    await client.query(`ALTER TABLE call_sessions DROP CONSTRAINT IF EXISTS call_sessions_caller_kind_check`);
    await client.query(`
      ALTER TABLE call_sessions
      ADD CONSTRAINT call_sessions_caller_kind_check
      CHECK (caller_kind IN ('user','admin'))
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS call_sessions_conversation_active_idx
      ON call_sessions (tenant_id, conversation_id, expires_at DESC)
      WHERE status='ringing'
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS call_sessions_conversation_history_idx
      ON call_sessions (tenant_id, conversation_id, created_at DESC)
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS attachments (
        id UUID PRIMARY KEY,
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        filename TEXT NOT NULL,
        mime TEXT NOT NULL CHECK (mime IN (
          'image/jpeg','image/png','image/webp','image/gif',
          'video/mp4','video/webm','video/quicktime',
          'audio/webm','audio/ogg','audio/mp4','audio/mpeg','audio/wav'
        )),
        size INTEGER NOT NULL CHECK (size > 0),
        uploader TEXT NOT NULL CHECK (uploader IN ('user','admin')),
        data BYTEA NOT NULL,
        linked_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`ALTER TABLE attachments ALTER COLUMN data DROP NOT NULL`);
    await client.query(`ALTER TABLE attachments ADD COLUMN IF NOT EXISTS storage TEXT NOT NULL DEFAULT 'database'`);
    await client.query(`ALTER TABLE attachments ADD COLUMN IF NOT EXISTS object_key TEXT`);
    await client.query(`ALTER TABLE attachments ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY,
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        role TEXT NOT NULL CHECK (role IN ('user','admin')),
        source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','auto')),
        type TEXT NOT NULL CHECK (type IN ('text','image','video','audio')),
        text TEXT NOT NULL DEFAULT '',
        attachment_id UUID UNIQUE REFERENCES attachments(id) ON DELETE CASCADE,
        asset_id UUID REFERENCES assets(id) ON DELETE RESTRICT,
        album_id UUID,
        album_position SMALLINT NOT NULL DEFAULT 0 CHECK (album_position BETWEEN 0 AND 9),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (
          (type = 'text' AND attachment_id IS NULL AND asset_id IS NULL AND length(text) > 0)
          OR
          (
            type IN ('image','video','audio')
            AND ((attachment_id IS NOT NULL)::int + (asset_id IS NOT NULL)::int) = 1
          )
        )
      )
    `);

    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS album_id UUID`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS album_position SMALLINT NOT NULL DEFAULT 0`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS recalled_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS asset_id UUID REFERENCES assets(id) ON DELETE RESTRICT`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS client_request_id TEXT NOT NULL DEFAULT ''`);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS messages_client_request_unique_idx
      ON messages (conversation_id,role,client_request_id,album_position)
      WHERE client_request_id <> '' AND source='manual'
    `);
    await client.query(`ALTER TABLE attachments DROP CONSTRAINT IF EXISTS attachments_mime_check`);
    await client.query(`
      ALTER TABLE attachments
      ADD CONSTRAINT attachments_mime_check CHECK (mime IN (
        'image/jpeg','image/png','image/webp','image/gif',
        'video/mp4','video/webm','video/quicktime',
        'audio/webm','audio/ogg','audio/mp4','audio/mpeg','audio/wav'
      ))
    `);
    await client.query(`ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_type_check`);
    await client.query(`
      ALTER TABLE messages
      ADD CONSTRAINT messages_type_check CHECK (type IN ('text','image','video','audio'))
    `);
    await client.query(`ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_check`);
    await client.query(`
      ALTER TABLE messages
      ADD CONSTRAINT messages_check CHECK (
        (type = 'text' AND attachment_id IS NULL AND asset_id IS NULL AND length(text) > 0)
        OR
        (
          type IN ('image','video','audio')
          AND ((attachment_id IS NOT NULL)::int + (asset_id IS NOT NULL)::int) = 1
        )
      )
    `);
    await client.query(`
      UPDATE messages m
      SET expires_at = m.created_at + (
        COALESCE(tc.retention_hours, 24)::text || ' hours'
      )::interval
      FROM conversations c
      LEFT JOIN tenant_config tc ON tc.tenant_id = c.tenant_id
      WHERE m.conversation_id = c.id
        AND m.expires_at IS NULL
    `);
    await client.query(`
      UPDATE attachments a
      SET expires_at = COALESCE(m.expires_at, a.created_at + INTERVAL '24 hours')
      FROM messages m
      WHERE m.attachment_id = a.id
        AND a.expires_at IS NULL
    `);
    await client.query(`
      UPDATE messages AS m
      SET read_at = m.created_at
      FROM conversations AS c
      WHERE m.conversation_id = c.id
        AND m.read_at IS NULL
        AND (
          (m.role = 'user' AND c.unread_admin = 0)
          OR (m.role = 'admin' AND c.unread_user = 0)
        )
    `);
    await client.query(`
      DO $migration$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'license_keys'::regclass
            AND conname = 'license_keys_status_check'
            AND pg_get_constraintdef(oid) LIKE '%archived%'
        ) THEN
          ALTER TABLE license_keys
            DROP CONSTRAINT IF EXISTS license_keys_status_check;
          ALTER TABLE license_keys
            ADD CONSTRAINT license_keys_status_check
            CHECK (status IN ('unused','active','superseded','revoked','archived'));
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'license_keys'::regclass
            AND conname = 'license_keys_duration_code_check'
            AND pg_get_constraintdef(oid) LIKE '%1h%'
        ) THEN
          ALTER TABLE license_keys
            DROP CONSTRAINT IF EXISTS license_keys_duration_code_check;
          ALTER TABLE license_keys
            ADD CONSTRAINT license_keys_duration_code_check
            CHECK (duration_code IN ('1h','1d','7d','30d','180d','365d'));
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'distributor_license_quotas'::regclass
            AND conname = 'distributor_license_quotas_duration_code_check'
            AND pg_get_constraintdef(oid) LIKE '%1h%'
        ) THEN
          ALTER TABLE distributor_license_quotas
            DROP CONSTRAINT IF EXISTS distributor_license_quotas_duration_code_check;
          ALTER TABLE distributor_license_quotas
            ADD CONSTRAINT distributor_license_quotas_duration_code_check
            CHECK (duration_code IN ('1h','1d','7d','30d','180d','365d'));
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'distributor_quota_logs'::regclass
            AND conname = 'distributor_quota_logs_duration_code_check'
            AND pg_get_constraintdef(oid) LIKE '%1h%'
        ) THEN
          ALTER TABLE distributor_quota_logs
            DROP CONSTRAINT IF EXISTS distributor_quota_logs_duration_code_check;
          ALTER TABLE distributor_quota_logs
            ADD CONSTRAINT distributor_quota_logs_duration_code_check
            CHECK (duration_code IN ('1h','1d','7d','30d','180d','365d'));
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'attachments'::regclass
            AND conname = 'attachments_mime_check'
            AND pg_get_constraintdef(oid) LIKE '%video/mp4%'
        ) THEN
          ALTER TABLE attachments
            DROP CONSTRAINT IF EXISTS attachments_mime_check;
          ALTER TABLE attachments
            ADD CONSTRAINT attachments_mime_check CHECK (mime IN (
              'image/jpeg','image/png','image/webp','image/gif',
              'video/mp4','video/webm','video/quicktime'
            ));
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'messages'::regclass
            AND conname = 'messages_type_check'
            AND pg_get_constraintdef(oid) LIKE '%video%'
        ) THEN
          ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_type_check;
          ALTER TABLE messages
            ADD CONSTRAINT messages_type_check
            CHECK (type IN ('text','image','video'));
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'messages'::regclass
            AND conname = 'messages_check'
            AND pg_get_constraintdef(oid) LIKE '%recalled_at%'
        ) THEN
          ALTER TABLE messages DROP CONSTRAINT IF EXISTS messages_check;
          ALTER TABLE messages
            ADD CONSTRAINT messages_check CHECK (
              (
                recalled_at IS NOT NULL
                AND type = 'text'
                AND attachment_id IS NULL
                AND length(text) > 0
              )
              OR
              (
                recalled_at IS NULL
                AND type = 'text'
                AND attachment_id IS NULL
                AND length(text) > 0
              )
              OR
              (
                recalled_at IS NULL
                AND type IN ('image','video','audio')
                AND attachment_id IS NOT NULL
              )
            );
        END IF;

        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conrelid = 'messages'::regclass
            AND conname = 'messages_album_position_check'
        ) THEN
          ALTER TABLE messages
            ADD CONSTRAINT messages_album_position_check
            CHECK (album_position BETWEEN 0 AND 9);
        END IF;
      END
      $migration$
    `);

    // 旧代理缺少的新期限额度只在启动迁移时一次性补齐，读取列表或登录时
    // 不再反复执行 ON CONFLICT 写操作。
    // 必须在同步环境变量管理员前验证，否则错误的数据密钥可能覆盖 TOTP。
    await ensureDataProtectionSecret(client);

    await client.query(
      `
        INSERT INTO distributor_license_quotas (
          distributor_id,duration_code
        )
        SELECT d.id,c.duration_code
        FROM distributors d
        CROSS JOIN unnest($1::text[]) AS c(duration_code)
        ON CONFLICT (distributor_id,duration_code) DO NOTHING
      `,
      [DISTRIBUTOR_DURATION_CODES],
    );

    await client.query(`
      CREATE INDEX IF NOT EXISTS conversations_updated_at_idx
      ON conversations (updated_at DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS conversations_tenant_updated_idx
      ON conversations (tenant_id, updated_at DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS conversations_tenant_page_idx
      ON conversations (tenant_id, updated_at DESC, id DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS conversations_tenant_group_page_idx
      ON conversations (tenant_id, visitor_group_id, updated_at DESC, id DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenant_config_frontend_template_idx
      ON tenant_config (frontend_template_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenants_updated_page_idx
      ON tenants (updated_at DESC, id DESC)
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS conversations_tenant_visitor_unique_idx
      ON conversations (tenant_id, visitor_key_hash)
      WHERE tenant_id IS NOT NULL
    `);
    await client.query(`CREATE INDEX IF NOT EXISTS license_keys_tenant_idx ON license_keys (tenant_id, created_at DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS license_keys_created_at_idx ON license_keys (created_at DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS license_keys_page_idx ON license_keys (created_at DESC, id DESC)`);
    await client.query(`CREATE INDEX IF NOT EXISTS license_keys_suffix_idx ON license_keys (key_suffix)`);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS license_keys_telegram_update_unique_idx
      ON license_keys (telegram_update_id)
      WHERE telegram_update_id IS NOT NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_conversation_created_idx
      ON messages (conversation_id, created_at ASC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_conversation_page_idx
      ON messages (conversation_id, created_at DESC, id DESC)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_unread_idx
      ON messages (conversation_id, role, created_at)
      WHERE read_at IS NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_created_at_idx
      ON messages (created_at)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_expires_at_idx
      ON messages (expires_at)
      WHERE expires_at IS NOT NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_conversation_album_idx
      ON messages (conversation_id, album_id)
      WHERE album_id IS NOT NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS attachments_created_at_idx
      ON attachments (created_at)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS attachments_expires_at_idx
      ON attachments (expires_at)
      WHERE expires_at IS NOT NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS attachments_conversation_idx
      ON attachments (conversation_id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS telegram_updates_created_at_idx
      ON telegram_updates (created_at)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenants_expiry_reminder_idx
      ON tenants (access_expires_at)
      WHERE status='active' AND expiry_reminder_sent_at IS NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS tenants_data_purge_idx
      ON tenants (access_expires_at)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS r2_delete_queue_next_attempt_idx
      ON r2_delete_queue (next_attempt_at,id)
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS qr_incidents_cleanup_idx
      ON qr_incidents (updated_at)
      WHERE status IN ('resolved','failed')
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS security_events (
        id UUID PRIMARY KEY,
        kind TEXT NOT NULL,
        severity TEXT NOT NULL DEFAULT 'warning'
          CHECK (severity IN ('info','warning','critical')),
        fingerprint TEXT NOT NULL,
        tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
        license_id UUID REFERENCES license_keys(id) ON DELETE SET NULL,
        conversation_id UUID REFERENCES conversations(id) ON DELETE SET NULL,
        ip_address TEXT NOT NULL DEFAULT '',
        user_agent TEXT NOT NULL DEFAULT '',
        details JSONB NOT NULL DEFAULT '{}'::jsonb,
        occurrences INTEGER NOT NULL DEFAULT 1 CHECK (occurrences > 0),
        status TEXT NOT NULL DEFAULT 'open'
          CHECK (status IN ('open','blocked','dismissed','resolved')),
        telegram_chat_id TEXT,
        telegram_message_id BIGINT,
        handled_by_telegram_user_id TEXT,
        first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        handled_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (endpoint, tenant_id, conversation_id)
      )
    `);
    await client.query(`
      DO $$
      DECLARE primary_column_count INTEGER;
      BEGIN
        SELECT COUNT(*)::int INTO primary_column_count
        FROM information_schema.table_constraints constraints
        JOIN information_schema.key_column_usage columns
          ON columns.constraint_name=constraints.constraint_name
         AND columns.constraint_schema=constraints.constraint_schema
        WHERE constraints.table_schema=current_schema()
          AND constraints.table_name='push_subscriptions'
          AND constraints.constraint_type='PRIMARY KEY';
        IF primary_column_count <> 3 THEN
          ALTER TABLE push_subscriptions
            DROP CONSTRAINT IF EXISTS push_subscriptions_pkey;
          ALTER TABLE push_subscriptions
            ADD CONSTRAINT push_subscriptions_pkey
            PRIMARY KEY (endpoint,tenant_id,conversation_id);
        END IF;
      END $$
    `);
    await client.query(`
      CREATE UNIQUE INDEX IF NOT EXISTS security_events_open_fingerprint_idx
      ON security_events (fingerprint)
      WHERE status='open'
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS security_events_created_idx
      ON security_events (created_at DESC)
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS blocked_ips (
        ip_address TEXT PRIMARY KEY,
        reason TEXT NOT NULL DEFAULT '',
        security_event_id UUID REFERENCES security_events(id) ON DELETE SET NULL,
        blocked_by_telegram_user_id TEXT NOT NULL DEFAULT '',
        expires_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS blocked_ips_expiry_idx
      ON blocked_ips (expires_at)
      WHERE expires_at IS NOT NULL
    `);
    await client.query(`
      CREATE TABLE IF NOT EXISTS telegram_blocked_users (
        user_id TEXT PRIMARY KEY,
        username TEXT NOT NULL DEFAULT '',
        display_name TEXT NOT NULL DEFAULT '',
        reason TEXT NOT NULL DEFAULT '',
        blocked_by_telegram_user_id TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
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
    await client.query(
      `
        UPDATE tenant_config
        SET settings = jsonb_set(
              COALESCE(settings, '{}'::jsonb),
              '{userSiteUrl}',
              to_jsonb($1::text),
              true
            ),
            updated_at = NOW()
        WHERE NULLIF(BTRIM(COALESCE(settings->>'userSiteUrl', '')), '') IS NULL
      `,
      [DEFAULT_USER_SITE_URL],
    );
    await client.query(
      `
        UPDATE app_config
        SET settings = jsonb_set(
              COALESCE(settings, '{}'::jsonb),
              '{userSiteUrl}',
              to_jsonb($1::text),
              true
            ),
            updated_at = NOW()
        WHERE id = 1
          AND NULLIF(BTRIM(COALESCE(settings->>'userSiteUrl', '')), '') IS NULL
      `,
      [DEFAULT_USER_SITE_URL],
    );
    await client.query(`
      UPDATE tenant_config
      SET settings = $1::jsonb || COALESCE(settings, '{}'::jsonb),
          frontend_template_id = COALESCE(frontend_template_id, $2),
          retention_hours = CASE
            WHEN retention_hours IN (1,6,12,24,72,168,240,360) THEN retention_hours
            ELSE 24
          END
    `, [JSON.stringify(defaults.settings), DEFAULT_TEMPLATE_ID]);
    await client.query(`
      INSERT INTO feature_catalog (
        id, code, name, description, category, icon
      ) VALUES
        ('20000000-0000-4000-8000-000000000001','realtime_chat','实时聊天','SSE 实时收发消息和状态','聊天','message-circle'),
        ('20000000-0000-4000-8000-000000000002','media_album','多图与视频','多图相册和视频消息','聊天','image'),
        ('20000000-0000-4000-8000-000000000003','read_receipts','已读状态','用户端与租户后台双向已读','聊天','check-check'),
        ('20000000-0000-4000-8000-000000000004','auto_reply','自动回复','关键词与默认自动回复','效率','bot'),
        ('20000000-0000-4000-8000-000000000005','frontend_templates','前端模板','选择平台批准的用户端界面','品牌','layout-template'),
        ('20000000-0000-4000-8000-000000000006','message_actions','消息删除与撤回','客服消息实时删除和撤回','聊天','undo'),
        ('20000000-0000-4000-8000-000000000007','tenant_branding','独立客服品牌','租户自定义名称、头像和欢迎信息','品牌','palette')
      ON CONFLICT (code) DO NOTHING
    `);
    for (const envAdmin of ENV_SUPER_ADMINS) {
      const current = await client.query(
        `SELECT * FROM super_admins WHERE username=$1 FOR UPDATE`,
        [envAdmin.username],
      );
      const existing = current.rows[0];
      if (!existing) {
        await client.query(
          `
            INSERT INTO super_admins (
              id,username,password_hash,role,totp_secret_ciphertext
            ) VALUES ($1,$2,$3,'owner',$4)
          `,
          [
            randomUUID(),
            envAdmin.username,
            hashPassword(envAdmin.password),
            envAdmin.totpSecret
              ? encryptSecret(envAdmin.totpSecret)
              : null,
          ],
        );
        continue;
      }
      const passwordChanged = !verifyPassword(
        envAdmin.password,
        existing.password_hash,
      );
      const currentTotp = existing.totp_secret_ciphertext
        ? decryptSecret(existing.totp_secret_ciphertext)
        : '';
      const totpChanged = !timingSafeTextEqual(
        currentTotp,
        envAdmin.totpSecret,
      );
      const credentialsChanged = passwordChanged || totpChanged;
      await client.query(
        `
          UPDATE super_admins
          SET password_hash=$2,
              role='owner',
              totp_secret_ciphertext=$3,
              enabled=TRUE,
              session_version=session_version+$4,
              updated_at=NOW()
          WHERE id=$1
        `,
        [
          existing.id,
          passwordChanged
            ? hashPassword(envAdmin.password)
            : existing.password_hash,
          totpChanged
            ? envAdmin.totpSecret
              ? encryptSecret(envAdmin.totpSecret)
              : null
            : existing.totp_secret_ciphertext,
          credentialsChanged ? 1 : 0,
        ],
      );
    }
    if (ENV_SUPER_ADMINS.length >= 1) {
      await client.query(
        `
          UPDATE super_admins
          SET enabled = FALSE,
              session_version = session_version + 1,
              updated_at = NOW()
          WHERE enabled = TRUE
            AND role='owner'
            AND NOT (username = ANY($1::text[]))
        `,
        [ENV_SUPER_ADMINS.map((item) => item.username)],
      );
    }

    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }

  await cleanupExpiredData();
  await refreshApprovedOrigins(true);
}

async function purgeExpiredTenantData(client, objectKeys) {
  const candidates = await client.query(
    `
      SELECT id,access_expires_at
      FROM tenants
      WHERE access_expires_at <=
        NOW() - ($1::int * INTERVAL '1 day')
      ORDER BY access_expires_at,id
      LIMIT 100
      FOR UPDATE SKIP LOCKED
    `,
    [EXPIRED_TENANT_GRACE_DAYS],
  );
  const tenantIds = candidates.rows.map((row) => row.id).filter(isUuid);
  if (!tenantIds.length) return [];

  const storedObjects = await client.query(
    `
      SELECT object_key
      FROM assets
      WHERE tenant_id=ANY($1::uuid[])
        AND storage='r2' AND object_key IS NOT NULL
      UNION
      SELECT a.object_key
      FROM attachments a
      JOIN conversations c ON c.id=a.conversation_id
      WHERE c.tenant_id=ANY($1::uuid[])
        AND a.storage='r2' AND a.object_key IS NOT NULL
    `,
    [tenantIds],
  );
  objectKeys.push(
    ...storedObjects.rows.map((row) => row.object_key).filter(Boolean),
  );
  await client.query(
    `
      DELETE FROM license_devices
      WHERE license_id IN (
        SELECT id FROM license_keys WHERE tenant_id=ANY($1::uuid[])
      )
    `,
    [tenantIds],
  );
  await client.query(
    `
      UPDATE license_keys
      SET status='archived',archived_at=COALESCE(archived_at,NOW()),
          updated_at=NOW()
      WHERE tenant_id=ANY($1::uuid[])
        AND status<>'archived'
    `,
    [tenantIds],
  );
  await client.query(
    `
      INSERT INTO audit_logs (
        action,target_type,target_id,result,metadata,risk_level,summary
      )
      SELECT
        'tenant.data_purge','tenant',candidate.id::text,'success',
        jsonb_build_object(
          'expiredAt',candidate.access_expires_at,
          'graceDays',$2::int
        ),
        'high','系统在到期宽限期后清除了租户业务数据'
      FROM unnest($1::uuid[]) AS selected(id)
      JOIN tenants candidate ON candidate.id=selected.id
    `,
    [tenantIds, EXPIRED_TENANT_GRACE_DAYS],
  );
  const deleted = await client.query(
    `
      DELETE FROM tenants
      WHERE id=ANY($1::uuid[])
        AND access_expires_at <=
          NOW() - ($2::int * INTERVAL '1 day')
      RETURNING id
    `,
    [tenantIds, EXPIRED_TENANT_GRACE_DAYS],
  );
  return deleted.rows.map((row) => row.id).filter(isUuid);
}

async function cleanupExpiredData() {
  const client = await pool.connect();
  const objectKeys = [];
  let purgedTenantIds = [];

  try {
    await client.query('BEGIN');

    const expiredObjects = await client.query(`
      SELECT DISTINCT a.object_key
      FROM attachments a
      LEFT JOIN messages m ON m.attachment_id = a.id
      WHERE a.storage = 'r2'
        AND a.object_key IS NOT NULL
        AND (
          COALESCE(m.expires_at, a.expires_at) <= NOW()
          OR (
            a.created_at < NOW() - INTERVAL '10 minutes'
            AND (a.linked_at IS NULL OR m.id IS NULL)
          )
        )
    `);
    objectKeys.push(
      ...expiredObjects.rows.map((row) => row.object_key).filter(Boolean),
    );

    const messages = await client.query(
      `
        DELETE FROM messages
        WHERE expires_at <= NOW()
      `,
    );

    const attachments = await client.query(
      `
        DELETE FROM attachments a
        WHERE
          a.expires_at <= NOW()
          OR
          (
            a.created_at < NOW() - INTERVAL '10 minutes'
            AND (
              a.linked_at IS NULL
              OR NOT EXISTS (
                SELECT 1 FROM messages m WHERE m.attachment_id = a.id
              )
            )
          )
      `,
    );

    const replyImages = await client.query(`
      DELETE FROM assets a
      WHERE a.kind = 'reply_image'
        AND a.created_at < NOW() - INTERVAL '7 days'
        AND NOT EXISTS (
          SELECT 1 FROM messages m WHERE m.asset_id = a.id
        )
        AND NOT EXISTS (
          SELECT 1
          FROM tenant_config tc
          WHERE tc.tenant_id = a.tenant_id
            AND (
              tc.canned_replies::text LIKE '%' || a.id::text || '%'
              OR tc.auto_replies::text LIKE '%' || a.id::text || '%'
              OR tc.settings::text LIKE '%' || a.id::text || '%'
            )
        )
      RETURNING object_key
    `);
    objectKeys.push(
      ...replyImages.rows.map((row) => row.object_key).filter(Boolean),
    );

    const conversations = await client.query(
      `
        DELETE FROM conversations c
        WHERE
          c.updated_at < NOW() - INTERVAL '1 hour'
          AND NOT EXISTS (
            SELECT 1 FROM messages m WHERE m.conversation_id = c.id
          )
      `,
    );

    await client.query(`DELETE FROM telegram_updates WHERE created_at < NOW() - INTERVAL '30 days'`);
    await client.query(`
      DELETE FROM license_generation_requests
      WHERE created_at < NOW() - INTERVAL '1 day'
    `);
    await client.query(`
      DELETE FROM auth_sessions
      WHERE expires_at <= NOW()
         OR revoked_at < NOW() - INTERVAL '7 days'
    `);
    await client.query(`DELETE FROM auth_attempt_limits WHERE expires_at<=NOW()`);
    await client.query(`DELETE FROM qr_incident_reports WHERE reported_at < NOW() - INTERVAL '180 days'`);
    await client.query(`DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at <= NOW()`);
    await client.query(`
      DELETE FROM security_events
      WHERE status <> 'open' AND updated_at < NOW() - INTERVAL '90 days'
    `);
    // 会话删除时订阅会级联清理；这里只处理长期失联的旧浏览器订阅。
    await client.query(
      `DELETE FROM push_subscriptions
       WHERE updated_at < NOW() - INTERVAL '30 days'`,
    );
    await client.query(`
      UPDATE call_sessions cs
      SET status='missed',
          ended_at=COALESCE(cs.ended_at,cs.expires_at),
          end_reason='missed',
          updated_at=NOW(),
          expires_at=NOW() + (COALESCE(tc.retention_hours,24)::text || ' hours')::interval
      FROM tenant_config tc
      WHERE cs.tenant_id=tc.tenant_id
        AND cs.status='ringing'
        AND cs.expires_at <= NOW()
    `);
    await client.query(`
      UPDATE call_sessions cs
      SET status='failed',
          ended_at=COALESCE(cs.ended_at,cs.expires_at),
          end_reason='network_timeout',
          duration_seconds=0,
          updated_at=NOW(),
          expires_at=NOW() + (COALESCE(tc.retention_hours,24)::text || ' hours')::interval
      FROM tenant_config tc
      WHERE cs.tenant_id=tc.tenant_id
        AND cs.status=ANY(ARRAY['answered','connected']::text[])
        AND cs.expires_at <= NOW()
    `);
    await client.query(
      `DELETE FROM call_sessions
       WHERE expires_at <= NOW()
         AND status NOT IN ('ringing','answered','connected')`,
    );
    await client.query(`
      DELETE FROM qr_incidents
      WHERE status IN ('resolved','failed')
        AND updated_at < NOW() - INTERVAL '180 days'
    `);
    await client.query(
      `DELETE FROM audit_logs
       WHERE created_at < NOW() - ($1::int * INTERVAL '1 day')`,
      [AUDIT_RETENTION_DAYS],
    );
    await client.query(`DELETE FROM system_metric_samples WHERE created_at < NOW() - INTERVAL '7 days'`);
    purgedTenantIds = await purgeExpiredTenantData(client, objectKeys);
    await queueObjectDeletes(objectKeys, client);

    await client.query('COMMIT');
    lastCleanupAt = Date.now();
    cleanupFailureCount = 0;
    nextCleanupRetryAt = 0;
    await processObjectDeleteQueue();

    for (const tenantId of purgedTenantIds) {
      invalidateTenantCaches(tenantId);
      disconnectTenant(tenantId, {
        type: 'tenant-data-purged',
        message: `卡密到期后 ${EXPIRED_TENANT_GRACE_DAYS} 天未续费，租户业务数据已自动清除。`,
        at: nowIso(),
      });
    }
    if (purgedTenantIds.length) {
      broadcastSuper({ type: 'licenses-updated' });
      broadcastSuper({ type: 'tenants-updated' });
    }

    return {
      messages: messages.rowCount,
      attachments: attachments.rowCount,
      conversations: conversations.rowCount,
      purgedTenants: purgedTenantIds.length,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

function maybeCleanupExpiredData(force = false) {
  if (!force && Date.now() - lastCleanupAt < ACTIVE_CLEANUP_INTERVAL_MS) {
    return Promise.resolve();
  }
  if (Date.now() < nextCleanupRetryAt) return Promise.resolve();
  if (cleanupPromise) return cleanupPromise;

  cleanupPromise = cleanupExpiredData()
    .catch((error) => {
      cleanupFailureCount += 1;
      nextCleanupRetryAt =
        Date.now() +
        Math.min(
          30 * 60_000,
          60_000 * 2 ** Math.min(cleanupFailureCount - 1, 5),
        );
      console.error('清理过期聊天失败：', error);
      if (force) throw error;
    })
    .finally(() => {
      cleanupPromise = null;
    });
  return cleanupPromise;
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
  return signToken(payload, Math.min(target - now, TOKEN_TTL_SECONDS));
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
  const source = String(value || '').trim().toUpperCase();
  const embedded = source.match(
    /(?:^|[^A-Z0-9])((?:SVIP|VIP)(?:[\s_-]*[A-Z2-9]{5}){4})(?=$|[^A-Z0-9])/,
  )?.[1];
  if (embedded) {
    const prefix = embedded.startsWith('SVIP') ? 'SVIP' : 'VIP';
    const raw = embedded.replace(/[^A-Z2-9]/g, '').slice(prefix.length);
    return `${prefix}-${raw.match(/.{5}/g).join('-')}`;
  }
  return source.replace(/[\s_]+/g, '-').replace(/-+/g, '-');
}

async function createAuthSession(kind, subjectId, expiresAt, client = pool) {
  const id = randomUUID();
  const expiry = new Date(expiresAt);
  if (
    !['super_admin', 'distributor', 'tenant_admin'].includes(kind) ||
    !isUuid(subjectId) ||
    !Number.isFinite(expiry.getTime()) ||
    expiry.getTime() <= Date.now()
  ) {
    throw new Error('无法创建无效的授权会话。');
  }
  await client.query(
    `
      INSERT INTO auth_sessions (id,kind,subject_id,expires_at)
      VALUES ($1,$2,$3,$4)
    `,
    [id, kind, subjectId, expiry.toISOString()],
  );
  return id;
}

async function revokeAuthSession(sessionId, kind, subjectId) {
  if (!isUuid(sessionId) || !isUuid(subjectId)) return false;
  const result = await pool.query(
    `
      UPDATE auth_sessions
      SET revoked_at=COALESCE(revoked_at,NOW())
      WHERE id=$1 AND kind=$2 AND subject_id=$3
      RETURNING id
    `,
    [sessionId, kind, subjectId],
  );
  return Boolean(result.rows[0]);
}
function licenseKeyKind(value) {
  const key = normalizeLicenseKey(value);
  if (/^SVIP-[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}$/.test(key)) {
    return 'super';
  }
  if (/^VIP-[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}$/.test(key)) {
    return 'normal';
  }
  return '';
}
function hashLicenseKey(value) {
  return createHmac('sha256', DATA_PROTECTION_SECRET)
    .update(`license:${normalizeLicenseKey(value)}`)
    .digest('base64url');
}
function encryptLicenseKey(value) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', LICENSE_ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([
    cipher.update(String(value), 'utf8'),
    cipher.final(),
  ]);
  return [
    iv.toString('base64url'),
    cipher.getAuthTag().toString('base64url'),
    encrypted.toString('base64url'),
  ].join('.');
}
function decryptLicenseKey(value) {
  try {
    const [iv, tag, encrypted, extra] = String(value || '').split('.');
    if (!iv || !tag || !encrypted || extra) return '';
    const decipher = createDecipheriv(
      'aes-256-gcm',
      LICENSE_ENCRYPTION_KEY,
      Buffer.from(iv, 'base64url'),
    );
    decipher.setAuthTag(Buffer.from(tag, 'base64url'));
    return Buffer.concat([
      decipher.update(Buffer.from(encrypted, 'base64url')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return '';
  }
}
const encryptSecret = encryptLicenseKey;
const decryptSecret = decryptLicenseKey;

function encryptAudioBuffer(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data || []);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', AUDIO_ENCRYPTION_KEY, iv);
  cipher.setAAD(AUDIO_ENCRYPTION_MAGIC);
  const ciphertext = Buffer.concat([cipher.update(input), cipher.final()]);
  return Buffer.concat([
    AUDIO_ENCRYPTION_MAGIC,
    iv,
    cipher.getAuthTag(),
    ciphertext,
  ]);
}

function decryptAudioBuffer(data) {
  const input = Buffer.isBuffer(data) ? data : Buffer.from(data || []);
  if (
    input.length < AUDIO_ENCRYPTION_MAGIC.length + 12 + 16 ||
    !input.subarray(0, AUDIO_ENCRYPTION_MAGIC.length).equals(AUDIO_ENCRYPTION_MAGIC)
  ) return input;
  const offset = AUDIO_ENCRYPTION_MAGIC.length;
  const iv = input.subarray(offset, offset + 12);
  const tag = input.subarray(offset + 12, offset + 28);
  const ciphertext = input.subarray(offset + 28);
  const decipher = createDecipheriv('aes-256-gcm', AUDIO_ENCRYPTION_KEY, iv);
  decipher.setAAD(AUDIO_ENCRYPTION_MAGIC);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

function dataProtectionVerificationTag() {
  return createHmac('sha256', DATA_PROTECTION_SECRET)
    .update('tuojie-data-protection-key-v1')
    .digest('base64url');
}

async function ensureDataProtectionSecret(client) {
  const expectedTag = dataProtectionVerificationTag();
  const existing = await client.query(
    `SELECT verification_tag FROM data_protection_state WHERE id=1 FOR UPDATE`,
  );
  if (existing.rows[0]) {
    if (!timingSafeTextEqual(existing.rows[0].verification_tag, expectedTag)) {
      throw new Error(
        'DATA_PROTECTION_SECRET 与数据库不匹配；已安全停止启动，禁止用新值覆盖旧数据。',
      );
    }
    await client.query(
      `UPDATE data_protection_state SET verified_at=NOW() WHERE id=1`,
    );
    return;
  }

  // 首次升级还没有校验标记，先用已有密文验证真实旧密钥；任一密文
  // 无法认证都中止事务，避免错误密钥把卡密、TOTP 或语音永久锁死。
  const licenseSamples = await client.query(`
    SELECT expected_hash,ciphertext
    FROM (
      SELECT key_hash AS expected_hash,key_ciphertext AS ciphertext
      FROM license_keys
      WHERE NULLIF(key_ciphertext,'') IS NOT NULL
      UNION ALL
      SELECT super_key_hash AS expected_hash,super_key_ciphertext AS ciphertext
      FROM license_keys
      WHERE NULLIF(super_key_ciphertext,'') IS NOT NULL
    ) protected_keys
    LIMIT 10
  `);
  for (const row of licenseSamples.rows) {
    const plaintext = decryptLicenseKey(row.ciphertext);
    if (
      !plaintext ||
      !timingSafeTextEqual(hashLicenseKey(plaintext), row.expected_hash)
    ) {
      throw new Error(
        'DATA_PROTECTION_SECRET 无法验证历史卡密；请使用升级前 TOKEN_SECRET 的真实值。',
      );
    }
  }

  const totpSamples = await client.query(`
    SELECT totp_secret_ciphertext AS ciphertext
    FROM super_admins
    WHERE NULLIF(totp_secret_ciphertext,'') IS NOT NULL
    LIMIT 3
  `);
  for (const row of totpSamples.rows) {
    if (!decryptSecret(row.ciphertext)) {
      throw new Error(
        'DATA_PROTECTION_SECRET 无法验证历史 TOTP；请使用升级前 TOKEN_SECRET 的真实值。',
      );
    }
  }

  const audioSample = await client.query(`
    SELECT data
    FROM attachments
    WHERE data IS NOT NULL
      AND mime=ANY($1::text[])
      AND substring(data FROM 1 FOR 5)=decode('544b414531','hex')
    LIMIT 1
  `, [[...ALLOWED_AUDIO_TYPES]]);
  if (audioSample.rows[0]?.data) {
    try {
      decryptAudioBuffer(audioSample.rows[0].data);
    } catch {
      throw new Error(
        'DATA_PROTECTION_SECRET 无法验证历史加密语音；请使用升级前 TOKEN_SECRET 的真实值。',
      );
    }
  }

  const inserted = await client.query(
    `
      INSERT INTO data_protection_state (id,verification_tag)
      VALUES (1,$1)
      ON CONFLICT (id) DO UPDATE SET verified_at=NOW()
      WHERE data_protection_state.verification_tag=EXCLUDED.verification_tag
      RETURNING verification_tag
    `,
    [expectedTag],
  );
  if (!inserted.rows[0]) {
    throw new Error('DATA_PROTECTION_SECRET 与另一实例写入的数据库标记不匹配。');
  }
}

function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

// 未知账号也只执行一次 scrypt，避免用户名枚举和额外的 CPU 放大。
const DUMMY_PASSWORD_HASH = hashPassword(
  randomBytes(32).toString('base64url'),
);

function verifyPassword(password, stored) {
  const [scheme, saltText, hashText, extra] = String(stored || '').split('$');
  if (scheme !== 'scrypt' || !saltText || !hashText || extra) return false;
  try {
    const expected = Buffer.from(hashText, 'base64url');
    const actual = scryptSync(
      String(password),
      Buffer.from(saltText, 'base64url'),
      expected.length,
    );
    return actual.length === expected.length && timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function decodeBase32(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = '';
  for (const char of String(value || '').replace(/=+$/g, '').toUpperCase()) {
    const index = alphabet.indexOf(char);
    if (index < 0) return Buffer.alloc(0);
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let index = 0; index + 8 <= bits.length; index += 8) {
    bytes.push(Number.parseInt(bits.slice(index, index + 8), 2));
  }
  return Buffer.from(bytes);
}

function verifyTotp(secret, code) {
  if (!secret) return true;
  if (!/^\d{6}$/.test(String(code || ''))) return false;
  const key = decodeBase32(secret);
  if (!key.length) return false;
  const counter = Math.floor(Date.now() / 30_000);
  for (let offset = -1; offset <= 1; offset += 1) {
    const data = Buffer.alloc(8);
    data.writeBigUInt64BE(BigInt(counter + offset));
    const digest = createHmac('sha1', key).update(data).digest();
    const position = digest[digest.length - 1] & 0x0f;
    const number =
      (digest.readUInt32BE(position) & 0x7fffffff) % 1_000_000;
    if (timingSafeTextEqual(String(number).padStart(6, '0'), String(code))) {
      return true;
    }
  }
  return false;
}

function parseCookies(req) {
  const result = {};
  for (const item of String(req.headers.cookie || '').split(';')) {
    const index = item.indexOf('=');
    if (index < 1) continue;
    const key = item.slice(0, index).trim();
    const value = item.slice(index + 1).trim();
    try {
      result[key] = decodeURIComponent(value);
    } catch {
      result[key] = value;
    }
  }
  return result;
}

function sessionCookie(token, maxAge = 8 * 60 * 60) {
  const parts = [
    `${SESSION_COOKIE}=${encodeURIComponent(token)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    `Max-Age=${Math.max(0, Math.trunc(maxAge))}`,
  ];
  if (COOKIE_SECURE) parts.push('Secure');
  if (COOKIE_DOMAIN) parts.push(`Domain=${COOKIE_DOMAIN}`);
  return parts.join('; ');
}

const LICENSE_DURATIONS = Object.freeze({
  '1h': { label: '一小时卡', days: 1, hours: 1 },
  '1d': { label: '一日卡', days: 1, hours: 24 },
  '7d': { label: '周卡', days: 7, hours: 7 * 24 },
  '30d': { label: '月卡', days: 30, hours: 30 * 24 },
  '180d': { label: '半年卡', days: 180, hours: 180 * 24 },
  '365d': { label: '年卡', days: 365, hours: 365 * 24 },
});

const DISTRIBUTOR_DURATION_CODES = Object.freeze(
  Object.keys(LICENSE_DURATIONS),
);

function cleanDurationCodes(value) {
  return Array.isArray(value)
    ? [...new Set(value)].filter((code) => LICENSE_DURATIONS[code])
    : [];
}

function verifyPasswordAsync(password, stored) {
  const [scheme, saltText, hashText, extra] = String(stored || '').split('$');
  if (scheme !== 'scrypt' || !saltText || !hashText || extra) {
    return Promise.resolve(false);
  }
  try {
    const expected = Buffer.from(hashText, 'base64url');
    const salt = Buffer.from(saltText, 'base64url');
    return new Promise((resolve) => {
      scrypt(String(password), salt, expected.length, (error, actual) => {
        resolve(
          !error &&
          actual.length === expected.length &&
          timingSafeEqual(actual, expected),
        );
      });
    });
  } catch {
    return Promise.resolve(false);
  }
}

function licenseDurationMilliseconds(license) {
  const configured = LICENSE_DURATIONS[license?.duration_code];
  if (Number.isFinite(configured?.hours) && configured.hours > 0) {
    return configured.hours * 3_600_000;
  }
  return Math.max(1, Number(license?.duration_days || 1)) * 86_400_000;
}

function licenseUnusedDurationLabel(license) {
  const configured = LICENSE_DURATIONS[license?.duration_code];
  if (configured?.hours && configured.hours < 24) {
    return `${configured.hours} 小时`;
  }
  return `${configured?.days || Math.max(1, Number(license?.duration_days || 1))} 天`;
}

function generatePrefixedLicenseKey(prefix) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = randomBytes(20);
  let raw = '';
  for (let i = 0; i < 20; i += 1) raw += alphabet[bytes[i] % alphabet.length];
  return `${prefix === 'SVIP' ? 'SVIP' : 'VIP'}-${raw.match(/.{1,5}/g).join('-')}`;
}
function generateLicenseKey() {
  return generatePrefixedLicenseKey('VIP');
}
function generateSuperLicenseKey() {
  return generatePrefixedLicenseKey('SVIP');
}

const requestContext = new AsyncLocalStorage();

function normalizedSqlForLog(value) {
  const text = typeof value === 'string' ? value : value?.text;
  return String(text || '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 300);
}

function observeDatabaseQuery(startedAt, sql, error = null) {
  const durationMs = performance.now() - startedAt;
  const context = requestContext.getStore();
  if (context) {
    context.sqlCount += 1;
    context.sqlDurationMs += durationMs;
  }
  if (durationMs >= SLOW_QUERY_MS || error) {
    console.warn(JSON.stringify({
      event: error ? 'database_query_error' : 'slow_database_query',
      requestId: context?.requestId || null,
      traceId: context?.traceId || null,
      durationMs: Number(durationMs.toFixed(1)),
      sql: normalizedSqlForLog(sql),
      errorCode: cleanText(error?.code, 40),
    }));
  }
}

pool.on('connect', (client) => {
  if (client.__tuojieQueryObserved) return;
  client.__tuojieQueryObserved = true;
  const query = client.query.bind(client);
  client.query = (...args) => {
    const startedAt = performance.now();
    const sql = args[0];
    const callbackIndex = typeof args.at(-1) === 'function'
      ? args.length - 1
      : -1;
    if (callbackIndex >= 0) {
      const callback = args[callbackIndex];
      args[callbackIndex] = (error, result) => {
        observeDatabaseQuery(startedAt, sql, error);
        callback(error, result);
      };
      return query(...args);
    }
    try {
      const result = query(...args);
      return Promise.resolve(result).then(
        (value) => {
          observeDatabaseQuery(startedAt, sql);
          return value;
        },
        (error) => {
          observeDatabaseQuery(startedAt, sql, error);
          throw error;
        },
      );
    } catch (error) {
      observeDatabaseQuery(startedAt, sql, error);
      throw error;
    }
  };
});

async function ensureSuperLicenseKey(row, queryClient = pool) {
  const existing = decryptLicenseKey(row?.super_key_ciphertext);
  if (existing) return existing;
  if (!isUuid(row?.id) || ['archived', 'superseded'].includes(row.status)) {
    return '';
  }
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const superLicenseKey = generateSuperLicenseKey();
    try {
      const updated = await queryClient.query(
        `
          UPDATE license_keys
          SET super_key_hash=$2,super_key_ciphertext=$3,
              super_key_suffix=$4,updated_at=NOW()
          WHERE id=$1 AND super_key_hash IS NULL
          RETURNING id
        `,
        [
          row.id,
          hashLicenseKey(superLicenseKey),
          encryptLicenseKey(superLicenseKey),
          superLicenseKey.slice(-5),
        ],
      );
      if (updated.rows[0]) return superLicenseKey;
      const current = await queryClient.query(
        `SELECT super_key_ciphertext FROM license_keys WHERE id=$1`,
        [row.id],
      );
      return decryptLicenseKey(current.rows[0]?.super_key_ciphertext);
    } catch (error) {
      if (error?.code !== '23505' || attempt === 4) throw error;
    }
  }
  return '';
}

async function backfillLegacySuperLicenseKeys(batchSize = 100) {
  const pending = await pool.query(
    `
      SELECT id,status
      FROM license_keys
      WHERE super_key_hash IS NULL
        AND status IN ('unused','active','revoked')
      ORDER BY created_at,id
      LIMIT $1
    `,
    [Math.min(250, Math.max(1, Math.trunc(Number(batchSize || 100))))],
  );
  if (!pending.rowCount) return { selected: 0, updated: 0 };
  const generated = pending.rows.map((row) => {
    const key = generateSuperLicenseKey();
    return {
      id: row.id,
      hash: hashLicenseKey(key),
      ciphertext: encryptLicenseKey(key),
      suffix: key.slice(-5),
    };
  });
  const updated = await pool.query(
    `
      UPDATE license_keys AS license
      SET super_key_hash=input.key_hash,
          super_key_ciphertext=input.key_ciphertext,
          super_key_suffix=input.key_suffix,
          updated_at=NOW()
      FROM unnest($1::uuid[],$2::text[],$3::text[],$4::text[])
        AS input(id,key_hash,key_ciphertext,key_suffix)
      WHERE license.id=input.id AND license.super_key_hash IS NULL
      RETURNING license.id
    `,
    [
      generated.map((item) => item.id),
      generated.map((item) => item.hash),
      generated.map((item) => item.ciphertext),
      generated.map((item) => item.suffix),
    ],
  );
  return { selected: pending.rowCount, updated: updated.rowCount };
}

function scheduleLegacySuperKeyBackfill(delayMs = 1000) {
  if (legacySuperKeyBackfillTimer) return;
  legacySuperKeyBackfillTimer = setTimeout(async () => {
    legacySuperKeyBackfillTimer = null;
    try {
      const result = await backfillLegacySuperLicenseKeys(100);
      if (result.selected >= 100) scheduleLegacySuperKeyBackfill(1000);
    } catch (error) {
      console.error('历史卡密补齐超级卡密失败：', error.message);
      scheduleLegacySuperKeyBackfill(5 * 60_000);
    }
  }, Math.max(250, Number(delayMs || 1000)));
  legacySuperKeyBackfillTimer.unref();
}
function generateTenantCode() {
  return `site_${randomBytes(12).toString('base64url')}`;
}
function licenseHint(row) {
  return row
    ? `${row.key_prefix || 'VIP'}-•••••-•••••-•••••-${row.key_suffix || '?????'}`
    : '';
}

function licenseGenerationIdempotencyKey(req) {
  const raw = Array.isArray(req.headers['idempotency-key'])
    ? req.headers['idempotency-key'][0]
    : req.headers['idempotency-key'];
  const key = cleanText(raw, 128);
  if (!/^[A-Za-z0-9_-]{16,128}$/.test(key)) {
    throw requestError(
      '生成卡密必须提供有效的 Idempotency-Key。',
      400,
      'IDEMPOTENCY_KEY',
    );
  }
  return key;
}

function licenseGenerationRequestHash(value) {
  return createHmac('sha256', DATA_PROTECTION_SECRET)
    .update(`license-generation:${JSON.stringify(value)}`)
    .digest('base64url');
}

async function claimLicenseGeneration(
  client,
  { actorKind, actorId, idempotencyKey, requestHash },
) {
  const inserted = await client.query(
    `
      INSERT INTO license_generation_requests (
        id,actor_kind,actor_id,idempotency_key,request_hash
      ) VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (actor_kind,actor_id,idempotency_key) DO NOTHING
      RETURNING id
    `,
    [randomUUID(), actorKind, actorId, idempotencyKey, requestHash],
  );
  if (inserted.rows[0]) {
    return { id: inserted.rows[0].id, replayed: false, licenseIds: [] };
  }
  const existing = await client.query(
    `
      SELECT id,request_hash,license_ids,completed_at,created_at
      FROM license_generation_requests
      WHERE actor_kind=$1 AND actor_id=$2 AND idempotency_key=$3
      FOR UPDATE
    `,
    [actorKind, actorId, idempotencyKey],
  );
  const row = existing.rows[0];
  if (!row || !timingSafeTextEqual(row.request_hash, requestHash)) {
    throw requestError(
      '同一个 Idempotency-Key 不能用于不同的发卡参数。',
      409,
      'IDEMPOTENCY_CONFLICT',
    );
  }
  if (
    Date.now() - new Date(row.created_at).getTime() >
      LICENSE_GENERATION_REPLAY_MS
  ) {
    throw requestError(
      '本次发卡结果的安全重试窗口已结束，请重新提交新请求。',
      409,
      'IDEMPOTENCY_EXPIRED',
    );
  }
  if (!row.completed_at || !Array.isArray(row.license_ids) || !row.license_ids.length) {
    throw requestError(
      '同一发卡请求正在处理，请稍后使用相同 Idempotency-Key 重试。',
      409,
      'IDEMPOTENCY_IN_PROGRESS',
    );
  }
  return { id: row.id, replayed: true, licenseIds: row.license_ids };
}

async function completeLicenseGeneration(client, requestId, licenseIds) {
  await client.query(
    `
      UPDATE license_generation_requests
      SET license_ids=$2::uuid[],completed_at=NOW()
      WHERE id=$1 AND completed_at IS NULL
    `,
    [requestId, licenseIds],
  );
}

async function replayedLicenseRecords(client, licenseIds) {
  const result = await client.query(
    `
      SELECT l.*
      FROM unnest($1::uuid[]) WITH ORDINALITY AS requested(id,position)
      JOIN license_keys l ON l.id=requested.id
      ORDER BY requested.position
    `,
    [licenseIds],
  );
  if (result.rows.length !== licenseIds.length) {
    throw requestError(
      '发卡幂等记录不完整，请联系平台管理员。',
      409,
      'IDEMPOTENCY_DATA',
    );
  }
  return result.rows.map((row) => {
    const licenseKey = decryptLicenseKey(row.key_ciphertext);
    const superLicenseKey = decryptLicenseKey(row.super_key_ciphertext);
    if (!licenseKey) {
      throw requestError(
        '本次发卡结果已无法安全重放，请联系平台管理员。',
        409,
        'IDEMPOTENCY_DATA',
      );
    }
    return {
      row,
      licenseKey,
      superLicenseKey,
      duration: LICENSE_DURATIONS[row.duration_code],
    };
  });
}


function getBearer(req) {
  const value = req.headers.authorization || '';
  return value.startsWith('Bearer ') ? value.slice(7) : '';
}

function tenantAdminAccessProof(licenseId, accessKind) {
  return createHmac('sha256', TOKEN_SECRET)
    .update(`tenant-admin-access:${licenseId}:${accessKind === 'super' ? 's' : 'n'}`)
    .digest('base64url');
}

function tenantAdminAccessKind(payload) {
  if (!isUuid(payload?.licenseId)) return '';
  // 兼容升级前已签发的短期令牌；新令牌只携带不可读的校验值。
  if (payload.accessKind === 'super' || payload.accessKind === 'normal') {
    return payload.accessKind;
  }
  const supplied = cleanText(payload.accessProof, 100);
  if (!supplied) return '';
  if (
    timingSafeTextEqual(
      supplied,
      tenantAdminAccessProof(payload.licenseId, 'super'),
    )
  ) return 'super';
  if (
    timingSafeTextEqual(
      supplied,
      tenantAdminAccessProof(payload.licenseId, 'normal'),
    )
  ) return 'normal';
  return '';
}

function authenticate(req, kind) {
  const payload = verifyToken(getBearer(req));
  if (!payload || (kind && payload.kind !== kind)) return null;
  return payload;
}

function superLicenseHint(row) {
  return row?.super_key_suffix
    ? `SVIP-•••••-•••••-•••••-${row.super_key_suffix}`
    : '';
}

function normalizeDeviceId(value) {
  const id = cleanText(value, 160);
  return /^[A-Za-z0-9._:-]{16,160}$/.test(id) ? id : '';
}

function hashLicenseDevice(value) {
  return createHmac('sha256', DATA_PROTECTION_SECRET)
    .update(`license-device:${value}`)
    .digest('base64url');
}

function classifyLicenseDevice(req, requestedType = '') {
  const userAgent = String(req?.headers?.['user-agent'] || '');
  if (
    /Android|iPhone|iPad|iPod|Mobile|Tablet|HarmonyOS|Windows Phone/i.test(
      userAgent,
    )
  ) return 'mobile';
  return requestedType === 'mobile' ? 'mobile' : 'desktop';
}

async function registerLicenseDevice(
  client,
  req,
  license,
  body,
  accessKind = 'normal',
) {
  const rawDeviceId = normalizeDeviceId(body?.deviceId);
  if (accessKind === 'super') {
    return rawDeviceId ? hashLicenseDevice(rawDeviceId) : '';
  }
  if (!rawDeviceId) {
    throw requestError(
      '需要登记当前设备，请刷新后台页面后重新登录。',
      400,
      'DEVICE_ID_REQUIRED',
    );
  }
  const deviceHash = hashLicenseDevice(rawDeviceId);
  const deviceType = classifyLicenseDevice(req, body?.deviceType);
  const deviceLabel = cleanText(
    body?.deviceLabel || req?.headers?.['user-agent'] || deviceType,
    120,
  );
  const ipAddress = cleanText(requestIp(req), 100);
  const existing = await client.query(
    `
      SELECT id,revoked_at,last_seen_at
      FROM license_devices
      WHERE license_id=$1 AND access_kind='normal' AND device_hash=$2
      FOR UPDATE
    `,
    [license.id, deviceHash],
  );
  if (existing.rows[0]?.revoked_at) {
    throw requestError(
      '这台设备已被管理员移除，请联系平台重新授权。',
      403,
      'DEVICE_REVOKED',
    );
  }
  if (existing.rows[0]) {
    await client.query(
      `
        UPDATE license_devices
        SET last_ip=$2,last_seen_at=NOW(),device_label=$3
        WHERE id=$1
          AND last_seen_at < NOW() - INTERVAL '15 minutes'
      `,
      [existing.rows[0].id, ipAddress, deviceLabel],
    );
    return deviceHash;
  }
  const limit = deviceType === 'mobile'
    ? Number(license.max_mobile_devices || LICENSE_MOBILE_DEVICE_DEFAULT)
    : Number(license.max_desktop_devices || LICENSE_DESKTOP_DEVICE_DEFAULT);
  const countResult = await client.query(
    `
      SELECT COUNT(*)::int AS count
      FROM license_devices
      WHERE license_id=$1 AND access_kind='normal'
        AND device_type=$2 AND revoked_at IS NULL
    `,
    [license.id, deviceType],
  );
  const currentCount = Number(countResult.rows[0]?.count || 0);
  if (currentCount >= limit) {
    const label = deviceType === 'mobile' ? '手机/平板' : '电脑';
    const error = requestError(
      `${label}设备已达到上限（${limit} 台），请联系管理员调整或清理设备。`,
      403,
      'DEVICE_LIMIT_REACHED',
    );
    error.deviceType = deviceType;
    error.deviceLimit = limit;
    throw error;
  }
  await client.query(
    `
      INSERT INTO license_devices (
        id,license_id,access_kind,device_hash,device_type,device_label,
        first_ip,last_ip
      ) VALUES ($1,$2,'normal',$3,$4,$5,$6,$6)
    `,
    [randomUUID(), license.id, deviceHash, deviceType, deviceLabel, ipAddress],
  );
  return deviceHash;
}

function inspectUserTokenOrigin(req, payload) {
  if (payload?.kind !== 'user' || !STRICT_CLIENT_ORIGIN) {
    return { allowed: true, reason: 'disabled', requestOrigin: '', tokenOrigin: '' };
  }
  const requestOrigin = normalizeOrigin(req.headers.origin);
  const tokenOrigin = normalizeOrigin(payload.clientOrigin);
  if (!tokenOrigin) {
    return { allowed: false, reason: 'legacy-token', requestOrigin, tokenOrigin };
  }
  if (!requestOrigin) {
    return { allowed: false, reason: 'missing-origin', requestOrigin, tokenOrigin };
  }
  return {
    allowed: timingSafeTextEqual(requestOrigin, tokenOrigin),
    reason: requestOrigin === tokenOrigin ? 'match' : 'mismatch',
    requestOrigin,
    tokenOrigin,
  };
}

function userTokenOriginAllowed(req, payload) {
  return inspectUserTokenOrigin(req, payload).allowed;
}

function observeConfirmedUserOriginReuse(
  req,
  payload,
  pathname,
  { requestOrigin = '', tokenOrigin = '', approvedOrigin = '' } = {},
) {
  observeBehaviorCounter(req, {
    kind: 'user-token-origin-mismatch',
    key: securityFingerprint([
      payload.tenantId,
      payload.conversationId,
      requestOrigin,
      tokenOrigin,
    ]),
    limit: 1,
    severity: 'critical',
    tenantId: payload.tenantId,
    conversationId: payload.conversationId,
    details: {
      path: pathname,
      requestOrigin,
      tokenOrigin,
      approvedOrigin,
      confidence: 'high',
      detection: 'confirmed-cross-origin-token-reuse',
      allowLicenseBlock: true,
    },
  });
}

async function rejectInvalidUserTokenOrigin(req, res, payload, pathname) {
  const check = inspectUserTokenOrigin(req, payload);
  if (check.reason === 'disabled') return false;

  // 租户历史上亲自选择过的每个启用模板都是独立批准来源。
  // 令牌仍然必须同时绑定到它原来的 Origin 和模板 ID，不能因为
  // 两个站都被批准就把 A 站令牌拿到 B 站使用。
  const config = await getConfig(payload.tenantId);
  const tokenTemplateId = cleanText(payload.clientTemplateId, 80);
  const approvedOrigins = tenantApprovedOriginSummary(config);
  const requestApproved = findTenantApprovedFrontend(
    config,
    check.requestOrigin,
  );
  const tokenApproved = findTenantApprovedFrontend(
    config,
    check.tokenOrigin,
    tokenTemplateId,
  );

  if (check.allowed && tokenApproved) return false;

  if (requestApproved) {
    sendError(
      res,
      401,
      '访客会话需要安全换新，请稍候重试。',
      'TOKEN_REFRESH_REQUIRED',
    );
    return true;
  }

  if (check.reason === 'mismatch') {
    observeConfirmedUserOriginReuse(req, payload, pathname, {
      requestOrigin: check.requestOrigin,
      tokenOrigin: check.tokenOrigin,
      approvedOrigin: approvedOrigins,
    });
    sendError(
      res,
      403,
      '访客会话不能在其他站点使用。',
      'CLIENT_ORIGIN',
    );
    return true;
  }
  if (check.reason === 'legacy-token') {
    sendError(
      res,
      403,
      '旧访客会话不属于该租户当前用户端，请从商家客服入口重新打开。',
      'CLIENT_ORIGIN',
    );
    return true;
  }
  if (check.allowed) {
    sendError(
      res,
      403,
      '此访客会话来自租户已经停用的用户端，请从最新客服入口重新打开。',
      'CLIENT_ORIGIN',
    );
    return true;
  }
  sendError(
    res,
    403,
    '浏览器没有提供可验证的页面来源，请从商家客服入口重新打开。',
    'CLIENT_ORIGIN_MISSING',
  );
  return true;
}

async function authenticateSuper(req) {
  const bearerToken = getBearer(req);
  const token = bearerToken || parseCookies(req)[SESSION_COOKIE] || '';
  const payload = verifyToken(token);
  if (
    payload?.kind !== 'super_admin' ||
    !isUuid(payload.adminId) ||
    !isUuid(payload.sessionId) ||
    !Number.isInteger(payload.sessionVersion)
  ) return null;
  const requestOrigin = normalizeOrigin(req.headers.origin);
  const sessionOrigin = normalizeOrigin(payload.clientOrigin);
  if (
    (sessionOrigin && requestOrigin &&
      !timingSafeTextEqual(sessionOrigin, requestOrigin)) ||
    (!bearerToken && requestOrigin && !sessionOrigin)
  ) return null;
  const result = await pool.query(
    `
      SELECT a.id,a.username,a.role,a.enabled,a.session_version,a.last_login_at,
             s.id AS auth_session_id,s.expires_at AS auth_session_expires_at
      FROM super_admins a
      JOIN auth_sessions s
        ON s.id=$2 AND s.kind='super_admin' AND s.subject_id=a.id
       AND s.revoked_at IS NULL AND s.expires_at>NOW()
      WHERE a.id = $1
    `,
    [payload.adminId, payload.sessionId],
  );
  const admin = result.rows[0];
  if (
    !admin?.enabled ||
    Number(admin.session_version) !== payload.sessionVersion
  ) return null;
  const authenticatedAdmin = {
    id: admin.id,
    username: admin.username,
    role: admin.role,
    sessionId: admin.auth_session_id,
    sessionExpiresAt: new Date(admin.auth_session_expires_at).toISOString(),
    lastLoginAt: admin.last_login_at
      ? new Date(admin.last_login_at).toISOString()
      : null,
  };
  return authenticatedAdmin;
}

async function authenticateDistributor(req) {
  const payload = verifyToken(getBearer(req));
  if (
    payload?.kind !== 'distributor' ||
    !isUuid(payload.distributorId) ||
    !isUuid(payload.sessionId) ||
    !Number.isInteger(payload.sessionVersion)
  ) return null;
  const result = await pool.query(
    `
      SELECT
        d.id,d.username,d.display_name,d.telegram_username,d.enabled,
        d.can_generate,d.allowed_duration_codes,d.session_version,
        d.last_login_at,d.created_at,s.id AS auth_session_id,
        s.expires_at AS auth_session_expires_at
      FROM distributors d
      JOIN auth_sessions s
        ON s.id=$2 AND s.kind='distributor' AND s.subject_id=d.id
       AND s.revoked_at IS NULL AND s.expires_at>NOW()
      WHERE d.id=$1
    `,
    [payload.distributorId, payload.sessionId],
  );
  const distributor = result.rows[0];
  if (
    !distributor?.enabled ||
    Number(distributor.session_version) !== payload.sessionVersion
  ) return null;
  const authenticatedDistributor = {
    id: distributor.id,
    username: distributor.username,
    displayName: distributor.display_name || '',
    telegramUsername: distributor.telegram_username || '',
    enabled: Boolean(distributor.enabled),
    canGenerate: Boolean(distributor.can_generate),
    allowedDurationCodes: Array.isArray(distributor.allowed_duration_codes)
      ? distributor.allowed_duration_codes.filter(
          (code) => LICENSE_DURATIONS[code],
        )
      : [],
    sessionVersion: Number(distributor.session_version),
    sessionId: distributor.auth_session_id,
    sessionExpiresAt: new Date(
      distributor.auth_session_expires_at,
    ).toISOString(),
    lastLoginAt: distributor.last_login_at
      ? new Date(distributor.last_login_at).toISOString()
      : null,
    createdAt: new Date(distributor.created_at).toISOString(),
  };
  return authenticatedDistributor;
}

const ROLE_LEVEL = Object.freeze({
  readonly: 0,
  support: 1,
  operations: 2,
  manager: 3,
  owner: 4,
});

function requireRole(admin, minimum) {
  if (
    !admin ||
    (ROLE_LEVEL[admin.role] ?? -1) < (ROLE_LEVEL[minimum] ?? 99)
  ) {
    throw requestError('没有执行此操作的权限。', 403, 'SUPER_FORBIDDEN');
  }
}

const TENANT_HIGH_RISK_AUDIT_ACTIONS = new Set([
  'tenant.logout',
  'tenant.config.update',
  'tenant.qr_incident.report',
  'tenant.message.delete',
  'tenant.message.recall',
  'tenant.conversation.delete',
]);

const AUDIT_SUMMARIES = Object.freeze({
  'tenant.logout': '租户主动注销了当前后台会话',
  'tenant.config.update': '租户修改了客服核心设置',
  'tenant.qr_incident.report': '租户上报了二维码或模板域名异常',
  'tenant.message.delete': '租户永久删除了客服消息',
  'tenant.message.recall': '租户撤回了客服消息',
  'tenant.conversation.delete': '租户永久删除了访客会话',
  'tenant.login': '租户后台发生高风险登录失败',
  'license.create': '管理员批量生成普通卡密和超级卡密',
  'license.disable': '管理员禁用了普通卡密',
  'license.restore': '管理员恢复了普通卡密',
  'license.archive': '管理员归档了整套卡密权限',
  'license.device_limits': '管理员修改了普通卡密设备上限',
  'license.devices_reset': '管理员清空了普通卡密登记设备',
  'license.cleanup_expired': '管理员手动执行了超过宽限期的数据清理',
  'license.reveal': '管理员查看了普通卡密和配套超级卡密明文',
  'license.copy': '管理员复制了普通卡密和配套超级卡密',
  'license.delete': '管理员彻底删除了一张未激活卡密',
  'tenant.update': '管理员修改了租户名称或备注',
  'tenant.assign_distributor': '管理员调整了租户所属二级代理',
  'tenant.force_logout': '管理员强制租户所有在线设备退出',
  'tenant.suspend': '管理员暂停了租户服务',
  'tenant.resume': '管理员恢复了租户服务',
  'distributor.create': '管理员创建了二级代理账号',
  'distributor.update': '管理员修改了二级代理权限或账号状态',
  'distributor.quota.update': '管理员调整了二级代理发卡额度',
  'distributor.login': '二级代理登录了代理后台',
  'distributor.logout': '二级代理退出了代理后台',
  'distributor.license.create': '二级代理生成了新卡密',
  'distributor.license.disable': '二级代理禁用了普通卡密',
  'distributor.tenant.remark.update': '二级代理修改了租户备注',
  'announcement.publish': '管理员发布了平台公告',
  'announcement.update': '管理员修改了平台公告',
  'announcement.retract': '管理员撤回了平台公告',
  'release.publish': '管理员发布了新版本说明',
  'release.update': '管理员修改了版本说明',
  'release.delete': '管理员删除了版本说明',
  'feature.create': '管理员新增了功能目录',
  'feature.update': '管理员修改了功能目录',
  'feature_flag.update': '管理员修改了功能开关及开放范围',
  'template.create': '管理员新增了批准的用户端模板',
  'template.update': '管理员修改了用户端模板配置',
  'template.validate': '管理员执行了模板兼容与来源检查',
  'template.cover': '管理员更换了模板封面',
  'platform.update': '管理员修改了平台核心设置',
  'super.login': '超级管理员后台发生登录事件',
  'super.logout': '超级管理员退出了后台',
  'security.ip_block': 'Telegram 管理员封禁了异常来源 IP',
  'security.license_block': 'Telegram 管理员封禁了异常普通卡密',
  'tenant.data_purge': '系统在到期宽限期后清除了租户业务数据',
});

function auditStorageDecision(action, result, actorTenantId, metadata) {
  const code = cleanText(metadata?.code, 80);
  if (action === 'tenant.login') {
    if (result === 'success') return { store: false, riskLevel: 'low' };
    if (['LICENSE_INVALID', 'AUTH'].includes(code)) {
      return { store: false, riskLevel: 'low' };
    }
    return { store: true, riskLevel: 'critical' };
  }
  if (
    actorTenantId &&
    result === 'success' &&
    !TENANT_HIGH_RISK_AUDIT_ACTIONS.has(action)
  ) return { store: false, riskLevel: 'low' };
  if (result === 'failed' || action.startsWith('security.')) {
    return { store: true, riskLevel: 'critical' };
  }
  return { store: true, riskLevel: 'high' };
}

async function writeAudit(
  req,
  admin,
  action,
  {
    targetType = '',
    targetId = '',
    result = 'success',
    metadata = {},
    actorTenantId = '',
    actorLicenseId = '',
    riskLevel = '',
    summary = '',
  } = {},
) {
  const decision = auditStorageDecision(
    cleanText(action, 100),
    cleanText(result, 30) || 'success',
    isUuid(actorTenantId) ? actorTenantId : '',
    metadata,
  );
  if (!decision.store) return null;
  const storedRiskLevel = ['high', 'critical'].includes(riskLevel)
    ? riskLevel
    : decision.riskLevel;
  await pool.query(
    `
      INSERT INTO audit_logs (
        actor_admin_id, actor_tenant_id, actor_license_id,
        action, target_type, target_id, ip_address, result, metadata,
        risk_level,summary
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11)
    `,
    [
      admin?.id || null,
      isUuid(actorTenantId) ? actorTenantId : null,
      isUuid(actorLicenseId) ? actorLicenseId : null,
      cleanText(action, 100),
      cleanText(targetType, 80),
      cleanText(targetId, 160),
      cleanText(requestIp(req), 100),
      cleanText(result, 30) || 'success',
      JSON.stringify(metadata || {}),
      storedRiskLevel,
      cleanText(summary || AUDIT_SUMMARIES[action] || '高风险后台操作', 300),
    ],
  );
  return true;
}

function writeTenantAudit(req, payload, action, options = {}) {
  return writeAudit(req, null, action, {
    ...options,
    actorTenantId: payload?.tenantId,
    actorLicenseId: payload?.licenseId,
    targetType: options.targetType || 'tenant',
    targetId: options.targetId || payload?.tenantId || '',
  });
}

async function writeDistributorAudit(
  req,
  distributor,
  action,
  {
    targetType = '',
    targetId = '',
    result = 'success',
    metadata = {},
  } = {},
) {
  await pool.query(
    `
      INSERT INTO audit_logs (
        actor_distributor_id,action,target_type,target_id,
        ip_address,result,metadata,risk_level,summary
      ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9)
    `,
    [
      distributor?.id || null,
      cleanText(action, 100),
      cleanText(targetType, 80),
      cleanText(targetId, 160),
      cleanText(requestIp(req), 100),
      cleanText(result, 30) || 'success',
      JSON.stringify(metadata || {}),
      result === 'failed' ? 'critical' : 'high',
      cleanText(
        AUDIT_SUMMARIES[action] ||
          (result === 'failed' ? '代理后台高风险操作失败' : '代理后台重要操作'),
        300,
      ),
    ],
  );
}

function normalizeOrigin(origin) {
  return String(origin || '').trim().replace(/\/$/, '');
}

const nonPublicAddresses = new BlockList();
for (const [network, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.0.2.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['198.51.100.0', 24],
  ['203.0.113.0', 24],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
]) {
  nonPublicAddresses.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
  ['::', 96],
  ['::', 128],
  ['::1', 128],
  ['64:ff9b::', 96],
  ['64:ff9b:1::', 48],
  ['100::', 64],
  ['2001::', 32],
  ['2001:2::', 48],
  ['2001:10::', 28],
  ['2001:20::', 28],
  ['2001:db8::', 32],
  ['2002::', 16],
  ['3fff::', 20],
  ['5f00::', 16],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
]) {
  nonPublicAddresses.addSubnet(network, prefix, 'ipv6');
}

function mappedIpv4Address(address) {
  const value = String(address || '').toLowerCase();
  if (!value.startsWith('::ffff:')) return '';
  const tail = value.slice('::ffff:'.length);
  if (isIP(tail) === 4) return tail;
  const parts = tail.split(':');
  if (
    parts.length !== 2 ||
    parts.some((part) => !/^[0-9a-f]{1,4}$/.test(part))
  ) return '';
  const high = Number.parseInt(parts[0], 16);
  const low = Number.parseInt(parts[1], 16);
  return [high >>> 8, high & 0xff, low >>> 8, low & 0xff].join('.');
}

function isPublicAddress(address) {
  const version = isIP(address);
  if (version === 4) return !nonPublicAddresses.check(address, 'ipv4');
  if (version === 6) {
    const mapped = mappedIpv4Address(address);
    return mapped
      ? isPublicAddress(mapped)
      : !nonPublicAddresses.check(address, 'ipv6');
  }
  return false;
}

// Cloudflare 官方公布的源站地址段。只有代理链的最邻近公网地址属于这些
// 网段，或 Worker 携带了源站密钥时，才信任 CF-Connecting-IP。
const cloudflareAddresses = new BlockList();
for (const [network, prefix] of [
  ['103.21.244.0', 22],
  ['103.22.200.0', 22],
  ['103.31.4.0', 22],
  ['104.16.0.0', 13],
  ['104.24.0.0', 14],
  ['108.162.192.0', 18],
  ['131.0.72.0', 22],
  ['141.101.64.0', 18],
  ['162.158.0.0', 15],
  ['172.64.0.0', 13],
  ['173.245.48.0', 20],
  ['188.114.96.0', 20],
  ['190.93.240.0', 20],
  ['197.234.240.0', 22],
  ['198.41.128.0', 17],
]) {
  cloudflareAddresses.addSubnet(network, prefix, 'ipv4');
}
for (const [network, prefix] of [
  ['2400:cb00::', 32],
  ['2606:4700::', 32],
  ['2803:f800::', 32],
  ['2405:b500::', 32],
  ['2405:8100::', 32],
  ['2a06:98c0::', 29],
  ['2c0f:f248::', 32],
]) {
  cloudflareAddresses.addSubnet(network, prefix, 'ipv6');
}

function isCloudflareAddress(address) {
  const version = isIP(address);
  if (version === 4) return cloudflareAddresses.check(address, 'ipv4');
  if (version === 6) {
    const mapped = mappedIpv4Address(address);
    return mapped
      ? cloudflareAddresses.check(mapped, 'ipv4')
      : cloudflareAddresses.check(address, 'ipv6');
  }
  return false;
}

function parseTemplateFetchTarget(inputUrl) {
  let target;
  try {
    target = new URL(inputUrl);
  } catch {
    throw requestError('只能检测标准 HTTPS 用户端地址。', 400, 'TEMPLATE_URL');
  }
  if (
    target.protocol !== 'https:' ||
    target.username ||
    target.password ||
    (target.port && target.port !== '443')
  ) {
    throw requestError('只能检测标准 HTTPS 用户端地址。', 400, 'TEMPLATE_URL');
  }
  const hostname = target.hostname.replace(/^\[|\]$/g, '');
  if (isIP(hostname) && !isPublicAddress(hostname)) {
    throw requestError(
      '模板地址不能指向本机、内网或保留网络。',
      400,
      'TEMPLATE_SSRF',
    );
  }
  return target;
}

// 模板检测会访问管理员填写的网址，因此 DNS 必须锁定到公网地址以阻断 SSRF。
function fetchTemplateHtml(inputUrl, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = parseTemplateFetchTarget(inputUrl);
    } catch (error) {
      reject(error);
      return;
    }
    const request = https.request(
      {
        protocol: 'https:',
        hostname: target.hostname,
        port: target.port || 443,
        path: `${target.pathname}${target.search}`,
        method: 'GET',
        servername: target.hostname,
        headers: {
          Accept: 'text/html,application/xhtml+xml',
          'Accept-Encoding': 'identity',
          'User-Agent': `Tuojie-Template-Validator/${APP_VERSION}`,
        },
        lookup(hostname, options, callback) {
          dnsLookup(
            hostname,
            { all: true, verbatim: true },
            (error, addresses) => {
              if (error) return callback(error);
              if (
                !addresses.length ||
                addresses.some((entry) => !isPublicAddress(entry.address))
              ) {
                return callback(new Error('模板域名解析到了非公网地址。'));
              }
              const selected =
                addresses.find((entry) => entry.family === 4) || addresses[0];
              return callback(null, selected.address, selected.family);
            },
          );
        },
      },
      (response) => {
        const status = Number(response.statusCode || 0);
        const location = response.headers.location;
        if (status >= 300 && status < 400 && location) {
          response.resume();
          if (redirectCount >= 3) {
            reject(
              requestError('模板地址重定向次数过多。', 400, 'TEMPLATE_REDIRECT'),
            );
            return;
          }
          let next;
          try {
            next = new URL(location, target);
          } catch {
            reject(requestError('模板重定向地址无效。', 400, 'TEMPLATE_REDIRECT'));
            return;
          }
          fetchTemplateHtml(next.toString(), redirectCount + 1)
            .then(resolve, reject);
          return;
        }
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > 768 * 1024) {
            response.destroy(
              requestError('模板页面超过检测上限。', 400, 'TEMPLATE_SIZE'),
            );
            return;
          }
          chunks.push(chunk);
        });
        response.on('end', () => {
          resolve({
            status,
            finalUrl: target.toString(),
            contentType: String(response.headers['content-type'] || ''),
            html: Buffer.concat(chunks).toString('utf8'),
          });
        });
        response.on('error', reject);
      },
    );
    request.setTimeout(10_000, () => {
      request.destroy(
        requestError('模板网站连接超时。', 504, 'TEMPLATE_TIMEOUT'),
      );
    });
    const deadline = setTimeout(() => {
      request.destroy(
        requestError('模板网站检测超过总时限。', 504, 'TEMPLATE_TIMEOUT'),
      );
    }, 15_000);
    deadline.unref();
    request.once('close', () => clearTimeout(deadline));
    request.on('error', reject);
    request.end();
  });
}

function extractTemplateContract(html) {
  const meta = {};
  for (const tag of String(html).match(/<meta\b[^>]*>/gi) || []) {
    const attributes = {};
    for (const match of tag.matchAll(
      /([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g,
    )) {
      attributes[match[1].toLowerCase()] =
        match[2] ?? match[3] ?? match[4] ?? '';
    }
    if (attributes.name) meta[attributes.name.toLowerCase()] = attributes.content || '';
  }
  const clientVersion =
    meta['tuojie-client-version'] ||
    String(html).match(
      /CLIENT_VERSION\s*=\s*['"]([^'"]+)['"]/,
    )?.[1] ||
    '';
  const apiBase =
    meta['tuojie-api-base'] ||
    String(html).match(
      /DEFAULT_API_BASE\s*=\s*['"]([^'"]+)['"]/,
    )?.[1] ||
    '';
  const contractVersion = cleanText(
    meta['tuojie-api-contract'] || '',
    30,
  );
  const requiredInlineMarkers = [
    '/api/user/session',
    '/api/user/conversation',
    '/api/events',
    'CLIENT_TEMPLATE_ID',
    'Last-Event-ID',
  ];
  const missingMarkers = requiredInlineMarkers.filter(
    (marker) => !String(html).includes(marker),
  );
  // Vite 会把 JS 拆成独立静态资源，部署页面可以用显式 meta 契约代替扫描内联源码。
  const declaredContractReady =
    /^v?2(?:\.|$)/i.test(contractVersion) &&
    Object.hasOwn(meta, 'tuojie-template-id') &&
    Boolean(clientVersion && apiBase);
  const contractReady = declaredContractReady || missingMarkers.length === 0;
  return {
    clientVersion: cleanText(clientVersion, 30),
    apiBase: cleanText(apiBase, 300).replace(/\/+$/, ''),
    contractVersion,
    contractReady,
    missingMarkers: declaredContractReady ? [] : missingMarkers,
  };
}

function compareVersions(left, right) {
  const parse = (value) =>
    String(value || '')
      .replace(/^v/i, '')
      .split(/[.-]/)
      .slice(0, 3)
      .map((part) => Number(part) || 0);
  const a = parse(left);
  const b = parse(right);
  for (let index = 0; index < 3; index += 1) {
    if ((a[index] || 0) !== (b[index] || 0)) {
      return (a[index] || 0) > (b[index] || 0) ? 1 : -1;
    }
  }
  return 0;
}

async function refreshApprovedOrigins(force = false) {
  if (!force && approvedOriginCacheExpiresAt > Date.now()) return;
  const origins = new Set(
    STATIC_ALLOWED_ORIGINS
      .map(normalizeOrigin)
      .filter((origin) => origin && origin !== '*'),
  );
  try {
    const result = await pool.query(`
      SELECT origin,entry_host
      FROM frontend_templates
      WHERE status IN ('testing','enabled')
      UNION ALL
      SELECT '' AS origin,aliases.hostname AS entry_host
      FROM frontend_template_entry_aliases aliases
      JOIN frontend_templates templates ON templates.id=aliases.template_id
      WHERE templates.status IN ('testing','enabled')
      UNION ALL
      SELECT '' AS origin,domains.hostname AS entry_host
      FROM tenant_template_domains domains
      JOIN frontend_templates templates ON templates.id=domains.template_id
      WHERE templates.status IN ('testing','enabled')
      UNION ALL
      SELECT '' AS origin,aliases.hostname AS entry_host
      FROM tenant_template_domain_aliases aliases
      JOIN frontend_templates templates ON templates.id=aliases.template_id
      WHERE templates.status IN ('testing','enabled')
    `);
    for (const row of result.rows) {
      const origin = normalizeOrigin(row.origin);
      if (origin) origins.add(origin);
      const entryOrigin = tenantEntryOrigin(row.entry_host);
      if (entryOrigin) origins.add(entryOrigin);
    }
  } catch (error) {
    if (!approvedOriginCache.size) throw error;
  }
  approvedOriginCache = origins;
  approvedOriginCacheExpiresAt = Date.now() + CONFIG_CACHE_MS;
}

function invalidateApprovedOrigins() {
  approvedOriginCacheExpiresAt = 0;
}

function originAllowed(origin) {
  if (!origin) return true;
  const normalized = normalizeOrigin(origin);
  return approvedOriginCache.has(normalized);
}

function setCommonHeaders(req, res) {
  const origin = req.headers.origin;
  if (origin && originAllowed(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }

  res.setHeader(
    'Access-Control-Allow-Methods',
    'GET,POST,PUT,PATCH,DELETE,OPTIONS',
  );
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Authorization,Content-Type,X-File-Name,Last-Event-ID,Idempotency-Key',
  );
  res.setHeader('Access-Control-Max-Age', '86400');
  res.setHeader('Access-Control-Expose-Headers', 'X-Request-ID');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000');
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
  res.setHeader('Content-Length', String(Buffer.byteLength(body)));
  res.setHeader('Cache-Control', 'no-store');
  res.end(body);
}

function sendError(res, status, message, code = 'ERROR') {
  return sendJson(res, status, {
    ok: false,
    error: message,
    code,
    requestId: String(res.getHeader('X-Request-ID') || ''),
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

function cleanSdpText(value, max = 200_000) {
  let sdp = String(value ?? '').replace(/\u0000/g, '');
  if (sdp.length > max) {
    throw requestError('通话描述过大。', 413, 'CALL_SDP_SIZE');
  }
  // SDP uses CRLF line endings. Do not call trim() here: Safari/WebKit can
  // reject an SDP whose final line terminator was removed in transit.
  sdp = sdp.replace(/\r\n|\r|\n/g, '\r\n');
  sdp = sdp.replace(/^(?:\r\n)+/, '').replace(/(?:\r\n)+$/, '');
  return sdp ? `${sdp}\r\n` : '';
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

function normalizeIp(value) {
  let ip = String(value || '').trim();
  if (ip.startsWith('[') && ip.includes(']')) ip = ip.slice(1, ip.indexOf(']'));
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(ip)) {
    ip = ip.slice(0, ip.lastIndexOf(':'));
  }
  return isIP(ip) ? ip : '';
}

// WeakMap 不会延长请求对象生命周期，只在同一请求内复用可信代理判断。
const requestNetworkContextCache = new WeakMap();

function requestNetworkContext(req) {
  const cached = requestNetworkContextCache.get(req);
  if (cached) return cached;
  const remoteAddress = normalizeIp(req.socket.remoteAddress);
  const forwarded = String(req.headers['x-forwarded-for'] || '')
    .split(',')
    .map(normalizeIp)
    .filter(Boolean);
  const nearestPublicProxy = isPublicAddress(remoteAddress)
    ? remoteAddress
    : [...forwarded].reverse().find(isPublicAddress) || '';
  const cloudflareIp = normalizeIp(req.headers['cf-connecting-ip']);
  const workerSecretValid = Boolean(
    CLOUDFLARE_ORIGIN_SECRET &&
      timingSafeTextEqual(
        req.headers['x-tuojie-origin-secret'],
        CLOUDFLARE_ORIGIN_SECRET,
      ),
  );
  const trustedCloudflare = Boolean(
    cloudflareIp &&
      (workerSecretValid || isCloudflareAddress(nearestPublicProxy)),
  );
  let ipAddress = '';
  let source = 'direct';
  if (
    trustedCloudflare
  ) {
    ipAddress = cloudflareIp;
    source = workerSecretValid ? 'cloudflare-worker' : 'cloudflare-edge';
  } else if (REQUIRE_CLOUDFLARE) {
    ipAddress = 'unknown';
    source = 'untrusted';
  } else if (remoteAddress && !isPublicAddress(remoteAddress)) {
    // Render 等受控反向代理会把直接客户端追加到链尾；Cloudflare 链已在上面
    // 单独验证并还原真实 IP，避免把 172.64.0.0/13 等边缘节点记成访客。
    ipAddress = forwarded.at(-1) || remoteAddress;
    source = forwarded.length ? 'trusted-platform-proxy' : 'private-proxy';
  } else {
    ipAddress = remoteAddress || forwarded.at(-1) || 'unknown';
  }
  const context = {
    ip: ipAddress,
    source,
    trustedCloudflare,
    workerSecretValid,
    nearestPublicProxy,
    remoteAddress,
    clientAddressIsCloudflare: isCloudflareAddress(normalizeIp(ipAddress)),
  };
  requestNetworkContextCache.set(req, context);
  return context;
}

function requestIp(req) {
  return requestNetworkContext(req).ip;
}

function securityIpBlockable(value) {
  const address = normalizeIp(value);
  return Boolean(
    address &&
      isPublicAddress(address) &&
      !isCloudflareAddress(address),
  );
}

function securityIpNote(value) {
  const address = normalizeIp(value);
  if (!address) return '无效地址，不可封禁';
  if (isCloudflareAddress(address)) {
    return 'Cloudflare 边缘节点，不可封禁';
  }
  if (!isPublicAddress(address)) return '非公网地址，不可封禁';
  return '';
}

const CHINA_REGION_CODES = Object.freeze({
  AH: '安徽', BJ: '北京', CQ: '重庆', FJ: '福建', GD: '广东',
  GS: '甘肃', GX: '广西', GZ: '贵州', HA: '河南', HB: '湖北',
  HE: '河北', HI: '海南', HK: '香港', HL: '黑龙江', HN: '湖南',
  JL: '吉林', JS: '江苏', JX: '江西', LN: '辽宁', MO: '澳门',
  NM: '内蒙古', NX: '宁夏', QH: '青海', SC: '四川', SD: '山东',
  SH: '上海', SN: '陕西', SX: '山西', TJ: '天津', TW: '台湾',
  XJ: '新疆', XZ: '西藏', YN: '云南', ZJ: '浙江',
});

const CHINA_LOCATION_NAMES = Object.freeze({
  anhui: '安徽', beijing: '北京', chongqing: '重庆', fujian: '福建',
  gansu: '甘肃', guangdong: '广东', guangxi: '广西',
  guangxizhuang: '广西', guizhou: '贵州', hainan: '海南',
  hebei: '河北', heilongjiang: '黑龙江', henan: '河南', hubei: '湖北',
  hunan: '湖南', innermongolia: '内蒙古', jiangsu: '江苏',
  jiangxi: '江西', jilin: '吉林', liaoning: '辽宁', neimenggu: '内蒙古',
  ningxia: '宁夏', ningxiahui: '宁夏', qinghai: '青海',
  shaanxi: '陕西', shandong: '山东', shanghai: '上海', shanxi: '山西',
  sichuan: '四川', tianjin: '天津', tibet: '西藏', xinjiang: '新疆',
  xinjianguygur: '新疆', xizang: '西藏', yunnan: '云南', zhejiang: '浙江',
  guangzhou: '广州', shenzhen: '深圳', dongguan: '东莞', foshan: '佛山',
  zhuhai: '珠海', zhongshan: '中山', huizhou: '惠州', jiangmen: '江门',
  shantou: '汕头', zhanjiang: '湛江', maoming: '茂名', zhaoqing: '肇庆',
  meizhou: '梅州', qingyuan: '清远', yangjiang: '阳江', shaoguan: '韶关',
  heyuan: '河源', shanwei: '汕尾', jieyang: '揭阳', chaozhou: '潮州',
  yunfu: '云浮', nanjing: '南京', suzhou: '苏州', hangzhou: '杭州',
  ningbo: '宁波', wenzhou: '温州', fuzhou: '福州', xiamen: '厦门',
  nanchang: '南昌', jinan: '济南', qingdao: '青岛', zhengzhou: '郑州',
  wuhan: '武汉', changsha: '长沙', chengdu: '成都', guiyang: '贵阳',
  kunming: '昆明', xian: '西安', lanzhou: '兰州', xining: '西宁',
  yinchuan: '银川', urumqi: '乌鲁木齐', shenyang: '沈阳',
  dalian: '大连', changchun: '长春', harbin: '哈尔滨',
  shijiazhuang: '石家庄', taiyuan: '太原', hohhot: '呼和浩特',
  nanning: '南宁', haikou: '海口', hefei: '合肥',
});

const CHINA_CITY_REGIONS = Object.freeze({
  guangzhou: '广东', shenzhen: '广东', dongguan: '广东', foshan: '广东',
  zhuhai: '广东', zhongshan: '广东', huizhou: '广东', jiangmen: '广东',
  shantou: '广东', zhanjiang: '广东', maoming: '广东', zhaoqing: '广东',
  meizhou: '广东', qingyuan: '广东', yangjiang: '广东', shaoguan: '广东',
  heyuan: '广东', shanwei: '广东', jieyang: '广东', chaozhou: '广东',
  yunfu: '广东', nanjing: '江苏', suzhou: '江苏', hangzhou: '浙江',
  ningbo: '浙江', wenzhou: '浙江', fuzhou: '福建', xiamen: '福建',
  nanchang: '江西', jinan: '山东', qingdao: '山东', zhengzhou: '河南',
  wuhan: '湖北', changsha: '湖南', chengdu: '四川', guiyang: '贵州',
  kunming: '云南', xian: '陕西', lanzhou: '甘肃', xining: '青海',
  yinchuan: '宁夏', urumqi: '新疆', shenyang: '辽宁', dalian: '辽宁',
  changchun: '吉林', harbin: '黑龙江', shijiazhuang: '河北',
  taiyuan: '山西', hohhot: '内蒙古', nanning: '广西', haikou: '海南',
  hefei: '安徽',
});

function cloudflareHeader(req, name, maxLength = 100) {
  if (!requestNetworkContext(req).trustedCloudflare) return '';
  const raw = Array.isArray(req.headers[name])
    ? req.headers[name][0]
    : req.headers[name];
  let value = String(raw || '').trim();
  if (/%[0-9a-f]{2}/i.test(value)) {
    try {
      value = decodeURIComponent(value);
    } catch {}
  }
  return cleanText(value, maxLength);
}

function chinaLocationKey(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/(?:province|city|autonomousregion)$/g, '')
    .replace(/[^a-z0-9]/g, '');
}

function cloudflareVisitorLocation(req) {
  const countryCode = cloudflareHeader(req, 'cf-ipcountry', 8).toUpperCase();
  let country = countryCode;
  if (/^[A-Z]{2}$/.test(countryCode) && countryCode !== 'XX') {
    try {
      country = new Intl.DisplayNames(['zh-CN'], {
        type: 'region',
      }).of(countryCode) || countryCode;
    } catch {
      country = countryCode;
    }
  }
  const rawRegion = cloudflareHeader(req, 'cf-region', 100);
  const rawRegionCode = cloudflareHeader(req, 'cf-region-code', 16)
    .toUpperCase()
    .replace(/^CN-/, '');
  const rawCity = cloudflareHeader(req, 'cf-ipcity', 100);
  const regionKey = chinaLocationKey(rawRegion);
  const cityKey = chinaLocationKey(rawCity);
  const region = countryCode === 'CN'
    ? CHINA_LOCATION_NAMES[regionKey] ||
      CHINA_REGION_CODES[rawRegionCode] ||
      CHINA_CITY_REGIONS[cityKey] ||
      rawRegion
    : rawRegion;
  const city = countryCode === 'CN'
    ? CHINA_LOCATION_NAMES[cityKey] || rawCity
    : rawCity;
  const parts = [
    country,
    region,
    city,
  ].filter(
    (item, index, list) =>
      item &&
      item !== 'XX' &&
      list.findIndex(
        (candidate) =>
          candidate.toLocaleLowerCase() === item.toLocaleLowerCase(),
      ) === index,
  );
  return {
    location: cleanText(parts.join(' · '), 250),
    timezone: cloudflareHeader(req, 'cf-timezone', 80),
  };
}

function securityFingerprint(parts) {
  return createHash('sha256')
    .update(parts.map((item) => String(item || '')).join('|'))
    .digest('base64url');
}

function claimSecurityAlert(fingerprint) {
  const now = Date.now();
  if ((securityAlertClaims.get(fingerprint) || 0) > now) return false;
  securityAlertClaims.delete(fingerprint);
  makeRoomInExpiringMap(
    securityAlertClaims,
    MAX_SECURITY_ALERT_CLAIMS,
    now,
    (expiresAt) => expiresAt,
  );
  securityAlertClaims.set(fingerprint, now + SECURITY_ALERT_COOLDOWN_MS);
  return true;
}

function cleanSecurityDetails(value = {}) {
  const result = {};
  for (const [key, item] of Object.entries(value || {}).slice(0, 30)) {
    if (item === null || ['string', 'number', 'boolean'].includes(typeof item)) {
      result[cleanText(key, 80)] = typeof item === 'string'
        ? cleanText(item, 500)
        : item;
    }
  }
  return result;
}

function securityKindLabel(kind) {
  if (kind === 'revoked-license-login') return '已禁用卡密仍在尝试登录';
  if (kind === 'visitor-session-ip') return '同一网络高频创建访客';
  if (kind === 'visitor-session-tenant') return '租户访客量异常';
  if (kind === 'message-conversation') return '单会话消息量异常';
  if (kind === 'message-tenant') return '租户消息量异常';
  if (kind === 'suspicious-path') return '敏感路径扫描';
  if (kind === 'suspicious-agent') return '自动化扫描工具';
  if (kind === 'template-origin-mismatch') return '用户端部署来源连续不匹配';
  if (kind === 'user-token-origin-mismatch') return '访客令牌跨站复用（高置信）';
  if (kind.startsWith('rate-limit:')) {
    return `接口频率异常（${kind.slice('rate-limit:'.length)}）`;
  }
  return kind || '异常访问';
}

function securityDetectionLabel(value) {
  if (value === 'confirmed-cross-origin-token-reuse') {
    return '有效访客令牌已确认从未批准的其他来源跨站使用';
  }
  return cleanText(value, 160);
}

function securityEventKeyboard(event) {
  const rows = [];
  // 访客异常不等于租户卡密被盗，禁止把普通来源/频率告警直接变成
  // “封禁租户”按钮。只有服务端多信号确认凭据跨站滥用时才开放。
  if (event.license_id && event.details?.allowLicenseBlock === true) {
    rows.push([{
      text: '⛔ 封禁租户卡密',
      callback_data: `sec:license:${event.id}`,
    }]);
  }
  if (securityIpBlockable(event.ip_address)) {
    rows.push([{
      text: `🛡 封禁此 IP（${SECURITY_IP_BLOCK_HOURS}小时）`,
      callback_data: `sec:ip:${event.id}`,
    }]);
  }
  rows.push([{
    text: '✅ 标记已核实',
    callback_data: `sec:dismiss:${event.id}`,
  }]);
  return { inline_keyboard: rows };
}

async function reportSecurityAnomaly({
  kind,
  req = null,
  tenantId = '',
  licenseId = '',
  conversationId = '',
  count = 1,
  threshold = 1,
  severity = 'warning',
  details = {},
} = {}) {
  const tokenPayload = req ? authenticate(req) : null;
  const resolvedTenantId = isUuid(tenantId)
    ? tenantId
    : isUuid(tokenPayload?.tenantId)
      ? tokenPayload.tenantId
      : '';
  let resolvedLicenseId = isUuid(licenseId)
    ? licenseId
    : isUuid(tokenPayload?.licenseId)
      ? tokenPayload.licenseId
      : '';
  const networkContext = req ? requestNetworkContext(req) : null;
  const ipAddress = req ? cleanText(requestIp(req), 100) : '';
  const cleanedDetails = cleanSecurityDetails({
    ...details,
    ipSource: networkContext?.source || '',
    cloudflareVerified: Boolean(networkContext?.trustedCloudflare),
    clientAddressIsCloudflare: Boolean(
      networkContext?.clientAddressIsCloudflare,
    ),
  });
  const isOriginMismatch = [
    'template-origin-mismatch',
    'user-token-origin-mismatch',
  ].includes(kind);
  const fingerprint = securityFingerprint(
    isOriginMismatch
      ? [
          kind,
          resolvedTenantId,
          isUuid(conversationId) ? conversationId : '',
          cleanedDetails.requestOrigin,
          cleanedDetails.approvedOrigin || cleanedDetails.tokenOrigin,
        ]
      : [
          kind,
          resolvedTenantId,
          isUuid(conversationId) ? conversationId : '',
          ipAddress,
          cleanedDetails.path,
        ],
  );
  if (!claimSecurityAlert(fingerprint)) return null;

  try {
  let tenant = null;
  if (resolvedTenantId) {
    const tenantResult = await pool.query(
      `
        SELECT t.id,t.name,t.note,t.public_code,
               l.id AS license_id,l.key_prefix,l.key_suffix,l.duration_code
        FROM tenants t
        LEFT JOIN LATERAL (
          SELECT id,key_prefix,key_suffix,duration_code,status
          FROM license_keys
          WHERE tenant_id=t.id
            AND ($2::uuid IS NULL OR id=$2)
          ORDER BY
            CASE WHEN id=$2::uuid THEN 0 ELSE 1 END,
            CASE WHEN status='active' THEN 0 ELSE 1 END,
            created_at DESC
          LIMIT 1
        ) l ON TRUE
        WHERE t.id=$1
      `,
      [resolvedTenantId, resolvedLicenseId || null],
    );
    tenant = tenantResult.rows[0] || null;
    if (!resolvedLicenseId && isUuid(tenant?.license_id)) {
      resolvedLicenseId = tenant.license_id;
    }
  }

  const eventResult = await pool.query(
    `
      INSERT INTO security_events (
        id,kind,severity,fingerprint,tenant_id,license_id,conversation_id,
        ip_address,user_agent,details,occurrences
      ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::jsonb,$11)
      ON CONFLICT (fingerprint) WHERE status='open'
      DO UPDATE SET
        severity=EXCLUDED.severity,
        tenant_id=COALESCE(security_events.tenant_id,EXCLUDED.tenant_id),
        license_id=COALESCE(security_events.license_id,EXCLUDED.license_id),
        conversation_id=COALESCE(security_events.conversation_id,EXCLUDED.conversation_id),
        ip_address=COALESCE(NULLIF(EXCLUDED.ip_address,''),security_events.ip_address),
        user_agent=COALESCE(NULLIF(EXCLUDED.user_agent,''),security_events.user_agent),
        details=EXCLUDED.details,
        occurrences=security_events.occurrences + EXCLUDED.occurrences,
        last_seen_at=NOW(),
        updated_at=CASE
          WHEN security_events.telegram_message_id=-1
            THEN security_events.updated_at
          ELSE NOW()
        END
      RETURNING *
    `,
    [
      randomUUID(),
      cleanText(kind, 100),
      ['info', 'warning', 'critical'].includes(severity) ? severity : 'warning',
      fingerprint,
      resolvedTenantId || null,
      resolvedLicenseId || null,
      isUuid(conversationId) ? conversationId : null,
      ipAddress,
      cleanText(req?.headers?.['user-agent'], 500),
      JSON.stringify({
        ...cleanedDetails,
        count: Math.max(1, Math.trunc(Number(count || 1))),
        threshold: Math.max(1, Math.trunc(Number(threshold || 1))),
        windowMinutes: Math.round(ANOMALY_WINDOW_MS / 60_000),
      }),
      Math.max(1, Math.trunc(Number(count || 1))),
    ],
  );
  const event = eventResult.rows[0];
  if (!event || !TELEGRAM_ENABLED) return event || null;
  const settings = await getPlatformSettings().catch(() => null);
  if (!settings?.telegramGroupId) return event;
  // 数据库原子占位，保证多实例或多路径同时命中时，同一未处理事件只发一条。
  const telegramClaim = await pool.query(
    `UPDATE security_events
     SET telegram_message_id=-1,updated_at=NOW()
     WHERE id=$1 AND (
       telegram_message_id IS NULL
       OR (telegram_message_id=-1 AND updated_at < NOW() - INTERVAL '5 minutes')
     )
     RETURNING id`,
    [event.id],
  );
  if (!telegramClaim.rows[0]) return event;
  const eventDetails = event.details || {};
  const ipNote = securityIpNote(event.ip_address);
  const licenseLabel = tenant?.license_id
    ? `${tenant.key_prefix || 'VIP'}-*****-*****-*****-${tenant.key_suffix || '?????'}（${LICENSE_DURATIONS[tenant.duration_code]?.label || tenant.duration_code || '未知期限'}）`
    : '未关联卡密';
  try {
    const sent = await telegramApi('sendMessage', {
      chat_id: settings.telegramGroupId,
      text: [
        `<b>🚨 安全异常告警</b>`,
        '',
        `<b>类型</b>：${escapeTelegramHtml(securityKindLabel(event.kind))}`,
        `<b>次数</b>：<code>${Number(eventDetails.count || count)}</code> / 阈值 <code>${Number(eventDetails.threshold || threshold)}</code>`,
        `<b>租户</b>：${escapeTelegramHtml(tenant?.name || '未关联租户')}`,
        tenant?.public_code
          ? `<b>入口编号</b>：<code>${escapeTelegramHtml(tenant.public_code)}</code>`
          : '',
        tenant?.note
          ? `<b>备注</b>：${escapeTelegramHtml(tenant.note)}`
          : '',
        `<b>卡密</b>：<code>${escapeTelegramHtml(licenseLabel)}</code>`,
        `<b>IP</b>：<code>${escapeTelegramHtml(event.ip_address || 'unknown')}</code>${ipNote ? `（${escapeTelegramHtml(ipNote)}）` : ''}`,
        eventDetails.confidence
          ? `<b>置信度</b>：${eventDetails.confidence === 'high' ? '高（多信号确认）' : escapeTelegramHtml(eventDetails.confidence)}`
          : '',
        eventDetails.detection
          ? `<b>判定</b>：${escapeTelegramHtml(securityDetectionLabel(eventDetails.detection))}`
          : '',
        eventDetails.requestOrigin
          ? `<b>请求来源</b>：<code>${escapeTelegramHtml(eventDetails.requestOrigin)}</code>`
          : '',
        eventDetails.tokenOrigin
          ? `<b>令牌来源</b>：<code>${escapeTelegramHtml(eventDetails.tokenOrigin)}</code>`
          : '',
        eventDetails.approvedOrigin
          ? `<b>租户批准来源</b>：<code>${escapeTelegramHtml(eventDetails.approvedOrigin)}</code>`
          : '',
        eventDetails.path
          ? `<b>路径</b>：<code>${escapeTelegramHtml(eventDetails.path)}</code>`
          : '',
        `<b>时间</b>：${escapeTelegramHtml(formatTelegramDate(event.last_seen_at))}`,
        '',
        event.kind === 'revoked-license-login'
          ? '该普通卡密已被禁用，但仍在尝试登录。登录已拒绝；如需阻止该来源，请点击下方封禁 IP。'
          : '异常请求已按规则拒绝或限流；系统不会自动封禁租户，请由管理员核实。',
      ].filter(Boolean).join('\n'),
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: securityEventKeyboard(event),
    });
    await pool.query(
      `UPDATE security_events
       SET telegram_chat_id=$2,telegram_message_id=$3,updated_at=NOW()
       WHERE id=$1 AND telegram_message_id=-1`,
      [event.id, String(settings.telegramGroupId), sent.message_id],
    );
  } catch (error) {
    await pool.query(
      `UPDATE security_events
       SET telegram_message_id=NULL,updated_at=NOW()
       WHERE id=$1 AND telegram_message_id=-1`,
      [event.id],
    ).catch(() => {});
    securityAlertClaims.delete(fingerprint);
    throw error;
  }
  return event;
  } catch (error) {
    securityAlertClaims.delete(fingerprint);
    throw error;
  }
}

function scheduleSecurityAnomaly(input, onFailure = null) {
  queueMicrotask(() => {
    reportSecurityAnomaly(input).catch((error) => {
      if (typeof onFailure === 'function') onFailure();
      console.error('安全异常记录失败：', error.message);
    });
  });
}

function getOnlineVisitorCounts() {
  if (onlineVisitorCountCache.expiresAt > Date.now()) {
    return onlineVisitorCountCache.counts;
  }
  const uniqueByTenant = new Map();
  for (const client of sseClients) {
    if (
      client.kind !== 'user' ||
      !isUuid(client.tenantId) ||
      !isUuid(client.conversationId)
    ) continue;
    const conversations = uniqueByTenant.get(client.tenantId) || new Set();
    conversations.add(client.conversationId);
    uniqueByTenant.set(client.tenantId, conversations);
  }
  onlineVisitorCountCache.counts = new Map(
    [...uniqueByTenant].map(([tenantId, conversations]) => [
      tenantId,
      conversations.size,
    ]),
  );
  onlineVisitorCountCache.expiresAt = Date.now() + 1000;
  return onlineVisitorCountCache.counts;
}

function observeBehaviorCounter(req, {
  kind,
  key,
  limit,
  tenantId = '',
  licenseId = '',
  conversationId = '',
  severity = 'warning',
  details = {},
  increment = 1,
}) {
  if (!key || !Number.isFinite(limit)) return;
  const networkContext = requestNetworkContext(req);
  if (
    networkContext.clientAddressIsCloudflare &&
    ['visitor-session-ip', 'message-conversation'].includes(kind)
  ) return;
  const onlineVisitors = isUuid(tenantId)
    ? getOnlineVisitorCounts().get(tenantId) || 0
    : 0;
  const adaptiveLimit = Math.max(
    limit,
    kind === 'visitor-session-tenant'
      ? limit + Math.min(limit, Math.ceil(Math.sqrt(onlineVisitors) * 4))
      : kind === 'message-tenant'
        ? limit + Math.min(limit, onlineVisitors * 10)
        : limit,
  );
  const now = Date.now();
  const bucketKey = `${kind}:${key}`;
  let bucket = behaviorBuckets.get(bucketKey);
  if (!bucket || bucket.resetAt <= now) {
    behaviorBuckets.delete(bucketKey);
    makeRoomInExpiringMap(
      behaviorBuckets,
      MAX_BEHAVIOR_BUCKETS,
      now,
      (item) => item.resetAt,
    );
    bucket = {
      count: 0,
      resetAt: now + ANOMALY_WINDOW_MS,
      alerted: false,
      uniqueIps: new Set(),
    };
    behaviorBuckets.set(bucketKey, bucket);
  }
  const observedIp = normalizeIp(networkContext.ip);
  if (
    securityIpBlockable(observedIp) &&
    bucket.uniqueIps.size < 100
  ) bucket.uniqueIps.add(observedIp);
  bucket.count += Math.max(1, Math.trunc(Number(increment || 1)));
  if (bucket.count < adaptiveLimit || bucket.alerted) return;
  bucket.alerted = true;
  scheduleSecurityAnomaly(
    {
      kind,
      req,
      tenantId,
      licenseId,
      conversationId,
      severity,
      count: bucket.count,
      threshold: adaptiveLimit,
      details: {
        ...details,
        baseThreshold: limit,
        adaptiveThreshold: adaptiveLimit,
        onlineVisitors,
        uniqueIpCount: bucket.uniqueIps.size,
      },
    },
    () => {
      if (behaviorBuckets.get(bucketKey) === bucket) bucket.alerted = false;
    },
  );
}

async function refreshBlockedIpCache(force = false) {
  if (!force && blockedIpCacheExpiresAt > Date.now()) return;
  if (blockedIpCachePromise) return blockedIpCachePromise;
  blockedIpCachePromise = pool.query(
    `SELECT ip_address,expires_at FROM blocked_ips
     WHERE expires_at IS NULL OR expires_at > NOW()`,
  ).then((result) => {
    blockedIpCache.clear();
    for (const row of result.rows) {
      blockedIpCache.set(
        row.ip_address,
        row.expires_at ? new Date(row.expires_at).getTime() : Infinity,
      );
    }
    blockedIpCacheExpiresAt = Date.now() + BLOCKLIST_CACHE_MS;
  }).finally(() => {
    blockedIpCachePromise = null;
  });
  return blockedIpCachePromise;
}

function ipIsBlocked(ipAddress) {
  const expiresAt = blockedIpCache.get(ipAddress);
  if (!expiresAt) return false;
  if (expiresAt <= Date.now()) {
    blockedIpCache.delete(ipAddress);
    return false;
  }
  return true;
}

function suspiciousRequest(req, pathname) {
  const path = String(pathname || '').toLowerCase();
  const userAgent = String(req.headers['user-agent'] || '').toLowerCase();
  const pathPatterns = [
    '/.env', '/.git', '/server.mjs', '/package.json', '/package-lock.json',
    '/wp-admin', '/wp-login', '/phpmyadmin', '/vendor/phpunit', '/actuator',
    '/.well-known/security.txt.bak', '.sql', '.bak', '.map',
  ];
  const agentPatterns = ['sqlmap', 'nikto', 'masscan', 'nmap scripting engine', 'acunetix', 'nessus'];
  const matchedPath = pathPatterns.find((pattern) => path.includes(pattern));
  if (matchedPath) return { kind: 'suspicious-path', reason: matchedPath };
  const matchedAgent = agentPatterns.find((pattern) => userAgent.includes(pattern));
  if (matchedAgent) return { kind: 'suspicious-agent', reason: matchedAgent };
  return null;
}

function rateLimit(req, res, name, max, windowMs, identity = '', context = {}) {
  const key = `${name}:${identity || requestIp(req)}`;
  const now = Date.now();
  if (now >= nextRateBucketCleanupAt) {
    for (const [bucketKey, value] of rateBuckets) {
      if (value.resetAt < now) rateBuckets.delete(bucketKey);
    }
    nextRateBucketCleanupAt = now + 10 * 60_000;
  }
  const current = rateBuckets.get(key);

  if (!current || current.resetAt <= now) {
    rateBuckets.delete(key);
    makeRoomInExpiringMap(
      rateBuckets,
      MAX_RATE_BUCKETS,
      now,
      (item) => item.resetAt,
    );
    rateBuckets.set(key, {
      count: 1,
      resetAt: now + windowMs,
      alerted: false,
    });
    return true;
  }

  current.count += 1;
  if (current.count > max) {
    res.setHeader(
      'Retry-After',
      String(Math.ceil((current.resetAt - now) / 1000)),
    );
    if (!current.alerted) {
      current.alerted = true;
      scheduleSecurityAnomaly(
        {
          kind: `rate-limit:${name}`,
          req,
          tenantId: context.tenantId,
          licenseId: context.licenseId,
          conversationId: context.conversationId,
          count: current.count,
          threshold: max,
          severity: name.includes('login') ? 'critical' : 'warning',
          details: {
            path: cleanText(req.url, 300),
            method: cleanText(req.method, 20),
          },
        },
        () => {
          if (rateBuckets.get(key) === current) current.alerted = false;
        },
      );
    }
    sendError(res, 429, '操作过于频繁，请稍后再试。', 'RATE_LIMIT');
    return false;
  }

  return true;
}

async function durableAuthRateLimit(
  req,
  res,
  scope,
  max,
  windowMs,
  identity = '',
) {
  const keyHash = createHmac('sha256', TOKEN_SECRET)
    .update(`auth-rate:${scope}:${identity || requestIp(req)}`)
    .digest('base64url');
  const result = await pool.query(
    `
      INSERT INTO auth_attempt_limits (
        key_hash,scope,attempts,window_started_at,expires_at
      ) VALUES ($1,$2,1,NOW(),NOW()+($3::bigint*INTERVAL '1 millisecond'))
      ON CONFLICT (key_hash) DO UPDATE SET
        attempts=CASE
          WHEN auth_attempt_limits.expires_at<=NOW() THEN 1
          ELSE auth_attempt_limits.attempts+1
        END,
        window_started_at=CASE
          WHEN auth_attempt_limits.expires_at<=NOW() THEN NOW()
          ELSE auth_attempt_limits.window_started_at
        END,
        expires_at=CASE
          WHEN auth_attempt_limits.expires_at<=NOW()
            THEN NOW()+($3::bigint*INTERVAL '1 millisecond')
          ELSE auth_attempt_limits.expires_at
        END
      RETURNING attempts,expires_at
    `,
    [keyHash, cleanText(scope, 80), Math.trunc(windowMs)],
  );
  const row = result.rows[0];
  if (Number(row?.attempts || 0) <= max) return true;
  res.setHeader(
    'Retry-After',
    String(Math.max(1, Math.ceil(
      (new Date(row.expires_at).getTime() - Date.now()) / 1000,
    ))),
  );
  sendError(res, 429, '登录尝试过于频繁，请稍后再试。', 'RATE_LIMIT');
  return false;
}

function mediaContentMatchesMime(data, mime) {
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

  if (mime === 'video/webm') {
    return (
      data.length >= 4 &&
      data.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))
    );
  }

  if (mime === 'video/mp4' || mime === 'video/quicktime' || mime === 'audio/mp4') {
    return data.length >= 12 && data.subarray(4, 8).toString('ascii') === 'ftyp';
  }

  if (mime === 'audio/webm') {
    return (
      data.length >= 4 &&
      data.subarray(0, 4).equals(Buffer.from([0x1a, 0x45, 0xdf, 0xa3]))
    );
  }

  if (mime === 'audio/ogg') {
    return data.length >= 4 && data.subarray(0, 4).toString('ascii') === 'OggS';
  }

  if (mime === 'audio/mpeg') {
    return (
      data.length >= 3 && data.subarray(0, 3).toString('ascii') === 'ID3'
    ) || (data.length >= 2 && data[0] === 0xff && (data[1] & 0xe0) === 0xe0);
  }

  if (mime === 'audio/wav') {
    return (
      data.length >= 12 &&
      data.subarray(0, 4).toString('ascii') === 'RIFF' &&
      data.subarray(8, 12).toString('ascii') === 'WAVE'
    );
  }

  return false;
}

async function putObject(objectKey, data, mime) {
  if (!R2_ENABLED) return false;
  await r2.send(
    new PutObjectCommand({
      Bucket: R2_BUCKET,
      Key: objectKey,
      Body: data,
      ContentType: mime,
      CacheControl: 'private, no-store',
    }),
  );
  return true;
}

async function readObject(objectKey) {
  if (!R2_ENABLED || !objectKey) return null;
  const result = await r2.send(
    new GetObjectCommand({ Bucket: R2_BUCKET, Key: objectKey }),
  );
  if (!result.Body) return null;
  return Buffer.from(await result.Body.transformToByteArray());
}

async function rollbackFreshObject(objectKey) {
  if (!R2_ENABLED || !objectKey) return;
  try {
    await r2.send(
      new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: objectKey }),
    );
  } catch {
    await queueObjectDeletes([objectKey]).catch(() => {});
  }
}

async function queueObjectDeletes(objectKeys, client = pool) {
  const unique = [...new Set(objectKeys.filter(Boolean))];
  if (!unique.length) return;
  await client.query(
    `
      INSERT INTO r2_delete_queue (object_key)
      SELECT object_key
      FROM unnest($1::text[]) AS queued(object_key)
      ON CONFLICT (object_key) DO NOTHING
    `,
    [unique],
  );
}

async function processObjectDeleteQueue(limit = 50) {
  if (!R2_ENABLED) return;
  const result = await pool.query(
    `
      SELECT id, object_key, attempts
      FROM r2_delete_queue
      WHERE next_attempt_at <= NOW()
      ORDER BY id
      LIMIT $1
    `,
    [limit],
  );
  const deletedIds = [];
  for (const row of result.rows) {
    try {
      await r2.send(
        new DeleteObjectCommand({
          Bucket: R2_BUCKET,
          Key: row.object_key,
        }),
      );
      deletedIds.push(row.id);
    } catch (error) {
      const attempts = Number(row.attempts || 0) + 1;
      const delayMinutes = Math.min(360, 2 ** Math.min(attempts, 8));
      await pool.query(
        `
          UPDATE r2_delete_queue
          SET attempts = $2,
              last_error = $3,
              next_attempt_at = NOW() + ($4::text || ' minutes')::interval
          WHERE id = $1
        `,
        [row.id, attempts, cleanText(error.message, 500), delayMinutes],
      );
    }
  }
  if (deletedIds.length) {
    await pool.query(
      `DELETE FROM r2_delete_queue WHERE id = ANY($1::bigint[])`,
      [deletedIds],
    );
  }
}

function mediaObjectKey(tenantId, conversationId, attachmentId, mime) {
  const extension = {
    'image/jpeg': 'jpg',
    'image/png': 'png',
    'image/webp': 'webp',
    'image/gif': 'gif',
    'video/mp4': 'mp4',
    'video/webm': 'webm',
    'video/quicktime': 'mov',
    'audio/webm': 'webm',
    'audio/ogg': 'ogg',
    'audio/mp4': 'm4a',
    'audio/mpeg': 'mp3',
    'audio/wav': 'wav',
  }[mime] || 'bin';
  return `chat/${tenantId}/${conversationId}/${attachmentId}.${extension}`;
}

async function saveAsset({
  tenantId = null,
  kind,
  filename,
  mime,
  data,
}) {
  const id = randomUUID();
  const objectKey = `assets/${kind}/${tenantId || 'platform'}/${id}.webp`;
  let storedInR2 = false;
  try {
    storedInR2 = await putObject(objectKey, data, mime);
    let result = await pool.query(
      `
        INSERT INTO assets (
          id, tenant_id, kind, filename, mime, size, storage, object_key, data
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
        RETURNING *
      `,
      [
        id,
        tenantId,
        kind,
        filename,
        mime,
        data.length,
        storedInR2 ? 'r2' : 'database',
        storedInR2 ? objectKey : null,
        storedInR2 ? null : data,
      ],
    );
    return result.rows[0];
  } catch (error) {
    if (storedInR2) await rollbackFreshObject(objectKey);
    throw error;
  }
}

async function deleteAsset(assetId, tenantId = undefined) {
  if (!isUuid(assetId)) return;
  if (
    tenantId !== undefined &&
    tenantId !== null &&
    !isUuid(tenantId)
  ) return;
  const params = [assetId];
  const tenantClause =
    tenantId === undefined
      ? ''
      : tenantId === null
        ? 'AND tenant_id IS NULL'
        : 'AND tenant_id = $2';
  if (tenantId && isUuid(tenantId)) params.push(tenantId);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `
        DELETE FROM assets
        WHERE id = $1 ${tenantClause}
        RETURNING object_key
      `,
      params,
    );
    const objectKey = result.rows[0]?.object_key;
    if (objectKey) await queueObjectDeletes([objectKey], client);
    await client.query('COMMIT');
    if (objectKey) processObjectDeleteQueue().catch(() => {});
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function withImageTransformSlot(task) {
  if (activeImageTransforms >= MAX_CONCURRENT_UPLOADS) {
    throw requestError('当前图片处理较多，请稍后重试。', 503, 'IMAGE_BUSY');
  }
  activeImageTransforms += 1;
  try {
    return await task();
  } finally {
    activeImageTransforms -= 1;
  }
}

async function prepareImageUpload(
  req,
  { maxBytes, width, height, fit = 'cover' },
) {
  const mime = String(req.headers['content-type'] || '')
    .split(';')[0]
    .trim()
    .toLowerCase();
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(mime)) {
    throw requestError(
      '仅支持 JPG、PNG、WebP 图片。',
      415,
      'IMAGE_TYPE',
    );
  }
  return withImageTransformSlot(async () => {
    const input = await readBody(req, maxBytes);
    if (!input.length || !mediaContentMatchesMime(input, mime)) {
      throw requestError('图片内容无效。', 415, 'IMAGE_SIGNATURE');
    }
    try {
      return await sharp(input, {
        limitInputPixels: 24_000_000,
        failOn: 'warning',
      })
        .rotate()
        .resize(width, height, {
          fit: fit === 'inside' ? 'inside' : 'cover',
          ...(fit === 'inside' ? {} : { position: 'attention' }),
          withoutEnlargement: fit === 'inside',
        })
        .webp({ quality: 84, effort: 4 })
        .toBuffer();
    } catch {
      throw requestError('图片无法解析或尺寸异常。', 415, 'IMAGE_INVALID');
    }
  });
}


async function prepareQrLogoUpload(req) {
  const mime = String(req.headers['content-type'] || '')
    .split(';')[0]
    .trim()
    .toLowerCase();
  if (!['image/jpeg', 'image/png', 'image/webp'].includes(mime)) {
    throw requestError(
      '二维码图片仅支持 JPG、PNG、WebP。',
      415,
      'QR_LOGO_TYPE',
    );
  }
  return withImageTransformSlot(async () => {
    const input = await readBody(req, MAX_QR_LOGO_BYTES);
    if (!input.length || !mediaContentMatchesMime(input, mime)) {
      throw requestError('二维码图片内容无效。', 415, 'QR_LOGO_SIGNATURE');
    }
    try {
      return await sharp(input, {
        limitInputPixels: 24_000_000,
        failOn: 'warning',
      })
        .rotate()
        .resize(512, 512, {
          fit: 'contain',
          background: { r: 255, g: 255, b: 255, alpha: 0 },
        })
        .webp({ quality: 88, effort: 4, alphaQuality: 100 })
        .toBuffer();
    } catch {
      throw requestError('二维码图片无法解析或尺寸异常。', 415, 'QR_LOGO_INVALID');
    }
  });
}

function escapeQrSvgText(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function qrCharacterUnits(character) {
  return /^[\u0000-\u00ff]$/.test(character) ? 0.58 : 1;
}

function wrapQrText(value, maxUnits, maxLines) {
  const normalized = String(value || '')
    .replace(/\r\n?/g, '\n')
    .trim();
  if (!normalized) return [];
  const lines = [];
  for (const paragraph of normalized.split('\n')) {
    if (!paragraph) {
      lines.push('');
      if (lines.length >= maxLines) break;
      continue;
    }
    let current = '';
    let units = 0;
    for (const character of paragraph) {
      const nextUnits = qrCharacterUnits(character);
      if (current && units + nextUnits > maxUnits) {
        lines.push(current);
        if (lines.length >= maxLines) return lines;
        current = character;
        units = nextUnits;
      } else {
        current += character;
        units += nextUnits;
      }
    }
    if (current || !paragraph) lines.push(current);
    if (lines.length >= maxLines) break;
  }
  return lines.slice(0, maxLines);
}

async function readTenantQrLogo(tenantId, assetId) {
  if (!isUuid(assetId)) return null;
  const result = await pool.query(
    `
      SELECT *
      FROM assets
      WHERE id=$1 AND tenant_id=$2 AND kind='qr_logo'
    `,
    [assetId, tenantId],
  );
  return readStoredRow(result.rows[0]);
}

async function buildTenantQrImage(entryUrl, {
  topText = '',
  bottomText = DEFAULT_QR_BOTTOM_TEXT,
  logoData = null,
} = {}) {
  const canvasWidth = 840;
  const qrSize = 720;
  const topFontSize = 46;
  const topLineHeight = 62;
  const bottomFontSize = 36;
  const bottomLineHeight = 50;
  const outerPadding = 34;
  const topLines = wrapQrText(topText, 18, 3);
  const bottomLines = wrapQrText(bottomText, 22, 7);
  const topHeight = topLines.length * topLineHeight;
  const bottomHeight = bottomLines.length * bottomLineHeight;
  const topGap = topLines.length ? 18 : 0;
  const bottomGap = bottomLines.length ? 24 : 0;
  const qrTop = outerPadding + topHeight + topGap;
  const canvasHeight =
    qrTop + qrSize + bottomGap + bottomHeight + outerPadding;

  let qrBuffer = await QRCode.toBuffer(entryUrl, {
    type: 'png',
    width: qrSize,
    margin: 3,
    errorCorrectionLevel: logoData ? 'H' : 'M',
    color: { dark: '#121827', light: '#ffffff' },
  });

  if (logoData) {
    const logoBoxSize = 164;
    const logoSize = 128;
    const logo = await sharp(logoData)
      .resize(logoSize, logoSize, {
        fit: 'contain',
        background: { r: 255, g: 255, b: 255, alpha: 0 },
      })
      .png()
      .toBuffer();
    const badgeSvg = Buffer.from(
      `<svg xmlns="http://www.w3.org/2000/svg" width="${logoBoxSize}" height="${logoBoxSize}"><rect x="0" y="0" width="${logoBoxSize}" height="${logoBoxSize}" rx="25" fill="#ffffff"/></svg>`,
      'utf8',
    );
    const badge = await sharp(badgeSvg)
      .composite([
        {
          input: logo,
          left: Math.round((logoBoxSize - logoSize) / 2),
          top: Math.round((logoBoxSize - logoSize) / 2),
        },
      ])
      .png()
      .toBuffer();
    qrBuffer = await sharp(qrBuffer)
      .composite([
        {
          input: badge,
          left: Math.round((qrSize - logoBoxSize) / 2),
          top: Math.round((qrSize - logoBoxSize) / 2),
        },
      ])
      .png()
      .toBuffer();
  }

  const topTextSvg = topLines
    .map((line, index) => {
      const y = outerPadding + topFontSize + index * topLineHeight;
      return `<text x="${canvasWidth / 2}" y="${y}" text-anchor="middle" font-family="Noto Sans CJK SC, Source Han Sans SC, Microsoft YaHei, PingFang SC, sans-serif" font-size="${topFontSize}" font-weight="700" fill="#39425d">${escapeQrSvgText(line)}</text>`;
    })
    .join('');
  const bottomStartY = qrTop + qrSize + bottomGap + bottomFontSize;
  const bottomTextSvg = bottomLines
    .map((line, index) => {
      const y = bottomStartY + index * bottomLineHeight;
      return `<text x="${canvasWidth / 2}" y="${y}" text-anchor="middle" font-family="Noto Sans CJK SC, Source Han Sans SC, Microsoft YaHei, PingFang SC, sans-serif" font-size="${bottomFontSize}" font-weight="500" fill="#4e5872">${escapeQrSvgText(line)}</text>`;
    })
    .join('');
  const textLayer = Buffer.from(
    `<svg xmlns="http://www.w3.org/2000/svg" width="${canvasWidth}" height="${canvasHeight}">${topTextSvg}${bottomTextSvg}</svg>`,
    'utf8',
  );

  return sharp({
    create: {
      width: canvasWidth,
      height: canvasHeight,
      channels: 4,
      background: { r: 255, g: 255, b: 255, alpha: 1 },
    },
  })
    .composite([
      {
        input: qrBuffer,
        left: Math.round((canvasWidth - qrSize) / 2),
        top: qrTop,
      },
      { input: textLayer, left: 0, top: 0 },
    ])
    .png({ compressionLevel: 9 })
    .toBuffer();
}

async function readStoredRow(row) {
  if (!row) return null;
  let data;
  if (row.storage === 'r2') {
    data = await readObject(row.object_key);
  } else {
    if (!Buffer.isBuffer(row.data)) return null;
    minuteCounters.databaseMediaReads += 1;
    minuteCounters.databaseMediaBytes += row.data.length;
    data = row.data;
  }
  if (!Buffer.isBuffer(data)) return null;
  if (ALLOWED_AUDIO_TYPES.has(row.mime)) {
    try {
      return decryptAudioBuffer(data);
    } catch (error) {
      console.error('语音媒体解密失败：', error.message);
      return null;
    }
  }
  return data;
}

function publicMessage(row) {
  return {
    id: row.id,
    role: row.role,
    source: row.source || 'manual',
    type: row.type,
    text: row.text || '',
    attachmentId: row.attachment_id || row.asset_id || null,
    assetId: row.asset_id || null,
    albumId: row.album_id || null,
    albumPosition: Number(row.album_position || 0),
    createdAt: new Date(row.created_at).toISOString(),
    read: Boolean(row.read_at),
    readAt: row.read_at ? new Date(row.read_at).toISOString() : null,
    recalled: Boolean(row.recalled_at),
    recalledAt: row.recalled_at
      ? new Date(row.recalled_at).toISOString()
      : null,
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

function conversationHasLiveVisitor(conversationId, tenantId) {
  return [...sseClients].some(
    (client) =>
      client.kind === 'user' &&
      client.conversationId === conversationId &&
      client.tenantId === tenantId,
  );
}

function staticRealtimeConfig() {
  const iceServers = [];
  if (WEBRTC_STUN_URLS.length) iceServers.push({ urls: WEBRTC_STUN_URLS });
  if (
    WEBRTC_TURN_URLS.length &&
    WEBRTC_TURN_USERNAME &&
    WEBRTC_TURN_CREDENTIAL
  ) {
    iceServers.push({
      urls: WEBRTC_TURN_URLS,
      username: WEBRTC_TURN_USERNAME,
      credential: WEBRTC_TURN_CREDENTIAL,
    });
  }
  return {
    iceServers,
    turnConfigured: Boolean(WEBRTC_TURN_URLS.length && WEBRTC_TURN_USERNAME && WEBRTC_TURN_CREDENTIAL),
    turnProvider: WEBRTC_TURN_URLS.length && WEBRTC_TURN_USERNAME && WEBRTC_TURN_CREDENTIAL
      ? 'static'
      : 'none',
    turnExpiresAt: '',
    pushEnabled: WEB_PUSH_ENABLED,
    vapidPublicKey: WEB_PUSH_ENABLED ? WEB_PUSH_VAPID_PUBLIC_KEY : '',
    callRingTimeoutSeconds: CALL_RING_TIMEOUT_SECONDS,
  };
}

function cleanCloudflareIceServers(value) {
  if (!Array.isArray(value)) return [];
  const result = [];
  for (const item of value.slice(0, 8)) {
    const rawUrls = Array.isArray(item?.urls) ? item.urls : [item?.urls];
    const urls = rawUrls
      .map((url) => String(url || '').trim())
      .filter((url) => /^(?:stun|stuns|turn|turns):/i.test(url))
      .filter((url) => !/:53(?:\?|$)/i.test(url))
      .slice(0, 12);
    if (!urls.length) continue;
    const server = { urls };
    if (urls.some((url) => /^turns?:/i.test(url))) {
      const username = String(item?.username || '').trim();
      const credential = String(item?.credential || '').trim();
      if (!username || !credential || username.length > 512 || credential.length > 512) {
        continue;
      }
      server.username = username;
      server.credential = credential;
    }
    result.push(server);
  }
  return result;
}

function pruneCloudflareTurnCredentialCache() {
  const now = Date.now();
  for (const [key, entry] of cloudflareTurnCredentialCache) {
    if (entry.expiresAt <= now) cloudflareTurnCredentialCache.delete(key);
  }
  while (cloudflareTurnCredentialCache.size > 2_000) {
    const oldestKey = cloudflareTurnCredentialCache.keys().next().value;
    if (!oldestKey) break;
    cloudflareTurnCredentialCache.delete(oldestKey);
  }
}

async function requestCloudflareTurnCredentials(scopeKey) {
  const now = Date.now();
  const cached = cloudflareTurnCredentialCache.get(scopeKey);
  if (cached && cached.refreshAt > now) return cached;
  if (cloudflareTurnCredentialRequests.has(scopeKey)) {
    return cloudflareTurnCredentialRequests.get(scopeKey);
  }

  const request = (async () => {
    const endpoint = `https://rtc.live.cloudflare.com/v1/turn/keys/${encodeURIComponent(CLOUDFLARE_TURN_KEY_ID)}/credentials/generate-ice-servers`;
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${CLOUDFLARE_TURN_KEY_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ ttl: CLOUDFLARE_TURN_TTL_SECONDS }),
      signal: AbortSignal.timeout(8_000),
    });
    const responseText = await response.text();
    if (!response.ok || responseText.length > 64 * 1024) {
      throw new Error(`Cloudflare TURN 凭证接口返回 ${response.status}`);
    }
    const payload = JSON.parse(responseText);
    const iceServers = cleanCloudflareIceServers(payload?.iceServers);
    if (!iceServers.some((server) =>
      server.urls.some((url) => /^turns?:/i.test(url)))) {
      throw new Error('Cloudflare TURN 凭证响应缺少可用中继地址');
    }
    const issuedAt = Date.now();
    const expiresAt = issuedAt + CLOUDFLARE_TURN_TTL_SECONDS * 1_000;
    const refreshMargin = Math.min(
      10 * 60_000,
      Math.max(5 * 60_000, CLOUDFLARE_TURN_TTL_SECONDS * 100),
    );
    const entry = {
      iceServers,
      expiresAt,
      refreshAt: expiresAt - refreshMargin,
    };
    cloudflareTurnCredentialCache.delete(scopeKey);
    cloudflareTurnCredentialCache.set(scopeKey, entry);
    pruneCloudflareTurnCredentialCache();
    return entry;
  })();

  cloudflareTurnCredentialRequests.set(scopeKey, request);
  try {
    return await request;
  } finally {
    cloudflareTurnCredentialRequests.delete(scopeKey);
  }
}

async function realtimeConfig(scopeKey = 'shared') {
  const fallback = staticRealtimeConfig();
  if (!CLOUDFLARE_TURN_ENABLED) return fallback;
  if (cloudflareTurnFailureUntil > Date.now()) {
    return {
      ...fallback,
      turnProvider: fallback.turnConfigured ? 'static-fallback' : 'stun-fallback',
      turnExpiresAt: new Date(cloudflareTurnFailureUntil).toISOString(),
    };
  }
  try {
    const cloudflare = await requestCloudflareTurnCredentials(scopeKey);
    cloudflareTurnFailureUntil = 0;
    return {
      ...fallback,
      iceServers: cloudflare.iceServers,
      turnConfigured: true,
      turnProvider: 'cloudflare',
      turnExpiresAt: new Date(cloudflare.expiresAt).toISOString(),
    };
  } catch (error) {
    const now = Date.now();
    cloudflareTurnFailureUntil = now + 30_000;
    if (now - lastCloudflareTurnErrorAt > 60_000) {
      lastCloudflareTurnErrorAt = now;
      console.error('Cloudflare TURN 临时凭证获取失败，已使用备用 ICE 配置：', error.message);
    }
    return {
      ...fallback,
      turnProvider: fallback.turnConfigured ? 'static-fallback' : 'stun-fallback',
      turnExpiresAt: new Date(cloudflareTurnFailureUntil).toISOString(),
    };
  }
}

function parseCallSignal(body = {}) {
  const action = cleanText(body.action, 20);
  const callId = cleanText(body.callId, 80);
  if (![
    'offer','claim','answer','ice','connected',
    'hangup','reject','busy','timeout','failed',
  ].includes(action)) {
    throw requestError('通话信令类型无效。', 400, 'CALL_ACTION');
  }
  if (!isUuid(callId)) {
    throw requestError('通话编号无效。', 400, 'CALL_ID');
  }
  const mode = cleanText(body.mode, 10) === 'video' ? 'video' : 'audio';
  const signal = {
    action,
    callId,
    mode,
    deviceId: cleanText(body.deviceId, 120),
    reason: cleanText(body.reason, 120),
  };
  if (action === 'offer' || action === 'answer') {
    const sdp = body.sdp;
    if (!sdp || typeof sdp !== 'object' || sdp.type !== action) {
      throw requestError('通话描述无效。', 400, 'CALL_SDP');
    }
    const value = cleanSdpText(sdp.sdp, 200_000);
    if (!value || !/^v=0\r\n/.test(value)) {
      throw requestError('通话描述为空或格式无效。', 400, 'CALL_SDP');
    }
    signal.sdp = { type: sdp.type, sdp: value };
  }
  if (action === 'ice') {
    const candidate = body.candidate;
    if (!candidate || typeof candidate !== 'object') {
      throw requestError('网络候选信息无效。', 400, 'CALL_ICE');
    }
    signal.candidate = {
      candidate: cleanText(candidate.candidate, 4096),
      sdpMid: cleanText(candidate.sdpMid, 100) || null,
      sdpMLineIndex: Number.isInteger(candidate.sdpMLineIndex)
        ? candidate.sdpMLineIndex
        : null,
      usernameFragment: cleanText(candidate.usernameFragment, 300) || null,
    };
  }
  return signal;
}

const ACTIVE_CALL_STATUSES = new Set(['ringing', 'answered', 'connected']);

function callActorKey(kind, deviceId) {
  const normalizedKind = kind === 'admin' ? 'admin' : 'user';
  const normalizedDevice = cleanText(deviceId, 120) || 'legacy';
  return `${normalizedKind}:${normalizedDevice}`;
}

function publicCallSession(row) {
  if (!row) return null;
  return {
    id: row.id,
    conversationId: row.conversation_id,
    mode: row.mode === 'video' ? 'video' : 'audio',
    callerKind: row.caller_kind === 'user' ? 'user' : 'admin',
    callerName: cleanText(row.caller_name, 80) ||
      (row.caller_kind === 'user' ? '访客' : '客服'),
    status: cleanText(row.status, 20) || 'ringing',
    createdAt: new Date(row.created_at).toISOString(),
    answeredAt: row.answered_at
      ? new Date(row.answered_at).toISOString()
      : null,
    connectedAt: row.connected_at
      ? new Date(row.connected_at).toISOString()
      : null,
    endedAt: row.ended_at ? new Date(row.ended_at).toISOString() : null,
    durationSeconds: Math.max(0, Number(row.duration_seconds || 0)),
    endReason: cleanText(row.end_reason, 120),
  };
}

function publishCallLogUpdate(row) {
  if (!row || !isUuid(row.tenant_id) || !isUuid(row.conversation_id)) return;
  const payload = {
    type: 'call-log-updated',
    conversationId: row.conversation_id,
    call: publicCallSession(row),
    at: nowIso(),
  };
  publishEvent(payload, {
    tenantId: row.tenant_id,
    conversationId: row.conversation_id,
    targetKind: 'user',
  });
  publishEvent(payload, {
    tenantId: row.tenant_id,
    conversationId: row.conversation_id,
    targetKind: 'tenant_admin',
  });
}

function publishCallControl(row, {
  action,
  handledByDeviceId = '',
  handledByKind = '',
} = {}) {
  if (!row || !action) return;
  const payload = {
    type: 'call-control',
    action,
    callId: row.id,
    conversationId: row.conversation_id,
    status: row.status,
    endReason: cleanText(row.end_reason, 120),
    handledByDeviceId,
    handledByKind,
    at: nowIso(),
  };
  publishEvent(payload, {
    tenantId: row.tenant_id,
    conversationId: row.conversation_id,
    targetKind: 'user',
  });
  publishEvent(payload, {
    tenantId: row.tenant_id,
    conversationId: row.conversation_id,
    targetKind: 'tenant_admin',
  });
}

async function finalizeExpiredCallSessions(
  tenantId,
  conversationId = null,
  client = pool,
) {
  const ringingResult = await client.query(
    `
      UPDATE call_sessions cs
      SET status='missed',
          ended_at=COALESCE(cs.ended_at,cs.expires_at),
          end_reason='missed',
          updated_at=NOW(),
          expires_at=NOW() + (COALESCE(tc.retention_hours,24)::text || ' hours')::interval
      FROM tenant_config tc
      WHERE cs.tenant_id=$1
        AND cs.tenant_id=tc.tenant_id
        AND ($2::uuid IS NULL OR cs.conversation_id=$2)
        AND cs.status='ringing'
        AND cs.expires_at <= NOW()
      RETURNING cs.*
    `,
    [tenantId, isUuid(conversationId) ? conversationId : null],
  );
  const activeResult = await client.query(
    `
      UPDATE call_sessions cs
      SET status='failed',
          ended_at=COALESCE(cs.ended_at,cs.expires_at),
          end_reason='network_timeout',
          duration_seconds=0,
          updated_at=NOW(),
          expires_at=NOW() + (COALESCE(tc.retention_hours,24)::text || ' hours')::interval
      FROM tenant_config tc
      WHERE cs.tenant_id=$1
        AND cs.tenant_id=tc.tenant_id
        AND ($2::uuid IS NULL OR cs.conversation_id=$2)
        AND cs.status=ANY($3::text[])
        AND cs.expires_at <= NOW()
      RETURNING cs.*
    `,
    [
      tenantId,
      isUuid(conversationId) ? conversationId : null,
      ['answered', 'connected'],
    ],
  );
  return [...ringingResult.rows, ...activeResult.rows];
}

async function getCallHistory(
  tenantId,
  conversationId,
  client = pool,
  limit = 50,
) {
  if (!isUuid(tenantId) || !isUuid(conversationId)) return [];
  await finalizeExpiredCallSessions(tenantId, conversationId, client);
  const result = await client.query(
    `
      SELECT *
      FROM call_sessions
      WHERE tenant_id=$1 AND conversation_id=$2
      ORDER BY created_at DESC,id DESC
      LIMIT $3
    `,
    [tenantId, conversationId, Math.max(1, Math.min(100, Number(limit) || 50))],
  );
  return result.rows.reverse().map(publicCallSession);
}

function pushSubscriptionCacheKey(tenantId, conversationId) {
  return `${tenantId}:${conversationId}`;
}

function webPushHostnameAllowed(value) {
  const hostname = String(value || '').trim().toLowerCase();
  if (!hostname || isIP(hostname)) return false;
  return [...WEB_PUSH_ALLOWED_HOSTS].some((rule) =>
    rule.startsWith('.')
      ? hostname.length > rule.length && hostname.endsWith(rule)
      : hostname === rule,
  );
}

function normalizeWebPushEndpoint(value) {
  const raw = cleanText(value, 2048);
  let endpoint;
  try {
    endpoint = new URL(raw);
  } catch {
    return '';
  }
  if (
    endpoint.protocol !== 'https:' ||
    endpoint.username ||
    endpoint.password ||
    endpoint.port && endpoint.port !== '443' ||
    endpoint.hash ||
    !webPushHostnameAllowed(endpoint.hostname)
  ) return '';
  return endpoint.toString();
}

function validWebPushKey(value, min, max) {
  const key = cleanText(value, max);
  return key.length >= min &&
    key.length <= max &&
    /^[A-Za-z0-9_-]+$/.test(key)
    ? key
    : '';
}

function invalidatePushSubscriptionCache(tenantId, conversationId) {
  pushSubscriptionCache.delete(
    pushSubscriptionCacheKey(tenantId, conversationId),
  );
}

async function getPushSubscriptions(tenantId, conversationId) {
  const key = pushSubscriptionCacheKey(tenantId, conversationId);
  const cached = cacheGet(pushSubscriptionCache, key);
  if (cached) return cached;
  const result = await pool.query(
    `SELECT endpoint,p256dh,auth
     FROM push_subscriptions
     WHERE tenant_id=$1 AND conversation_id=$2
     ORDER BY updated_at DESC,endpoint`,
    [tenantId, conversationId],
  );
  const subscriptions = result.rows
    .filter((subscription) =>
      normalizeWebPushEndpoint(subscription.endpoint) &&
      validWebPushKey(subscription.p256dh, 80, 120) &&
      validWebPushKey(subscription.auth, 16, 64),
    )
    .slice(0, MAX_PUSH_SUBSCRIPTIONS_PER_CONVERSATION);
  if (subscriptions.length !== result.rows.length) {
    const invalidEndpoints = result.rows
      .filter((subscription) => !subscriptions.includes(subscription))
      .map((subscription) => subscription.endpoint);
    await pool.query(
      `DELETE FROM push_subscriptions
       WHERE tenant_id=$1 AND conversation_id=$2
         AND endpoint=ANY($3::text[])`,
      [tenantId, conversationId, invalidEndpoints],
    );
  }
  makeRoomInExpiringMap(
    pushSubscriptionCache,
    MAX_PUSH_SUBSCRIPTION_CACHE,
    Date.now(),
    (item) => item.expiresAt,
  );
  return cacheSet(
    pushSubscriptionCache,
    key,
    subscriptions,
    PUSH_SUBSCRIPTION_CACHE_MS,
  );
}

async function sendConversationCallNotification(
  tenantId,
  conversationId,
  { callId, mode = 'audio' } = {},
) {
  if (!WEB_PUSH_ENABLED || !isUuid(callId)) return;
  const [subscriptions, config, tenant] = await Promise.all([
    getPushSubscriptions(tenantId, conversationId),
    getConfig(tenantId),
    getTenantById(tenantId),
  ]);
  if (!subscriptions.length) return;
  const serviceName = cleanText(config?.settings?.siteName, 80) || '客服';
  const callLabel = mode === 'video' ? '视频' : '语音';
  const payload = JSON.stringify({
    type: 'incoming-call',
    title: `${serviceName}邀请你进行${callLabel}通话`,
    body: '点击打开客服并接听。摄像头和麦克风只会在你接听后请求授权。',
    tag: `incoming-call-${callId}`,
    icon: './icons/icon-192.png',
    badge: './icons/icon-192.png',
    data: {
      callId,
      mode,
      url: `./?${new URLSearchParams({
        tenant: tenant?.public_code || '',
        call: callId,
      })}`,
    },
  });
  const staleEndpoints = [];
  for (let index = 0; index < subscriptions.length; index += 20) {
    const batch = subscriptions.slice(index, index + 20);
    const results = await Promise.allSettled(
      batch.map((subscription) =>
        webpush.sendNotification(
          {
            endpoint: subscription.endpoint,
            keys: { p256dh: subscription.p256dh, auth: subscription.auth },
          },
          payload,
          { TTL: 90, urgency: 'high' },
        ),
      ),
    );
    results.forEach((result, resultIndex) => {
      const statusCode = Number(result.reason?.statusCode || 0);
      if (result.status === 'rejected' && [404, 410].includes(statusCode)) {
        staleEndpoints.push(batch[resultIndex].endpoint);
      }
    });
  }
  if (staleEndpoints.length) {
    await pool.query(
      `DELETE FROM push_subscriptions WHERE endpoint = ANY($1::text[])`,
      [staleEndpoints],
    );
    invalidatePushSubscriptionCache(tenantId, conversationId);
  }
}

async function callIdentitySnapshot(client, tenantId, conversationId, callerKind) {
  const result = await client.query(
    `
      SELECT
        c.visitor_name,
        COALESCE(
          NULLIF(tc.settings->>'siteName',''),
          NULLIF(t.name,''),
          '客服'
        ) AS service_name,
        COALESCE(tc.retention_hours,24)::int AS retention_hours
      FROM conversations c
      JOIN tenants t ON t.id=c.tenant_id
      LEFT JOIN tenant_config tc ON tc.tenant_id=c.tenant_id
      WHERE c.id=$1 AND c.tenant_id=$2
    `,
    [conversationId, tenantId],
  );
  const row = result.rows[0];
  if (!row) throw requestError('会话不存在。', 404, 'NOT_FOUND');
  return {
    callerName: callerKind === 'user'
      ? cleanText(row.visitor_name, 80) || '访客'
      : cleanText(row.service_name, 80) || '客服',
    retentionHours: Math.max(1, Math.min(360, Number(row.retention_hours) || 24)),
  };
}

async function savePendingCallOffer(
  tenantId,
  conversationId,
  signal,
  callerKind,
) {
  const normalizedCallerKind = callerKind === 'user' ? 'user' : 'admin';
  const callerDeviceId = cleanText(signal.deviceId, 120) || 'legacy';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext($1))`,
      [`call:${tenantId}`],
    );
    await finalizeExpiredCallSessions(tenantId, null, client);
    const existingResult = await client.query(
      `SELECT * FROM call_sessions WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3 FOR UPDATE`,
      [signal.callId, tenantId, conversationId],
    );
    const existing = existingResult.rows[0];
    if (existing) {
      if (
        existing.caller_kind !== normalizedCallerKind ||
        existing.caller_device_id && existing.caller_device_id !== callerDeviceId
      ) {
        throw requestError('通话编号已被使用。', 409, 'CALL_ID_CONFLICT');
      }
      if (!ACTIVE_CALL_STATUSES.has(existing.status)) {
        throw requestError('这次通话已经结束。', 409, 'CALL_ENDED');
      }
      const updated = await client.query(
        `
          UPDATE call_sessions
          SET mode=$4,
              offer=$5::jsonb,
              caller_device_id=CASE
                WHEN caller_device_id='' THEN $8
                ELSE caller_device_id
              END,
              updated_at=NOW(),
              expires_at=NOW() + (
                CASE WHEN status='ringing' THEN $6::int ELSE $7::int END::text || ' seconds'
              )::interval
          WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3
          RETURNING *
        `,
        [
          signal.callId,
          tenantId,
          conversationId,
          signal.mode,
          JSON.stringify(signal.sdp),
          CALL_RING_TIMEOUT_SECONDS,
          CALL_ACTIVE_TIMEOUT_SECONDS,
          callerDeviceId,
        ],
      );
      await client.query('COMMIT');
      return { isNew: false, busy: false, call: updated.rows[0] };
    }

    const identity = await callIdentitySnapshot(
      client,
      tenantId,
      conversationId,
      normalizedCallerKind,
    );
    const activeResult = await client.query(
      `
        SELECT id
        FROM call_sessions
        WHERE tenant_id=$1
          AND status=ANY($2::text[])
          AND expires_at > NOW()
        ORDER BY created_at DESC
        LIMIT 1
        FOR UPDATE
      `,
      [tenantId, [...ACTIVE_CALL_STATUSES]],
    );
    if (activeResult.rows[0]) {
      const busyResult = await client.query(
        `
          INSERT INTO call_sessions (
            id,tenant_id,conversation_id,mode,offer,caller_kind,caller_name,
            caller_device_id,status,ended_at,end_reason,expires_at
          ) VALUES (
            $1,$2,$3,$4,$5::jsonb,$6,$7,
            $8,'busy',NOW(),'busy',NOW() + ($9::int::text || ' hours')::interval
          )
          RETURNING *
        `,
        [
          signal.callId,
          tenantId,
          conversationId,
          signal.mode,
          JSON.stringify(signal.sdp),
          normalizedCallerKind,
          identity.callerName,
          callerDeviceId,
          identity.retentionHours,
        ],
      );
      await client.query('COMMIT');
      return { isNew: true, busy: true, call: busyResult.rows[0] };
    }

    const inserted = await client.query(
      `
        INSERT INTO call_sessions (
          id,tenant_id,conversation_id,mode,offer,caller_kind,caller_name,
          caller_device_id,status,expires_at
        ) VALUES (
          $1,$2,$3,$4,$5::jsonb,$6,$7,
          $8,'ringing',NOW() + ($9::int::text || ' seconds')::interval
        )
        RETURNING *
      `,
      [
        signal.callId,
        tenantId,
        conversationId,
        signal.mode,
        JSON.stringify(signal.sdp),
        normalizedCallerKind,
        identity.callerName,
        callerDeviceId,
        CALL_RING_TIMEOUT_SECONDS,
      ],
    );
    await client.query('COMMIT');
    return { isNew: true, busy: false, call: inserted.rows[0] };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function claimPendingCall(
  callId,
  tenantId,
  conversationId,
  actorKind,
  deviceId,
) {
  if (!isUuid(callId)) return { accepted: false, call: null };
  const actorKey = callActorKey(actorKind, deviceId);
  const result = await pool.query(
    `
      UPDATE call_sessions
      SET claimed_by=COALESCE(claimed_by,$5),
          claimed_at=COALESCE(claimed_at,NOW()),
          updated_at=NOW()
      WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3
        AND caller_kind <> $4
        AND status='ringing'
        AND expires_at > NOW()
        AND (claimed_by IS NULL OR claimed_by=$5)
      RETURNING *
    `,
    [callId, tenantId, conversationId, actorKind, actorKey],
  );
  if (result.rows[0]) return { accepted: true, call: result.rows[0] };
  const current = await pool.query(
    `SELECT * FROM call_sessions WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3`,
    [callId, tenantId, conversationId],
  );
  return { accepted: false, call: current.rows[0] || null };
}

async function answerPendingCall(
  callId,
  tenantId,
  conversationId,
  actorKind,
  deviceId,
) {
  if (!isUuid(callId)) return { accepted: false, call: null };
  const actorKey = callActorKey(actorKind, deviceId);
  const result = await pool.query(
    `
      UPDATE call_sessions
      SET status=CASE WHEN status='ringing' THEN 'answered' ELSE status END,
          claimed_by=COALESCE(claimed_by,$5),
          claimed_at=COALESCE(claimed_at,NOW()),
          answered_at=COALESCE(answered_at,NOW()),
          updated_at=NOW(),
          expires_at=NOW() + ($6::int::text || ' seconds')::interval
      WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3
        AND caller_kind <> $4
        AND status=ANY($7::text[])
        AND expires_at > NOW()
        AND (claimed_by IS NULL OR claimed_by=$5)
      RETURNING *
    `,
    [
      callId,
      tenantId,
      conversationId,
      actorKind,
      actorKey,
      CALL_ACTIVE_TIMEOUT_SECONDS,
      ['ringing', 'answered', 'connected'],
    ],
  );
  if (result.rows[0]) return { accepted: true, call: result.rows[0] };
  const current = await pool.query(
    `SELECT * FROM call_sessions WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3`,
    [callId, tenantId, conversationId],
  );
  return { accepted: false, call: current.rows[0] || null };
}

async function markPendingCallConnected(
  callId,
  tenantId,
  conversationId,
  actorKind,
  deviceId,
) {
  if (!isUuid(callId)) return null;
  const actorDeviceId = cleanText(deviceId, 120) || 'legacy';
  const actorKey = callActorKey(actorKind, actorDeviceId);
  const result = await pool.query(
    `
      UPDATE call_sessions
      SET status='connected',
          connected_at=COALESCE(connected_at,NOW()),
          updated_at=NOW(),
          expires_at=NOW() + ($7::int::text || ' seconds')::interval
      WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3
        AND status=ANY($8::text[])
        AND (
          (caller_kind=$4 AND (caller_device_id='' OR caller_device_id=$5))
          OR (caller_kind <> $4 AND claimed_by=$6)
        )
      RETURNING *
    `,
    [
      callId,
      tenantId,
      conversationId,
      actorKind,
      actorDeviceId,
      actorKey,
      CALL_ACTIVE_TIMEOUT_SECONDS,
      ['answered', 'connected'],
    ],
  );
  return result.rows[0] || null;
}

async function finishPendingCall(
  callId,
  tenantId,
  conversationId,
  action,
  actorKind,
  deviceId,
  reason = '',
) {
  if (!isUuid(callId)) return { accepted: false, call: null };
  const actorDeviceId = cleanText(deviceId, 120) || 'legacy';
  const actorKey = callActorKey(actorKind, deviceId);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const currentResult = await client.query(
      `
        SELECT cs.*,COALESCE(tc.retention_hours,24)::int AS retention_hours
        FROM call_sessions cs
        LEFT JOIN tenant_config tc ON tc.tenant_id=cs.tenant_id
        WHERE cs.id=$1 AND cs.tenant_id=$2 AND cs.conversation_id=$3
        FOR UPDATE OF cs
      `,
      [callId, tenantId, conversationId],
    );
    const current = currentResult.rows[0];
    if (!current || !ACTIVE_CALL_STATUSES.has(current.status)) {
      await client.query('COMMIT');
      return { accepted: false, call: current || null };
    }
    const wrongCallerDevice =
      current.caller_kind === actorKind &&
      current.caller_device_id &&
      current.caller_device_id !== actorDeviceId;
    const wrongClaimedDevice =
      current.caller_kind !== actorKind &&
      current.claimed_by &&
      current.claimed_by !== actorKey;
    if (wrongCallerDevice || wrongClaimedDevice) {
      await client.query('COMMIT');
      return { accepted: false, call: current };
    }
    let finalStatus;
    if (action === 'reject') {
      finalStatus = current.caller_kind === actorKind ? 'cancelled' : 'rejected';
    } else if (action === 'busy') {
      finalStatus = current.caller_kind === actorKind ? 'cancelled' : 'busy';
    }
    else if (action === 'timeout') finalStatus = 'missed';
    else if (action === 'failed') finalStatus = 'failed';
    else if (current.status === 'ringing') {
      finalStatus = current.caller_kind === actorKind ? 'cancelled' : 'rejected';
    } else if (!current.connected_at) finalStatus = 'failed';
    else finalStatus = 'completed';
    const finalReason = cleanText(reason, 120) || finalStatus;
    const retentionHours = Math.max(
      1,
      Math.min(360, Number(current.retention_hours) || 24),
    );
    const durationSeconds = current.connected_at
      ? Math.max(
          0,
          Math.floor((Date.now() - new Date(current.connected_at).getTime()) / 1000),
        )
      : 0;
    const updated = await client.query(
      `
        UPDATE call_sessions
        SET status=$4,
            ended_at=NOW(),
            duration_seconds=$5,
            end_reason=$6,
            updated_at=NOW(),
            expires_at=NOW() + ($7::int::text || ' hours')::interval
        WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3
        RETURNING *
      `,
      [
        callId,
        tenantId,
        conversationId,
        finalStatus,
        durationSeconds,
        finalReason,
        retentionHours,
      ],
    );
    await client.query('COMMIT');
    return { accepted: true, call: updated.rows[0] };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

function pendingCallEvent(row) {
  return row
    ? {
        type: 'call-signal',
        action: 'offer',
        callId: row.id,
        mode: row.mode,
        sdp: row.offer,
        conversationId: row.conversation_id,
        from: row.caller_kind,
        callerName: row.caller_name,
        at: new Date(row.created_at).toISOString(),
      }
    : null;
}

async function getPendingCall(callId, tenantId, conversationId) {
  if (!isUuid(callId)) return null;
  await finalizeExpiredCallSessions(tenantId, conversationId);
  const result = await pool.query(
    `
      SELECT * FROM call_sessions
      WHERE id=$1 AND tenant_id=$2 AND conversation_id=$3
        AND caller_kind='admin'
        AND status='ringing' AND expires_at > NOW()
        AND claimed_by IS NULL
    `,
    [callId, tenantId, conversationId],
  );
  return pendingCallEvent(result.rows[0]);
}

async function getPendingAdminCall(tenantId) {
  if (!isUuid(tenantId)) return null;
  await finalizeExpiredCallSessions(tenantId);
  const result = await pool.query(
    `
      SELECT * FROM call_sessions
      WHERE tenant_id=$1
        AND caller_kind='user'
        AND status='ringing' AND expires_at > NOW()
        AND claimed_by IS NULL
      ORDER BY created_at DESC
      LIMIT 1
    `,
    [tenantId],
  );
  return pendingCallEvent(result.rows[0]);
}

async function savePushSubscription(payload, body, req) {
  if (!WEB_PUSH_ENABLED) {
    throw requestError('服务器尚未配置离线推送。', 503, 'PUSH_DISABLED');
  }
  const subscription = body?.subscription || body;
  const endpoint = normalizeWebPushEndpoint(subscription?.endpoint);
  const p256dh = validWebPushKey(subscription?.keys?.p256dh, 80, 120);
  const auth = validWebPushKey(subscription?.keys?.auth, 16, 64);
  if (!endpoint || !p256dh || !auth) {
    throw requestError('推送订阅信息无效。', 400, 'PUSH_SUBSCRIPTION');
  }
  const saved = await pool.query(
    `
      INSERT INTO push_subscriptions (
        endpoint,tenant_id,conversation_id,p256dh,auth,user_agent
      ) VALUES ($1,$2,$3,$4,$5,$6)
      ON CONFLICT (endpoint,tenant_id,conversation_id) DO UPDATE SET
        p256dh=EXCLUDED.p256dh,
        auth=EXCLUDED.auth,
        user_agent=EXCLUDED.user_agent,
        updated_at=NOW()
      WHERE push_subscriptions.p256dh IS DISTINCT FROM EXCLUDED.p256dh
         OR push_subscriptions.auth IS DISTINCT FROM EXCLUDED.auth
         OR push_subscriptions.user_agent IS DISTINCT FROM EXCLUDED.user_agent
         OR push_subscriptions.updated_at < NOW() - INTERVAL '7 days'
      RETURNING endpoint
    `,
    [
      endpoint,
      payload.tenantId,
      payload.conversationId,
      p256dh,
      auth,
      cleanText(req.headers['user-agent'], 500),
    ],
  );
  if (!saved.rows[0]) return;
  await pool.query(
    `DELETE FROM push_subscriptions
     WHERE tenant_id=$1 AND conversation_id=$2
       AND endpoint NOT IN (
         SELECT endpoint
         FROM push_subscriptions
         WHERE tenant_id=$1 AND conversation_id=$2
         ORDER BY updated_at DESC,endpoint
         LIMIT $3
       )`,
    [
      payload.tenantId,
      payload.conversationId,
      MAX_PUSH_SUBSCRIPTIONS_PER_CONVERSATION,
    ],
  );
  invalidatePushSubscriptionCache(payload.tenantId, payload.conversationId);
}

async function removePushSubscription(payload, body) {
  const endpoint = cleanText(body?.endpoint, 2048);
  if (!endpoint) return;
  await pool.query(
    `DELETE FROM push_subscriptions
     WHERE endpoint=$1 AND tenant_id=$2 AND conversation_id=$3`,
    [endpoint, payload.tenantId, payload.conversationId],
  );
  invalidatePushSubscriptionCache(payload.tenantId, payload.conversationId);
}

function conversationBase(row) {
  const lastSeenAt = row.last_seen_at ? new Date(row.last_seen_at).toISOString() : null;
  return {
    id: row.id,
    tenantId: row.tenant_id || null,
    visitorName: row.visitor_name,
    visitorNote: row.visitor_note || '',
    visitorGroupId: row.visitor_group_id || null,
    status: row.status,
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    lastSeenAt,
    online:
      conversationHasLiveVisitor(row.id, row.tenant_id) ||
      Boolean(
        lastSeenAt &&
          Date.now() - new Date(lastSeenAt).getTime() < 75_000,
      ),
    unreadAdmin: Number(row.unread_admin || 0),
    unreadUser: Number(row.unread_user || 0),
    ipAddress: row.ip_address || '',
    ipLocation: row.ip_location || '',
    timezone: row.timezone || '',
    deviceType: row.device_type || '',
    deviceLabel: row.device_label || '',
    entrySource: row.entry_source || '',
    networkType: row.network_type || '',
    networkEffectiveType: row.network_effective_type || '',
    downlinkMbps:
      row.downlink_mbps == null ? null : Number(row.downlink_mbps),
    rttMs: row.rtt_ms == null ? null : Number(row.rtt_ms),
    saveData: row.save_data == null ? null : Boolean(row.save_data),
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
            : row.latest_type === 'video'
              ? row.latest_text || '[视频]'
              : row.latest_type === 'audio'
                ? row.latest_text || '[语音]'
                : row.latest_text || '',
        role: row.latest_role,
        createdAt: new Date(row.latest_created_at).toISOString(),
      }
    : null;
  return result;
}

async function rememberTenantFrontendTemplate(
  client,
  tenantId,
  templateId,
) {
  if (!isUuid(tenantId) || !isUuid(templateId)) return;
  await client.query(
    `
      INSERT INTO tenant_frontend_templates (
        tenant_id,template_id,first_selected_at,last_selected_at
      ) VALUES ($1,$2,NOW(),NOW())
      ON CONFLICT (tenant_id,template_id)
      DO UPDATE SET last_selected_at=NOW()
    `,
    [tenantId, templateId],
  );
}

function tenantTemplateShortPrefix(template = {}) {
  const source = `${template.name || ''} ${template.base_url || template.baseUrl || ''}`;
  return ([
    [/企业微信|微信企业|微信|wecom|weixin/i, 'wxmb'],
    [/小红书|xiaohongshu|xhs/i, 'xhsmb'],
    [/抖音|douyin|tiktok/i, 'dymb'],
    [/快手|kuaishou|kwai/i, 'ksmb'],
    [/闲鱼|xianyu/i, 'xymb'],
    [/支付宝|alipay/i, 'zfbmb'],
    [/拼多多|pinduoduo|pdd/i, 'pddmb'],
    [/淘宝|taobao/i, 'tbmb'],
    [/qq/i, 'qqmb'],
    [/经典|default|zxkf/i, 'kfmb'],
  ].find(([pattern]) => pattern.test(source))?.[1] || 'kfmb');
}

function tenantTemplateDomainUrl(hostname) {
  const normalized = normalizeTenantEntryHost(hostname);
  return normalized ? `https://${normalized}/` : '';
}

async function ensureTenantTemplateDomain(
  client,
  tenantId,
  templateId,
) {
  if (
    !TENANT_ENTRY_ENABLED ||
    !TENANT_TEMPLATE_DOMAINS_ENABLED ||
    !isUuid(tenantId) ||
    !isUuid(templateId)
  ) {
    return null;
  }
  const existing = await client.query(
    `SELECT * FROM tenant_template_domains
     WHERE tenant_id=$1 AND template_id=$2`,
    [tenantId, templateId],
  );
  if (existing.rows[0]) return existing.rows[0];
  const rootDomain = normalizeTenantDomainSuffix(
    activeTenantEntryRootDomain || TENANT_ENTRY_DOMAIN_SUFFIXES[0],
  );
  if (!rootDomain) return null;
  const templateResult = await client.query(
    `SELECT id,name,base_url FROM frontend_templates WHERE id=$1`,
    [templateId],
  );
  const template = templateResult.rows[0];
  if (!template) return null;
  const prefix = tenantTemplateShortPrefix(template);
  // 优先分配 10–99 的短号码；紧凑号码用完后扩展到 3–9 位数字。
  // 已写入数据库的 (tenant_id, template_id) 映射始终直接复用，不会因扩容而改变。
  const compactPoolSize = 90;
  const compactSeed = randomBytes(1)[0] % compactPoolSize;
  const extendedPoolStart = 100;
  const extendedPoolSize = 999_999_900;
  const extendedAttempts = 256;
  const extendedSeed = randomBytes(4).readUInt32BE(0) % extendedPoolSize;
  for (
    let attempt = 0;
    attempt < compactPoolSize + extendedAttempts;
    attempt += 1
  ) {
    const suffix = attempt < compactPoolSize
      ? 10 + ((compactSeed + attempt) % compactPoolSize)
      : extendedPoolStart + (
          (extendedSeed + attempt - compactPoolSize) % extendedPoolSize
        );
    const label = `${prefix}${suffix}`;
    const hostname = normalizeTenantEntryHost(`${label}.${rootDomain}`);
    if (!hostname) continue;
    const inserted = await client.query(
      `INSERT INTO tenant_template_domains (
         tenant_id,template_id,hostname,label,root_domain
       )
       SELECT $1,$2,$3,$4,$5
       WHERE NOT EXISTS (
         SELECT 1 FROM frontend_templates WHERE entry_host=$3
         UNION ALL
         SELECT 1 FROM frontend_template_entry_aliases WHERE hostname=$3
         UNION ALL
         SELECT 1 FROM tenant_template_domain_aliases WHERE hostname=$3
       )
       ON CONFLICT DO NOTHING
       RETURNING *`,
      [tenantId, templateId, hostname, label, rootDomain],
    );
    if (inserted.rows[0]) return inserted.rows[0];
    const concurrent = await client.query(
      `SELECT * FROM tenant_template_domains
       WHERE tenant_id=$1 AND template_id=$2`,
      [tenantId, templateId],
    );
    if (concurrent.rows[0]) return concurrent.rows[0];
  }
  throw requestError(
    `模板“${cleanText(template.name, 80) || '用户端'}”的短域名暂时分配失败，请重试。`,
    503,
    'TENANT_DOMAIN_ALLOCATION_RETRY',
  );
}

async function ensureTenantTemplateDomains(tenantId, client = pool) {
  if (
    !TENANT_ENTRY_ENABLED ||
    !TENANT_TEMPLATE_DOMAINS_ENABLED ||
    !isUuid(tenantId)
  ) return new Map();
  const templates = await client.query(
    `SELECT DISTINCT template_id
     FROM (
       SELECT frontend_template_id AS template_id
       FROM tenant_config
       WHERE tenant_id=$1 AND frontend_template_id IS NOT NULL
       UNION
       SELECT template_id FROM tenant_frontend_templates WHERE tenant_id=$1
       UNION
       SELECT id AS template_id FROM frontend_templates
       WHERE status IN ('enabled','testing')
     ) available
     WHERE template_id IS NOT NULL`,
    [tenantId],
  );
  const result = new Map();
  for (const row of templates.rows) {
    const domain = await ensureTenantTemplateDomain(
      client,
      tenantId,
      row.template_id,
    );
    if (domain) result.set(domain.template_id, domain);
  }
  return result;
}

async function createTenantConfig(tenantId, client = pool) {
  const defaults = defaultConfig();
  await client.query(
    `
      INSERT INTO tenant_config (
        tenant_id, canned_replies, auto_replies, settings,
        frontend_template_id, retention_hours
      )
      VALUES ($1, $2::jsonb, $3::jsonb, $4::jsonb, $5, 24)
      ON CONFLICT (tenant_id) DO NOTHING
    `,
    [
      tenantId,
      JSON.stringify(defaults.cannedReplies),
      JSON.stringify(defaults.autoReplies),
      JSON.stringify(defaults.settings),
      DEFAULT_TEMPLATE_ID,
    ],
  );
  await client.query(
    `
      INSERT INTO tenant_frontend_templates (tenant_id,template_id)
      SELECT tenant_id,frontend_template_id
      FROM tenant_config
      WHERE tenant_id=$1 AND frontend_template_id IS NOT NULL
      ON CONFLICT (tenant_id,template_id) DO NOTHING
    `,
    [tenantId],
  );
}

async function getConfig(tenantId, client = pool) {
  if (!tenantId) throw new Error('缺少租户标识。');
  if (client === pool) {
    const cached = cacheGet(tenantConfigCache, tenantId);
    if (cached) return cached;
  }
  const tenantDomains = await ensureTenantTemplateDomains(tenantId, client);
  const tenantAliasRows = TENANT_ENTRY_ENABLED
    ? await client.query(
        `SELECT template_id,hostname FROM tenant_template_domain_aliases
         WHERE tenant_id=$1`,
        [tenantId],
      )
    : { rows: [] };
  const tenantAliases = new Map();
  for (const row of tenantAliasRows.rows) {
    const aliases = tenantAliases.get(row.template_id) || [];
    aliases.push(row.hostname);
    tenantAliases.set(row.template_id, aliases);
  }
  const result = await client.query(
    `
      SELECT
        tc.canned_replies,
        tc.auto_replies,
        tc.settings,
        tc.retention_hours,
        tc.frontend_template_id,
        ft.name AS frontend_template_name,
        ft.base_url AS frontend_base_url,
        ft.origin AS frontend_origin,
        ft.netlify_site_id AS frontend_netlify_site_id,
        ft.entry_host AS frontend_entry_host,
        ft.status AS frontend_template_status,
        approved.approved_frontends
      FROM tenant_config tc
      LEFT JOIN frontend_templates ft ON ft.id = tc.frontend_template_id
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'id', history_template.id,
            'name', history_template.name,
            'baseUrl', history_template.base_url,
            'origin', history_template.origin,
            'netlifySiteId', history_template.netlify_site_id,
            'entryHost', history_template.entry_host,
            'entryAliases', COALESCE((
              SELECT jsonb_agg(entry_alias.hostname ORDER BY entry_alias.hostname)
              FROM frontend_template_entry_aliases entry_alias
              WHERE entry_alias.template_id=history_template.id
            ), '[]'::jsonb),
            'status', history_template.status
          )
          ORDER BY
            (history_template.id=tc.frontend_template_id) DESC,
            history.last_selected_at DESC,
            history_template.created_at DESC
        ) AS approved_frontends
        FROM tenant_frontend_templates history
        JOIN frontend_templates history_template
          ON history_template.id=history.template_id
        WHERE history.tenant_id=tc.tenant_id
          AND (
            history_template.status='enabled'
            OR (
              history_template.status='testing'
              AND EXISTS (
                SELECT 1
                FROM jsonb_array_elements_text(
                  history_template.test_tenant_ids
                ) allowed(id)
                WHERE allowed.id=tc.tenant_id::text
              )
            )
          )
      ) approved ON TRUE
      WHERE tc.tenant_id = $1
    `,
    [tenantId],
  );
  if (!result.rows[0]) {
    await createTenantConfig(tenantId, client);
    return getConfig(tenantId, client);
  }
  const approvedFrontends = Array.isArray(result.rows[0].approved_frontends)
    ? result.rows[0].approved_frontends
        .map((item) => ({
          id: cleanText(item?.id, 80),
          name: cleanText(item?.name, 80),
          baseUrl: cleanText(item?.baseUrl, 500),
          origin: normalizeOrigin(item?.origin),
          netlifySiteId: cleanText(item?.netlifySiteId, 120),
          entryHost: normalizeTenantEntryHost(item?.entryHost),
          entryAliases: Array.isArray(item?.entryAliases)
            ? item.entryAliases
                .map((host) => normalizeTenantEntryHost(host))
                .filter(Boolean)
            : [],
          status: cleanText(item?.status, 30),
        }))
        .filter((item) => isUuid(item.id) && item.origin)
    : [];
  const approvedWithTenantDomains = approvedFrontends.map((item) => {
    const domain = tenantDomains.get(item.id);
    return {
      ...item,
      entryHost: normalizeTenantEntryHost(domain?.hostname) || item.entryHost,
      entryAliases: [
        ...new Set([
          ...item.entryAliases,
          ...(tenantAliases.get(item.id) || []),
        ].map((host) => normalizeTenantEntryHost(host)).filter(Boolean)),
      ],
      tenantDomain: Boolean(domain),
    };
  });
  const currentTemplateId =
    result.rows[0].frontend_template_id || DEFAULT_TEMPLATE_ID;
  const currentDomain = tenantDomains.get(currentTemplateId);
  const currentDomainUrl = tenantTemplateDomainUrl(currentDomain?.hostname);
  const config = {
    cannedReplies: result.rows[0].canned_replies || [],
    autoReplies: result.rows[0].auto_replies || [],
    approvedFrontends: approvedWithTenantDomains,
    settings: {
      ...defaultConfig().settings,
      ...(result.rows[0].settings || {}),
      qrBottomText:
        result.rows[0].settings?.qrBottomText === LEGACY_QR_BOTTOM_TEXT
          ? DEFAULT_QR_BOTTOM_TEXT
          : result.rows[0].settings?.qrBottomText ?? DEFAULT_QR_BOTTOM_TEXT,
      retentionHours: Number(result.rows[0].retention_hours || 24),
      frontendTemplateId: currentTemplateId,
      frontendTemplateName:
        result.rows[0].frontend_template_name || '拓界经典版',
      frontendBaseUrl: currentDomainUrl ||
        result.rows[0].frontend_base_url || DEFAULT_USER_SITE_URL,
      frontendOrigin: normalizeOrigin(currentDomainUrl) ||
        result.rows[0].frontend_origin || new URL(DEFAULT_USER_SITE_URL).origin,
      frontendEntryHost: normalizeTenantEntryHost(currentDomain?.hostname) ||
        normalizeTenantEntryHost(result.rows[0].frontend_entry_host),
      frontendTenantDomain: Boolean(currentDomain),
    },
  };
  return client === pool
    ? cacheSet(tenantConfigCache, tenantId, config)
    : config;
}

function findTenantApprovedFrontend(
  config,
  requestOrigin,
  templateIdentifier = '',
) {
  const origin = normalizeOrigin(requestOrigin);
  if (!origin) return null;
  const candidates = (config?.approvedFrontends || []).filter(
    (item) =>
      timingSafeTextEqual(normalizeOrigin(item.origin), origin) ||
      Boolean(tenantEntryOrigin(item.entryHost)) &&
        timingSafeTextEqual(tenantEntryOrigin(item.entryHost), origin) ||
      (item.entryAliases || []).some((host) =>
        timingSafeTextEqual(tenantEntryOrigin(host), origin),
      ),
  );
  if (!candidates.length) return null;
  if (templateIdentifier) {
    return candidates.find((item) =>
      clientTemplateIdentifierMatches(templateIdentifier, {
        id: item.id,
        netlify_site_id: item.netlifySiteId,
      })) || null;
  }
  return candidates.find((item) =>
    item.id === config?.settings?.frontendTemplateId) || candidates[0];
}

function findTenantApprovedFrontendByTemplate(config, templateIdentifier) {
  if (!templateIdentifier) return null;
  return (config?.approvedFrontends || []).find((item) =>
    clientTemplateIdentifierMatches(templateIdentifier, {
      id: item.id,
      netlify_site_id: item.netlifySiteId,
    })) || null;
}

function tenantApprovedOriginSummary(config) {
  return [...new Set(
    (config?.approvedFrontends || [])
      .flatMap((item) => [
        normalizeOrigin(item.origin),
        tenantEntryOrigin(item.entryHost),
        ...(item.entryAliases || []).map((host) => tenantEntryOrigin(host)),
      ])
      .filter(Boolean),
  )].sort().join(', ');
}

async function getTemplateCatalog(
  { audience = 'tenant', tenantId = '' } = {},
  client = pool,
) {
  const isSuper = audience === 'super';
  const tenantDomains = isSuper
    ? new Map()
    : await ensureTenantTemplateDomains(tenantId, client);
  const result = await client.query(
    `
      SELECT
        ft.id, ft.name, ft.base_url, ft.origin, ft.netlify_site_id,
        ft.entry_host,
        ft.cover_asset_id,
        ft.client_version, ft.min_backend_version, ft.status,
        ft.selection_closed, ft.sort_order, ft.recommended, ft.is_default,
        ft.test_tenant_ids,
        CASE WHEN $2::uuid IS NOT NULL THEN EXISTS (
          SELECT 1
          FROM tenant_frontend_templates history
          WHERE history.tenant_id=$2::uuid
            AND history.template_id=ft.id
        ) ELSE FALSE END AS previously_selected,
        CASE WHEN $1::boolean THEN (
          SELECT COUNT(*)::int
          FROM tenant_config tc
          WHERE tc.frontend_template_id = ft.id
        ) ELSE 0 END AS usage_count,
        CASE WHEN $1::boolean THEN (
          SELECT COUNT(*)::int
          FROM qr_incidents qi
          WHERE qi.template_id = ft.id
            AND qi.status IN ('open','processing')
        ) ELSE 0 END AS active_incident_count
      FROM frontend_templates ft
      WHERE $1::boolean
         OR (
           ft.status = 'enabled'
           AND (
             ft.selection_closed = FALSE
             OR EXISTS (
               SELECT 1
               FROM tenant_frontend_templates selected
               WHERE selected.tenant_id = $2::uuid
                 AND selected.template_id = ft.id
             )
           )
         )
         OR (
           ft.status = 'testing'
           AND $2::uuid IS NOT NULL
           AND EXISTS (
             SELECT 1
             FROM jsonb_array_elements_text(ft.test_tenant_ids) allowed(id)
             WHERE allowed.id = $2::text
           )
         )
      ORDER BY
        CASE ft.status
          WHEN 'enabled' THEN 0
          WHEN 'testing' THEN 1
          ELSE 2
        END,
        ft.is_default DESC,
        ft.recommended DESC,
        ft.sort_order,
        ft.created_at
    `,
    [isSuper, isUuid(tenantId) ? tenantId : null],
  );
  return result.rows.flatMap((row) => {
    let baseUrl;
    try {
      const parsed = parseTemplateFetchTarget(row.base_url);
      parsed.hash = '';
      baseUrl = parsed.toString();
    } catch {
      // 兼容旧版本数据库：历史非法地址既不能进入租户选择，也不能成为
      // 超级后台可点击链接。管理员修正数据库记录后会自动重新出现。
      return [];
    }
    const tenantDomain = tenantDomains.get(row.id);
    const entryHost = normalizeTenantEntryHost(tenantDomain?.hostname) ||
      normalizeTenantEntryHost(row.entry_host);
    const entryUrl = tenantEntryBaseUrl(entryHost);
    const catalogUrl = !isSuper && entryUrl ? entryUrl : baseUrl;
    return [{
      id: row.id,
      name: row.name,
      baseUrl: catalogUrl,
      displayUrl: catalogUrl.replace(/^https:\/\//i, '').replace(/\/$/, ''),
      origin: new URL(catalogUrl).origin,
      entryUrl,
      entryHost,
      tenantDomain: Boolean(tenantDomain),
      ...(isSuper
        ? { netlifySiteId: row.netlify_site_id || '' }
        : { netlifyReady: Boolean(row.netlify_site_id && NETLIFY_AUTH_TOKEN) }),
      coverUrl: row.cover_asset_id
        ? `${PUBLIC_API_BASE}/api/public/assets/${row.cover_asset_id}`
        : '',
      clientVersion: row.client_version,
      minBackendVersion: row.min_backend_version,
      status: row.status,
      selectionClosed: Boolean(row.selection_closed),
      sortOrder: Number(row.sort_order || 0),
      recommended: Boolean(row.recommended),
      isDefault: Boolean(row.is_default),
      previouslySelected: Boolean(row.previously_selected),
      testTenantIds: Array.isArray(row.test_tenant_ids)
        ? row.test_tenant_ids
        : [],
      usageCount: Number(row.usage_count || 0),
      activeIncidentCount: Number(row.active_incident_count || 0),
    }];
  });
}

function tenantEntryUrl(settings, publicCode) {
  const base = tenantEntryBaseUrl(settings?.frontendEntryHost) ||
    settings?.frontendBaseUrl || DEFAULT_USER_SITE_URL;
  const url = new URL(base);
  // 即使客户级域名本身也能映射客户，链接仍保留公开识别码：
  // 兼容旧 Worker、禁用 Cookie 的浏览器，并便于人工核对入口归属。
  url.searchParams.set('tenant', publicCode);
  return url.toString();
}

async function getPlatformSettings(client = pool) {
  if (
    lastPlatformSettings &&
    platformSettingsCacheExpiresAt > Date.now()
  ) {
    return lastPlatformSettings;
  }
  try {
    const result = await client.query(
      `SELECT * FROM platform_settings WHERE id = 1`,
    );
    const row = result.rows[0] || {};
    lastPlatformSettings = {
      brandName: row.brand_name || '拓界云客服',
      currentVersion: row.current_version || APP_VERSION,
      supportTelegram: row.support_telegram || SUPPORT_TELEGRAM,
      technicalSupportTelegram:
        row.support_telegram || SUPPORT_TELEGRAM,
      customerServiceTelegram:
        row.customer_service_telegram || CUSTOMER_SERVICE_TELEGRAM,
      telegramGroupId: row.telegram_group_id || '',
      netlifyConfigured: Boolean(NETLIFY_AUTH_TOKEN),
      reportTime: row.report_time || '09:00',
      reportTimezone: row.report_timezone || 'Asia/Shanghai',
      dailyReportEnabled: Boolean(row.daily_report_enabled),
      weeklyReportEnabled: Boolean(row.weekly_report_enabled),
      alertSettings: row.alert_settings || {},
    };
    platformSettingsCacheExpiresAt = Date.now() + CONFIG_CACHE_MS;
    return lastPlatformSettings;
  } catch (error) {
    if (lastPlatformSettings) return lastPlatformSettings;
    throw error;
  }
}

function rowTargetsTenant(row, tenantId) {
  if (row.scope === 'all') return true;
  return Array.isArray(row.tenant_ids) && row.tenant_ids.includes(tenantId);
}

function tenantEntitledToFeature(row, tenantId, durationCode) {
  const entitlements = row?.entitlements || {};
  if (entitlements.scope === 'selected') {
    return (
      Array.isArray(entitlements.tenantIds) &&
      entitlements.tenantIds.includes(tenantId)
    );
  }
  if (entitlements.scope === 'durations') {
    return (
      Array.isArray(entitlements.durationCodes) &&
      entitlements.durationCodes.includes(durationCode)
    );
  }
  return true;
}

function featureFlagAllowsTenant(row, tenantId) {
  if (!row || row.enabled === null || row.enabled === undefined) return true;
  if (!row.enabled) return false;
  const now = Date.now();
  if (row.starts_at && new Date(row.starts_at).getTime() > now) return false;
  if (row.ends_at && new Date(row.ends_at).getTime() <= now) return false;
  if (row.scope === 'all') return true;
  return (
    row.scope === 'selected' &&
    Array.isArray(row.tenant_ids) &&
    row.tenant_ids.includes(tenantId)
  );
}

async function tenantFeatureEnabled(code, tenantId, client = pool) {
  if (!SUPPORTED_FEATURE_FLAGS.has(code) || !isUuid(tenantId)) return false;
  if (client === pool) {
    const states = await getTenantFeatureStates(tenantId, pool);
    return Boolean(states[code]);
  }
  const result = await client.query(
    `
      SELECT
        fc.entitlements,
        ff.enabled,
        ff.scope,
        ff.tenant_ids,
        ff.starts_at,
        ff.ends_at,
        (
          SELECT lk.duration_code
          FROM license_keys lk
          WHERE lk.tenant_id=$2 AND lk.status='active'
          ORDER BY lk.created_at DESC
          LIMIT 1
        ) AS duration_code
      FROM feature_catalog fc
      LEFT JOIN feature_flags ff ON ff.code=fc.code
      WHERE fc.code=$1
      LIMIT 1
    `,
    [code, tenantId],
  );
  const row = result.rows[0];
  return Boolean(
    row &&
      tenantEntitledToFeature(row, tenantId, row.duration_code) &&
      featureFlagAllowsTenant(row, tenantId),
  );
}

async function requireTenantFeature(code, tenantId, client = pool) {
  if (await tenantFeatureEnabled(code, tenantId, client)) return;
  throw requestError(
    '此功能当前未向该租户开放。',
    403,
    'FEATURE_DISABLED',
  );
}

async function getTenantFeatureStates(tenantId, client = pool) {
  if (client === pool) {
    const cached = cacheGet(tenantFeatureCache, tenantId);
    if (cached) return cached;
  }
  const result = await client.query(
    `
      SELECT
        fc.code,
        fc.entitlements,
        ff.enabled,
        ff.scope,
        ff.tenant_ids,
        ff.starts_at,
        ff.ends_at,
        (
          SELECT lk.duration_code
          FROM license_keys lk
          WHERE lk.tenant_id=$2 AND lk.status='active'
          ORDER BY lk.created_at DESC
          LIMIT 1
        ) AS duration_code
      FROM feature_catalog fc
      LEFT JOIN feature_flags ff ON ff.code=fc.code
      WHERE fc.code=ANY($1::text[])
    `,
    [[...SUPPORTED_FEATURE_FLAGS], tenantId],
  );
  const rows = new Map(result.rows.map((row) => [row.code, row]));
  const states = Object.fromEntries(
    [...SUPPORTED_FEATURE_FLAGS].map((code) => {
      const row = rows.get(code);
      return [
        code,
        Boolean(
          row &&
            tenantEntitledToFeature(row, tenantId, row.duration_code) &&
            featureFlagAllowsTenant(row, tenantId),
        ),
      ];
    }),
  );
  return client === pool
    ? cacheSet(tenantFeatureCache, tenantId, states)
    : states;
}

async function getTenantNotices(tenantId, client = pool) {
  const [
    announcements,
    releases,
    featureCatalog,
    flags,
    platform,
    activeLicense,
  ] =
    await Promise.all([
      client.query(`
        SELECT a.*, ar.read_at
        FROM announcements a
        LEFT JOIN announcement_reads ar
          ON ar.announcement_id = a.id AND ar.tenant_id = $1
        WHERE a.active = TRUE
          AND a.retracted_at IS NULL
          AND a.starts_at <= NOW()
          AND (a.ends_at IS NULL OR a.ends_at > NOW())
        ORDER BY a.starts_at DESC
      `, [tenantId]),
      client.query(`
        SELECT r.*, rr.read_at
        FROM releases r
        LEFT JOIN release_reads rr
          ON rr.release_id = r.id AND rr.tenant_id = $1
        ORDER BY r.published_at DESC
        LIMIT 20
      `, [tenantId]),
      client.query(`
        SELECT *
        FROM feature_catalog
        ORDER BY category, name
      `),
      client.query(`SELECT * FROM feature_flags`),
      getPlatformSettings(client),
      client.query(
        `
          SELECT duration_code
          FROM license_keys
          WHERE tenant_id=$1 AND status='active'
          ORDER BY created_at DESC
          LIMIT 1
        `,
        [tenantId],
      ),
    ]);
  const scopedAnnouncements = announcements.rows
    .filter((row) => rowTargetsTenant(row, tenantId))
    .map((row) => ({
      id: row.id,
      type: row.type,
      title: row.title,
      content: row.content,
      displayMode: row.display_mode,
      forceModal: Boolean(row.force_modal),
      startsAt: new Date(row.starts_at).toISOString(),
      endsAt: row.ends_at ? new Date(row.ends_at).toISOString() : null,
      read: Boolean(row.read_at),
    }));
  const scopedReleases = releases.rows
    .filter((row) => rowTargetsTenant(row, tenantId))
    .map((row) => ({
      id: row.id,
      version: row.version,
      title: row.title,
      newFeatures: row.new_features,
      improvements: row.improvements,
      fixes: row.fixes,
      knownIssues: row.known_issues,
      forceModal: Boolean(row.force_modal),
      publishedAt: new Date(row.published_at).toISOString(),
      read: Boolean(row.read_at),
    }));
  const visibleVersion =
    scopedReleases[0]?.version || platform.currentVersion;
  const durationCode = activeLicense.rows[0]?.duration_code;
  const featureRows = new Map(
    featureCatalog.rows.map((row) => [row.code, row]),
  );
  const flagRows = new Map(flags.rows.map((row) => [row.code, row]));
  const scopedFlags = Object.fromEntries(
    [...SUPPORTED_FEATURE_FLAGS].map((code) => {
      const feature = featureRows.get(code);
      return [
        code,
        Boolean(
          feature &&
            tenantEntitledToFeature(feature, tenantId, durationCode) &&
            featureFlagAllowsTenant(flagRows.get(code), tenantId),
        ),
      ];
    }),
  );
  return {
    announcements: scopedAnnouncements,
    releases: scopedReleases,
    featureCatalog: featureCatalog.rows
      .filter((row) => {
        return (
          row.public_visible &&
          tenantEntitledToFeature(row, tenantId, durationCode)
        );
      })
      .map((row) => ({
        id: row.id,
        code: row.code,
        name: row.name,
        description: row.description,
        category: row.category,
        icon: row.icon,
        status: row.status,
        entitlements: row.entitlements || {},
      })),
    featureFlags: scopedFlags,
    platform: {
      brandName: platform.brandName,
      currentVersion: visibleVersion,
      supportTelegram: platform.supportTelegram,
    },
  };
}

async function getConversationRow(id, client = pool, forUpdate = false, tenantId) {
  if (!isUuid(id) || !isUuid(tenantId)) return null;
  const result = await client.query(
    `
      SELECT * FROM conversations
      WHERE id = $1 AND tenant_id = $2
      ${forUpdate ? 'FOR UPDATE' : ''}
    `,
    [id, tenantId],
  );
  return result.rows[0] || null;
}

async function getPublicConversation(id, client = pool, tenantId) {
  if (!isUuid(id) || !isUuid(tenantId)) return null;
  const conversationResult = await client.query(
    `SELECT * FROM conversations WHERE id = $1 AND tenant_id = $2`,
    [id, tenantId],
  );
  const conversation = conversationResult.rows[0];
  if (!conversation) return null;

  const messagesResult = await client.query(
    `
      WITH recent AS (
        SELECT *
        FROM messages
        WHERE conversation_id = $1
        ORDER BY
          created_at DESC,
          CASE WHEN source = 'auto' THEN 1 ELSE 0 END DESC,
          album_position DESC,
          id DESC
        LIMIT $2
      ),
      recent_albums AS (
        SELECT DISTINCT album_id
        FROM recent
        WHERE album_id IS NOT NULL
      )
      SELECT m.*
      FROM messages m
      WHERE m.conversation_id = $1
        AND (
          m.id IN (SELECT id FROM recent)
          OR m.album_id IN (SELECT album_id FROM recent_albums)
        )
      ORDER BY
        m.created_at ASC,
        CASE WHEN m.source = 'auto' THEN 1 ELSE 0 END ASC,
        m.album_position ASC,
        m.id ASC
    `,
    [id, MAX_MESSAGES_PER_CONVERSATION],
  );

  minuteCounters.fullHistoryReads += 1;
  minuteCounters.fullHistoryMessages += messagesResult.rowCount;
  const calls = await getCallHistory(tenantId, id, client);

  return {
    ...conversationBase(conversation),
    messages: messagesResult.rows.map(publicMessage),
    calls,
  };
}

async function requireAnyTenantFeature(codes, tenantId, client = pool) {
  for (const code of codes) {
    if (await tenantFeatureEnabled(code, tenantId, client)) return;
  }
  throw requestError(
    '此功能当前未向该租户开放。',
    403,
    'FEATURE_DISABLED',
  );
}

async function getConversationMessagePage(
  id,
  tenantId,
  { cursor = null, limit = API_PAGE_DEFAULT } = {},
  client = pool,
) {
  if (!isUuid(id) || !isUuid(tenantId)) return null;
  const conversationResult = await client.query(
    `SELECT * FROM conversations WHERE id=$1 AND tenant_id=$2`,
    [id, tenantId],
  );
  const conversation = conversationResult.rows[0];
  if (!conversation) return null;
  const decoded = decodeCursor(cursor);
  const result = await client.query(
    `
      WITH page_base AS (
        SELECT *
        FROM messages
        WHERE conversation_id=$1
          AND (
            $3::timestamptz IS NULL
            OR (created_at,id) < ($3::timestamptz,$4::uuid)
          )
        ORDER BY created_at DESC,id DESC
        LIMIT ($2::int + 1)
      ),
      chosen AS (
        SELECT * FROM page_base
        ORDER BY created_at DESC,id DESC
        LIMIT $2
      ),
      chosen_albums AS (
        SELECT DISTINCT album_id
        FROM chosen
        WHERE album_id IS NOT NULL
      )
      SELECT
        m.*,
        ((SELECT COUNT(*) FROM page_base) > $2)::boolean AS _has_more
      FROM messages m
      WHERE m.conversation_id=$1
        AND (
          m.id IN (SELECT id FROM chosen)
          OR m.album_id IN (SELECT album_id FROM chosen_albums)
        )
      ORDER BY
        m.created_at ASC,
        CASE WHEN m.source='auto' THEN 1 ELSE 0 END ASC,
        m.album_position ASC,
        m.id ASC
    `,
    [id, limit, decoded?.at || null, decoded?.id || null],
  );
  const rows = result.rows;
  const earliest = rows.reduce((current, row) => {
    if (!current) return row;
    if (new Date(row.created_at).getTime() < new Date(current.created_at).getTime()) {
      return row;
    }
    if (
      new Date(row.created_at).getTime() === new Date(current.created_at).getTime() &&
      row.id < current.id
    ) return row;
    return current;
  }, null);
  const hasMore = Boolean(rows[0]?._has_more);
  const calls = decoded ? null : await getCallHistory(tenantId, id, client);
  return {
    ...conversationBase(conversation),
    messages: rows.map(publicMessage),
    ...(calls ? { calls } : {}),
    messagePage: {
      limit,
      hasMore,
      nextCursor:
        hasMore && earliest
          ? encodeCursor({
              at: new Date(earliest.created_at).toISOString(),
              id: earliest.id,
            })
          : null,
    },
  };
}

async function getConversationSummaryById(id, tenantId, client = pool) {
  if (!isUuid(id) || !isUuid(tenantId)) return null;
  const result = await client.query(
    `
      SELECT
        c.*,
        latest.id AS latest_id,
        latest.type AS latest_type,
        latest.text AS latest_text,
        latest.role AS latest_role,
        latest.created_at AS latest_created_at
      FROM conversations c
      LEFT JOIN LATERAL (
        SELECT m.id,m.type,m.text,m.role,m.created_at
        FROM messages m
        WHERE m.conversation_id=c.id
        ORDER BY m.created_at DESC,m.id DESC
        LIMIT 1
      ) latest ON TRUE
      WHERE c.id=$1 AND c.tenant_id=$2
    `,
    [id, tenantId],
  );
  return result.rows[0] ? conversationSummary(result.rows[0]) : null;
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
      ORDER BY
        m.created_at DESC,
        CASE WHEN m.source = 'auto' THEN 1 ELSE 0 END DESC,
        m.id DESC
      LIMIT 1
    ) latest ON TRUE
    WHERE c.tenant_id = $1
    ORDER BY c.updated_at DESC
  `, [tenantId]);
  return result.rows.map(conversationSummary);
}

const MAX_VISITOR_GROUPS_PER_TENANT = 50;

function cleanVisitorGroupName(value) {
  return cleanText(value, 40).replace(/\s+/g, ' ');
}

function publicVisitorGroupRow(row) {
  return {
    id: row.id,
    name: row.name,
    visitorCount: Number(row.visitor_count || 0),
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
  };
}

async function getVisitorGroups(tenantId, queryClient = pool) {
  if (!isUuid(tenantId)) return [];
  const result = await queryClient.query(
    `
      SELECT
        vg.id,vg.name,vg.created_at,vg.updated_at,
        COUNT(c.id)::int AS visitor_count
      FROM visitor_groups vg
      LEFT JOIN conversations c
        ON c.tenant_id=vg.tenant_id
       AND c.visitor_group_id=vg.id
      WHERE vg.tenant_id=$1
      GROUP BY vg.id,vg.name,vg.created_at,vg.updated_at
      ORDER BY lower(vg.name),vg.id
    `,
    [tenantId],
  );
  return result.rows.map(publicVisitorGroupRow);
}

async function getAllSummariesPage(
  tenantId,
  {
    cursor = null,
    limit = API_PAGE_DEFAULT,
    search = '',
    groupId = '',
  } = {},
) {
  if (!isUuid(tenantId)) {
    return {
      items: [],
      nextCursor: null,
      hasMore: false,
      totals: { all: 0, open: 0, unread: 0 },
    };
  }
  const decoded = decodeCursor(cursor);
  const keyword = cleanText(search, 120).trim();
  const requestedGroup = cleanText(groupId, 50);
  const selectedGroupId = isUuid(requestedGroup) ? requestedGroup : null;
  const onlyUngrouped = requestedGroup === 'ungrouped';
  const pagePromise = pool.query(
    `
      SELECT
        c.*,
        latest.id AS latest_id,
        latest.type AS latest_type,
        latest.text AS latest_text,
        latest.role AS latest_role,
        latest.created_at AS latest_created_at
      FROM conversations c
      LEFT JOIN LATERAL (
        SELECT m.id,m.type,m.text,m.role,m.created_at
        FROM messages m
        WHERE m.conversation_id=c.id
        ORDER BY m.created_at DESC,m.id DESC
        LIMIT 1
      ) latest ON TRUE
      WHERE c.tenant_id=$1
        AND (
          $2::timestamptz IS NULL
          OR (c.updated_at,c.id) < ($2::timestamptz,$3::uuid)
        )
        AND (
          $4::text=''
          OR c.visitor_name ILIKE '%' || $4 || '%'
          OR c.visitor_note ILIKE '%' || $4 || '%'
          OR c.ip_address ILIKE '%' || $4 || '%'
          OR c.ip_location ILIKE '%' || $4 || '%'
          OR COALESCE(latest.text,'') ILIKE '%' || $4 || '%'
        )
        AND ($5::uuid IS NULL OR c.visitor_group_id=$5::uuid)
        AND (NOT $6::boolean OR c.visitor_group_id IS NULL)
      ORDER BY c.updated_at DESC,c.id DESC
      LIMIT ($7::int + 1)
    `,
    [
      tenantId,
      decoded?.at || null,
      decoded?.id || null,
      keyword,
      selectedGroupId,
      onlyUngrouped,
      limit,
    ],
  );
  const totalsPromise = decoded
    ? Promise.resolve(null)
    : keyword
      ? pool.query(
          `
            SELECT
              COUNT(*)::int AS total_count,
              COUNT(*) FILTER (WHERE c.status='open')::int AS open_count,
              COALESCE(SUM(c.unread_admin),0)::int AS unread_count
            FROM conversations c
            LEFT JOIN LATERAL (
              SELECT m.text
              FROM messages m
              WHERE m.conversation_id=c.id
              ORDER BY m.created_at DESC,m.id DESC
              LIMIT 1
            ) latest ON TRUE
            WHERE c.tenant_id=$1
              AND (
                c.visitor_name ILIKE '%' || $2 || '%'
                OR c.visitor_note ILIKE '%' || $2 || '%'
                OR c.ip_address ILIKE '%' || $2 || '%'
                OR c.ip_location ILIKE '%' || $2 || '%'
                OR COALESCE(latest.text,'') ILIKE '%' || $2 || '%'
              )
              AND ($3::uuid IS NULL OR c.visitor_group_id=$3::uuid)
              AND (NOT $4::boolean OR c.visitor_group_id IS NULL)
          `,
          [tenantId, keyword, selectedGroupId, onlyUngrouped],
        )
      : pool.query(
          `
            SELECT
              COUNT(*)::int AS total_count,
              COUNT(*) FILTER (WHERE status='open')::int AS open_count,
              COALESCE(SUM(unread_admin),0)::int AS unread_count
            FROM conversations
            WHERE tenant_id=$1
              AND ($2::uuid IS NULL OR visitor_group_id=$2::uuid)
              AND (NOT $3::boolean OR visitor_group_id IS NULL)
          `,
          [tenantId, selectedGroupId, onlyUngrouped],
        );
  const [result, totalsResult] = await Promise.all([
    pagePromise,
    totalsPromise,
  ]);
  const hasMore = result.rows.length > limit;
  const pageRows = result.rows.slice(0, limit);
  const last = pageRows.at(-1);
  const totalsRow = totalsResult?.rows?.[0] || {};
  return {
    items: pageRows.map(conversationSummary),
    nextCursor:
      hasMore && last
        ? encodeCursor({
            at: new Date(last.updated_at).toISOString(),
            id: last.id,
          })
        : null,
    hasMore,
    totals: decoded
      ? null
      : {
          all: Number(totalsRow.total_count || 0),
          open: Number(totalsRow.open_count || 0),
          unread: Number(totalsRow.unread_count || 0),
        },
  };
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
  if (!config.settings?.autoReplyEnabled) return null;
  const normalized = String(text || '').toLowerCase();

  for (const rule of Array.isArray(config.autoReplies) ? config.autoReplies : []) {
    if (!rule?.enabled || (!rule.replyText && !rule.imageAssetId)) continue;
    const keywords = Array.isArray(rule.keywords) ? rule.keywords : [];
    if (
      keywords.some((keyword) =>
        normalized.includes(String(keyword || '').toLowerCase()),
      )
    ) {
      return {
        text: cleanText(rule.replyText, 4000),
        imageAssetId: cleanText(rule.imageAssetId, 80),
      };
    }
  }

  if (config.settings?.defaultAutoReplyEnabled) {
    const reply = {
      text: cleanText(config.settings.defaultAutoReply, 4000),
      imageAssetId: cleanText(
        config.settings.defaultAutoReplyImageAssetId,
        80,
      ),
    };
    if (reply.text || reply.imageAssetId) return reply;
  }

  return null;
}

async function validateAdminSettings(body, current, tenantId) {
  const cannedReplies = Array.isArray(body.cannedReplies)
    ? body.cannedReplies
        .slice(0, 100)
        .map((item) => ({
          id: cleanText(item?.id, 80) || randomUUID(),
          title: cleanText(item?.title, 40) || '快捷语',
          text: cleanText(item?.text, 2000),
          imageAssetId: cleanText(item?.imageAssetId, 80),
        }))
        .filter((item) => item.text || item.imageAssetId)
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
          imageAssetId: cleanText(item?.imageAssetId, 80),
        }))
        .filter((item) => item.replyText || item.imageAssetId)
    : current.autoReplies;

  const input =
    body.settings && typeof body.settings === 'object' ? body.settings : {};
  const defaultAutoReplyImageAssetId = cleanText(
    input.defaultAutoReplyImageAssetId !== undefined
      ? input.defaultAutoReplyImageAssetId
      : current.settings.defaultAutoReplyImageAssetId,
    80,
  );
  const replyImageAssetIds = [
    ...cannedReplies.map((item) => item.imageAssetId),
    ...autoReplies.map((item) => item.imageAssetId),
    defaultAutoReplyImageAssetId,
  ].filter(Boolean);
  if (replyImageAssetIds.some((assetId) => !isUuid(assetId))) {
    throw requestError('快捷语或自动回复图片无效。', 400, 'INVALID_REPLY_IMAGE');
  }
  const uniqueReplyImageAssetIds = [...new Set(replyImageAssetIds)];
  if (uniqueReplyImageAssetIds.length) {
    const assetResult = await pool.query(
      `
        SELECT id
        FROM assets
        WHERE id = ANY($1::uuid[])
          AND tenant_id = $2
          AND kind = 'reply_image'
          AND mime = 'image/webp'
      `,
      [uniqueReplyImageAssetIds, tenantId],
    );
    if (assetResult.rows.length !== uniqueReplyImageAssetIds.length) {
      throw requestError(
        '快捷语或自动回复图片不存在，或不属于当前客户。',
        400,
        'INVALID_REPLY_IMAGE',
      );
    }
  }
  const brandFields = [
    'siteName',
    'welcomeText',
    'onlineStatusText',
    'pageTitle',
  ];
  const changesBrand = brandFields.some(
    (field) =>
      input[field] !== undefined &&
      cleanText(input[field], field === 'welcomeText' ? 2000 : 80) !==
        cleanText(
          current.settings[field],
          field === 'welcomeText' ? 2000 : 80,
        ),
  );
  if (changesBrand) {
    await requireTenantFeature('tenant_branding', tenantId);
  }

  const cooldownRaw = Number(
    input.autoReplyCooldownSeconds ??
      current.settings.autoReplyCooldownSeconds ??
      20,
  );
  const frontendTemplateId = cleanText(
    input.frontendTemplateId ??
      current.settings.frontendTemplateId ??
      DEFAULT_TEMPLATE_ID,
    80,
  );
  if (!isUuid(frontendTemplateId)) {
    throw requestError('用户端模板无效。', 400, 'FRONTEND_TEMPLATE');
  }
  if (
    frontendTemplateId !== current.settings.frontendTemplateId
  ) {
    await requireTenantFeature('frontend_templates', tenantId);
  }
  const templateResult = await pool.query(
    `
      SELECT id
      FROM frontend_templates
      WHERE id = $1
        AND (
          (
            status = 'enabled'
            AND (
              selection_closed = FALSE
              OR EXISTS (
                SELECT 1
                FROM tenant_frontend_templates selected
                WHERE selected.tenant_id = $2
                  AND selected.template_id = frontend_templates.id
              )
            )
          )
          OR (
            status = 'testing'
            AND EXISTS (
              SELECT 1
              FROM jsonb_array_elements_text(test_tenant_ids) allowed(id)
              WHERE allowed.id = $2::text
            )
          )
        )
    `,
    [frontendTemplateId, tenantId],
  );
  if (!templateResult.rows[0]) {
    throw requestError(
      '该用户端模板已停用，请选择其他模板。',
      400,
      'FRONTEND_TEMPLATE',
    );
  }
  const retentionHours = Number(
    input.retentionHours ?? current.settings.retentionHours ?? 24,
  );
  if (!RETENTION_OPTIONS.has(retentionHours)) {
    throw requestError('消息保存时间无效。', 400, 'RETENTION');
  }

  const settings = {
    ...current.settings,
    siteName:
      input.siteName !== undefined
        ? cleanText(input.siteName, 80) || '在线客服'
        : current.settings.siteName,
    avatarAssetId: cleanText(current.settings.avatarAssetId, 80),
    qrTopText:
      input.qrTopText !== undefined
        ? cleanText(input.qrTopText, 120)
        : cleanText(current.settings.qrTopText, 120),
    qrBottomText:
      input.qrBottomText !== undefined
        ? cleanText(input.qrBottomText, 360)
        : current.settings.qrBottomText !== undefined
          ? cleanText(current.settings.qrBottomText, 360)
          : DEFAULT_QR_BOTTOM_TEXT,
    qrLogoAssetId: cleanText(current.settings.qrLogoAssetId, 80),
    welcomeText:
      input.welcomeText !== undefined
        ? cleanText(input.welcomeText, 2000)
        : current.settings.welcomeText,
    onlineStatusText:
      input.onlineStatusText !== undefined
        ? cleanText(input.onlineStatusText, 40) || '客服在线'
        : current.settings.onlineStatusText || '客服在线',
       pageTitle:
      input.pageTitle !== undefined
        ? cleanText(input.pageTitle, 80) || '在线客服'
        : current.settings.pageTitle ||
          current.settings.siteName ||
          '在线客服',
    quickReplyDirectSend:
      input.quickReplyDirectSend !== undefined
        ? Boolean(input.quickReplyDirectSend)
        : current.settings.quickReplyDirectSend !== false,
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
    defaultAutoReplyImageAssetId,
    autoReplyCooldownSeconds: Number.isFinite(cooldownRaw)
      ? Math.min(3600, Math.max(0, cooldownRaw))
      : 20,
    frontendTemplateId,
    retentionHours,
    announcementEnabled:
      input.announcementEnabled !== undefined
        ? Boolean(input.announcementEnabled)
        : Boolean(current.settings.announcementEnabled),
    announcementText:
      input.announcementText !== undefined
        ? cleanText(input.announcementText, 1000)
        : cleanText(current.settings.announcementText, 1000),
  };

  return {
    cannedReplies,
    autoReplies,
    settings,
    frontendTemplateId,
    retentionHours,
    applyRetentionToExisting:
      body.applyRetentionToExisting === true,
  };
}

function sendSse(res, payload, id = null) {
  if (id != null) res.write(`id: ${id}\n`);
  res.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function clientAcceptsEvent(client, event) {
  if (
    event.apiVersion &&
    Number(client.apiVersion || 1) !== Number(event.apiVersion)
  ) return false;
  if (event.targetKind && client.kind !== event.targetKind) return false;
  if (
    event.distributorId &&
    client.distributorId !== event.distributorId
  ) return false;
  if (event.tenantId && client.tenantId !== event.tenantId) return false;
  if (
    event.conversationId &&
    client.kind === 'user' &&
    client.conversationId !== event.conversationId
  ) return false;
  return true;
}

function publishEvent(
  payload,
  {
    conversationId = null,
    tenantId = null,
    distributorId = null,
    targetKind = null,
    apiVersion = null,
    keepHistory = true,
  } = {},
) {
  const event = {
    id: nextEventId++,
    payload: { ...payload, eventId: nextEventId - 1 },
    conversationId,
    tenantId,
    distributorId,
    targetKind,
    apiVersion,
  };
  if (keepHistory) {
    eventHistory.push(event);
    if (eventHistory.length > 1200) eventHistory.shift();
  }
  for (const client of sseClients) {
    if (!clientAcceptsEvent(client, event)) continue;
    try {
      sendSse(client.res, event.payload, event.id);
    } catch {
      sseClients.delete(client);
    }
  }
  return event.id;
}

function broadcast(payload, conversationId = null, tenantId = null) {
  if (!isUuid(tenantId)) return;
  publishEvent(payload, { conversationId, tenantId });
}

function broadcastVersion(
  payload,
  apiVersion,
  conversationId = null,
  tenantId = null,
) {
  if (!isUuid(tenantId)) return;
  publishEvent(payload, {
    conversationId,
    tenantId,
    apiVersion,
  });
}

function hasLegacyConversationClient(conversationId, tenantId) {
  return [...sseClients].some(
    (client) =>
      Number(client.apiVersion || 1) === 1 &&
      client.tenantId === tenantId &&
      (client.kind === 'tenant_admin' ||
        client.conversationId === conversationId),
  );
}

function broadcastSuper(payload) {
  publishEvent(payload, { targetKind: 'super_admin' });
}

function broadcastDistributor(payload, distributorId) {
  if (!isUuid(distributorId)) return;
  publishEvent(payload, {
    distributorId,
    targetKind: 'distributor',
  });
}

function scheduleDistributorPresenceUpdate(distributorId) {
  if (!isUuid(distributorId) || distributorPresenceTimers.has(distributorId)) {
    return;
  }
  const timer = setTimeout(() => {
    distributorPresenceTimers.delete(distributorId);
    broadcastDistributor(
      {
        type: 'distributor-presence-updated',
        presence: getDistributorPresenceSnapshot(distributorId),
      },
      distributorId,
    );
  }, 300);
  timer.unref();
  distributorPresenceTimers.set(distributorId, timer);
}

function scheduleSuperPresenceUpdate() {
  if (scheduleSuperPresenceUpdate.timer) return;
  scheduleSuperPresenceUpdate.timer = setTimeout(() => {
    scheduleSuperPresenceUpdate.timer = null;
    broadcastSuper({
      type: 'tenant-presence-updated',
      presence: getRealtimePresenceSnapshot(),
    });
  }, 300);
  scheduleSuperPresenceUpdate.timer.unref();
}

function replayEvents(client, lastEventId) {
  const cursor = Number(lastEventId || 0);
  if (!Number.isSafeInteger(cursor) || cursor <= 0) return;
  for (const event of eventHistory) {
    if (event.id <= cursor || !clientAcceptsEvent(client, event)) continue;
    sendSse(client.res, event.payload, event.id);
  }
}

async function markConversationRead(conversationId, tenantId, reader) {
  const senderRole = reader === 'admin' ? 'user' : 'admin';
  const unreadColumn = reader === 'admin' ? 'unread_admin' : 'unread_user';
  const result = await pool.query(
    `
      WITH cleared AS (
        UPDATE conversations
        SET ${unreadColumn} = 0
        WHERE id = $1 AND tenant_id = $2
          AND ${unreadColumn} <> 0
        RETURNING id
      )
      UPDATE messages AS m
      SET read_at = NOW()
      FROM cleared
      WHERE m.conversation_id = cleared.id
        AND m.role = $3
        AND m.read_at IS NULL
      RETURNING m.id, m.read_at
    `,
    [conversationId, tenantId, senderRole],
  );
  const messageIds = result.rows.map((row) => row.id);
  const readAt = result.rows[0]?.read_at
    ? new Date(result.rows[0].read_at).toISOString()
    : null;

  if (messageIds.length) {
    broadcast(
      {
        type: 'messages-read',
        conversationId,
        reader,
        messageIds,
        readAt,
      },
      conversationId,
      tenantId,
    );
  }
  return { messageIds, readAt };
}

function disconnectTenant(tenantId, payload) {
  if (!tenantId) return;
  for (const client of sseClients) {
    if (client.tenantId !== tenantId) continue;
    try {
      sendSse(client.res, payload);
      client.res.end();
    } catch {}
    sseClients.delete(client);
  }
}

function disconnectDistributor(distributorId, payload = {}) {
  if (!isUuid(distributorId)) return;
  for (const client of sseClients) {
    if (
      client.kind !== 'distributor' ||
      client.distributorId !== distributorId
    ) continue;
    try {
      sendSse(client.res, {
        type: 'distributor-session-revoked',
        message: '代理账号状态已更新，请重新登录。',
        at: nowIso(),
        ...payload,
      });
      client.res.end();
    } catch {}
    sseClients.delete(client);
  }
}

function updateTenantConnectionsAfterRenewal(
  tenantId,
  accessExpiresAt,
  activeLicenseId,
) {
  const expiry = new Date(accessExpiresAt).getTime();
  for (const client of sseClients) {
    if (client.tenantId !== tenantId) continue;
    if (
      client.kind === 'tenant_admin' &&
      client.licenseId !== activeLicenseId
    ) {
      try {
        sendSse(client.res, {
          type: 'license-replaced',
          licenseId: client.licenseId,
          at: nowIso(),
        });
        client.res.end();
      } catch {}
      sseClients.delete(client);
      continue;
    }
    client.accessExpiresAt = expiry;
    try {
      sendSse(client.res, {
        type: 'tenant-renewed',
        accessExpiresAt: new Date(accessExpiresAt).toISOString(),
        at: nowIso(),
      });
    } catch {
      sseClients.delete(client);
    }
  }
}

setInterval(() => {
  for (const client of sseClients) {
    try {
      if (client.accessExpiresAt && client.accessExpiresAt <= Date.now()) {
        sendSse(client.res, {
          type: ['tenant_admin', 'user'].includes(client.kind)
            ? 'tenant-expired'
            : 'session-expired',
          at: nowIso(),
        });
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
  await requireTenantFeature('media_album', payload.tenantId);

  const rateIdentity = `${payload.kind}:${payload.tenantId}:${conversation.id}`;
  if (
    !rateLimit(req, res, 'upload', 30, 60_000, rateIdentity, {
      tenantId: payload.tenantId,
      conversationId: conversation.id,
    })
  ) return;

  const mime = String(req.headers['content-type'] || '')
    .split(';')[0]
    .trim()
    .toLowerCase();
  const isImage = ALLOWED_IMAGE_TYPES.has(mime);
  const isVideo = ALLOWED_VIDEO_TYPES.has(mime);
  const isAudio = ALLOWED_AUDIO_TYPES.has(mime);

  if (!isImage && !isVideo && !isAudio) {
    return sendError(
      res,
      415,
      '仅支持图片、MP4/WEBM/MOV 视频，以及 WEBM/OGG/M4A/MP3/WAV 语音。',
      'MEDIA_TYPE',
    );
  }

  const maxBytes = isVideo
    ? MAX_VIDEO_BYTES
    : isAudio
      ? MAX_AUDIO_BYTES
      : MAX_IMAGE_BYTES;
  if (activeUploads >= MAX_CONCURRENT_UPLOADS) {
    return sendError(res, 503, '当前上传较多，请稍后重试。', 'UPLOAD_BUSY');
  }
  activeUploads += 1;
  let data;
  try {
    data = await readBody(req, maxBytes);
  } finally {
    activeUploads -= 1;
  }
  if (!data.length) {
    return sendError(res, 400, '媒体内容为空。', 'EMPTY_MEDIA');
  }

  if (!mediaContentMatchesMime(data, mime)) {
    return sendError(
      res,
      415,
      '媒体内容与文件类型不匹配。',
      'MEDIA_SIGNATURE',
    );
  }

  const attachmentId = randomUUID();
  const filename = safeFilename(
    req.headers['x-file-name'] || `${isVideo ? 'video' : isAudio ? 'audio' : 'image'}-${attachmentId}`,
  );
  const objectKey = mediaObjectKey(
    payload.tenantId,
    conversation.id,
    attachmentId,
    mime,
  );
  const storedData = isAudio ? encryptAudioBuffer(data) : data;
  let storedInR2 = false;
  try {
    storedInR2 = await putObject(
      objectKey,
      storedData,
      isAudio ? 'application/octet-stream' : mime,
    );
    const config = await getConfig(payload.tenantId);
    const retentionHours = Number(config.settings.retentionHours || 24);
    const result = await pool.query(
      `
        INSERT INTO attachments (
          id, conversation_id, filename, mime, size, uploader, data,
          storage, object_key, expires_at
        )
        VALUES (
          $1,$2,$3,$4,$5,$6,$7,$8,$9,
          NOW() + ($10::text || ' hours')::interval
        )
        RETURNING
          id, conversation_id, filename, mime, size, uploader, created_at
      `,
      [
        attachmentId,
        conversation.id,
        filename,
        mime,
        data.length,
        payload.kind === 'tenant_admin' ? 'admin' : 'user',
        storedInR2 ? null : storedData,
        storedInR2 ? 'r2' : 'database',
        storedInR2 ? objectKey : null,
        retentionHours,
      ],
    );
    minuteCounters.uploads += 1;
    return sendJson(res, 201, {
      ok: true,
      attachment: publicAttachment(result.rows[0]),
      mediaType: isVideo ? 'video' : isAudio ? 'audio' : 'image',
    });
  } catch (error) {
    minuteCounters.uploadFailures += 1;
    if (storedInR2) await rollbackFreshObject(objectKey);
    throw error;
  }
}

function disconnectAuthSession(sessionId, message = '登录会话已注销。') {
  if (!isUuid(sessionId)) return;
  for (const client of sseClients) {
    if (client.sessionId !== sessionId) continue;
    try {
      sendSse(client.res, {
        type: 'session-expired',
        message,
        at: nowIso(),
      });
      client.res.end();
    } catch {}
    sseClients.delete(client);
  }
}

function publicTelegramHandle(value, fallback = CUSTOMER_SERVICE_TELEGRAM) {
  const username = cleanText(value, 80).trim().replace(/^@+/, '');
  if (/^[A-Za-z0-9_]{5,32}$/.test(username)) return `@${username}`;
  const fallbackUsername = cleanText(fallback, 80).trim().replace(/^@+/, '');
  return /^[A-Za-z0-9_]{5,32}$/.test(fallbackUsername)
    ? `@${fallbackUsername}`
    : '@kjwh8';
}

async function currentCustomerServiceTelegram(client = pool) {
  const platform = await getPlatformSettings(client).catch(() => null);
  return publicTelegramHandle(platform?.customerServiceTelegram);
}

async function tenantLicenseDisablePayload(disableMode = 'notice') {
  if (disableMode === 'busy') {
    return { type: 'session-ended', at: nowIso() };
  }
  const supportTelegram = await currentCustomerServiceTelegram();
  return {
    type: 'license-revoked',
    message: `你的卡密已被禁用，如有疑问请联系平台客服 Telegram ${supportTelegram}。`,
    supportTelegram,
    at: nowIso(),
  };
}

function disconnectTenantLicense(tenantId, licenseId, payload) {
  if (!isUuid(tenantId) || !isUuid(licenseId)) return;
  for (const client of sseClients) {
    if (
      client.kind !== 'tenant_admin' ||
      client.tenantId !== tenantId ||
      client.licenseId !== licenseId ||
      client.accessKind === 'super'
    ) continue;
    try {
      sendSse(client.res, payload);
      client.res.end();
    } catch {}
    sseClients.delete(client);
  }
  scheduleSuperPresenceUpdate();
}

function requestError(message, statusCode, code) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.code = code;
  return error;
}

function parseMessageInput(body = {}) {
  const requestedType = cleanText(body.type, 20) || 'text';
  if (!['text', 'image', 'video', 'audio'].includes(requestedType)) {
    throw requestError('消息类型无效。', 400, 'INVALID_MESSAGE_TYPE');
  }
  const suppliedClientRequestId = cleanText(body.clientRequestId, 128);
  if (
    suppliedClientRequestId &&
    !/^[A-Za-z0-9_-]{16,128}$/.test(suppliedClientRequestId)
  ) {
    throw requestError(
      '消息请求编号无效，请刷新页面后重试。',
      400,
      'INVALID_MESSAGE_REQUEST_ID',
    );
  }
  const clientRequestId = suppliedClientRequestId || randomUUID();

  const text = cleanText(body.text, 4000);
  if (requestedType === 'text') {
    if (!text) throw requestError('消息不能为空。', 400, 'EMPTY_MESSAGE');
    return {
      type: 'text', text, attachmentIds: [], assetIds: [], clientRequestId,
    };
  }

  const inputIds = Array.isArray(body.attachmentIds)
    ? body.attachmentIds
    : [body.attachmentId];
  const attachmentIds = inputIds
    .map((value) => cleanText(value, 80))
    .filter(Boolean);
  const inputAssetIds = Array.isArray(body.assetIds)
    ? body.assetIds
    : [body.assetId];
  const assetIds = inputAssetIds
    .map((value) => cleanText(value, 80))
    .filter(Boolean);

  if (
    (!attachmentIds.length && !assetIds.length) ||
    (attachmentIds.length && assetIds.length) ||
    attachmentIds.some((id) => !isUuid(id)) ||
    assetIds.some((id) => !isUuid(id)) ||
    new Set(attachmentIds).size !== attachmentIds.length ||
    new Set(assetIds).size !== assetIds.length
  ) {
    throw requestError('媒体附件无效。', 400, 'INVALID_ATTACHMENT');
  }
  const mediaCount = attachmentIds.length || assetIds.length;
  if (assetIds.length && requestedType !== 'image') {
    throw requestError('预设素材只能作为图片发送。', 400, 'INVALID_ASSET_TYPE');
  }
  if (requestedType === 'image' && mediaCount > MAX_ALBUM_IMAGES) {
    throw requestError(
      `一次最多发送 ${MAX_ALBUM_IMAGES} 张图片。`,
      400,
      'ALBUM_LIMIT',
    );
  }
  if (requestedType === 'video' && mediaCount !== 1) {
    throw requestError('一次只能发送一个视频。', 400, 'VIDEO_LIMIT');
  }
  if (requestedType === 'audio' && mediaCount !== 1) {
    throw requestError('一次只能发送一条语音。', 400, 'AUDIO_LIMIT');
  }

  return { type: requestedType, text, attachmentIds, assetIds, clientRequestId };
}

async function findManualMessageReplay(
  client,
  conversationId,
  role,
  clientRequestId,
) {
  const result = await client.query(
    `SELECT * FROM messages
     WHERE conversation_id=$1 AND role=$2 AND source='manual'
       AND client_request_id=$3
     ORDER BY album_position,created_at,id`,
    [conversationId, role, clientRequestId],
  );
  return result.rows;
}

async function findAutomaticMessageReplay(
  client,
  conversationId,
  clientRequestId,
) {
  const result = await client.query(
    `SELECT * FROM messages
     WHERE conversation_id=$1 AND role='admin' AND source='auto'
       AND client_request_id=$2
     ORDER BY created_at,album_position,id`,
    [conversationId, clientRequestId],
  );
  return result.rows;
}

async function lockReplyImageAssets(client, tenantId, assetIds) {
  const result = await client.query(
    `
      SELECT id
      FROM assets
      WHERE id = ANY($1::uuid[])
        AND tenant_id = $2
        AND kind = 'reply_image'
        AND mime = 'image/webp'
      FOR SHARE
    `,
    [assetIds, tenantId],
  );
  if (result.rows.length !== assetIds.length) {
    throw requestError(
      '快捷语或自动回复图片无效，或不属于当前客户。',
      400,
      'INVALID_REPLY_IMAGE',
    );
  }
}

async function insertAssetImageMessages(
  client,
  conversationId,
  assetIds,
  {
    source = 'manual',
    text = '',
    retentionHours = 24,
    createdAfter = null,
    clientRequestId = '',
  } = {},
) {
  const albumId = assetIds.length > 1 ? randomUUID() : null;
  const result = await client.query(
    `
      INSERT INTO messages (
        id, conversation_id, role, source, type, text, asset_id,
        album_id, album_position, client_request_id, created_at, expires_at
      )
      SELECT
        input.id,$4,'admin',$5,'image',input.body_text,input.asset_id,
        $6,input.position,$10,
        COALESCE(
          $9::timestamptz + ((input.position + 2)::text || ' milliseconds')::interval,
          NOW()
        ),
        COALESCE(
          $9::timestamptz + ((input.position + 2)::text || ' milliseconds')::interval,
          NOW()
        ) + ($7::text || ' hours')::interval
      FROM unnest(
        $1::uuid[],$2::uuid[],$3::text[],$8::int[]
      ) AS input(id,asset_id,body_text,position)
      RETURNING *
    `,
    [
      assetIds.map(() => randomUUID()),
      assetIds,
      assetIds.map((_, index) => index === 0 ? text : ''),
      conversationId,
      source,
      albumId,
      retentionHours,
      assetIds.map((_, index) => index),
      createdAfter,
      clientRequestId,
    ],
  );
  return result.rows.sort(
    (left, right) =>
      Number(left.album_position || 0) - Number(right.album_position || 0),
  );
}

async function lockPendingAttachments(
  client,
  conversationId,
  uploader,
  type,
  attachmentIds,
) {
  const result = await client.query(
    `
      SELECT id, mime
      FROM attachments
      WHERE id = ANY($1::uuid[])
        AND conversation_id = $2
        AND uploader = $3
        AND linked_at IS NULL
      FOR UPDATE
    `,
    [attachmentIds, conversationId, uploader],
  );
  if (result.rows.length !== attachmentIds.length) {
    throw requestError(
      '媒体附件无效、已使用或不属于当前会话。',
      400,
      'INVALID_ATTACHMENT',
    );
  }
  const byId = new Map(result.rows.map((row) => [row.id, row]));
  const valid = attachmentIds.every((id) => {
    const mime = byId.get(id)?.mime;
    if (type === 'image') return ALLOWED_IMAGE_TYPES.has(mime);
    if (type === 'video') return ALLOWED_VIDEO_TYPES.has(mime);
    return ALLOWED_AUDIO_TYPES.has(mime);
  });
  if (!valid) {
    throw requestError('媒体附件类型不匹配。', 400, 'INVALID_ATTACHMENT_TYPE');
  }
}

async function insertMediaMessages(
  client,
  conversationId,
  role,
  type,
  text,
  attachmentIds,
  retentionHours,
  clientRequestId,
) {
  const albumId =
    type === 'image' && attachmentIds.length > 1 ? randomUUID() : null;
  const messageIds = attachmentIds.map(() => randomUUID());
  const messageTexts = attachmentIds.map((_, index) =>
    index === 0 ? text : '',
  );
  const positions = attachmentIds.map((_, index) => index);
  const result = await client.query(
    `
      INSERT INTO messages (
        id, conversation_id, role, source, type, text, attachment_id,
        album_id, album_position, client_request_id, expires_at
      )
      SELECT
        input.id,$5,$6,'manual',$7,input.body_text,input.attachment_id,
        $8,input.position,$10,NOW() + ($9::text || ' hours')::interval
      FROM unnest(
        $1::uuid[],$2::uuid[],$3::text[],$4::int[]
      ) AS input(id,attachment_id,body_text,position)
      RETURNING *
    `,
    [
      messageIds,
      attachmentIds,
      messageTexts,
      positions,
      conversationId,
      role,
      type,
      albumId,
      retentionHours,
      clientRequestId,
    ],
  );
  await client.query(
    `
      UPDATE attachments
      SET linked_at = NOW(),
          expires_at = NOW() + ($2::text || ' hours')::interval
      WHERE id = ANY($1::uuid[])
    `,
    [attachmentIds, retentionHours],
  );
  return result.rows.sort(
    (left, right) =>
      Number(left.album_position || 0) - Number(right.album_position || 0),
  );
}

async function createUserMessage(
  conversationId,
  body,
  tenantId,
  { includeConversation = true } = {},
) {
  const input = parseMessageInput(body);
  if (input.assetIds.length) {
    throw requestError('访客不能发送后台预设素材。', 403, 'FORBIDDEN_ASSET');
  }
  const [config, featureStates] = await Promise.all([
    getConfig(tenantId),
    getTenantFeatureStates(tenantId),
  ]);
  if (input.type !== 'text' && !featureStates.media_album) {
    throw requestError(
      '此功能当前未向该租户开放。',
      403,
      'FEATURE_DISABLED',
    );
  }
  const retentionHours = Number(config.settings.retentionHours || 24);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const conversation = await getConversationRow(
      conversationId,
      client,
      true,
      tenantId,
    );
    if (!conversation) {
      throw requestError('访客会话不存在。', 401, 'AUTH');
    }
    if (conversation.status === 'closed') {
      throw requestError('此会话已结束。', 409, 'CLOSED');
    }

    const replayRows = await findManualMessageReplay(
      client,
      conversationId,
      'user',
      input.clientRequestId,
    );
    if (replayRows.length) {
      const replayAutoReplyRows = await findAutomaticMessageReplay(
        client,
        conversationId,
        input.clientRequestId,
      );
      await client.query('COMMIT');
      const messages = replayRows.map(publicMessage);
      const autoReplies = replayAutoReplyRows.map(publicMessage);
      const latestRow = replayAutoReplyRows.at(-1) || replayRows.at(-1);
      const replaySummary = conversationSummary({
        ...conversation,
        latest_id: latestRow?.id,
        latest_type: latestRow?.type,
        latest_text: latestRow?.text,
        latest_role: latestRow?.role,
        latest_created_at: latestRow?.created_at,
      });
      const publicConversation = includeConversation
        ? await getPublicConversation(conversationId, pool, tenantId)
        : replaySummary;
      return {
        message: messages[0],
        messages,
        autoReply: autoReplies[0] || null,
        autoReplies,
        conversation: publicConversation,
        summary: includeConversation ? publicConversation : replaySummary,
        idempotentReplay: true,
      };
    }

    let messageRows;
    if (input.type === 'text') {
      const result = await client.query(
        `
          INSERT INTO messages (
            id, conversation_id, role, source, type, text,
            client_request_id, expires_at
          )
          VALUES (
            $1,$2,'user','manual','text',$3,$5,
            NOW() + ($4::text || ' hours')::interval
          )
          RETURNING *
        `,
        [
          randomUUID(),
          conversationId,
          input.text,
          retentionHours,
          input.clientRequestId,
        ],
      );
      messageRows = [result.rows[0]];
    } else {
      await lockPendingAttachments(
        client,
        conversationId,
        'user',
        input.type,
        input.attachmentIds,
      );
      messageRows = await insertMediaMessages(
        client,
        conversationId,
        'user',
        input.type,
        input.text,
        input.attachmentIds,
        retentionHours,
        input.clientRequestId,
      );
    }

    let updatedConversation = (
      await client.query(
      `
        UPDATE conversations
        SET unread_admin = unread_admin + $3::int, updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        RETURNING *
      `,
      [conversationId, tenantId, messageRows.length],
      )
    ).rows[0];

    let autoReplyRows = [];
    if (input.type === 'text') {
      const cooldownSeconds = Math.min(
        3600,
        Math.max(0, Number(config.settings.autoReplyCooldownSeconds ?? 20)),
      );
      const lastAutoReplyAt = conversation.last_auto_reply_at
        ? new Date(conversation.last_auto_reply_at).getTime()
        : 0;
      const cooldownPassed =
        !lastAutoReplyAt ||
        Date.now() - lastAutoReplyAt >= cooldownSeconds * 1000;
      const autoReply =
        cooldownPassed &&
        featureStates.auto_reply
        ? matchAutoReply(config, input.text)
        : null;

      if (autoReply) {
        if (autoReply.text) {
          const autoResult = await client.query(
            `
              INSERT INTO messages (
                id, conversation_id, role, source, type, text,
                client_request_id, created_at, expires_at
              )
              VALUES (
                $1,$2,'admin','auto','text',$3,$6,
                $5::timestamptz + INTERVAL '1 millisecond',
                $5::timestamptz + INTERVAL '1 millisecond'
                  + ($4::text || ' hours')::interval
              )
              RETURNING *
            `,
            [
              randomUUID(),
              conversationId,
              autoReply.text,
              retentionHours,
              messageRows.at(-1).created_at,
              input.clientRequestId,
            ],
          );
          autoReplyRows.push(autoResult.rows[0]);
        }
        if (autoReply.imageAssetId) {
          await lockReplyImageAssets(
            client,
            tenantId,
            [autoReply.imageAssetId],
          );
          autoReplyRows.push(...await insertAssetImageMessages(
            client,
            conversationId,
            [autoReply.imageAssetId],
            {
              source: 'auto',
              retentionHours,
              createdAfter: messageRows.at(-1).created_at,
              clientRequestId: input.clientRequestId,
            },
          ));
        }
        if (autoReplyRows.length) {
          updatedConversation = (
            await client.query(
            `
              UPDATE conversations
              SET unread_user = unread_user + $3::int,
                  last_auto_reply_at = NOW(),
                  updated_at = NOW()
              WHERE id = $1 AND tenant_id = $2
              RETURNING *
            `,
            [conversationId, tenantId, autoReplyRows.length],
            )
          ).rows[0];
        }
      }
    }

    await client.query('COMMIT');
    minuteCounters.messages +=
      messageRows.length + autoReplyRows.length;
    const messages = messageRows.map(publicMessage);
    const latestRow = autoReplyRows.at(-1) || messageRows.at(-1);
    const summary = conversationSummary({
      ...updatedConversation,
      latest_id: latestRow?.id,
      latest_type: latestRow?.type,
      latest_text: latestRow?.text,
      latest_role: latestRow?.role,
      latest_created_at: latestRow?.created_at,
    });
    const publicConversation = includeConversation
      ? await getPublicConversation(
          conversationId,
          pool,
          conversation.tenant_id,
        )
      : summary;
    return {
      message: messages[0],
      messages,
      autoReply: autoReplyRows[0] ? publicMessage(autoReplyRows[0]) : null,
      autoReplies: autoReplyRows.map(publicMessage),
      conversation: publicConversation,
      summary,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function createAdminMessage(
  conversationId,
  body,
  tenantId,
  { includeConversation = true } = {},
) {
  const input = parseMessageInput(body);
  const [config, featureStates] = await Promise.all([
    getConfig(tenantId),
    getTenantFeatureStates(tenantId),
  ]);
  if (input.type !== 'text' && !featureStates.media_album) {
    throw requestError(
      '此功能当前未向该租户开放。',
      403,
      'FEATURE_DISABLED',
    );
  }
  const retentionHours = Number(config.settings.retentionHours || 24);
  const client = await pool.connect();

  try {
    await client.query('BEGIN');
    const conversation = await getConversationRow(
      conversationId,
      client,
      true,
      tenantId,
    );
    if (!conversation) {
      throw requestError('会话不存在。', 404, 'NOT_FOUND');
    }
    if (conversation.status === 'closed') {
      throw requestError('此会话已结束。', 409, 'CLOSED');
    }

    const replayRows = await findManualMessageReplay(
      client,
      conversationId,
      'admin',
      input.clientRequestId,
    );
    if (replayRows.length) {
      await client.query('COMMIT');
      const messages = replayRows.map(publicMessage);
      const latestRow = replayRows.at(-1);
      const replaySummary = conversationSummary({
        ...conversation,
        latest_id: latestRow?.id,
        latest_type: latestRow?.type,
        latest_text: latestRow?.text,
        latest_role: latestRow?.role,
        latest_created_at: latestRow?.created_at,
      });
      const publicConversation = includeConversation
        ? await getPublicConversation(conversationId, pool, tenantId)
        : replaySummary;
      return {
        message: messages[0],
        messages,
        conversation: publicConversation,
        summary: includeConversation ? publicConversation : replaySummary,
        idempotentReplay: true,
      };
    }

    let messageRows;
    if (input.type === 'text') {
      const result = await client.query(
        `
          INSERT INTO messages (
            id, conversation_id, role, source, type, text,
            client_request_id, expires_at
          )
          VALUES (
            $1,$2,'admin','manual','text',$3,$5,
            NOW() + ($4::text || ' hours')::interval
          )
          RETURNING *
        `,
        [
          randomUUID(),
          conversationId,
          input.text,
          retentionHours,
          input.clientRequestId,
        ],
      );
      messageRows = [result.rows[0]];
    } else if (input.assetIds.length) {
      await lockReplyImageAssets(client, tenantId, input.assetIds);
      messageRows = await insertAssetImageMessages(
        client,
        conversationId,
        input.assetIds,
        {
          text: input.text,
          retentionHours,
          clientRequestId: input.clientRequestId,
        },
      );
    } else {
      await lockPendingAttachments(
        client,
        conversationId,
        'admin',
        input.type,
        input.attachmentIds,
      );
      messageRows = await insertMediaMessages(
        client,
        conversationId,
        'admin',
        input.type,
        input.text,
        input.attachmentIds,
        retentionHours,
        input.clientRequestId,
      );
    }

    const updatedConversation = (
      await client.query(
      `
        UPDATE conversations
        SET unread_user = unread_user + $3::int, updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
        RETURNING *
      `,
      [conversationId, tenantId, messageRows.length],
      )
    ).rows[0];

    await client.query('COMMIT');
    minuteCounters.messages += messageRows.length;
    const messages = messageRows.map(publicMessage);
    const latestRow = messageRows.at(-1);
    const summary = conversationSummary({
      ...updatedConversation,
      latest_id: latestRow?.id,
      latest_type: latestRow?.type,
      latest_text: latestRow?.text,
      latest_role: latestRow?.role,
      latest_created_at: latestRow?.created_at,
    });
    const publicConversation = includeConversation
      ? await getPublicConversation(
          conversationId,
          pool,
          conversation.tenant_id,
        )
      : summary;
    return {
      message: messages[0],
      messages,
      conversation: publicConversation,
      summary,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function broadcastMessageResult(
  result,
  trigger,
  conversationId,
  tenantId,
  requestApiVersion,
) {
  const appended = [
    ...(result.messages || []),
    ...(
      Array.isArray(result.autoReplies)
        ? result.autoReplies
        : result.autoReply
          ? [result.autoReply]
          : []
    ),
  ];
  for (const message of appended) {
    if (
      ['user', 'admin'].includes(message?.role) &&
      message?.source !== 'auto'
    ) {
      recordRealtimeChatActivity(
        tenantId,
        conversationId,
        message.role,
        message.createdAt || message.created_at,
      );
    }
  }
  broadcastVersion(
    {
      type: 'messages-appended',
      trigger,
      conversationId,
      messages: appended,
      summary: result.summary || result.conversation,
    },
    2,
    conversationId,
    tenantId,
  );

  let legacyConversation =
    requestApiVersion < 2 && Array.isArray(result.conversation?.messages)
      ? result.conversation
      : null;
  if (
    !legacyConversation &&
    hasLegacyConversationClient(conversationId, tenantId)
  ) {
    legacyConversation = await getPublicConversation(
      conversationId,
      pool,
      tenantId,
    );
  }
  if (legacyConversation) {
    broadcastVersion(
      {
        type: 'conversation-updated',
        trigger,
        conversation: legacyConversation,
      },
      1,
      conversationId,
      tenantId,
    );
  }
}

async function selectAdminMessageGroup(
  client,
  conversationId,
  messageId,
  tenantId,
) {
  const target = await client.query(
    `
      SELECT m.*
      FROM messages m
      JOIN conversations c ON c.id = m.conversation_id
      WHERE m.id = $1
        AND m.conversation_id = $2
        AND c.tenant_id = $3
        AND m.role = 'admin'
        AND m.source = 'manual'
      FOR UPDATE
    `,
    [messageId, conversationId, tenantId],
  );
  const row = target.rows[0];
  if (!row) {
    throw requestError(
      '只能操作当前租户中由客服发送的消息。',
      403,
      'MESSAGE_FORBIDDEN',
    );
  }
  if (!row.album_id) return [row];
  const album = await client.query(
    `
      SELECT *
      FROM messages
      WHERE conversation_id = $1
        AND album_id = $2
        AND role = 'admin'
        AND source = 'manual'
      ORDER BY album_position, created_at, id
      FOR UPDATE
    `,
    [conversationId, row.album_id],
  );
  return album.rows;
}

async function refreshConversationCounters(
  client,
  conversationId,
  tenantId,
) {
  await client.query(
    `
      UPDATE conversations c
      SET unread_admin = (
            SELECT COUNT(*)::int
            FROM messages m
            WHERE m.conversation_id = c.id
              AND m.role = 'user'
              AND m.read_at IS NULL
          ),
          unread_user = (
            SELECT COUNT(*)::int
            FROM messages m
            WHERE m.conversation_id = c.id
              AND m.role = 'admin'
              AND m.read_at IS NULL
          ),
          updated_at = COALESCE(
            (
              SELECT MAX(m.created_at)
              FROM messages m
              WHERE m.conversation_id = c.id
            ),
            c.created_at
          )
      WHERE c.id = $1 AND c.tenant_id = $2
    `,
    [conversationId, tenantId],
  );
}

async function finishAdminMessageMutation({
  type,
  conversationId,
  tenantId,
  messageIds,
  message = null,
  requestApiVersion = 1,
}) {
  const summary = await getConversationSummaryById(
    conversationId,
    tenantId,
  );
  const delta = {
    type,
    conversationId,
    messageIds,
    ...(message ? { message } : {}),
    ...(summary ? { summary } : {}),
  };
  broadcastVersion(delta, 2, conversationId, tenantId);

  let legacyConversation = null;
  if (
    requestApiVersion < 2 ||
    hasLegacyConversationClient(conversationId, tenantId)
  ) {
    legacyConversation = await getPublicConversation(
      conversationId,
      pool,
      tenantId,
    );
    if (legacyConversation) {
      broadcastVersion(
        { ...delta, conversation: legacyConversation },
        1,
        conversationId,
        tenantId,
      );
    }
  }

  return requestApiVersion >= 2
    ? {
        messageIds,
        ...(message ? { message } : {}),
        ...(summary ? { summary } : {}),
      }
    : {
        messageIds,
        ...(message ? { message } : {}),
        conversation: legacyConversation,
      };
}

async function deleteAdminMessage(
  conversationId,
  messageId,
  tenantId,
  requestApiVersion = 1,
) {
  const client = await pool.connect();
  const objectKeys = [];
  let messageIds = [];
  try {
    await client.query('BEGIN');
    const rows = await selectAdminMessageGroup(
      client,
      conversationId,
      messageId,
      tenantId,
    );
    messageIds = rows.map((row) => row.id);
    const attachmentIds = rows
      .map((row) => row.attachment_id)
      .filter(Boolean);
    if (attachmentIds.length) {
      const attachments = await client.query(
        `
          SELECT object_key
          FROM attachments
          WHERE id = ANY($1::uuid[])
        `,
        [attachmentIds],
      );
      objectKeys.push(
        ...attachments.rows.map((row) => row.object_key).filter(Boolean),
      );
    }
    await client.query(
      `DELETE FROM messages WHERE id = ANY($1::uuid[])`,
      [messageIds],
    );
    if (attachmentIds.length) {
      await client.query(
        `DELETE FROM attachments WHERE id = ANY($1::uuid[])`,
        [attachmentIds],
      );
    }
    await refreshConversationCounters(client, conversationId, tenantId);
    await queueObjectDeletes(objectKeys, client);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
  processObjectDeleteQueue().catch(() => {});
  return finishAdminMessageMutation({
    type: 'message-deleted',
    conversationId,
    tenantId,
    messageIds,
    requestApiVersion,
  });
}

async function recallAdminMessage(
  conversationId,
  messageId,
  tenantId,
  requestApiVersion = 1,
) {
  const client = await pool.connect();
  const objectKeys = [];
  let messageIds = [];
  let recalledMessageId = '';
  let recalledMessage = null;
  try {
    await client.query('BEGIN');
    const rows = await selectAdminMessageGroup(
      client,
      conversationId,
      messageId,
      tenantId,
    );
    if (rows.some((row) => row.recalled_at)) {
      throw requestError('该消息已经撤回。', 409, 'MESSAGE_RECALLED');
    }
    messageIds = rows.map((row) => row.id);
    recalledMessageId = rows[0].id;
    const attachmentIds = rows
      .map((row) => row.attachment_id)
      .filter(Boolean);
    if (attachmentIds.length) {
      const attachments = await client.query(
        `SELECT object_key FROM attachments WHERE id = ANY($1::uuid[])`,
        [attachmentIds],
      );
      objectKeys.push(
        ...attachments.rows.map((row) => row.object_key).filter(Boolean),
      );
    }
    if (messageIds.length > 1) {
      await client.query(
        `DELETE FROM messages WHERE id = ANY($1::uuid[]) AND id <> $2`,
        [messageIds, recalledMessageId],
      );
    }
    const recalled = await client.query(
      `
        UPDATE messages
        SET type = 'text',
            text = '客服已撤回了一条消息',
            attachment_id = NULL,
            asset_id = NULL,
            album_id = NULL,
            album_position = 0,
            recalled_at = NOW()
        WHERE id = $1
        RETURNING *
      `,
      [recalledMessageId],
    );
    recalledMessage = recalled.rows[0]
      ? publicMessage(recalled.rows[0])
      : null;
    if (attachmentIds.length) {
      await client.query(
        `DELETE FROM attachments WHERE id = ANY($1::uuid[])`,
        [attachmentIds],
      );
    }
    await refreshConversationCounters(client, conversationId, tenantId);
    await queueObjectDeletes(objectKeys, client);
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
  processObjectDeleteQueue().catch(() => {});
  return finishAdminMessageMutation({
    type: 'message-recalled',
    conversationId,
    tenantId,
    messageIds,
    message: recalledMessage,
    requestApiVersion,
  });
}


async function getTenantById(tenantId, client = pool, forUpdate = false) {
  if (!isUuid(tenantId)) return null;
  const result = await client.query(
    `SELECT * FROM tenants WHERE id = $1 ${forUpdate ? 'FOR UPDATE' : ''}`,
    [tenantId],
  );
  return result.rows[0] || null;
}

async function getTenantForAdminToken(payload, client = pool) {
  if (
    !isUuid(payload?.tenantId) ||
    !isUuid(payload?.licenseId) ||
    !isUuid(payload?.sessionId)
  ) return null;
  const accessKind = tenantAdminAccessKind(payload);
  if (!accessKind) return null;
  const deviceHash = cleanText(payload.deviceHash, 100);
  const result = await client.query(
    `
      SELECT t.*
      FROM tenants t
      JOIN auth_sessions auth
        ON auth.id=$6
       AND auth.kind='tenant_admin'
       AND auth.subject_id=t.id
       AND auth.revoked_at IS NULL
       AND auth.expires_at>NOW()
      JOIN license_keys l
        ON l.id = $2
       AND l.tenant_id = t.id
       AND (
         (
           $4='super'
           AND l.super_key_hash IS NOT NULL
           AND l.status IN ('active','revoked')
         )
         OR
         (
           $4='normal'
           AND l.status='active'
           AND EXISTS (
             SELECT 1
             FROM license_devices ld
             WHERE ld.license_id=l.id
               AND ld.access_kind='normal'
               AND ld.device_hash=$5
               AND ld.revoked_at IS NULL
           )
         )
       )
      WHERE t.id = $1
        AND t.session_version = $3
    `,
    [
      payload.tenantId,
      payload.licenseId,
      Number(payload.sessionVersion || 0),
      accessKind,
      deviceHash,
      payload.sessionId,
    ],
  );
  const tenant = result.rows[0] || null;
  return tenant;
}

async function getTenantByCode(publicCode, client = pool) {
  const code = cleanText(publicCode, 100);
  if (!code) return null;
  const result = await client.query(`SELECT * FROM tenants WHERE public_code = $1`, [code]);
  return result.rows[0] || null;
}

function tenantAccessIssue(tenant) {
  if (!tenant) return 'TENANT_NOT_FOUND';
  if (tenant.status !== 'active') return 'LICENSE_REVOKED';
  if (new Date(tenant.access_expires_at).getTime() <= Date.now()) {
    return 'TENANT_EXPIRED';
  }
  return '';
}

function sendTenantAccessError(res, tenant, audience = 'admin') {
  const issue = tenantAccessIssue(tenant);
  if (issue === 'LICENSE_REVOKED') {
    return sendJson(res, 403, {
      ok: false,
      error:
        audience === 'admin'
          ? `你的卡密已被禁用，如有疑问请联系 Telegram ${CUSTOMER_SERVICE_TELEGRAM}。`
          : '该客服服务已停用，请联系商家。',
      code: issue,
      supportTelegram: CUSTOMER_SERVICE_TELEGRAM,
    });
  }
  const expiresAt = tenant?.access_expires_at
    ? new Date(tenant.access_expires_at).toISOString()
    : null;
  return sendJson(res, 403, {
    ok: false,
    error:
      audience === 'admin'
        ? `卡密已到期；${EXPIRED_TENANT_GRACE_DAYS} 天内续费可保留数据，逾期将自动清除。`
        : '该客服服务已到期，请联系商家续费。',
    code: issue === 'TENANT_NOT_FOUND' ? 'TENANT_NOT_FOUND' : 'TENANT_EXPIRED',
    expiresAt,
    dataDeleteAt: expiresAt
      ? new Date(
          new Date(expiresAt).getTime() +
            EXPIRED_TENANT_GRACE_DAYS * 86_400_000,
        ).toISOString()
      : null,
    graceDays: EXPIRED_TENANT_GRACE_DAYS,
  });
}

function publicTenant(tenant) {
  const expiresAt = new Date(tenant.access_expires_at);
  const remainingMs = expiresAt.getTime() - Date.now();
  return {
    id: tenant.id,
    publicCode: tenant.public_code,
    name: tenant.name || '',
    note: tenant.note || '',
    status: tenant.status,
    accessExpiresAt: expiresAt.toISOString(),
    dataDeleteAt: new Date(
      expiresAt.getTime() + EXPIRED_TENANT_GRACE_DAYS * 86_400_000,
    ).toISOString(),
    dataGraceDays: EXPIRED_TENANT_GRACE_DAYS,
    expiryWarning:
      tenant.status === 'active' &&
      remainingMs > 0 &&
      remainingMs <= 3 * 86_400_000,
    expiryReminderSentAt: tenant.expiry_reminder_sent_at
      ? new Date(tenant.expiry_reminder_sent_at).toISOString()
      : null,
    createdAt: new Date(tenant.created_at).toISOString(),
  };
}

async function touchConversation(conversationId, body = {}, req = null, tenantId) {
  if (!isUuid(conversationId) || !isUuid(tenantId)) return;
  const visitorIp = req ? cleanText(requestIp(req), 100) : '';
  const cloudflare = req
    ? cloudflareVisitorLocation(req)
    : { location: '', timezone: '' };
  const downlink = Number(body.downlinkMbps);
  const rtt = Number(body.rttMs);
  const result = await pool.query(
    `
      UPDATE conversations SET
        last_seen_at = NOW(),
        ip_address = CASE WHEN $2 <> '' THEN $2 ELSE ip_address END,
        ip_location = CASE
          WHEN $2 <> '' AND ip_address IS DISTINCT FROM $2 THEN $3
          WHEN $3 <> '' THEN $3
          ELSE ip_location
        END,
        timezone = CASE
          WHEN $2 <> '' AND ip_address IS DISTINCT FROM $2 THEN $4
          WHEN $4 <> '' THEN $4
          ELSE timezone
        END,
        device_type = CASE WHEN $5 <> '' THEN $5 ELSE device_type END,
        device_label = CASE WHEN $6 <> '' THEN $6 ELSE device_label END,
        entry_source = CASE WHEN $7 <> '' THEN $7 ELSE entry_source END,
        user_agent = CASE WHEN $8 <> '' THEN $8 ELSE user_agent END,
        referrer_url = CASE WHEN $9 <> '' THEN $9 ELSE referrer_url END,
        network_type = CASE WHEN $10 <> '' THEN $10 ELSE network_type END,
        network_effective_type = CASE
          WHEN $11 <> '' THEN $11
          ELSE network_effective_type
        END,
        downlink_mbps = CASE WHEN $12::numeric IS NOT NULL THEN $12 ELSE downlink_mbps END,
        rtt_ms = CASE WHEN $13::int IS NOT NULL THEN $13 ELSE rtt_ms END,
        save_data = CASE WHEN $14::boolean IS NOT NULL THEN $14 ELSE save_data END,
        client_template_id = CASE
          WHEN $15::uuid IS NOT NULL THEN $15
          ELSE client_template_id
        END,
        client_version = CASE WHEN $16 <> '' THEN $16 ELSE client_version END
      WHERE id = $1 AND tenant_id = $17
        AND (
          last_seen_at IS NULL
          OR last_seen_at < NOW() - INTERVAL '20 seconds'
          OR ($2 <> '' AND ip_address IS DISTINCT FROM $2)
          OR ($5 <> '' AND device_type IS DISTINCT FROM $5)
          OR ($6 <> '' AND device_label IS DISTINCT FROM $6)
          OR ($7 <> '' AND entry_source IS DISTINCT FROM $7)
          OR ($10 <> '' AND network_type IS DISTINCT FROM $10)
          OR ($11 <> '' AND network_effective_type IS DISTINCT FROM $11)
        )
      RETURNING *
    `,
    [
      conversationId,
      visitorIp,
      cloudflare.location,
      cloudflare.timezone,
      cleanText(body.deviceType, 30),
      cleanText(body.deviceLabel, 100),
      cleanText(body.entrySource, 80),
      cleanText(body.userAgent, 500),
      cleanText(body.referrerUrl, 500),
      cleanText(body.networkType, 30),
      cleanText(body.networkEffectiveType, 30),
      Number.isFinite(downlink) ? Math.max(0, Math.min(10000, downlink)) : null,
      Number.isFinite(rtt) ? Math.max(0, Math.min(120000, Math.trunc(rtt))) : null,
      typeof body.saveData === 'boolean' ? body.saveData : null,
      isUuid(body.clientTemplateId) ? body.clientTemplateId : null,
      cleanText(body.clientVersion, 30),
      tenantId,
    ],
  );
  return result.rows[0] || null;
}

async function createLicenseRecord(
  durationCode,
  metadata = {},
  queryClient = pool,
) {
  const duration = LICENSE_DURATIONS[durationCode];
  if (!duration) throw new Error('卡密时长无效。');
  const updateId = Number(metadata.telegramUpdateId);
  const telegramUpdateId = Number.isSafeInteger(updateId) ? updateId : null;

  async function existingForUpdate() {
    if (telegramUpdateId == null) return null;
    const result = await queryClient.query(
      `SELECT * FROM license_keys WHERE telegram_update_id = $1`,
      [telegramUpdateId],
    );
    const row = result.rows[0];
    if (!row) return null;
    const licenseKey = decryptLicenseKey(row.key_ciphertext);
    const superLicenseKey = decryptLicenseKey(row.super_key_ciphertext);
    if (!licenseKey) {
      throw new Error('此发卡请求已经处理，卡密已激活或不再可重复显示。');
    }
    return {
      licenseKey,
      superLicenseKey,
      row,
      duration: LICENSE_DURATIONS[row.duration_code] || duration,
    };
  }

  const existing = await existingForUpdate();
  if (existing) return existing;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const licenseKey = generateLicenseKey();
    const superLicenseKey = generateSuperLicenseKey();
    const maxDesktopDevices = Math.min(
      50,
      Math.max(
        1,
        Math.trunc(
          Number(metadata.maxDesktopDevices || LICENSE_DESKTOP_DEVICE_DEFAULT),
        ),
      ),
    );
    const maxMobileDevices = Math.min(
      50,
      Math.max(
        1,
        Math.trunc(
          Number(metadata.maxMobileDevices || LICENSE_MOBILE_DEVICE_DEFAULT),
        ),
      ),
    );
    const result = await queryClient.query(
        `
          INSERT INTO license_keys (
            id, key_hash, key_ciphertext, key_prefix, key_suffix,
            super_key_hash,super_key_ciphertext,super_key_suffix,
            max_desktop_devices,max_mobile_devices,
            duration_code, duration_days,
            telegram_chat_id, telegram_user_id, telegram_username,
            telegram_display_name, telegram_update_id, generated_by_admin_id,
            generated_by_distributor_id
          ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19
          )
          ON CONFLICT DO NOTHING
          RETURNING *
        `,
        [randomUUID(), hashLicenseKey(licenseKey), encryptLicenseKey(licenseKey),
         'VIP', licenseKey.slice(-5), hashLicenseKey(superLicenseKey),
         encryptLicenseKey(superLicenseKey), superLicenseKey.slice(-5),
         maxDesktopDevices, maxMobileDevices, durationCode, duration.days,
         cleanText(metadata.telegramChatId, 50),
         cleanText(metadata.telegramUserId, 50),
         cleanText(metadata.telegramUsername, 64),
         cleanText(metadata.telegramDisplayName, 120),
         telegramUpdateId,
         isUuid(metadata.generatedByAdminId)
           ? metadata.generatedByAdminId
           : null,
         isUuid(metadata.generatedByDistributorId)
           ? metadata.generatedByDistributorId
           : null],
    );
    if (result.rows[0]) {
      return {
        licenseKey,
        superLicenseKey,
        row: result.rows[0],
        duration,
      };
    }
    const duplicateUpdate = await existingForUpdate();
    if (duplicateUpdate) return duplicateUpdate;
    if (attempt === 4) throw new Error('生成卡密发生唯一值冲突。');
  }
  throw new Error('生成卡密失败。');
}

async function createLicenseRecordsBatch(
  durationCode,
  count,
  metadata = {},
  queryClient = pool,
) {
  const duration = LICENSE_DURATIONS[durationCode];
  if (!duration) throw new Error('卡密时长无效。');
  const requested = Math.max(1, Math.trunc(Number(count || 1)));
  const created = [];
  const generatedByAdminId = isUuid(metadata.generatedByAdminId)
    ? metadata.generatedByAdminId
    : null;
  const generatedByDistributorId = isUuid(metadata.generatedByDistributorId)
    ? metadata.generatedByDistributorId
    : null;
  const maxDesktopDevices = Math.min(
    50,
    Math.max(
      1,
      Math.trunc(
        Number(metadata.maxDesktopDevices || LICENSE_DESKTOP_DEVICE_DEFAULT),
      ),
    ),
  );
  const maxMobileDevices = Math.min(
    50,
    Math.max(
      1,
      Math.trunc(
        Number(metadata.maxMobileDevices || LICENSE_MOBILE_DEVICE_DEFAULT),
      ),
    ),
  );

  for (let attempt = 0; attempt < 5 && created.length < requested; attempt += 1) {
    const candidates = Array.from(
      { length: requested - created.length },
      () => {
        const licenseKey = generateLicenseKey();
        const superLicenseKey = generateSuperLicenseKey();
        return {
          id: randomUUID(),
          licenseKey,
          keyHash: hashLicenseKey(licenseKey),
          keyCiphertext: encryptLicenseKey(licenseKey),
          keySuffix: licenseKey.slice(-5),
          superLicenseKey,
          superKeyHash: hashLicenseKey(superLicenseKey),
          superKeyCiphertext: encryptLicenseKey(superLicenseKey),
          superKeySuffix: superLicenseKey.slice(-5),
        };
      },
    );
    const result = await queryClient.query(
      `
        INSERT INTO license_keys (
          id,key_hash,key_ciphertext,key_prefix,key_suffix,
          super_key_hash,super_key_ciphertext,super_key_suffix,
          max_desktop_devices,max_mobile_devices,
          duration_code,duration_days,telegram_chat_id,telegram_user_id,
          telegram_username,telegram_display_name,telegram_update_id,
          generated_by_admin_id,generated_by_distributor_id
        )
        SELECT
          input.id,input.key_hash,input.key_ciphertext,input.key_prefix,
          input.key_suffix,input.super_key_hash,input.super_key_ciphertext,
          input.super_key_suffix,input.max_desktop_devices,
          input.max_mobile_devices,input.duration_code,input.duration_days,
          input.telegram_chat_id,input.telegram_user_id,
          input.telegram_username,input.telegram_display_name,
          input.telegram_update_id,input.generated_by_admin_id,
          input.generated_by_distributor_id
        FROM unnest(
          $1::uuid[],$2::text[],$3::text[],$4::text[],$5::text[],
          $6::text[],$7::text[],$8::text[],$9::int[],$10::int[],
          $11::text[],$12::int[],$13::text[],$14::text[],$15::text[],
          $16::text[],$17::bigint[],$18::uuid[],$19::uuid[]
        ) AS input(
          id,key_hash,key_ciphertext,key_prefix,key_suffix,
          super_key_hash,super_key_ciphertext,super_key_suffix,
          max_desktop_devices,max_mobile_devices,duration_code,duration_days,
          telegram_chat_id,telegram_user_id,
          telegram_username,telegram_display_name,telegram_update_id,
          generated_by_admin_id,generated_by_distributor_id
        )
        ON CONFLICT DO NOTHING
        RETURNING *
      `,
      [
        candidates.map((item) => item.id),
        candidates.map((item) => item.keyHash),
        candidates.map((item) => item.keyCiphertext),
        candidates.map(() => 'VIP'),
        candidates.map((item) => item.keySuffix),
        candidates.map((item) => item.superKeyHash),
        candidates.map((item) => item.superKeyCiphertext),
        candidates.map((item) => item.superKeySuffix),
        candidates.map(() => maxDesktopDevices),
        candidates.map(() => maxMobileDevices),
        candidates.map(() => durationCode),
        candidates.map(() => duration.days),
        candidates.map(() => cleanText(metadata.telegramChatId, 50)),
        candidates.map(() => cleanText(metadata.telegramUserId, 50)),
        candidates.map(() => cleanText(metadata.telegramUsername, 64)),
        candidates.map(() => cleanText(metadata.telegramDisplayName, 120)),
        candidates.map(() => null),
        candidates.map(() => generatedByAdminId),
        candidates.map(() => generatedByDistributorId),
      ],
    );
    const rowsById = new Map(result.rows.map((row) => [row.id, row]));
    for (const candidate of candidates) {
      const row = rowsById.get(candidate.id);
      if (row) {
        created.push({
          licenseKey: candidate.licenseKey,
          superLicenseKey: candidate.superLicenseKey,
          row,
          duration,
        });
      }
    }
  }
  if (created.length !== requested) {
    throw new Error('生成卡密发生多次唯一值冲突。');
  }
  return created;
}

async function handleTenantLogin(req, res) {
  if (
    !rateLimit(req, res, 'tenant-login', 15, 10 * 60_000) ||
    !rateLimit(req, res, 'tenant-login-global', 120, 60_000, 'global')
  ) return;
  if (!await durableAuthRateLimit(
    req,
    res,
    'tenant-login',
    30,
    10 * 60_000,
  )) return;
  const body = await readJson(req, 64 * 1024);
  const key = normalizeLicenseKey(body.licenseKey);
  let accessKind = licenseKeyKind(key);
  if (!accessKind) {
    minuteCounters.licenseFailures += 1;
    await writeAudit(req, null, 'tenant.login', {
      targetType: 'tenant',
      result: 'failed',
      metadata: { code: 'LICENSE_INVALID' },
    }).catch(() => {});
    return sendError(res, 401, '卡密格式不正确。', 'LICENSE_INVALID');
  }
  const client = await pool.connect();
  let tenant;
  let license;
  let deviceHash = '';
  let sessionId = '';
  let newlyActivated = false;
  let activatedDistributorId = null;
  try {
    await client.query('BEGIN');
    const result = await client.query(
      `
        SELECT *,
          CASE WHEN super_key_hash=$1 THEN 'super' ELSE 'normal' END
            AS presented_access_kind
        FROM license_keys
        WHERE key_hash=$1 OR super_key_hash=$1
        FOR UPDATE
      `,
      [hashLicenseKey(key)],
    );
    license = result.rows[0];
    if (!license) {
      minuteCounters.licenseFailures += 1;
      const error = new Error('卡密不存在或输入错误。'); error.statusCode = 401; error.code = 'LICENSE_INVALID'; throw error;
    }
    accessKind = license.presented_access_kind === 'super' ? 'super' : 'normal';
    if (accessKind === 'normal' && license.status === 'revoked') {
      const error = new Error('此卡密已被停用，请联系平台。'); error.statusCode = 403; error.code = 'LICENSE_REVOKED'; throw error;
    }
    if (license.status === 'superseded') {
      const error = new Error('此卡密已被续费卡替换，请使用最新卡密。'); error.statusCode = 403; error.code = 'LICENSE_REPLACED'; throw error;
    }
    if (license.status === 'archived') {
      const error = new Error('此卡密已归档并停止使用，请联系平台。'); error.statusCode = 403; error.code = 'LICENSE_ARCHIVED'; throw error;
    }
    if (!license.tenant_id) {
      if (accessKind === 'normal' && license.status !== 'unused') {
        throw requestError('此卡密当前不能激活租户。', 409, 'LICENSE_STATE');
      }
      if (
        accessKind === 'super' &&
        !['unused', 'active', 'revoked'].includes(license.status)
      ) {
        throw requestError('此超级卡密当前不能激活租户。', 409, 'LICENSE_STATE');
      }
      const tenantId = randomUUID();
      const expiry = new Date(Date.now() + licenseDurationMilliseconds(license));
      const tenantResult = await client.query(
        `
          INSERT INTO tenants (
            id,public_code,access_expires_at,owner_distributor_id
          ) VALUES ($1,$2,$3,$4)
          RETURNING *
        `,
        [
          tenantId,
          generateTenantCode(),
          expiry.toISOString(),
          isUuid(license.generated_by_distributor_id)
            ? license.generated_by_distributor_id
            : null,
        ],
      );
      tenant = tenantResult.rows[0];
      newlyActivated = true;
      activatedDistributorId = tenant.owner_distributor_id || null;
      await createTenantConfig(tenantId, client);
      await client.query(
        `
          UPDATE license_keys
          SET tenant_id=$2,
              status=CASE WHEN status='unused' THEN 'active' ELSE status END,
              key_ciphertext=CASE WHEN $5='normal'
                THEN COALESCE(key_ciphertext,$4) ELSE key_ciphertext END,
              super_key_ciphertext=CASE WHEN $5='super'
                THEN COALESCE(super_key_ciphertext,$4)
                ELSE super_key_ciphertext END,
              activated_at=COALESCE(activated_at,NOW()),expires_at=$3,
              last_used_at=NOW(),updated_at=NOW()
          WHERE id=$1
        `,
        [
          license.id,
          tenantId,
          expiry.toISOString(),
          encryptLicenseKey(key),
          accessKind,
        ],
      );
      license = {
        ...license,
        tenant_id: tenantId,
        status: license.status === 'unused' ? 'active' : license.status,
        expires_at: expiry,
      };
    } else {
      tenant = await getTenantById(license.tenant_id, client, true);
      if (!tenant) {
        const error = new Error('租户账户不存在，请联系平台。'); error.statusCode = 409; error.code = 'LICENSE_STATE'; throw error;
      }
      const accessIssue = tenantAccessIssue(tenant);
      if (accessIssue === 'LICENSE_REVOKED') {
        throw requestError(
          `你的卡密已被禁用，如有疑问请联系 Telegram ${CUSTOMER_SERVICE_TELEGRAM}。`,
          403,
          'LICENSE_REVOKED',
        );
      }
      if (accessIssue === 'TENANT_EXPIRED') {
        const error = new Error(
          `卡密已到期，请尽快续费；到期后 ${EXPIRED_TENANT_GRACE_DAYS} 天未续费将自动清除租户数据。`,
        );
        error.statusCode = 403;
        error.code = 'TENANT_EXPIRED';
        error.expiresAt = new Date(tenant.access_expires_at).toISOString();
        error.dataDeleteAt = new Date(
          new Date(tenant.access_expires_at).getTime() +
            EXPIRED_TENANT_GRACE_DAYS * 86_400_000,
        ).toISOString();
        throw error;
      }
      await client.query(
        `
          UPDATE license_keys
          SET key_ciphertext=CASE WHEN $3='normal'
                THEN COALESCE(key_ciphertext,$2) ELSE key_ciphertext END,
              super_key_ciphertext=CASE WHEN $3='super'
                THEN COALESCE(super_key_ciphertext,$2)
                ELSE super_key_ciphertext END,
              last_used_at=CASE
                WHEN last_used_at IS NULL
                  OR last_used_at < NOW() - INTERVAL '15 minutes'
                THEN NOW() ELSE last_used_at END,
              updated_at=CASE
                WHEN last_used_at IS NULL
                  OR last_used_at < NOW() - INTERVAL '15 minutes'
                THEN NOW() ELSE updated_at END
          WHERE id=$1
        `,
        [license.id, encryptLicenseKey(key), accessKind],
      );
    }
    deviceHash = await registerLicenseDevice(
      client,
      req,
      license,
      body,
      accessKind,
    );
    sessionId = await createAuthSession(
      'tenant_admin',
      tenant.id,
      tenant.access_expires_at,
      client,
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    await writeAudit(req, null, 'tenant.login', {
      targetType: 'tenant',
      targetId: license?.tenant_id || '',
      result: 'failed',
      actorTenantId: license?.tenant_id || '',
      actorLicenseId: license?.id || '',
      metadata: { code: cleanText(error.code || 'ERROR', 80) },
    }).catch(() => {});
    if (error.code === 'LICENSE_REVOKED' && license?.id) {
      scheduleSecurityAnomaly({
        kind: 'revoked-license-login',
        req,
        tenantId: license.tenant_id || '',
        licenseId: license.id,
        severity: 'critical',
        count: 1,
        threshold: 1,
        details: {
          path: '/api/admin/login',
          detection: 'disabled-license-login-attempt',
          accessKind,
          allowLicenseBlock: false,
        },
      });
      if (
        accessKind === 'normal' &&
        license.status === 'revoked' &&
        license.disable_mode === 'busy'
      ) {
        return sendError(
          res,
          503,
          '服务器繁忙，请稍后再试。',
          'SERVER_BUSY',
        );
      }
      const supportTelegram = await currentCustomerServiceTelegram(client);
      return sendJson(res, 403, {
        ok: false,
        error: `你的卡密已被禁用，如有疑问请联系平台客服 Telegram ${supportTelegram}。`,
        code: 'LICENSE_REVOKED',
        supportTelegram,
      });
    }
    if (error.code === 'TENANT_EXPIRED') {
      return sendJson(res, error.statusCode, {
        ok: false,
        error: error.message,
        code: error.code,
        expiresAt: error.expiresAt,
        dataDeleteAt: error.dataDeleteAt,
        graceDays: EXPIRED_TENANT_GRACE_DAYS,
      });
    }
    throw error;
  } finally { client.release(); }
  const config = await getConfig(tenant.id);
  await writeAudit(req, null, 'tenant.login', {
    targetType: 'tenant',
    targetId: tenant.id,
    actorTenantId: tenant.id,
    actorLicenseId: license.id,
    metadata: { newlyActivated },
  }).catch(() => {});
  if (newlyActivated) {
    requestExpiryReminderReschedule();
    requestExpiredTenantPurgeReschedule();
    broadcastSuper({ type: 'licenses-updated' });
    broadcastSuper({ type: 'tenants-updated' });
    if (activatedDistributorId) {
      broadcastSuper({ type: 'distributors-updated' });
      broadcastDistributor(
        { type: 'distributor-licenses-updated' },
        activatedDistributorId,
      );
      broadcastDistributor(
        { type: 'distributor-tenants-updated' },
        activatedDistributorId,
      );
    }
  }
  return sendJson(res, 200, {
    ok: true,
    token: signTokenUntil({
      kind:'tenant_admin',
      tenantId:tenant.id,
      licenseId:license.id,
      sessionId,
      accessProof:tenantAdminAccessProof(license.id, accessKind),
      deviceHash,
      sessionVersion:Number(tenant.session_version || 1),
    }, tenant.access_expires_at),
    tenant: publicTenant(tenant),
    settings: config.settings,
  });
}

async function handleTenantRenew(req, res) {
  if (!rateLimit(req, res, 'tenant-renew', 10, 10 * 60_000)) return;
  const body = await readJson(req, 64 * 1024);
  const currentKey = normalizeLicenseKey(body.currentLicenseKey);
  const newKey = normalizeLicenseKey(body.newLicenseKey);
  if (
    licenseKeyKind(currentKey) !== 'normal' ||
    licenseKeyKind(newKey) !== 'normal' ||
    currentKey === newKey
  ) {
    return sendError(res, 400, '请输入当前卡密和新的续费卡密。', 'LICENSE_RENEW_INPUT');
  }
  const client = await pool.connect();
  let tenant, newLicense, newExpiry, deviceHash = '', sessionId = '';
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
    if (
      isUuid(tenant.owner_distributor_id) &&
      isUuid(newLicense.generated_by_distributor_id) &&
      tenant.owner_distributor_id !== newLicense.generated_by_distributor_id
    ) {
      const error = new Error('该租户归属其他代理，请向原代理购买续费卡密。');
      error.statusCode = 403;
      error.code = 'DISTRIBUTOR_OWNERSHIP';
      throw error;
    }
    const base = Math.max(Date.now(), new Date(tenant.access_expires_at).getTime());
    newExpiry = new Date(base + licenseDurationMilliseconds(newLicense));
    const tenantResult = await client.query(
      `
        UPDATE tenants
        SET status='active',
            access_expires_at=$2,
            owner_distributor_id=COALESCE(owner_distributor_id,$3),
            expiry_reminder_sent_at=NULL,
            updated_at=NOW()
        WHERE id=$1
        RETURNING *
      `,
      [
        tenant.id,
        newExpiry.toISOString(),
        isUuid(newLicense.generated_by_distributor_id)
          ? newLicense.generated_by_distributor_id
          : null,
      ],
    );
    tenant = tenantResult.rows[0];
    await client.query(
      `UPDATE license_keys SET key_ciphertext=COALESCE(key_ciphertext,$2),updated_at=NOW() WHERE id=$1`,
      [current.id, encryptLicenseKey(currentKey)],
    );
    await client.query(`UPDATE license_keys SET status='superseded',updated_at=NOW() WHERE tenant_id=$1 AND status='active'`, [tenant.id]);
    await client.query(
      `UPDATE license_keys SET tenant_id=$2,status='active',key_ciphertext=COALESCE(key_ciphertext,$4),activated_at=NOW(),expires_at=$3,last_used_at=NOW(),updated_at=NOW() WHERE id=$1`,
      [newLicense.id, tenant.id, newExpiry.toISOString(), encryptLicenseKey(newKey)],
    );
    newLicense = {
      ...newLicense,
      tenant_id: tenant.id,
      status: 'active',
      expires_at: newExpiry,
    };
    deviceHash = await registerLicenseDevice(
      client,
      req,
      newLicense,
      body,
      'normal',
    );
    sessionId = await createAuthSession(
      'tenant_admin',
      tenant.id,
      newExpiry,
      client,
    );
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
  updateTenantConnectionsAfterRenewal(tenant.id, newExpiry, newLicense.id);
  requestExpiryReminderReschedule();
  requestExpiredTenantPurgeReschedule();
  broadcastSuper({ type: 'licenses-updated' });
  broadcastSuper({ type: 'tenants-updated' });
  if (tenant.owner_distributor_id) {
    broadcastSuper({ type: 'distributors-updated' });
    broadcastDistributor(
      { type: 'distributor-licenses-updated' },
      tenant.owner_distributor_id,
    );
    broadcastDistributor(
      { type: 'distributor-tenants-updated' },
      tenant.owner_distributor_id,
    );
  }
  return sendJson(res, 200, {
    ok:true,
    token: signTokenUntil({
      kind:'tenant_admin',
      tenantId:tenant.id,
      licenseId:newLicense.id,
      sessionId,
      accessProof:tenantAdminAccessProof(newLicense.id, 'normal'),
      deviceHash,
      sessionVersion:Number(tenant.session_version || 1),
    }, newExpiry),
    tenant: publicTenant(tenant),
  });
}

function telegramOperatorAllowed(chat, userId) {
  if (userId == null || !TELEGRAM_ALLOWED_USER_IDS.has(String(userId))) {
    return false;
  }
  if (chat?.type === 'private') return true;
  return Boolean(
    ['group', 'supergroup'].includes(chat?.type) &&
      TELEGRAM_ALLOWED_GROUP_IDS.has(String(chat.id)),
  );
}

async function telegramOperatorAllowedAsync(chat, userId) {
  // 群管理员身份不等于平台管理员权限。所有敏感机器人操作都必须同时
  // 命中显式用户白名单；群聊还必须命中显式群白名单。
  return telegramOperatorAllowed(chat, userId);
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
      [{ text: '一小时卡', callback_data: 'license:1h' }],
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

function telegramGenerationClaimKey(callback) {
  const chatId = callback?.message?.chat?.id;
  const messageId = callback?.message?.message_id;
  return chatId != null && messageId != null
    ? `${chatId}:${messageId}`
    : '';
}

function claimTelegramGeneration(callback) {
  const key = telegramGenerationClaimKey(callback);
  if (!key) return { key: '', claimed: true };
  const now = Date.now();
  if (telegramGenerationClaims.size > 500) {
    for (const [item, expiresAt] of telegramGenerationClaims) {
      if (expiresAt <= now) telegramGenerationClaims.delete(item);
    }
  }
  if ((telegramGenerationClaims.get(key) || 0) > now) {
    return { key, claimed: false };
  }
  telegramGenerationClaims.set(key, now + 10 * 60_000);
  return { key, claimed: true };
}

function telegramGeneratedLicenseText(created) {
  return [
    '<b>普通卡密和管理员超级卡密已生成</b>',
    '你的后台网站是 <b>YKF000.com</b>',
    '为了你的隐私和客户安全',
    '请保护好你的卡密 不要泄露！',
    '',
    `卡密类型：${created.duration.label}`,
    `有效时长：首次登录后台后 ${licenseUnusedDurationLabel(created.row)}`,
    '',
    '<b>普通卡密（发给租户）</b>',
    `<code>${created.licenseKey}</code>`,
    '',
    '<b>管理员超级卡密（禁止发给租户）</b>',
    `<code>${created.superLicenseKey || '历史卡密未生成'}</code>`,
    '',
    `普通卡密设备上限：电脑 ${Number(created.row.max_desktop_devices || LICENSE_DESKTOP_DEVICE_DEFAULT)} 台｜手机/平板 ${Number(created.row.max_mobile_devices || LICENSE_MOBILE_DEVICE_DEFAULT)} 台`,
  ].join('\n');
}

function telegramGeneratedLicenseKeyboard(licenseKey, superLicenseKey = '') {
  return {
    inline_keyboard: [
      [
        {
          text: '📋 点击复制卡密',
          copy_text: { text: licenseKey },
        },
      ],
      ...(superLicenseKey
        ? [[{
            text: '🔐 复制管理员超级卡密',
            copy_text: { text: superLicenseKey },
          }]]
        : []),
    ],
  };
}

async function showTelegramGeneratedLicense(callback, created) {
  const chatId = callback.message?.chat?.id;
  const messageId = callback.message?.message_id;
  const payload = {
    text: telegramGeneratedLicenseText(created),
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    reply_markup: telegramGeneratedLicenseKeyboard(
      created.licenseKey,
      created.superLicenseKey,
    ),
  };
  if (chatId != null && messageId != null) {
    await telegramApi('editMessageText', {
      chat_id: chatId,
      message_id: messageId,
      ...payload,
    });
    return;
  }
  await telegramApi('sendMessage', {
    chat_id: chatId,
    ...payload,
    ...telegramThread(callback.message),
  });
}

function telegramThread(message) {
  return message?.message_thread_id
    ? { message_thread_id: message.message_thread_id }
    : {};
}

function telegramDisplayName(user = {}) {
  return cleanText(
    [user.first_name, user.last_name].filter(Boolean).join(' '),
    120,
  );
}

function escapeTelegramHtml(value) {
  return String(value ?? '').replace(
    /[&<>]/g,
    (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[char],
  );
}

function formatTelegramDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(date);
}

function assessCurrentCapacity(snapshot, yesterday = null) {
  const app = snapshot?.application || {};
  const database = snapshot?.database || {};
  const serverPressure =
    Number(app.cpuPercent || 0) >= 85 ||
    Number(app.memoryPercent || 0) >= 85 ||
    Number(app.p95ResponseMs || 0) >= 1000 ||
    (Number(app.requestsInWindow || 0) >= 20 &&
      Number(app.errorRate || 0) >= 5);
  const databasePressure =
    Number(database.poolWaiting || 0) > 0 ||
    Number(database.queryLatencyMs || 0) >= 500 ||
    Number(database.activeConnections || 0) >= Math.max(4, DB_POOL_MAX);
  const serverSustained = yesterday?.server?.status === 'upgrade';
  const databaseSustained = yesterday?.database?.status === 'upgrade';
  const server = serverPressure && serverSustained
    ? 'upgrade'
    : serverPressure
      ? 'watch'
      : 'healthy';
  const db = databasePressure && databaseSustained
    ? 'upgrade'
    : databasePressure
      ? 'watch'
      : 'healthy';
  const status = [server, db].includes('upgrade')
    ? 'upgrade'
    : [server, db].includes('watch')
      ? 'watch'
      : 'healthy';
  return {
    status,
    server,
    database: db,
    text: status === 'upgrade'
      ? `检测到当前压力且昨日也持续偏高：${server === 'upgrade' ? '建议增加服务器规格' : '服务器暂不升级'}；${db === 'upgrade' ? '建议增加数据库规格或连接容量' : '数据库暂不升级'}。`
      : status === 'watch'
        ? '当前出现短时峰值，但尚未达到持续扩容条件；先观察连续 3 个监控样本，避免不必要付费。'
        : '当前与历史指标均未达到扩容条件，服务器和数据库暂时都不用增加。',
  };
}

async function sendTelegramSystemStatus(message) {
  const [monitor, presence, yesterday] = await Promise.all([
    getMonitorSnapshotCached({ force: false, persist: false }),
    getRealtimeTenantPresence(),
    getYesterdaySystemAssessment(),
  ]);
  const capacity = assessCurrentCapacity(monitor, yesterday);
  const cf = monitor.provider?.cloudflareTurn || {};
  const serverStatus = capacity.server === 'upgrade'
    ? '建议扩容'
    : capacity.server === 'watch'
      ? '观察中'
      : '正常';
  const databaseStatus = capacity.database === 'upgrade'
    ? '建议扩容'
    : capacity.database === 'watch'
      ? '观察中'
      : '正常';
  const tenantLines = presence.tenants.slice(0, 15).map((tenant) => {
    const admin = tenant.adminDevices > 0
      ? `后台 ${tenant.adminDevices} 台在线`
      : '后台离线';
    const chat = tenant.activeChats > 0
      ? `正在双向聊天 ${tenant.activeChats} 个会话`
      : tenant.onlineVisitors > 0
        ? `在线访客 ${tenant.onlineVisitors} 人，暂未双向聊天`
        : '无在线访客';
    return `• ${escapeTelegramHtml(cleanText(tenant.name || '未命名租户', 40))}（<code>${escapeTelegramHtml(cleanText(tenant.publicCode || tenant.tenantId, 60))}</code>）：${admin}；${chat}`;
  });
  const cloudflareLines = cf.configured && cf.reachable
    ? [
        `<b>CF 本月计费出站</b>：${escapeTelegramHtml(formatBytes(cf.egressBytes))}`,
        `<b>CF 参考总额度</b>：${Number(cf.quotaGb || 0).toLocaleString('zh-CN')} GB`,
        `<b>CF 估算剩余</b>：${escapeTelegramHtml(formatBytes(cf.remainingBytes))}（已用 ${Number(cf.usedPercent || 0)}%）`,
      ]
    : [
        `<b>CF 通话额度</b>：${cf.configured ? `读取失败（${escapeTelegramHtml(cf.error || '未知错误')}）` : '尚未配置 Account Analytics 只读令牌'}`,
      ];
  await telegramApi('sendMessage', {
    chat_id: message.chat.id,
    text: [
      '<b>🖥 当前服务器状态</b>',
      `<b>采样时间</b>：${escapeTelegramHtml(formatTelegramDate(monitor.at))}`,
      `<b>运行时长</b>：${Math.floor(Number(monitor.uptimeSeconds || 0) / 3600)} 小时`,
      `<b>服务器</b>：${serverStatus}｜CPU ${Number(monitor.application?.cpuPercent || 0)}%｜内存 ${Number(monitor.application?.memoryPercent || 0)}%｜P95 ${Number(monitor.application?.p95ResponseMs || 0)}ms`,
      `<b>数据库</b>：${databaseStatus}｜查询 ${Number(monitor.database?.queryLatencyMs || 0)}ms｜容量 ${escapeTelegramHtml(formatBytes(monitor.database?.sizeBytes))}｜等待 ${Number(monitor.database?.poolWaiting || 0)}`,
      ...cloudflareLines,
      '',
      `<b>智能扩容判断</b>：${escapeTelegramHtml(capacity.text)}`,
      '',
      `<b>租户在线</b>：${presence.onlineTenantCount} 个后台 / ${presence.onlineTenantDevices} 台设备`,
      `<b>真实双向聊天</b>：${presence.chattingTenantCount} 个租户 / ${presence.onlineVisitors} 位在线访客`,
      ...tenantLines,
      ...(presence.tenants.length > 15
        ? [`…另有 ${presence.tenants.length - 15} 个在线租户未展开`]
        : []),
    ].join('\n'),
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    ...telegramThread(message),
  });
}

function telegramLicenseStatus(row) {
  if (row.status === 'unused') return '未激活';
  if (
    row.status === 'active' &&
    row.expires_at &&
    new Date(row.expires_at).getTime() <= Date.now()
  ) return '已到期';
  if (row.status === 'active') return '使用中';
  if (row.status === 'superseded') return '已续费替换';
  if (row.status === 'revoked') return '已禁用';
  if (row.status === 'archived') return '已归档';
  return row.status || '未知';
}

function telegramLicenseCreator(row) {
  const parts = [];
  if (row.telegram_display_name) parts.push(row.telegram_display_name);
  if (row.telegram_username) parts.push(`@${row.telegram_username}`);
  if (row.telegram_user_id) parts.push(`ID ${row.telegram_user_id}`);
  return parts.join(' · ') || '历史记录（未保存生成者）';
}

async function sendTelegramChunks(chatId, lines, message = null) {
  const chunks = [];
  let current = '';
  for (const line of lines) {
    const next = current ? `${current}\n${line}` : line;
    if (next.length > 3600 && current) {
      chunks.push(current);
      current = line;
    } else {
      current = next;
    }
  }
  if (current) chunks.push(current);
  for (const text of chunks) {
    await telegramApi('sendMessage', {
      chat_id: chatId,
      text,
      ...telegramThread(message),
    });
  }
}

async function sendAllLicenses(chatId, message, requestedPage = 1) {
  const pageSize = 50;
  const page = Math.min(
    10_000,
    Math.max(1, Math.trunc(Number(requestedPage || 1))),
  );
  const offset = (page - 1) * pageSize;
  const result = await pool.query(
    `
      WITH totals AS (
        SELECT COUNT(*)::int AS total_count FROM license_keys
      ), page_rows AS (
        SELECT
          id,key_prefix,key_suffix,duration_code,duration_days,
          super_key_suffix,
          status,telegram_user_id,telegram_username,telegram_display_name,
          activated_at,expires_at,revoked_at,created_at
        FROM license_keys
        ORDER BY created_at DESC,id DESC
        LIMIT $1 OFFSET $2
      )
      SELECT page_rows.*,totals.total_count AS _total_count
      FROM totals
      LEFT JOIN page_rows ON TRUE
      ORDER BY page_rows.created_at DESC,page_rows.id DESC
    `,
    [pageSize, offset],
  );
  const total = Number(result.rows[0]?._total_count || 0);
  const rows = result.rows.filter((row) => row.id);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const lines = [
    `📋 当前共有 ${total} 张卡密｜第 ${page}/${totalPages} 页`,
    '🔒 历史记录仅显示脱敏尾号；完整卡密只在生成当次显示。',
    '',
  ];
  if (!rows.length) {
    lines.push('该页没有卡密记录。');
  }
  rows.forEach((row, index) => {
    const expiry =
      row.status === 'unused'
        ? `首次登录后 ${licenseUnusedDurationLabel(row)}`
        : formatTelegramDate(row.expires_at);
    lines.push(
      `${offset + index + 1}. ${licenseHint(row)} · ${telegramLicenseStatus(row)}`,
      `管理员超级卡密：${superLicenseHint(row) || '历史卡密未生成'}`,
      `生成者：${telegramLicenseCreator(row)}`,
      `生成：${formatTelegramDate(row.created_at)}｜到期：${expiry}`,
      ...(row.revoked_at
        ? [`禁用：${formatTelegramDate(row.revoked_at)}`]
        : []),
      '',
    );
  });
  if (page < totalPages) {
    lines.push(`下一页：/keys ${page + 1}`);
  }
  await sendTelegramChunks(chatId, lines, message);
}

function normalizeNetlifySiteId(value) {
  const siteId = cleanText(value, 120);
  return /^[a-z0-9][a-z0-9-]{0,119}$/i.test(siteId) ? siteId : '';
}

function clientTemplateIdentifierMatches(value, template) {
  const identifier = cleanText(value, 120).toLowerCase();
  if (!isUuid(identifier)) return false;
  const internalTemplateId = String(template?.id || '').trim().toLowerCase();
  const netlifySiteId = normalizeNetlifySiteId(
    template?.netlify_site_id,
  ).toLowerCase();
  return (
    timingSafeTextEqual(identifier, internalTemplateId) ||
    Boolean(netlifySiteId) && timingSafeTextEqual(identifier, netlifySiteId)
  );
}

function normalizeNetlifyDomain(value) {
  let domain = cleanText(value, 300).trim().toLowerCase();
  domain = domain
    .replace(/^https?:\/\//i, '')
    .replace(/[/?#].*$/, '')
    .replace(/\.+$/, '');
  return /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.netlify\.app$/i.test(domain)
    ? domain
    : '';
}

function parseQrIncidentDomainReply(value) {
  const raw = cleanText(value, 500).trim();
  const match = raw.match(/^更换域名\s*(.+)$/i);
  if (!match) return { matched: false, domain: '' };
  if (!/\.netlify\.app(?:[/?#]|$)/i.test(match[1])) {
    return { matched: false, domain: '' };
  }
  return { matched: true, domain: normalizeNetlifyDomain(match[1]) };
}

function parseTenantEntryDomainSwitchCommand(value) {
  const raw = cleanText(value, 500).trim();
  const match = raw.match(/^更换域名\s*(.+)$/i);
  if (!match || /\.netlify\.app(?:[/?#]|$)/i.test(match[1])) {
    return { matched: false, domain: '' };
  }
  return {
    matched: true,
    domain: normalizeTenantDomainSuffix(match[1]),
  };
}

function displayTemplateDomain(value) {
  try {
    return new URL(value).hostname;
  } catch {
    return cleanText(value, 300) || '未知域名';
  }
}

function displayTenantEntryDomain(value, entryHost = '') {
  return normalizeTenantEntryHost(entryHost) ||
    tenantEntryHostFromNetlifyUrl(value) ||
    displayTemplateDomain(value);
}

async function sendTelegramReply(message, text, extra = {}) {
  return telegramApi('sendMessage', {
    chat_id: message.chat.id,
    text,
    reply_parameters: {
      message_id: message.message_id,
      allow_sending_without_reply: true,
    },
    ...telegramThread(message),
    ...extra,
  });
}

async function cloudflareApi(pathname, { method = 'GET', body } = {}) {
  if (!CLOUDFLARE_API_TOKEN) {
    throw new Error('服务器尚未配置 CLOUDFLARE_API_TOKEN。');
  }
  const response = await fetch(
    `https://api.cloudflare.com/client/v4${pathname}`,
    {
      method,
      headers: {
        Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(20_000),
    },
  );
  const result = await response.json().catch(() => null);
  if (!response.ok || result?.success === false) {
    const message = cleanText(
      result?.errors?.[0]?.message ||
        result?.messages?.[0]?.message ||
        `Cloudflare 返回状态 ${response.status}`,
      300,
    );
    throw new Error(message || 'Cloudflare 请求失败。');
  }
  return result?.result;
}

async function inspectCloudflareTenantEntryDomain(
  value,
  { ensure = false } = {},
) {
  const domain = normalizeTenantDomainSuffix(value);
  if (!domain) throw new Error('根域名格式无效。');
  const zones = await cloudflareApi(
    `/zones?name=${encodeURIComponent(domain)}&per_page=5`,
  );
  const zone = Array.isArray(zones)
    ? zones.find((item) => String(item?.name || '').toLowerCase() === domain)
    : null;
  if (!zone) {
    throw new Error(`Cloudflare 中没有找到 ${domain}，请先添加该域名。`);
  }
  if (zone.status !== 'active') {
    throw new Error(
      `${domain} 在 Cloudflare 中尚未 Active，请先把 Cloudflare 名称服务器填入 Spaceship。`,
    );
  }

  const wildcardName = `*.${domain}`;
  let dnsRecords = await cloudflareApi(
    `/zones/${encodeURIComponent(zone.id)}/dns_records?name=${encodeURIComponent(wildcardName)}&per_page=100`,
  );
  dnsRecords = Array.isArray(dnsRecords) ? dnsRecords : [];
  let dnsRecord = dnsRecords.find((item) =>
    String(item?.name || '').toLowerCase() === wildcardName &&
    ['A', 'AAAA', 'CNAME'].includes(item?.type),
  );
  if (ensure && !dnsRecord) {
    dnsRecord = await cloudflareApi(
      `/zones/${encodeURIComponent(zone.id)}/dns_records`,
      {
        method: 'POST',
        body: {
          type: 'A',
          name: '*',
          content: CLOUDFLARE_TENANT_ENTRY_DNS_IPV4,
          ttl: 1,
          proxied: true,
          comment: 'Tuojie tenant entry Worker wildcard',
        },
      },
    );
  } else if (ensure && dnsRecord && !dnsRecord.proxied) {
    dnsRecord = await cloudflareApi(
      `/zones/${encodeURIComponent(zone.id)}/dns_records/${encodeURIComponent(dnsRecord.id)}`,
      { method: 'PATCH', body: { proxied: true } },
    );
  }

  const routePattern = `*.${domain}/*`;
  let routes = await cloudflareApi(
    `/zones/${encodeURIComponent(zone.id)}/workers/routes`,
  );
  routes = Array.isArray(routes) ? routes : [];
  let workerRoute = routes.find((item) =>
    String(item?.pattern || '').toLowerCase() === routePattern,
  );
  if (ensure && !workerRoute) {
    workerRoute = await cloudflareApi(
      `/zones/${encodeURIComponent(zone.id)}/workers/routes`,
      {
        method: 'POST',
        body: {
          pattern: routePattern,
          script: CLOUDFLARE_TENANT_ENTRY_WORKER_SCRIPT,
        },
      },
    );
  }

  const ready = Boolean(
    dnsRecord?.proxied &&
    workerRoute &&
    String(workerRoute.script || '') === CLOUDFLARE_TENANT_ENTRY_WORKER_SCRIPT,
  );
  if (ensure && !ready) {
    throw new Error(`${domain} 的通配 DNS 或 Worker 路由尚未就绪。`);
  }
  return {
    domain,
    zoneId: cleanText(zone.id, 80),
    zoneStatus: cleanText(zone.status, 30),
    dnsRecordId: cleanText(dnsRecord?.id, 80),
    dnsReady: Boolean(dnsRecord?.proxied),
    workerRouteId: cleanText(workerRoute?.id, 80),
    routeReady: Boolean(
      workerRoute &&
      String(workerRoute.script || '') === CLOUDFLARE_TENANT_ENTRY_WORKER_SCRIPT,
    ),
    ready,
  };
}

async function recordTenantEntryDomainInspection(
  domain,
  inspection = null,
  error = null,
) {
  const normalized = normalizeTenantDomainSuffix(domain);
  if (!normalized) return;
  tenantEntryRootDomains.add(normalized);
  await pool.query(
    `
      INSERT INTO tenant_entry_root_domains (
        domain,status,cloudflare_zone_id,dns_record_id,worker_route_id,
        last_error,last_checked_at,updated_at
      ) VALUES (
        $1,$2,$3,$4,$5,$6,NOW(),NOW()
      )
      ON CONFLICT (domain) DO UPDATE SET
        status=CASE
          WHEN tenant_entry_root_domains.status IN ('current','historical')
            THEN tenant_entry_root_domains.status
          ELSE EXCLUDED.status
        END,
        cloudflare_zone_id=EXCLUDED.cloudflare_zone_id,
        dns_record_id=EXCLUDED.dns_record_id,
        worker_route_id=EXCLUDED.worker_route_id,
        last_error=EXCLUDED.last_error,
        last_checked_at=NOW(),
        updated_at=CASE
          WHEN tenant_entry_root_domains.status IS DISTINCT FROM EXCLUDED.status
            OR tenant_entry_root_domains.cloudflare_zone_id IS DISTINCT FROM EXCLUDED.cloudflare_zone_id
            OR tenant_entry_root_domains.dns_record_id IS DISTINCT FROM EXCLUDED.dns_record_id
            OR tenant_entry_root_domains.worker_route_id IS DISTINCT FROM EXCLUDED.worker_route_id
            OR tenant_entry_root_domains.last_error IS DISTINCT FROM EXCLUDED.last_error
          THEN NOW()
          ELSE tenant_entry_root_domains.updated_at
        END
    `,
    [
      normalized,
      inspection?.ready ? 'available' : error ? 'error' : 'pending',
      cleanText(inspection?.zoneId, 80),
      cleanText(inspection?.dnsRecordId, 80),
      cleanText(inspection?.workerRouteId, 80),
      cleanText(error?.message || error, 500),
    ],
  );
  tenantEntryDomainStatusCache.expiresAt = 0;
}

async function listTenantEntryRootDomains(force = false) {
  if (!force && tenantEntryDomainStatusCache.expiresAt > Date.now()) {
    return tenantEntryDomainStatusCache.rows;
  }
  const result = await pool.query(`
    SELECT domain,status,cloudflare_zone_id,dns_record_id,worker_route_id,
           last_error,last_checked_at,activated_at,created_at,updated_at
    FROM tenant_entry_root_domains
    ORDER BY
      CASE status
        WHEN 'current' THEN 0
        WHEN 'available' THEN 1
        WHEN 'historical' THEN 2
        WHEN 'pending' THEN 3
        ELSE 4
      END,
      domain
  `);
  tenantEntryDomainStatusCache = {
    expiresAt: Date.now() + TENANT_ENTRY_DOMAIN_STATUS_CACHE_MS,
    rows: result.rows,
  };
  for (const row of result.rows) {
    const domain = normalizeTenantDomainSuffix(row.domain);
    if (domain) tenantEntryRootDomains.add(domain);
  }
  return result.rows;
}

async function refreshTenantEntryDomainStatuses() {
  const rows = await listTenantEntryRootDomains(true);
  for (const row of rows) {
    const checkedAt = row.last_checked_at
      ? new Date(row.last_checked_at).getTime()
      : 0;
    if (checkedAt && Date.now() - checkedAt < TENANT_ENTRY_DOMAIN_STATUS_CACHE_MS) {
      continue;
    }
    try {
      const inspection = await inspectCloudflareTenantEntryDomain(row.domain);
      await recordTenantEntryDomainInspection(row.domain, inspection);
    } catch (error) {
      await recordTenantEntryDomainInspection(row.domain, null, error);
    }
  }
  return listTenantEntryRootDomains(true);
}

function tenantEntryDomainSwitchKeyboard(requestId) {
  return {
    inline_keyboard: [[
      {
        text: '✅ 确认切换',
        callback_data: `domain:switch:${requestId}`,
      },
      {
        text: '取消',
        callback_data: `domain:cancel:${requestId}`,
      },
    ]],
  };
}

function tenantEntryDomainListText(rows) {
  const group = (status) => rows.filter((row) => row.status === status);
  const current = group('current');
  const available = group('available');
  const historical = group('historical');
  const pending = group('pending');
  const errors = group('error');
  const lines = [
    '<b>🌐 客服入口域名池</b>',
    '',
    '<b>🟢 当前使用</b>',
    ...(current.length
      ? current.map((row) => `  • <code>${escapeTelegramHtml(row.domain)}</code>`)
      : ['  • 暂无']),
    '',
    `<b>✅ 已解析 · 未使用（${available.length}）</b>`,
    ...(available.length
      ? available.map((row) => `  • <code>${escapeTelegramHtml(row.domain)}</code>`)
      : ['  • 暂无']),
    '',
    `<b>📚 历史保留（${historical.length}）</b>`,
    ...(historical.length
      ? historical.map((row) => `  • <code>${escapeTelegramHtml(row.domain)}</code> · 旧二维码继续有效`)
      : ['  • 暂无']),
  ];
  if (pending.length) {
    lines.push(
      '',
      `<b>🕘 待完成解析（${pending.length}）</b>`,
      ...pending.map((row) => `  • <code>${escapeTelegramHtml(row.domain)}</code>`),
    );
  }
  if (errors.length) {
    lines.push(
      '',
      `<b>⚠️ 需要处理（${errors.length}）</b>`,
      ...errors.map((row) =>
        `  • <code>${escapeTelegramHtml(row.domain)}</code>\n    ${escapeTelegramHtml(cleanText(row.last_error, 160) || '检查失败')}`,
      ),
    );
  }
  lines.push(
    '',
    '<b>切换格式</b>',
    '<code>更换域名 6687878.xyz</code>',
    '',
    '切换后旧域名不会删除，原链接、二维码和聊天记录继续有效。',
  );
  return lines.join('\n');
}

async function sendTenantEntryDomainList(message) {
  let rows;
  try {
    rows = await refreshTenantEntryDomainStatuses();
  } catch (error) {
    rows = await listTenantEntryRootDomains(true);
  }
  await sendTelegramReply(message, tenantEntryDomainListText(rows), {
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
  });
}

async function createTenantEntryDomainSwitchRequest(message, domain) {
  if (!domain) {
    await sendTelegramReply(
      message,
      '❌ 域名格式不正确。\n\n请使用：<code>更换域名 6687878.xyz</code>',
      { parse_mode: 'HTML' },
    );
    return;
  }
  tenantEntryRootDomains.add(domain);
  let inspection;
  try {
    inspection = await inspectCloudflareTenantEntryDomain(domain);
    await recordTenantEntryDomainInspection(domain, inspection);
  } catch (error) {
    await recordTenantEntryDomainInspection(domain, null, error).catch(() => {});
    await sendTelegramReply(
      message,
      [
        '<b>❌ 域名暂时不能切换</b>',
        '',
        `<b>域名</b>：<code>${escapeTelegramHtml(domain)}</code>`,
        `<b>原因</b>：${escapeTelegramHtml(cleanText(error.message, 300))}`,
        '',
        '请先在 Cloudflare 添加域名，并把 Cloudflare 提供的名称服务器填入 Spaceship，等待状态变为 Active。',
      ].join('\n'),
      { parse_mode: 'HTML', link_preview_options: { is_disabled: true } },
    );
    return;
  }

  const current = (await listTenantEntryRootDomains(true))
    .find((row) => row.status === 'current');
  if (current?.domain === domain) {
    await sendTelegramReply(
      message,
      `ℹ️ <code>${escapeTelegramHtml(domain)}</code> 已经是当前使用的域名。`,
      { parse_mode: 'HTML' },
    );
    return;
  }
  const requestId = randomUUID();
  await pool.query(
    `
      INSERT INTO tenant_entry_domain_switch_requests (
        id,domain,telegram_chat_id,requested_by_telegram_user_id,
        previous_domain
      ) VALUES ($1,$2,$3,$4,$5)
    `,
    [
      requestId,
      domain,
      String(message.chat.id),
      String(message.from?.id || ''),
      cleanText(current?.domain, 253),
    ],
  );
  const sent = await sendTelegramReply(
    message,
    [
      '<b>⚠️ 确认切换客服入口域名</b>',
      '',
      `<b>当前域名</b>：<code>${escapeTelegramHtml(current?.domain || '未设置')}</code>`,
      `<b>目标域名</b>：<code>${escapeTelegramHtml(domain)}</code>`,
      '',
      `<b>Cloudflare Zone</b>：${inspection.zoneStatus === 'active' ? '✅ Active' : '⚠️ 未就绪'}`,
      `<b>通配 DNS</b>：${inspection.dnsReady ? '✅ 已解析' : '🛠 将自动创建'}`,
      `<b>Worker 路由</b>：${inspection.routeReady ? '✅ 已绑定' : '🛠 将自动绑定'}`,
      '',
      '确认后系统会配置缺少的项目、更新全部模板入口并逐个验收。全部成功后才完成切换；失败会恢复原域名。',
      '',
      '旧域名会作为历史入口永久保留，旧二维码和聊天记录不会失效。',
    ].join('\n'),
    {
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      reply_markup: tenantEntryDomainSwitchKeyboard(requestId),
    },
  );
  await pool.query(
    `UPDATE tenant_entry_domain_switch_requests
     SET telegram_message_id=$2,updated_at=NOW()
     WHERE id=$1`,
    [requestId, sent.message_id],
  );
}

async function smokeTestTenantEntryHosts(changes) {
  for (const change of changes.filter((item) =>
    ['testing', 'enabled'].includes(item.status),
  )) {
    const response = await fetch(
      `https://${change.newHost}/?tenant=domain-switch-smoke`,
      {
        method: 'GET',
        redirect: 'manual',
        headers: { 'User-Agent': 'Tuojie-Domain-Switch-Smoke/2.4.8' },
        signal: AbortSignal.timeout(20_000),
      },
    );
    const contentType = String(response.headers.get('content-type') || '')
      .toLowerCase();
    if (
      response.status !== 200 ||
      !contentType.includes('text/html')
    ) {
      throw new Error(`${change.newHost} HTTPS 验收失败（${response.status}）。`);
    }
    const html = await response.text();
    if (
      !/<html[\s>]/i.test(html) ||
      !/tuojie-template-(?:id|name)|notificationSettingsButton|在线客服/i.test(html)
    ) {
      throw new Error(`${change.newHost} 返回的不是客服模板页面。`);
    }
  }
}

async function restoreTenantEntryRootDomainSwitch(
  changes,
  tenantChanges,
  previousDomain,
  targetDomain,
) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext('tenant-entry-host-registry'))`,
    );
    for (const change of changes) {
      await client.query(
        `UPDATE frontend_templates SET entry_host=$2,updated_at=NOW() WHERE id=$1`,
        [change.templateId, change.oldHost],
      );
    }
    for (const change of tenantChanges) {
      await client.query(
        `UPDATE tenant_template_domains
         SET hostname=$3,root_domain=$4,updated_at=NOW()
         WHERE tenant_id=$1 AND template_id=$2`,
        [
          change.tenantId,
          change.templateId,
          change.oldHost,
          previousDomain,
        ],
      );
    }
    await client.query(
      `UPDATE tenant_entry_root_domains
       SET status='available',updated_at=NOW()
       WHERE domain=$1`,
      [targetDomain],
    );
    await client.query(
      `UPDATE tenant_entry_root_domains
       SET status='current',updated_at=NOW()
       WHERE domain=$1`,
      [previousDomain],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }
  activeTenantEntryRootDomain = previousDomain;
  invalidateTenantCaches();
  invalidateTenantEntryCaches();
  invalidateApprovedOrigins();
  await refreshApprovedOrigins(true);
}

async function switchTenantEntryRootDomain(
  value,
  { telegramUserId = '', requestId = '' } = {},
) {
  const domain = normalizeTenantDomainSuffix(value);
  if (!domain) throw new Error('目标根域名格式无效。');
  tenantEntryRootDomains.add(domain);
  const inspection = await inspectCloudflareTenantEntryDomain(
    domain,
    { ensure: true },
  );
  await recordTenantEntryDomainInspection(domain, inspection);

  const client = await pool.connect();
  let changes = [];
  let tenantChanges = [];
  let previousDomain = '';
  try {
    await client.query('BEGIN');
    await client.query(
      `SELECT pg_advisory_xact_lock(hashtext('tenant-entry-host-registry'))`,
    );
    const currentDomain = await client.query(
      `SELECT domain FROM tenant_entry_root_domains WHERE status='current' LIMIT 1`,
    );
    previousDomain = cleanText(currentDomain.rows[0]?.domain, 253);
    if (previousDomain === domain) {
      await client.query('ROLLBACK');
      return { duplicate: true, previousDomain, domain, changes: [] };
    }
    const templates = await client.query(`
      SELECT id,name,base_url,entry_host,status
      FROM frontend_templates
      ORDER BY sort_order,created_at
      FOR UPDATE
    `);
    for (const template of templates.rows) {
      const oldHost = normalizeTenantEntryHost(template.entry_host);
      const label = tenantEntryHostLabel(oldHost) || netlifySiteLabel(template.base_url);
      const newHost = normalizeTenantEntryHost(`${label}.${domain}`);
      if (!oldHost || !label || !newHost) {
        throw new Error(`模板 ${template.name || template.id} 无法生成新入口域名。`);
      }
      await assertTemplateEntryHostAvailable(client, newHost, template.id);
      await storeTemplateEntryAlias(client, template.id, oldHost);
      await client.query(
        `DELETE FROM frontend_template_entry_aliases
         WHERE hostname=$1 AND template_id=$2`,
        [newHost, template.id],
      );
      changes.push({
        templateId: template.id,
        templateName: template.name,
        status: template.status,
        oldHost,
        newHost,
      });
    }
    for (const change of changes) {
      await client.query(
        `UPDATE frontend_templates SET entry_host=$2,updated_at=NOW() WHERE id=$1`,
        [change.templateId, change.newHost],
      );
    }
    const tenantDomains = await client.query(`
      SELECT domains.*,templates.name AS template_name,
             templates.status AS template_status
      FROM tenant_template_domains domains
      JOIN frontend_templates templates ON templates.id=domains.template_id
      ORDER BY domains.created_at
      FOR UPDATE OF domains
    `);
    for (const tenantDomain of tenantDomains.rows) {
      const oldHost = normalizeTenantEntryHost(tenantDomain.hostname);
      const label = tenantEntryHostLabel(tenantDomain.label || oldHost);
      const newHost = normalizeTenantEntryHost(`${label}.${domain}`);
      if (!oldHost || !label || !newHost) {
        throw new Error('租户模板短域名无法生成新的入口地址。');
      }
      await client.query(
        `INSERT INTO tenant_template_domain_aliases (
           hostname,tenant_id,template_id
         ) VALUES ($1,$2,$3)
         ON CONFLICT (hostname) DO NOTHING`,
        [oldHost, tenantDomain.tenant_id, tenantDomain.template_id],
      );
      const aliasOwner = await client.query(
        `SELECT tenant_id,template_id FROM tenant_template_domain_aliases
         WHERE hostname=$1`,
        [oldHost],
      );
      if (
        aliasOwner.rows[0]?.tenant_id !== tenantDomain.tenant_id ||
        aliasOwner.rows[0]?.template_id !== tenantDomain.template_id
      ) {
        throw new Error(`历史短域名 ${oldHost} 归属冲突。`);
      }
      await client.query(
        `UPDATE tenant_template_domains
         SET hostname=$3,root_domain=$4,updated_at=NOW()
         WHERE tenant_id=$1 AND template_id=$2`,
        [tenantDomain.tenant_id, tenantDomain.template_id, newHost, domain],
      );
      tenantChanges.push({
        tenantId: tenantDomain.tenant_id,
        templateId: tenantDomain.template_id,
        templateName: tenantDomain.template_name,
        status: tenantDomain.template_status,
        oldHost,
        newHost,
      });
    }
    await client.query(
      `UPDATE tenant_entry_root_domains
       SET status='historical',last_error='',updated_at=NOW()
       WHERE domain=$1`,
      [previousDomain],
    );
    await client.query(
      `UPDATE tenant_entry_root_domains
       SET status='current',activated_at=NOW(),last_error='',updated_at=NOW()
       WHERE domain=$1`,
      [domain],
    );
    await client.query(
      `INSERT INTO audit_logs (
        action,target_type,target_id,metadata,risk_level,summary
      ) VALUES (
        'tenant_entry.root_domain_switch','tenant_entry_root_domain',
        $2,$1::jsonb,'critical','Telegram 管理员切换了客服入口根域名'
      )`,
      [JSON.stringify({
        requestId,
        previousDomain,
        domain,
        telegramUserId: cleanText(telegramUserId, 80),
        templateCount: changes.length,
        tenantTemplateDomainCount: tenantChanges.length,
      }), domain],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    client.release();
  }

  activeTenantEntryRootDomain = domain;
  invalidateTenantCaches();
  invalidateTenantEntryCaches();
  invalidateApprovedOrigins();
  try {
    await refreshApprovedOrigins(true);
    const tenantSmokeSample = tenantChanges
      .filter((item) => ['testing', 'enabled'].includes(item.status))
      .slice(0, 20);
    await smokeTestTenantEntryHosts([...changes, ...tenantSmokeSample]);
  } catch (error) {
    await restoreTenantEntryRootDomainSwitch(
      changes,
      tenantChanges,
      previousDomain,
      domain,
    );
    throw error;
  }
  publishEvent(
    { type: 'frontend_catalog_updated' },
    { targetKind: 'tenant_admin' },
  );
  broadcastSuper({ type: 'frontend_catalog_updated' });
  return {
    duplicate: false,
    previousDomain,
    domain,
    changes,
    tenantChanges,
  };
}

async function handleTenantEntryDomainCallback(callback) {
  const match = String(callback?.data || '').match(
    /^domain:(switch|cancel):([0-9a-f-]{36})$/i,
  );
  if (!match || !isUuid(match[2])) return false;
  const chat = callback.message?.chat;
  const userId = callback.from?.id;
  if (!(await telegramOperatorAllowedAsync(chat, userId))) {
    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '当前用户或群组未被授权。',
      show_alert: true,
    });
    return true;
  }
  const requestId = match[2];
  const request = await pool.query(
    `SELECT * FROM tenant_entry_domain_switch_requests WHERE id=$1 LIMIT 1`,
    [requestId],
  );
  const row = request.rows[0];
  if (!row || row.status !== 'pending' || new Date(row.expires_at) <= new Date()) {
    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '此切换确认已失效或已经处理。',
      show_alert: true,
    });
    return true;
  }
  if (match[1] === 'cancel') {
    await pool.query(
      `UPDATE tenant_entry_domain_switch_requests
       SET status='cancelled',updated_at=NOW()
       WHERE id=$1 AND status='pending'`,
      [requestId],
    );
    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '已取消切换。',
    });
    await clearTelegramCallbackKeyboard(callback.message);
    await sendTelegramReply(callback.message, '已取消本次域名切换。');
    return true;
  }

  const claimed = await pool.query(
    `UPDATE tenant_entry_domain_switch_requests
     SET status='processing',confirmed_by_telegram_user_id=$2,updated_at=NOW()
     WHERE id=$1 AND status='pending' AND expires_at>NOW()
     RETURNING *`,
    [requestId, String(userId || '')],
  );
  if (!claimed.rows[0]) {
    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '切换已经由其他管理员处理。',
      show_alert: true,
    });
    return true;
  }
  await telegramApi('answerCallbackQuery', {
    callback_query_id: callback.id,
    text: '正在配置和验收，请稍候…',
  }).catch(() => {});
  await clearTelegramCallbackKeyboard(callback.message);
  try {
    const result = await switchTenantEntryRootDomain(row.domain, {
      telegramUserId: String(userId || ''),
      requestId,
    });
    await pool.query(
      `UPDATE tenant_entry_domain_switch_requests
       SET status='completed',previous_domain=$2,error='',updated_at=NOW()
       WHERE id=$1`,
      [requestId, result.previousDomain],
    );
    await telegramApi('sendMessage', {
      chat_id: chat.id,
      text: [
        '<b>✅ 客服入口域名切换完成</b>',
        '',
        `<b>原域名</b>：<code>${escapeTelegramHtml(result.previousDomain)}</code>`,
        `<b>新域名</b>：<code>${escapeTelegramHtml(result.domain)}</code>`,
        `<b>模板数量</b>：${result.changes.length} 个`,
        '',
        '✅ 通配 DNS 已就绪',
        '✅ Worker 路由已就绪',
        '✅ HTTPS 与模板入口已验收',
        '✅ 新生成链接已使用新域名',
        '✅ 旧链接、旧二维码和原聊天记录继续有效',
      ].join('\n'),
      parse_mode: 'HTML',
      link_preview_options: { is_disabled: true },
      ...telegramThread(callback.message),
    });
  } catch (error) {
    await pool.query(
      `UPDATE tenant_entry_domain_switch_requests
       SET status='failed',error=$2,updated_at=NOW()
       WHERE id=$1`,
      [requestId, cleanText(error.message, 500)],
    ).catch(() => {});
    await telegramApi('sendMessage', {
      chat_id: chat.id,
      text: [
        '<b>❌ 域名切换失败</b>',
        '',
        `<b>目标域名</b>：<code>${escapeTelegramHtml(row.domain)}</code>`,
        `<b>原因</b>：${escapeTelegramHtml(cleanText(error.message, 300))}`,
        '',
        '系统已停止切换；如果数据库已进入新域名阶段，也已自动恢复原域名。',
      ].join('\n'),
      parse_mode: 'HTML',
      ...telegramThread(callback.message),
    });
  }
  return true;
}

async function updateNetlifySiteDomain(siteId, domain) {
  if (!NETLIFY_AUTH_TOKEN) {
    throw new Error('服务器尚未配置 NETLIFY_AUTH_TOKEN。');
  }
  const normalizedSiteId = normalizeNetlifySiteId(siteId);
  const normalizedDomain = normalizeNetlifyDomain(domain);
  if (!normalizedSiteId || !normalizedDomain) {
    throw new Error('Netlify Site ID 或目标域名格式无效。');
  }
  const siteName = normalizedDomain.slice(0, -'.netlify.app'.length);
  const response = await fetch(
    `https://api.netlify.com/api/v1/sites/${encodeURIComponent(normalizedSiteId)}`,
    {
      method: 'PATCH',
      headers: {
        Authorization: `Bearer ${NETLIFY_AUTH_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ name: siteName }),
      signal: AbortSignal.timeout(20_000),
    },
  );
  const result = await response.json().catch(() => null);
  if (!response.ok) {
    throw new Error(
      cleanText(
        result?.message || result?.error || `Netlify 返回状态 ${response.status}`,
        300,
      ),
    );
  }
  const returnedName = cleanText(result?.name, 120).toLowerCase();
  if (returnedName && returnedName !== siteName) {
    throw new Error('Netlify 返回的站点名称与目标域名不一致。');
  }
  return `https://${normalizedDomain}/`;
}

function incrementNetlifyDomain(domain, offset = 1) {
  const normalized = normalizeNetlifyDomain(domain);
  if (!normalized) return '';
  const suffix = '.netlify.app';
  const label = normalized.slice(0, -suffix.length);
  const match = label.match(/^(.*?)(\d+)$/);
  const nextLabel = match
    ? `${match[1]}${Number(match[2]) + offset}`
    : `${label}${offset}`;
  return normalizeNetlifyDomain(`${nextLabel}${suffix}`);
}

async function qrDomainCandidates(currentDomain, templateId, limit = 40) {
  const candidates = [];
  for (let offset = 1; offset <= limit; offset += 1) {
    const domain = incrementNetlifyDomain(currentDomain, offset);
    if (!domain) break;
    candidates.push(domain);
  }
  if (!candidates.length) return [];
  const urls = candidates.map((domain) => `https://${domain}/`);
  const collisions = await pool.query(
    `SELECT base_url
     FROM frontend_templates
     WHERE base_url=ANY($1::text[]) AND id<>$2`,
    [urls, templateId],
  );
  const occupied = new Set(collisions.rows.map((row) => row.base_url));
  return candidates.filter((domain) => !occupied.has(`https://${domain}/`));
}

function qrIncidentKeyboard(incidentId) {
  return {
    inline_keyboard: [
      [
        { text: '✅ 核实并自动更换', callback_data: `qr:auto:${incidentId}` },
      ],
      [
        { text: '🟢 二维码正常', callback_data: `qr:normal:${incidentId}` },
        { text: '⛔ 封禁用户卡密', callback_data: `qr:block:${incidentId}` },
      ],
    ],
  };
}

async function getQrIncident(incidentId) {
  if (!isUuid(incidentId)) return null;
  const result = await pool.query(
    `
      SELECT
        qi.*,ft.name AS template_name,ft.base_url AS current_base_url,
        ft.entry_host AS current_entry_host,
        ft.netlify_site_id,t.name AS tenant_name,t.public_code,
        lk.key_prefix AS reporter_key_prefix,lk.key_suffix AS reporter_key_suffix,
        lk.status AS reporter_license_status
      FROM qr_incidents qi
      JOIN frontend_templates ft ON ft.id=qi.template_id
      JOIN tenants t ON t.id=qi.tenant_id
      LEFT JOIN license_keys lk ON lk.id=qi.reporter_license_id
      WHERE qi.id=$1
      LIMIT 1
    `,
    [incidentId],
  );
  return result.rows[0] || null;
}

async function clearQrIncidentKeyboard(incident) {
  if (!incident?.telegram_chat_id || !incident?.telegram_message_id) return;
  await telegramApi('editMessageReplyMarkup', {
    chat_id: incident.telegram_chat_id,
    message_id: incident.telegram_message_id,
    reply_markup: { inline_keyboard: [] },
  }).catch(() => {});
}

function domainChangeMessage(oldDomain, newDomain) {
  return `微信模板入口已由 ${oldDomain} 更新为 ${newDomain}。新生成的链接会使用新域名；原有 ${oldDomain} 链接和二维码仍然有效，访客会继续进入原商家的聊天记录。`;
}

function normalizeTenantDomainSuffix(value) {
  let suffix = String(value || '').trim().toLowerCase();
  suffix = suffix
    .replace(/^https?:\/\//i, '')
    .replace(/[\/?#].*$/, '')
    .replace(/^\.+|\.+$/g, '');
  return /^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(suffix)
    ? suffix
    : '';
}

function normalizeTenantEntryHost(value) {
  let host = String(value || '').trim().toLowerCase();
  if (/^https?:\/\//i.test(host)) {
    try {
      host = new URL(host).hostname.toLowerCase();
    } catch {
      return '';
    }
  } else {
    host = host.replace(/[\/?#].*$/, '').replace(/\.+$/, '');
  }
  if (!/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(host)) {
    return '';
  }
  let suffix = '';
  for (const item of tenantEntryRootDomains) {
    if (host.endsWith(`.${item}`) && item.length > suffix.length) {
      suffix = item;
    }
  }
  if (!suffix) return '';
  const label = host.slice(0, -(suffix.length + 1));
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
    ? host
    : '';
}

function tenantEntryRootDomain(value) {
  const host = normalizeTenantEntryHost(value);
  if (!host) return '';
  let matched = '';
  for (const domain of tenantEntryRootDomains) {
    if (host.endsWith(`.${domain}`) && domain.length > matched.length) {
      matched = domain;
    }
  }
  return matched;
}

function netlifySiteLabel(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    return '';
  }
  const netlifyDomain = normalizeNetlifyDomain(parsed.hostname);
  if (!netlifyDomain) return '';
  return netlifyDomain.slice(0, -'.netlify.app'.length);
}

function tenantEntryHostLabel(value) {
  let host = String(value || '').trim().toLowerCase();
  if (/^https?:\/\//i.test(host)) {
    try {
      host = new URL(host).hostname.toLowerCase();
    } catch {
      return '';
    }
  } else {
    host = host.replace(/[\/?#].*$/, '').replace(/\.+$/, '');
  }
  if (!/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(host)) {
    return '';
  }
  return host.split('.')[0] || '';
}

function isManagedTenantEntryHost(value, baseUrl) {
  const entryLabel = tenantEntryHostLabel(value);
  const siteLabel = netlifySiteLabel(baseUrl);
  return Boolean(entryLabel && siteLabel && entryLabel === siteLabel);
}

function tenantEntryHostFromNetlifyUrl(value) {
  if (!TENANT_ENTRY_ENABLED || !TENANT_ENTRY_DOMAIN_SUFFIXES.length) return '';
  const label = netlifySiteLabel(value);
  if (!label) return '';
  return normalizeTenantEntryHost(
    `${label}.${activeTenantEntryRootDomain || TENANT_ENTRY_DOMAIN_SUFFIXES[0]}`,
  );
}

function tenantEntryOrigin(value) {
  if (!TENANT_ENTRY_ENABLED) return '';
  const host = normalizeTenantEntryHost(value);
  return host ? `https://${host}` : '';
}

function tenantEntryBaseUrl(value) {
  const origin = tenantEntryOrigin(value);
  return origin ? `${origin}/` : '';
}

async function assertTemplateEntryHostAvailable(
  client,
  hostname,
  templateId,
) {
  const normalized = normalizeTenantEntryHost(hostname);
  if (!normalized || !isUuid(templateId)) {
    throw new Error('模板入口域名格式无效。');
  }
  const collision = await client.query(
    `
      SELECT template_id
      FROM (
        SELECT id AS template_id
        FROM frontend_templates
        WHERE entry_host=$1 AND id<>$2
        UNION ALL
        SELECT template_id
        FROM frontend_template_entry_aliases
        WHERE hostname=$1 AND template_id<>$2
        UNION ALL
        SELECT template_id
        FROM tenant_template_domains
        WHERE hostname=$1
        UNION ALL
        SELECT template_id
        FROM tenant_template_domain_aliases
        WHERE hostname=$1
      ) conflicts
      LIMIT 1
    `,
    [normalized, templateId],
  );
  if (collision.rows[0]) {
    throw new Error(`入口域名 ${normalized} 已归属于其他模板。`);
  }
  return normalized;
}

async function storeTemplateEntryAlias(client, templateId, hostname) {
  const normalized = normalizeTenantEntryHost(hostname);
  if (!normalized) return '';
  await assertTemplateEntryHostAvailable(client, normalized, templateId);
  await client.query(
    `INSERT INTO frontend_template_entry_aliases (hostname,template_id)
     VALUES ($1,$2)
     ON CONFLICT (hostname) DO NOTHING`,
    [normalized, templateId],
  );
  const owner = await client.query(
    `SELECT template_id FROM frontend_template_entry_aliases WHERE hostname=$1`,
    [normalized],
  );
  if (!owner.rows[0] || owner.rows[0].template_id !== templateId) {
    throw new Error(`历史入口域名 ${normalized} 归属冲突。`);
  }
  return normalized;
}

async function resolveTenantEntryUpstream(value, client = pool) {
  if (!TENANT_ENTRY_ENABLED) return null;
  const entryHost = normalizeTenantEntryHost(value);
  if (!entryHost) return null;
  if (client === pool) {
    const cached = cacheGet(tenantEntryResolutionCache, entryHost);
    if (cached) return cached.resolved;
  }
  const result = await client.query(
    `
      WITH matched AS (
        SELECT tenant_id,template_id,0 AS priority
        FROM tenant_template_domains
        WHERE hostname=$1
        UNION ALL
        SELECT tenant_id,template_id,0 AS priority
        FROM tenant_template_domain_aliases
        WHERE hostname=$1
        UNION ALL
        SELECT NULL::uuid AS tenant_id,id AS template_id,1 AS priority
        FROM frontend_templates
        WHERE entry_host=$1
        UNION ALL
        SELECT NULL::uuid AS tenant_id,template_id,1 AS priority
        FROM frontend_template_entry_aliases
        WHERE hostname=$1
      )
      SELECT templates.base_url,templates.origin,
             tenants.public_code AS tenant_code,
             tenants.status AS tenant_status,
             tenants.access_expires_at
      FROM matched
      JOIN frontend_templates templates ON templates.id=matched.template_id
      LEFT JOIN tenants ON tenants.id=matched.tenant_id
      WHERE templates.status IN ('testing','enabled')
      ORDER BY matched.priority
      LIMIT 1
    `,
    [entryHost],
  );
  const row = result.rows[0];
  if (!row) {
    if (client === pool) {
      cacheTenantEntryResolution(
        entryHost,
        { resolved: null },
        TENANT_ENTRY_NEGATIVE_CACHE_MS,
      );
    }
    return null;
  }
  if (row.tenant_code && tenantAccessIssue({
    status: row.tenant_status,
    access_expires_at: row.access_expires_at,
  })) return null;
  let target;
  try {
    target = parseTemplateFetchTarget(row.base_url);
  } catch {
    return null;
  }
  const netlifyDomain = normalizeNetlifyDomain(target.hostname);
  if (!netlifyDomain || netlifyDomain !== target.hostname.toLowerCase()) {
    return null;
  }
  if (!timingSafeTextEqual(normalizeOrigin(row.origin), target.origin)) {
    return null;
  }
  target.username = '';
  target.password = '';
  target.search = '';
  target.hash = '';
  const resolved = {
    entryHost,
    upstreamBaseUrl: target.toString(),
    tenantCode: cleanText(row.tenant_code, 120),
  };
  if (client === pool) {
    cacheTenantEntryResolution(
      entryHost,
      { resolved },
      TENANT_ENTRY_RESOLUTION_CACHE_MS,
    );
  }
  return resolved;
}

async function publishDomainChange(incident, oldDomain, newDomain) {
  const message = domainChangeMessage(oldDomain, newDomain);
  const affected = await pool.query(
    `SELECT tenant_id
     FROM tenant_frontend_templates
     WHERE template_id=$1`,
    [incident.template_id],
  );
  const tenantIds = affected.rows.map((row) => row.tenant_id).filter(isUuid);
  if (tenantIds.length) {
    await pool.query(
      `
        INSERT INTO announcements (
          id,type,title,content,scope,tenant_ids,starts_at,ends_at,
          display_mode,force_modal,active
        ) VALUES (
          $1,'important','用户端模板域名已更换',$2,'selected',$3::jsonb,
          NOW(),NOW() + INTERVAL '30 days','both',TRUE,TRUE
        )
      `,
      [randomUUID(), message, JSON.stringify(tenantIds)],
    );
  }
  for (const tenantId of tenantIds) {
    publishEvent(
      {
        type: 'platform-domain-changed',
        oldDomain,
        newDomain,
        tenantId,
        templateName: incident.template_name || '',
        message,
        at: nowIso(),
      },
      { tenantId, targetKind: 'tenant_admin' },
    );
  }
  broadcastSuper({
    type: 'frontend_catalog_updated',
    oldDomain,
    newDomain,
  });
  return tenantIds.length;
}

async function sendQrResolvedTelegram(incident, oldDomain, newDomain, source) {
  const settings = await getPlatformSettings();
  const chatId = incident.telegram_chat_id || settings.telegramGroupId;
  if (!chatId || !TELEGRAM_ENABLED) return;
  await telegramApi('sendMessage', {
    chat_id: chatId,
    text: [
      '<b>✅ 域名已自动更换</b>',
      '',
      `<b>商家</b>：${escapeTelegramHtml(incident.tenant_name || '未命名商家')}`,
      `<b>编号</b>：<code>${escapeTelegramHtml(incident.public_code)}</code>`,
      `<b>模板</b>：${escapeTelegramHtml(incident.template_name)}`,
      `<b>处理方式</b>：${source === 'automatic' ? '自动递增' : '管理员确认'}`,
      '',
      `<b>旧域名</b>：<code>${escapeTelegramHtml(oldDomain)}</code>`,
      `<b>新域名</b>：<code>${escapeTelegramHtml(newDomain)}</code>`,
      '',
      '已向正在使用该模板的商家推送并保存通知。旧链接和旧二维码仍然有效，聊天记录不会丢失；新链接会使用新域名。',
    ].join('\n'),
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    reply_markup: {
      inline_keyboard: [[{
        text: '📋 复制新域名',
        copy_text: { text: newDomain },
      }]],
    },
  });
}

async function resolveQrIncidentDomain(
  incidentId,
  { targetDomain = '', telegramUserId = '', source = 'automatic' } = {},
) {
  let incident = await getQrIncident(incidentId);
  if (!incident) throw new Error('二维码异常记录不存在。');
  if (incident.status === 'resolved') {
    return {
      duplicate: true,
      oldDomain: displayTenantEntryDomain(incident.reported_base_url),
      newDomain: displayTenantEntryDomain(
        incident.requested_base_url || incident.current_base_url,
        incident.current_entry_host,
      ),
    };
  }
  if (!NETLIFY_AUTH_TOKEN) throw new Error('服务器尚未配置 NETLIFY_AUTH_TOKEN。');
  if (!normalizeNetlifySiteId(incident.netlify_site_id)) {
    throw new Error('请先在超级后台为该模板填写 Netlify Site ID。');
  }
  const oldNetlifyDomain = displayTemplateDomain(incident.current_base_url);
  const oldDomain = displayTenantEntryDomain(
    incident.current_base_url,
    incident.current_entry_host,
  );
  if (!normalizeNetlifyDomain(oldNetlifyDomain)) {
    throw new Error(`当前后台域名 ${oldNetlifyDomain} 不是可自动更换的 netlify.app 域名。`);
  }
  const manualDomain = targetDomain ? normalizeNetlifyDomain(targetDomain) : '';
  if (targetDomain && !manualDomain) throw new Error('目标域名格式无效。');

  const claimed = await pool.query(
    `
      UPDATE qr_incidents
      SET status='processing',
          resolved_by_telegram_user_id=$2,
          processing_started_at=NOW(),error='',updated_at=NOW()
      WHERE id=$1
        AND (
          status IN ('open','failed')
          OR (
            status='processing'
            AND processing_started_at < NOW() - INTERVAL '15 minutes'
          )
        )
      RETURNING id
    `,
    [incident.id, cleanText(telegramUserId, 80)],
  );
  if (!claimed.rows[0]) {
    incident = await getQrIncident(incidentId);
    if (incident?.status === 'processing') throw new Error('该异常正在处理中。');
    throw new Error('异常状态已经变化，请刷新后重试。');
  }

  let selectedDomain = '';
  let netlifyRenamed = false;
  let databaseCommitted = false;
  try {
    const candidates = manualDomain
      ? [manualDomain]
      : await qrDomainCandidates(oldNetlifyDomain, incident.template_id);
    if (!candidates.length) throw new Error('没有找到可用的递增域名。');
    let nextBaseUrl = '';
    let lastError = null;
    for (const candidate of candidates) {
      try {
        nextBaseUrl = oldNetlifyDomain === candidate
          ? `https://${candidate}/`
          : await updateNetlifySiteDomain(incident.netlify_site_id, candidate);
        selectedDomain = candidate;
        netlifyRenamed = oldNetlifyDomain !== candidate;
        break;
      } catch (error) {
        lastError = error;
        if (manualDomain) break;
      }
    }
    if (!nextBaseUrl || !selectedDomain) {
      throw lastError || new Error('Netlify 未接受候选域名。');
    }
    const nextEntryHost = tenantEntryHostFromNetlifyUrl(nextBaseUrl);
    if (TENANT_ENTRY_ENABLED && !nextEntryHost) {
      throw new Error('新 Netlify 后台域名无法生成对应的自有域名入口。');
    }
    const newDomain = nextEntryHost || selectedDomain;

    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `SELECT pg_advisory_xact_lock(hashtext('tenant-entry-host-registry'))`,
      );
      await storeTemplateEntryAlias(
        client,
        incident.template_id,
        incident.current_entry_host,
      );
      if (nextEntryHost) {
        await assertTemplateEntryHostAvailable(
          client,
          nextEntryHost,
          incident.template_id,
        );
        await client.query(
          `DELETE FROM frontend_template_entry_aliases
           WHERE hostname=$1 AND template_id=$2`,
          [nextEntryHost, incident.template_id],
        );
      }
      await client.query(
        `UPDATE frontend_templates
         SET base_url=$2,origin=$3,entry_host=$4,updated_at=NOW()
         WHERE id=$1`,
        [
          incident.template_id,
          nextBaseUrl,
          new URL(nextBaseUrl).origin,
          nextEntryHost,
        ],
      );
      await client.query(
        `UPDATE qr_incidents
         SET status='resolved',requested_base_url=$2,resolved_at=NOW(),
             error='',updated_at=NOW()
         WHERE id=$1`,
        [incident.id, nextBaseUrl],
      );
      await client.query(
        `INSERT INTO audit_logs (
           action,target_type,target_id,metadata,risk_level,summary
         ) VALUES (
           'frontend_template.netlify_domain_change','frontend_template',
           $1,$2::jsonb,'critical','Telegram 管理员处理异常并更换了模板域名'
         )`,
        [
          incident.template_id,
          JSON.stringify({
            incidentId: incident.id,
            tenantId: incident.tenant_id,
            oldDomain,
            newDomain,
            oldNetlifyDomain,
            newNetlifyDomain: selectedDomain,
            telegramUserId: cleanText(telegramUserId, 80),
            source,
          }),
        ],
      );
      await client.query('COMMIT');
      databaseCommitted = true;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    invalidateTenantCaches();
    invalidateTenantEntryCaches();
    invalidateApprovedOrigins();
    await refreshApprovedOrigins(true).catch((error) =>
      console.error('域名更换后来源缓存刷新失败：', error.message),
    );
    publishEvent(
      { type: 'frontend_catalog_updated' },
      { targetKind: 'tenant_admin' },
    );
    await publishDomainChange(incident, oldDomain, newDomain).catch((error) =>
      console.error('域名更换通知保存失败：', error.message),
    );
    await clearQrIncidentKeyboard(incident).catch(() => {});
    await sendQrResolvedTelegram(incident, oldDomain, newDomain, source).catch(
      (error) => console.error('域名更换 Telegram 回执失败：', error.message),
    );
    broadcastSuper({ type: 'qr-incident-updated' });
    return { oldDomain, newDomain, duplicate: false };
  } catch (error) {
    if (netlifyRenamed && !databaseCommitted) {
      await updateNetlifySiteDomain(
        incident.netlify_site_id,
        oldNetlifyDomain,
      ).catch((rollbackError) =>
        console.error('Netlify 域名自动恢复失败：', rollbackError.message),
      );
    }
    await pool.query(
      `UPDATE qr_incidents
       SET status='failed',error=$2,updated_at=NOW()
       WHERE id=$1`,
      [incident.id, cleanText(error.message, 500)],
    ).catch(() => {});
    throw error;
  }
}

async function sendQrReviewTelegram(incident, domain, clickCount, reason = '') {
  const settings = await getPlatformSettings();
  if (!settings.telegramGroupId) throw new Error('平台尚未设置 Telegram 异常通知群。');
  const sent = await telegramApi('sendMessage', {
    chat_id: settings.telegramGroupId,
    text: [
      '<b>🚨 二维码异常 · 需要管理员核实</b>',
      '',
      `<b>租户</b>：${escapeTelegramHtml(incident.tenant_name || '未命名租户')}`,
      `<b>编号</b>：<code>${escapeTelegramHtml(incident.public_code)}</code>`,
      `<b>模板</b>：${escapeTelegramHtml(incident.template_name)}`,
      `<b>异常域名</b>：<code>${escapeTelegramHtml(domain)}</code>`,
      `<b>${QR_INCIDENT_WINDOW_MINUTES}分钟点击次数</b>：<code>${clickCount}</code>`,
      incident.reporter_key_suffix
        ? `<b>报告卡密</b>：<code>${escapeTelegramHtml(`${incident.reporter_key_prefix || ''}***${incident.reporter_key_suffix}`)}</code>`
        : '<b>报告卡密</b>：未知',
      '',
      clickCount >= QR_INCIDENT_REVIEW_THRESHOLD
        ? `⚠️ 该租户在${QR_INCIDENT_WINDOW_MINUTES}分钟内点击二维码异常达到 ${QR_INCIDENT_REVIEW_THRESHOLD} 次以上，请管理员先核实。`
        : `自动更换未完成：${escapeTelegramHtml(reason || '未知错误')}`,
      '核实后可点击下方按钮自动处理。',
    ].join('\n'),
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    reply_markup: qrIncidentKeyboard(incident.id),
  });
  await pool.query(
    `UPDATE qr_incidents
     SET status='open',telegram_chat_id=$2,telegram_message_id=$3,
         requires_admin_review=TRUE,updated_at=NOW()
     WHERE id=$1`,
    [incident.id, String(settings.telegramGroupId), sent.message_id],
  );
}

async function createQrIncidentReport(tenant, template, reporter = {}) {
  if (!TELEGRAM_ENABLED) {
    throw requestError('Telegram 机器人尚未启用，请联系平台管理员。', 503, 'TELEGRAM_DISABLED');
  }
  const settings = await getPlatformSettings();
  if (!settings.telegramGroupId) {
    throw requestError('平台尚未设置 Telegram 异常通知群。', 503, 'TELEGRAM_GROUP');
  }
  const reportId = randomUUID();
  await pool.query(
    `INSERT INTO qr_incident_reports (
       id,tenant_id,template_id,reporter_license_id,reported_domain
     ) VALUES ($1,$2,$3,$4,$5)`,
    [
      reportId,
      tenant.id,
      template.id,
      isUuid(reporter.licenseId) ? reporter.licenseId : null,
      displayTenantEntryDomain(template.base_url, template.entry_host),
    ],
  );
  const countResult = await pool.query(
    `SELECT COUNT(*)::int AS count
     FROM qr_incident_reports
     WHERE tenant_id=$1
       AND reported_at >= NOW() - ($2::int * INTERVAL '1 minute')`,
    [tenant.id, QR_INCIDENT_WINDOW_MINUTES],
  );
  const clickCount = Number(countResult.rows[0]?.count || 1);

  const existing = await pool.query(
    `SELECT id,status FROM qr_incidents
     WHERE tenant_id=$1 AND template_id=$2
       AND status IN ('open','processing')
     ORDER BY reported_at DESC LIMIT 1`,
    [tenant.id, template.id],
  );
  if (existing.rows[0]) {
    await pool.query(
      `UPDATE qr_incidents
       SET click_count_10m=$2,reporter_license_id=COALESCE($3,reporter_license_id),
           requires_admin_review=requires_admin_review OR $4,updated_at=NOW()
       WHERE id=$1`,
      [
        existing.rows[0].id,
        clickCount,
        isUuid(reporter.licenseId) ? reporter.licenseId : null,
        clickCount >= QR_INCIDENT_REVIEW_THRESHOLD,
      ],
    );
    return {
      id: existing.rows[0].id,
      duplicate: true,
      status: existing.rows[0].status,
      clickCount,
      requiresAdminReview: clickCount >= QR_INCIDENT_REVIEW_THRESHOLD,
    };
  }

  const incidentId = randomUUID();
  await pool.query(
    `INSERT INTO qr_incidents (
       id,tenant_id,template_id,reported_base_url,status,
       reporter_license_id,click_count_10m,requires_admin_review
     ) VALUES ($1,$2,$3,$4,'open',$5,$6,$7)`,
    [
      incidentId,
      tenant.id,
      template.id,
      template.base_url,
      isUuid(reporter.licenseId) ? reporter.licenseId : null,
      clickCount,
      clickCount >= QR_INCIDENT_REVIEW_THRESHOLD,
    ],
  );
  let incident = await getQrIncident(incidentId);
  const domain = displayTenantEntryDomain(template.base_url, template.entry_host);

  if (clickCount >= QR_INCIDENT_REVIEW_THRESHOLD) {
    await sendQrReviewTelegram(incident, domain, clickCount);
    broadcastSuper({ type: 'qr-incident-updated' });
    return {
      id: incidentId,
      duplicate: false,
      status: 'open',
      clickCount,
      requiresAdminReview: true,
    };
  }

  try {
    const changed = await resolveQrIncidentDomain(incidentId, {
      source: 'automatic',
    });
    return {
      id: incidentId,
      duplicate: false,
      status: 'resolved',
      clickCount,
      requiresAdminReview: false,
      ...changed,
    };
  } catch (error) {
    incident = await getQrIncident(incidentId);
    await sendQrReviewTelegram(incident, domain, clickCount, error.message);
    broadcastSuper({ type: 'qr-incident-updated' });
    return {
      id: incidentId,
      duplicate: false,
      status: 'open',
      clickCount,
      requiresAdminReview: true,
      error: cleanText(error.message, 300),
    };
  }
}

async function markQrIncidentNormal(incidentId, telegramUserId) {
  const incident = await getQrIncident(incidentId);
  if (!incident) throw new Error('二维码异常记录不存在。');
  if (incident.status === 'resolved') return incident;
  const currentDomain = displayTenantEntryDomain(
    incident.current_base_url,
    incident.current_entry_host,
  );
  await pool.query(
    `UPDATE qr_incidents
     SET status='resolved',requested_base_url=$2,
         resolved_by_telegram_user_id=$3,resolved_at=NOW(),
         error='管理员核实二维码正常',updated_at=NOW()
     WHERE id=$1`,
    [incident.id, incident.current_base_url, cleanText(telegramUserId, 80)],
  );
  await clearQrIncidentKeyboard(incident);
  publishEvent(
    {
      type: 'qr-incident-feedback',
      status: 'normal',
      message: `管理员已核实：二维码 ${currentDomain} 正常，无需更换。`,
      domain: currentDomain,
      at: nowIso(),
    },
    { tenantId: incident.tenant_id, targetKind: 'tenant_admin' },
  );
  broadcastSuper({ type: 'qr-incident-updated' });
  return incident;
}

async function blockQrIncidentReporter(incidentId, telegramUserId) {
  const incident = await getQrIncident(incidentId);
  if (!incident) throw new Error('二维码异常记录不存在。');
  if (!isUuid(incident.reporter_license_id)) throw new Error('该异常没有可封禁的报告卡密。');
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const license = await client.query(
      `SELECT * FROM license_keys WHERE id=$1 FOR UPDATE`,
      [incident.reporter_license_id],
    );
    const row = license.rows[0];
    if (!row) throw new Error('报告卡密不存在。');
    await client.query(
      `UPDATE license_keys
       SET status='revoked',disable_mode='notice',
           revoked_at=NOW(),updated_at=NOW()
       WHERE id=$1`,
      [row.id],
    );
    await client.query(
      `UPDATE qr_incidents
       SET status='resolved',resolved_by_telegram_user_id=$2,
           resolved_at=NOW(),error='管理员封禁报告卡密',updated_at=NOW()
       WHERE id=$1`,
      [incident.id, cleanText(telegramUserId, 80)],
    );
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
  await clearQrIncidentKeyboard(incident);
  disconnectTenantLicense(
    incident.tenant_id,
    incident.reporter_license_id,
    await tenantLicenseDisablePayload('notice'),
  );
  broadcastSuper({ type: 'licenses-updated' });
  broadcastSuper({ type: 'tenants-updated' });
  broadcastSuper({ type: 'qr-incident-updated' });
  return incident;
}

async function handleQrIncidentCallback(callback) {
  const match = String(callback?.data || '').match(/^qr:(auto|normal|block):([0-9a-f-]+)$/i);
  if (!match || !isUuid(match[2])) return false;
  const chat = callback.message?.chat;
  const userId = callback.from?.id;
  if (!(await telegramOperatorAllowedAsync(chat, userId))) {
    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '当前用户或群组未被授权。',
      show_alert: true,
    });
    return true;
  }
  await telegramApi('answerCallbackQuery', {
    callback_query_id: callback.id,
    text: '正在处理，请稍候…',
  }).catch(() => {});
  try {
    if (match[1] === 'auto') {
      const changed = await resolveQrIncidentDomain(match[2], {
        telegramUserId: String(userId || ''),
        source: 'telegram',
      });
      await telegramApi('sendMessage', {
        chat_id: chat.id,
        text: `✅ 已自动更换：${changed.oldDomain} → ${changed.newDomain}`,
        ...telegramThread(callback.message),
      });
    } else if (match[1] === 'normal') {
      const incident = await markQrIncidentNormal(match[2], String(userId || ''));
      await telegramApi('sendMessage', {
        chat_id: chat.id,
        text: `🟢 已确认二维码正常，并已反馈到租户后台：${displayTenantEntryDomain(incident.current_base_url, incident.current_entry_host)}`,
        ...telegramThread(callback.message),
      });
    } else {
      const incident = await blockQrIncidentReporter(match[2], String(userId || ''));
      await telegramApi('sendMessage', {
        chat_id: chat.id,
        text: `⛔ 已封禁报告普通卡密，管理员超级卡密仍可使用：${incident.public_code}`,
        ...telegramThread(callback.message),
      });
    }
  } catch (error) {
    await telegramApi('sendMessage', {
      chat_id: chat.id,
      text: `❌ 处理失败：${cleanText(error.message, 300)}`,
      ...telegramThread(callback.message),
    }).catch(() => {});
  }
  return true;
}

async function handleQrIncidentDomainReply(message, targetDomain) {
  const repliedMessageId = Number(message.reply_to_message?.message_id);
  if (!Number.isSafeInteger(repliedMessageId)) {
    await sendTelegramReply(message, '请直接回复机器人发送的二维码异常消息，再输入：更换域名wxmb2.netlify.app');
    return;
  }
  if (!targetDomain) {
    await sendTelegramReply(message, '域名格式不正确。请使用：更换域名wxmb2.netlify.app');
    return;
  }
  const result = await pool.query(
    `SELECT id FROM qr_incidents
     WHERE telegram_chat_id=$1 AND telegram_message_id=$2
     ORDER BY reported_at DESC LIMIT 1`,
    [String(message.chat.id), repliedMessageId],
  );
  if (!result.rows[0]) {
    await sendTelegramReply(message, '没有找到这条异常记录，请确认回复的是机器人异常消息。');
    return;
  }
  try {
    const changed = await resolveQrIncidentDomain(result.rows[0].id, {
      targetDomain,
      telegramUserId: String(message.from?.id || ''),
      source: 'telegram',
    });
    await sendTelegramReply(
      message,
      `✅ 域名已更换：${changed.oldDomain} → ${changed.newDomain}`,
    );
  } catch (error) {
    await sendTelegramReply(message, `❌ 自动更换失败：${cleanText(error.message, 300)}`);
  }
}

async function clearTelegramCallbackKeyboard(message) {
  if (!message?.chat?.id || !message?.message_id) return;
  await telegramApi('editMessageReplyMarkup', {
    chat_id: message.chat.id,
    message_id: message.message_id,
    reply_markup: { inline_keyboard: [] },
  }).catch(() => {});
}

async function editTelegramCallbackResult(message, resultText) {
  if (!message?.chat?.id || !message?.message_id) return;
  const original = cleanText(message.text || message.caption || '安全告警', 3500);
  const suffix = cleanText(resultText, 500);
  const text = `${original}\n\n${suffix}`.slice(0, 4096);
  await telegramApi('editMessageText', {
    chat_id: message.chat.id,
    message_id: message.message_id,
    text,
    link_preview_options: { is_disabled: true },
    reply_markup: { inline_keyboard: [] },
  });
}

async function handleSecurityEventCallback(callback) {
  const match = String(callback?.data || '').match(
    /^sec:(license|ip|dismiss):([0-9a-f-]+)$/i,
  );
  if (!match || !isUuid(match[2])) return false;
  const chat = callback.message?.chat;
  const userId = callback.from?.id;
  if (!(await telegramOperatorAllowedAsync(chat, userId))) {
    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '仅该管理群的管理员可以执行此操作。',
      show_alert: true,
    });
    return true;
  }
  await telegramApi('answerCallbackQuery', {
    callback_query_id: callback.id,
    text: '正在处理…',
  }).catch(() => {});

  try {
    const eventResult = await pool.query(
      `
        SELECT se.*,t.name AS tenant_name,t.public_code,
               lk.key_prefix,lk.key_suffix,lk.status AS license_status,
               lk.tenant_id AS license_tenant_id
        FROM security_events se
        LEFT JOIN tenants t ON t.id=se.tenant_id
        LEFT JOIN license_keys lk ON lk.id=se.license_id
        WHERE se.id=$1
        LIMIT 1
      `,
      [match[2]],
    );
    const event = eventResult.rows[0];
    if (!event) throw new Error('安全事件不存在。');
    if (event.status !== 'open') {
      await clearTelegramCallbackKeyboard(callback.message);
      throw new Error('该安全事件已经被处理。');
    }

    let resultText = '';
    let disconnectedTenantId = '';
    let disconnectedLicenseId = '';
    if (match[1] === 'license') {
      if (!isUuid(event.license_id)) throw new Error('该事件没有可封禁的关联卡密。');
      if (event.details?.allowLicenseBlock !== true) {
        throw new Error('该事件未达到可封禁卡密的高置信安全条件。');
      }
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const eventLock = await client.query(
          `SELECT status FROM security_events WHERE id=$1 FOR UPDATE`,
          [event.id],
        );
        if (eventLock.rows[0]?.status !== 'open') {
          throw new Error('该安全事件已经被处理。');
        }
        const licenseResult = await client.query(
          `SELECT id,status,tenant_id FROM license_keys WHERE id=$1 FOR UPDATE`,
          [event.license_id],
        );
        const license = licenseResult.rows[0];
        if (!license) throw new Error('关联卡密不存在。');
        if (license.status !== 'revoked') {
          await client.query(
            `UPDATE license_keys
             SET status='revoked',disable_mode='notice',
                 revoked_at=NOW(),updated_at=NOW()
             WHERE id=$1`,
            [license.id],
          );
        }
        if (isUuid(license.tenant_id)) {
          disconnectedTenantId = license.tenant_id;
          disconnectedLicenseId = license.id;
        }
        await client.query(
          `UPDATE security_events
           SET status='blocked',handled_by_telegram_user_id=$2,
               handled_at=NOW(),updated_at=NOW()
           WHERE id=$1`,
          [event.id, String(userId || '')],
        );
        await client.query(
          `INSERT INTO audit_logs (
             action,target_type,target_id,metadata,risk_level,summary
           ) VALUES (
             'security.license_block','security_event',$1,$2::jsonb,
             'critical','Telegram 管理员根据安全告警禁用了普通卡密'
           )`,
          [
            event.id,
            JSON.stringify({
              telegramUserId: String(userId || ''),
              tenantId: disconnectedTenantId || event.tenant_id || '',
              licenseId: event.license_id,
              kind: event.kind,
            }),
          ],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      resultText = `⛔ 已封禁普通卡密 ${event.key_prefix || 'VIP'}-***-${event.key_suffix || '?????'}${disconnectedTenantId ? '，并中断该普通卡密后台会话；管理员超级卡密仍可使用' : ''}。`;
    } else if (match[1] === 'ip') {
      if (!securityIpBlockable(event.ip_address)) {
        throw new Error(
          isCloudflareAddress(normalizeIp(event.ip_address))
            ? '该地址属于 Cloudflare 边缘节点，不能封禁共享基础设施 IP。'
            : '该事件没有可封禁的公网 IP。',
        );
      }
      const blockedAddress = normalizeIp(event.ip_address);
      const expiresAt = new Date(
        Date.now() + SECURITY_IP_BLOCK_HOURS * 60 * 60_000,
      );
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const eventLock = await client.query(
          `SELECT status FROM security_events WHERE id=$1 FOR UPDATE`,
          [event.id],
        );
        if (eventLock.rows[0]?.status !== 'open') {
          throw new Error('该安全事件已经被处理。');
        }
        await client.query(
          `
            INSERT INTO blocked_ips (
              ip_address,reason,security_event_id,
              blocked_by_telegram_user_id,expires_at
            ) VALUES ($1,$2,$3,$4,$5)
            ON CONFLICT (ip_address) DO UPDATE SET
              reason=EXCLUDED.reason,
              security_event_id=EXCLUDED.security_event_id,
              blocked_by_telegram_user_id=EXCLUDED.blocked_by_telegram_user_id,
              expires_at=EXCLUDED.expires_at,updated_at=NOW()
          `,
          [
            blockedAddress,
            `Telegram 处理安全事件：${event.kind}`,
            event.id,
            String(userId || ''),
            expiresAt.toISOString(),
          ],
        );
        await client.query(
          `UPDATE security_events
           SET status='blocked',handled_by_telegram_user_id=$2,
               handled_at=NOW(),updated_at=NOW()
           WHERE id=$1`,
          [event.id, String(userId || '')],
        );
        await client.query(
          `INSERT INTO audit_logs (
             action,target_type,target_id,ip_address,metadata,risk_level,summary
           ) VALUES (
             'security.ip_block','security_event',$1,$2,$3::jsonb,
             'critical','Telegram 管理员根据安全告警封禁了公网 IP'
           )`,
          [
            event.id,
            blockedAddress,
            JSON.stringify({
              telegramUserId: String(userId || ''),
              kind: event.kind,
              expiresAt: expiresAt.toISOString(),
            }),
          ],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      blockedIpCache.set(blockedAddress, expiresAt.getTime());
      resultText = `🛡 已封禁 IP ${blockedAddress} ${SECURITY_IP_BLOCK_HOURS} 小时。`;
    } else {
      const dismissed = await pool.query(
        `UPDATE security_events
         SET status='dismissed',handled_by_telegram_user_id=$2,
             handled_at=NOW(),updated_at=NOW()
         WHERE id=$1 AND status='open'
         RETURNING id`,
        [event.id, String(userId || '')],
      );
      if (!dismissed.rows[0]) throw new Error('该安全事件已经被处理。');
      resultText = '✅ 该安全事件已标记为已核实，未封禁用户。';
    }

    if (disconnectedTenantId && disconnectedLicenseId) {
      invalidateTenantCaches(disconnectedTenantId);
      disconnectTenantLicense(
        disconnectedTenantId,
        disconnectedLicenseId,
        await tenantLicenseDisablePayload('notice'),
      );
      broadcastSuper({ type: 'licenses-updated' });
      broadcastSuper({ type: 'tenants-updated' });
    }
    await editTelegramCallbackResult(callback.message, resultText);
  } catch (error) {
    await editTelegramCallbackResult(
      callback.message,
      `❌ 处理失败：${cleanText(error.message, 300)}`,
    ).catch(() => {});
  }
  return true;
}

async function telegramUserIsBlocked(userId) {
  const key = String(userId || '');
  if (!/^\d+$/.test(key)) return false;
  const cached = telegramBlockedUserCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.blocked;
  const result = await pool.query(
    `SELECT 1 FROM telegram_blocked_users WHERE user_id=$1 LIMIT 1`,
    [key],
  );
  const blocked = Boolean(result.rows[0]);
  telegramBlockedUserCache.set(key, {
    blocked,
    expiresAt: Date.now() + (blocked ? 10 : 1) * 60_000,
  });
  return blocked;
}

function telegramPrivateContent(message) {
  const text = cleanText(message.text || message.caption, 1500);
  if (text) return text;
  if (message.photo) return '[图片]';
  if (message.video) return '[视频]';
  if (message.voice) return '[语音]';
  if (message.audio) return '[音频]';
  if (message.document) return `[文件] ${cleanText(message.document.file_name, 200)}`;
  if (message.sticker) return `[贴纸] ${cleanText(message.sticker.emoji, 20)}`;
  if (message.contact) return '[联系人]';
  if (message.location) return '[位置]';
  return '[不支持预览的消息类型]';
}

function telegramUserChatUrl(user) {
  const username = cleanText(user?.username, 80);
  return /^[A-Za-z0-9_]{5,32}$/.test(username)
    ? `https://t.me/${username}`
    : `tg://user?id=${encodeURIComponent(String(user?.id || ''))}`;
}

async function handleTelegramPrivateInbound(message) {
  if (message?.chat?.type !== 'private' || message?.from?.is_bot) return false;
  const userId = String(message.from?.id || '');
  if (!/^\d+$/.test(userId) || TELEGRAM_ALLOWED_USER_IDS.has(userId)) {
    return false;
  }
  if (await telegramUserIsBlocked(userId)) {
    await telegramApi('sendMessage', {
      chat_id: message.chat.id,
      text: '你已被管理员禁止访问机器人。你的 Telegram 用户 ID 和相关记录已被保留；Telegram 机器人无法获取你的 IP。',
    }).catch(() => {});
    return true;
  }
  const settings = await getPlatformSettings().catch(() => null);
  if (!settings?.telegramGroupId) {
    await telegramApi('sendMessage', {
      chat_id: message.chat.id,
      text: '管理员消息群尚未配置，请稍后再试。',
    }).catch(() => {});
    return true;
  }
  const displayName = telegramDisplayName(message.from) || '未设置姓名';
  const username = cleanText(message.from.username, 80);
  await telegramApi('sendMessage', {
    chat_id: settings.telegramGroupId,
    text: [
      '<b>📨 机器人收到新私信</b>',
      '',
      `<b>用户</b>：${escapeTelegramHtml(displayName)}`,
      `<b>用户名</b>：${username ? `@${escapeTelegramHtml(username)}` : '未设置'}`,
      `<b>Telegram ID</b>：<code>${escapeTelegramHtml(userId)}</code>`,
      `<b>内容</b>：${escapeTelegramHtml(telegramPrivateContent(message))}`,
    ].join('\n'),
    parse_mode: 'HTML',
    link_preview_options: { is_disabled: true },
    reply_markup: {
      inline_keyboard: [
        [{ text: '💬 点击与他聊天', url: telegramUserChatUrl(message.from) }],
        [{ text: '⛔ 禁止他访问机器人', callback_data: `tg:block:${userId}` }],
      ],
    },
  });
  if (!message.text && !message.caption) {
    await telegramApi('copyMessage', {
      chat_id: settings.telegramGroupId,
      from_chat_id: message.chat.id,
      message_id: message.message_id,
    }).catch(() => {});
  }
  await telegramApi('sendMessage', {
    chat_id: message.chat.id,
    text: '✅ 你的消息已转发给管理员。',
  }).catch(() => {});
  return true;
}

async function handleTelegramUserBlockCallback(callback) {
  const match = String(callback?.data || '').match(/^tg:block:(\d+)$/);
  if (!match) return false;
  const chat = callback.message?.chat;
  const operatorId = callback.from?.id;
  if (!(await telegramOperatorAllowedAsync(chat, operatorId))) {
    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '仅该管理群的管理员可以执行此操作。',
      show_alert: true,
    });
    return true;
  }
  const targetUserId = match[1];
  await telegramApi('answerCallbackQuery', {
    callback_query_id: callback.id,
    text: '正在禁止该用户…',
  }).catch(() => {});
  const userChat = await telegramApi('getChat', {
    chat_id: targetUserId,
  }).catch(() => ({}));
  await pool.query(
    `
      INSERT INTO telegram_blocked_users (
        user_id,username,display_name,reason,blocked_by_telegram_user_id
      ) VALUES ($1,$2,$3,$4,$5)
      ON CONFLICT (user_id) DO UPDATE SET
        username=EXCLUDED.username,display_name=EXCLUDED.display_name,
        reason=EXCLUDED.reason,
        blocked_by_telegram_user_id=EXCLUDED.blocked_by_telegram_user_id,
        updated_at=NOW()
    `,
    [
      targetUserId,
      cleanText(userChat.username, 80),
      telegramDisplayName(userChat),
      '管理群管理员通过私信通知封禁',
      String(operatorId || ''),
    ],
  );
  telegramBlockedUserCache.set(targetUserId, {
    blocked: true,
    expiresAt: Number.POSITIVE_INFINITY,
  });
  await clearTelegramCallbackKeyboard(callback.message);
  await telegramApi('sendMessage', {
    chat_id: targetUserId,
    text: '你已被管理员禁止访问机器人。你的 Telegram 用户 ID 和相关记录已被保留；Telegram 机器人无法获取你的 IP。',
  }).catch(() => {});
  await telegramApi('sendMessage', {
    chat_id: chat.id,
    text: `⛔ 已禁止 Telegram 用户 ${targetUserId} 继续访问机器人。`,
    ...telegramThread(callback.message),
  });
  return true;
}

async function processTelegramUpdate(update) {
  const message = update?.message;
  const callback = update?.callback_query;

  if (message && (await handleTelegramPrivateInbound(message))) return;

  if (message?.text) {
    const chat = message.chat;
    const chatId = chat?.id;
    const userId = message.from?.id;
    const raw = String(message.text || '').trim();
    const command = (raw.split(/\s+/)[0] || '')
      .replace(/@[A-Za-z0-9_]+$/i, '')
      .toLowerCase();
    const isHelp = ['/start', '/help'].includes(command);
    const isGenerate =
      ['生成密钥', '生成卡密'].includes(raw) ||
      ['/key', '/card', '/generate'].includes(command);
    const isSystemStatus =
      ['查看服务器状态', '/查看服务器状态'].includes(raw) ||
      ['/status', '/server_status'].includes(command);
    const isTenantEntryDomainList =
      ['查看可用域名', '/查看可用域名'].includes(raw) ||
      ['/domains', '/available_domains'].includes(command);
    const revokeMatch = raw.match(
      /^(?:\/revoke(?:@[A-Za-z0-9_]+)?|禁用卡密)\s+(.+)$/i,
    );
    const listMatch = raw.match(
      /^(?:查看(?:所有)?卡密|\/(?:licenses|keys)(?:@[A-Za-z0-9_]+)?)(?:\s+(\d+))?$/i,
    );
    const isList = Boolean(listMatch);
    const listPage = Math.min(
      10_000,
      Math.max(1, Math.trunc(Number(listMatch?.[1] || 1))),
    );
    const qrDomainReply = parseQrIncidentDomainReply(raw);
    const rootDomainSwitch = parseTenantEntryDomainSwitchCommand(raw);

    if (
      !isHelp &&
      !isGenerate &&
      !isSystemStatus &&
      !isTenantEntryDomainList &&
      !revokeMatch &&
      !isList &&
      !qrDomainReply.matched &&
      !rootDomainSwitch.matched
    ) return;

    if (!(await telegramOperatorAllowedAsync(chat, userId))) {
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text: '⛔ 当前用户或群组未被授权使用此机器人。',
        ...telegramThread(message),
      });
      return;
    }

    if (rootDomainSwitch.matched) {
      await createTenantEntryDomainSwitchRequest(
        message,
        rootDomainSwitch.domain,
      );
      return;
    }

    if (qrDomainReply.matched) {
      await handleQrIncidentDomainReply(message, qrDomainReply.domain);
      return;
    }

    if (isHelp) {
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text: [
          '✅ 卡密管理机器人已启用。',
          '',
          '生成卡密：发送“生成卡密”或 /key',
          '禁用卡密：禁用卡密 VIP-XXXXX-XXXXX-XXXXX-XXXXX',
          '历史卡密：也可发送“禁用卡密 尾号5位”',
          '查看卡密：发送“查看卡密”或 /licenses，每页 50 张',
          '服务器状态：发送“/查看服务器状态”或 /status',
          '域名池：发送“查看可用域名”或 /domains',
          '切换根域名：发送“更换域名 6687878.xyz”并点击确认',
          '二维码异常：回复异常消息并发送“更换域名wxmb2.netlify.app”',
        ].join('\n'),
        ...telegramThread(message),
      });
      return;
    }

    if (isSystemStatus) {
      await sendTelegramSystemStatus(message);
      return;
    }

    if (isTenantEntryDomainList) {
      await sendTenantEntryDomainList(message);
      return;
    }

    if (isGenerate) {
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text: '请点击下方按键选择，请注意：请确认钱包收款成功后，再把密钥发给客户！',
        reply_markup: telegramGenerateKeyboard(),
        ...telegramThread(message),
      });
      return;
    }

    if (revokeMatch) {
      const key = normalizeLicenseKey(revokeMatch[1]);
      const hasFullKey = /^VIP-[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}$/.test(key);
      const suffix = hasFullKey
        ? ''
        : String(revokeMatch[1] || '')
            .trim()
            .toUpperCase()
            .match(/([A-Z2-9]{5})$/)?.[1] || '';
      if (!hasFullKey && !suffix) {
        await telegramApi('sendMessage', {
          chat_id: chatId,
          text: '卡密格式不正确，请输入完整卡密或卡密尾号5位。',
          ...telegramThread(message),
        });
        return;
      }
      const client = await pool.connect();
      let text = '卡密不存在。';
      let revokedTenantId = null;
      let revokedLicenseId = null;
      try {
        await client.query('BEGIN');
        const result = hasFullKey
          ? await client.query(
              `SELECT * FROM license_keys WHERE key_hash=$1 FOR UPDATE`,
              [hashLicenseKey(key)],
            )
          : await client.query(
              `SELECT * FROM license_keys WHERE key_suffix=$1 ORDER BY created_at DESC FOR UPDATE`,
              [suffix],
            );
        const row = result.rows.length === 1 ? result.rows[0] : null;
        if (!hasFullKey && result.rows.length > 1) {
          text = '此尾号对应多张卡密，请输入完整卡密以免禁用错误。';
        }
        if (row) {
          const displayKey = licenseHint(row);
          if (row.status === 'revoked') {
            text = `此卡密已经被禁用：${displayKey}`;
          } else {
            await client.query(
              `UPDATE license_keys
               SET status='revoked',
                   disable_mode='notice',
                   key_ciphertext=COALESCE(key_ciphertext,$2),
                   revoked_at=NOW(),
                   updated_at=NOW()
               WHERE id=$1`,
              [row.id, hasFullKey ? encryptLicenseKey(key) : null],
            );
            if (row.tenant_id && row.status === 'active') {
              revokedTenantId = row.tenant_id;
              revokedLicenseId = row.id;
            }
            text = `✅ 已禁用普通卡密：${displayKey}\n管理员超级卡密仍可登录。`;
          }
        }
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      if (revokedTenantId && revokedLicenseId) {
        disconnectTenantLicense(
          revokedTenantId,
          revokedLicenseId,
          await tenantLicenseDisablePayload('notice'),
        );
      }
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text,
        ...telegramThread(message),
      });
      return;
    }

    if (isList) {
      await sendAllLicenses(chatId, message, listPage);
      return;
    }
  }

  if (callback?.data?.startsWith('qr:')) {
    if (await handleQrIncidentCallback(callback)) return;
  }

  if (callback?.data?.startsWith('domain:')) {
    if (await handleTenantEntryDomainCallback(callback)) return;
  }

  if (callback?.data?.startsWith('sec:')) {
    if (await handleSecurityEventCallback(callback)) return;
  }

  if (callback?.data?.startsWith('tg:block:')) {
    if (await handleTelegramUserBlockCallback(callback)) return;
  }

  if (callback?.data?.startsWith('license:')) {
    const chat = callback.message?.chat;
    const chatId = chat?.id;
    const userId = callback.from?.id;
    const code = callback.data.slice(8);

    if (!(await telegramOperatorAllowedAsync(chat, userId))) {
      await telegramApi('answerCallbackQuery', {
        callback_query_id: callback.id,
        text: '当前用户或群组未被授权。',
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

    const generationClaim = claimTelegramGeneration(callback);
    if (!generationClaim.claimed) {
      await telegramApi('answerCallbackQuery', {
        callback_query_id: callback.id,
        text: '这张卡密已经生成，请查看当前消息。',
        show_alert: true,
      }).catch(() => {});
      return;
    }

    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '正在生成卡密…',
    }).catch(() => {});

    try {
      const created = await createLicenseRecord(code, {
        telegramChatId: chatId,
        telegramUserId: userId,
        telegramUsername: callback.from?.username || '',
        telegramDisplayName: telegramDisplayName(callback.from),
        telegramUpdateId: update.update_id,
      });
      await showTelegramGeneratedLicense(callback, created);
      broadcastSuper({ type: 'licenses-updated' });
    } catch (error) {
      if (generationClaim.key) {
        telegramGenerationClaims.delete(generationClaim.key);
      }
      throw error;
    }
  }
}

function percentile(values, percentileValue) {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const index = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((percentileValue / 100) * sorted.length) - 1),
  );
  return Number(sorted[index].toFixed(1));
}

function summarizeMetricSeries(series) {
  const values = (Array.isArray(series) ? series : [])
    .flatMap((item) => Array.isArray(item.values) ? item.values : [])
    .map((item) => Number(item.value))
    .filter(Number.isFinite);
  return {
    current: values.length ? values[values.length - 1] : null,
    average: values.length
      ? Number(
          (values.reduce((sum, value) => sum + value, 0) / values.length)
            .toFixed(3),
        )
      : null,
    peak: values.length ? Math.max(...values) : null,
    total: values.reduce((sum, value) => sum + value, 0),
    unit: Array.isArray(series) ? series[0]?.unit || '' : '',
  };
}

function summarizeHttpStatusSeries(series) {
  const result = { total: 0, clientErrors: 0, serverErrors: 0 };
  for (const item of Array.isArray(series) ? series : []) {
    const status = String(
      item.labels?.find((label) => label.field === 'statusCode')?.value || '',
    );
    const count = (item.values || []).reduce(
      (sum, value) => sum + Number(value.value || 0),
      0,
    );
    result.total += count;
    if (/^4/.test(status)) result.clientErrors += count;
    if (/^5/.test(status)) result.serverErrors += count;
  }
  return result;
}

async function fetchCloudflareTurnAnalytics() {
  const configured = Boolean(
    CLOUDFLARE_ACCOUNT_ID && CLOUDFLARE_ANALYTICS_API_TOKEN,
  );
  if (!configured) {
    return {
      configured: false,
      reachable: null,
      quotaGb: CLOUDFLARE_REALTIME_MONTHLY_QUOTA_GB,
      note: '需要配置 Cloudflare Account Analytics 只读令牌。',
    };
  }
  if (
    cloudflareTurnAnalyticsCache.value &&
    cloudflareTurnAnalyticsCache.expiresAt > Date.now()
  ) return cloudflareTurnAnalyticsCache.value;
  if (cloudflareTurnAnalyticsCache.promise) {
    return cloudflareTurnAnalyticsCache.promise;
  }
  const request = (async () => {
    const now = new Date();
    const monthStart = new Date(Date.UTC(
      now.getUTCFullYear(),
      now.getUTCMonth(),
      1,
    ));
    const dateFrom = monthStart.toISOString().slice(0, 10);
    const dateTo = now.toISOString().slice(0, 10);
    const response = await fetch(
      'https://api.cloudflare.com/client/v4/graphql',
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${CLOUDFLARE_ANALYTICS_API_TOKEN}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          query: `
            query TurnMonthlyUsage(
              $accountId: String!, $dateFrom: Date!, $dateTo: Date!
            ) {
              viewer {
                accounts(filter: { accountTag: $accountId }) {
                  callsTurnUsageAdaptiveGroups(
                    limit: 100
                    filter: { date_geq: $dateFrom, date_leq: $dateTo }
                  ) {
                    sum { egressBytes ingressBytes }
                  }
                }
              }
            }
          `,
          variables: {
            accountId: CLOUDFLARE_ACCOUNT_ID,
            dateFrom,
            dateTo,
          },
        }),
        signal: AbortSignal.timeout(10_000),
      },
    );
    const result = await response.json().catch(() => null);
    const graphErrors = Array.isArray(result?.errors) ? result.errors : [];
    if (!response.ok || graphErrors.length) {
      throw new Error(
        cleanText(
          graphErrors[0]?.message ||
            result?.errors?.[0]?.message ||
            `Cloudflare Analytics 返回状态 ${response.status}`,
          240,
        ),
      );
    }
    const groups =
      result?.data?.viewer?.accounts?.[0]?.callsTurnUsageAdaptiveGroups || [];
    const egressBytes = groups.reduce(
      (sum, item) => sum + Number(item?.sum?.egressBytes || 0),
      0,
    );
    const ingressBytes = groups.reduce(
      (sum, item) => sum + Number(item?.sum?.ingressBytes || 0),
      0,
    );
    const quotaBytes = CLOUDFLARE_REALTIME_MONTHLY_QUOTA_GB * 1_000_000_000;
    const remainingBytes = Math.max(0, quotaBytes - egressBytes);
    return {
      configured: true,
      reachable: true,
      monthStart: dateFrom,
      throughDate: dateTo,
      egressBytes,
      ingressBytes,
      quotaBytes,
      quotaGb: CLOUDFLARE_REALTIME_MONTHLY_QUOTA_GB,
      remainingBytes,
      usedPercent: Number(
        Math.min(100, (egressBytes / quotaBytes) * 100).toFixed(2),
      ),
      sampledAt: nowIso(),
      billingMetric: 'egressBytes',
      sharedRealtimeQuota: true,
    };
  })().catch((error) => ({
    configured: true,
    reachable: false,
    quotaGb: CLOUDFLARE_REALTIME_MONTHLY_QUOTA_GB,
    error: cleanText(error.message, 240),
  }));
  cloudflareTurnAnalyticsCache.promise = request;
  try {
    const value = await request;
    cloudflareTurnAnalyticsCache.value = value;
    cloudflareTurnAnalyticsCache.expiresAt = Date.now() +
      (value.reachable === false ? 5 * 60_000 : CLOUDFLARE_ANALYTICS_CACHE_MS);
    return value;
  } finally {
    if (cloudflareTurnAnalyticsCache.promise === request) {
      cloudflareTurnAnalyticsCache.promise = null;
    }
  }
}

async function fetchProviderMetrics() {
  if (providerMetricsCache.expiresAt > Date.now()) return providerMetricsCache;
  if (providerMetricsPromise) return providerMetricsPromise;
  const request = fetchProviderMetricsFresh();
  providerMetricsPromise = request;
  try {
    return await request;
  } finally {
    if (providerMetricsPromise === request) providerMetricsPromise = null;
  }
}

async function fetchProviderMetricsFresh() {
  const next = {
    expiresAt: Date.now() + 60_000,
    render: {
      configured: Boolean(RENDER_API_KEY && RENDER_SERVICE_ID),
      reachable: null,
    },
    neon: {
      configured: Boolean(NEON_API_KEY && NEON_PROJECT_ID),
      reachable: null,
    },
    cloudflareTurn: null,
  };
  const cloudflareTurnPromise = fetchCloudflareTurnAnalytics();
  if (next.render.configured) {
    try {
      const endTime = new Date();
      const startTime = new Date(endTime.getTime() - 10 * 60_000);
      const metricUrl = (path, extras = {}) => {
        const url = new URL(`https://api.render.com/v1/metrics/${path}`);
        url.searchParams.set('resource', RENDER_SERVICE_ID);
        url.searchParams.set('startTime', startTime.toISOString());
        url.searchParams.set('endTime', endTime.toISOString());
        url.searchParams.set('resolutionSeconds', '60');
        for (const [key, value] of Object.entries(extras)) {
          url.searchParams.set(key, String(value));
        }
        return url;
      };
      const requestOptions = {
        headers: { Authorization: `Bearer ${RENDER_API_KEY}` },
        signal: AbortSignal.timeout(8000),
      };
      const [
        serviceResponse,
        deployResponse,
        cpuResponse,
        memoryResponse,
        requestResponse,
        latencyResponse,
        bandwidthResponse,
      ] = await Promise.all([
        fetch(`https://api.render.com/v1/services/${RENDER_SERVICE_ID}`, {
          ...requestOptions,
        }),
        fetch(
          `https://api.render.com/v1/services/${RENDER_SERVICE_ID}/deploys?limit=1`,
          { ...requestOptions },
        ),
        fetch(metricUrl('cpu', { aggregationMethod: 'AVG' }), {
          ...requestOptions,
        }),
        fetch(metricUrl('memory', { aggregationMethod: 'AVG' }), {
          ...requestOptions,
        }),
        fetch(metricUrl('http-requests', { aggregateBy: 'statusCode' }), {
          ...requestOptions,
        }),
        fetch(metricUrl('http-latency', { quantile: '0.95' }), {
          ...requestOptions,
        }),
        fetch(metricUrl('bandwidth'), { ...requestOptions }),
      ]);
      const service = serviceResponse.ok
        ? await serviceResponse.json()
        : null;
      const deploys = deployResponse.ok ? await deployResponse.json() : null;
      const cpu = cpuResponse.ok ? await cpuResponse.json() : [];
      const memory = memoryResponse.ok ? await memoryResponse.json() : [];
      const requests = requestResponse.ok ? await requestResponse.json() : [];
      const latency = latencyResponse.ok ? await latencyResponse.json() : [];
      const bandwidth = bandwidthResponse.ok
        ? await bandwidthResponse.json()
        : [];
      const deploy = Array.isArray(deploys)
        ? deploys[0]?.deploy || deploys[0]
        : null;
      next.render = {
        configured: true,
        reachable: serviceResponse.ok,
        metricsAvailable:
          cpuResponse.ok &&
          memoryResponse.ok,
        serviceName: service?.service?.name || service?.name || '',
        suspended: service?.service?.suspended || service?.suspended || '',
        latestDeployStatus: deploy?.status || '',
        latestDeployAt:
          deploy?.finishedAt || deploy?.createdAt || deploy?.updatedAt || null,
        cpu: summarizeMetricSeries(cpu),
        memory: summarizeMetricSeries(memory),
        requests: summarizeHttpStatusSeries(requests),
        latency: summarizeMetricSeries(latency),
        outboundBandwidth: summarizeMetricSeries(bandwidth),
        metricsStatus: {
          cpu: cpuResponse.status,
          memory: memoryResponse.status,
          requests: requestResponse.status,
          latency: latencyResponse.status,
          bandwidth: bandwidthResponse.status,
        },
      };
    } catch (error) {
      next.render.error = cleanText(error.message, 200);
      next.render.reachable = false;
    }
  }
  if (next.neon.configured) {
    try {
      const requestOptions = {
        headers: { Authorization: `Bearer ${NEON_API_KEY}` },
        signal: AbortSignal.timeout(8000),
      };
      const consumptionUrl = new URL(
        'https://console.neon.tech/api/v2/consumption_history/v2/projects',
      );
      const now = new Date();
      const from = new Date(now.getTime() - 24 * 60 * 60_000);
      consumptionUrl.searchParams.set('project_ids', NEON_PROJECT_ID);
      consumptionUrl.searchParams.set('from', from.toISOString());
      consumptionUrl.searchParams.set('to', now.toISOString());
      consumptionUrl.searchParams.set('granularity', 'hourly');
      consumptionUrl.searchParams.set('org_id', NEON_ORG_ID);
      consumptionUrl.searchParams.set(
        'metrics',
        [
          'compute_unit_seconds',
          'root_branch_bytes_month',
          'instant_restore_bytes_month',
          'public_network_transfer_bytes',
        ].join(','),
      );
      const [response, consumptionResponse] = await Promise.all([
        fetch(
          `https://console.neon.tech/api/v2/projects/${encodeURIComponent(NEON_PROJECT_ID)}`,
          { ...requestOptions },
        ),
        NEON_ORG_ID
          ? fetch(consumptionUrl, { ...requestOptions })
          : Promise.resolve(null),
      ]);
      const result = response.ok ? await response.json() : null;
      const project = result?.project || result || {};
      const consumptionResult = consumptionResponse?.ok
        ? await consumptionResponse.json()
        : null;
      const totals = {};
      for (const projectEntry of consumptionResult?.projects || []) {
        for (const period of projectEntry.periods || []) {
          for (const timeframe of period.consumption || []) {
            for (const metric of timeframe.metrics || []) {
              totals[metric.metric_name] =
                Number(totals[metric.metric_name] || 0) +
                Number(metric.value || 0);
            }
          }
        }
      }
      next.neon = {
        configured: true,
        reachable: response.ok,
        projectName: project.name || '',
        regionId: project.region_id || project.regionId || '',
        platformId: project.platform_id || project.platformId || '',
        consumptionConfigured: Boolean(NEON_ORG_ID),
        consumptionAvailable: Boolean(consumptionResponse?.ok),
        consumptionStatus: consumptionResponse?.status || 0,
        consumption24h: totals,
      };
    } catch (error) {
      next.neon.error = cleanText(error.message, 200);
      next.neon.reachable = false;
    }
  }
  next.cloudflareTurn = await cloudflareTurnPromise;
  providerMetricsCache = next;
  return next;
}

function sampleCpuPercent() {
  const currentUsage = process.cpuUsage();
  const currentTime = process.hrtime.bigint();
  const elapsedMicros = Number(currentTime - lastCpuSampleAt) / 1000;
  const usedMicros =
    currentUsage.user -
    lastCpuUsage.user +
    currentUsage.system -
    lastCpuUsage.system;
  lastCpuUsage = currentUsage;
  lastCpuSampleAt = currentTime;
  if (elapsedMicros <= 0) return 0;
  return Number(
    Math.min(
      100,
      (usedMicros / elapsedMicros / INSTANCE_CPU_CORES) * 100,
    ).toFixed(2),
  );
}

async function collectMonitorSnapshot({ persist = true } = {}) {
  const databaseStartedAt = performance.now();
  const databasePromise = pool.query(`
      SELECT
        pg_database_size(current_database())::bigint AS database_size,
        COUNT(*) FILTER (WHERE state = 'active')::int AS active_connections,
        COUNT(*) FILTER (WHERE state = 'idle')::int AS idle_connections
      FROM pg_stat_activity
      WHERE datname = current_database()
    `).then((result) => ({
      result,
      latencyMs: Number((performance.now() - databaseStartedAt).toFixed(1)),
    }));
  const [databaseSample, tables, business, provider] = await Promise.all([
    databasePromise,
    pool.query(`
      SELECT
        relname,
        pg_total_relation_size(relid)::bigint AS bytes
      FROM pg_catalog.pg_statio_user_tables
      ORDER BY pg_total_relation_size(relid) DESC
      LIMIT 12
    `),
    pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM tenants) AS tenants,
        (SELECT COUNT(*)::int FROM conversations
          WHERE created_at >= date_trunc('day', NOW())) AS visitors_today,
        (SELECT COUNT(*)::int FROM conversations
          WHERE updated_at >= date_trunc('day', NOW())) AS conversations_today,
        (SELECT COUNT(*)::int FROM messages
          WHERE created_at >= date_trunc('day', NOW())) AS messages_today,
        (SELECT COALESCE(SUM(size),0)::bigint FROM attachments) +
          (SELECT COALESCE(SUM(size),0)::bigint FROM assets) AS media_bytes,
        (SELECT COUNT(*)::int FROM r2_delete_queue) AS delete_queue
    `),
    fetchProviderMetrics(),
  ]);
  const database = databaseSample.result;
  const memory = process.memoryUsage();
  const cpuPercent = sampleCpuPercent();
  const memoryPercent = Number(
    Math.min(
      100,
      (memory.rss / (INSTANCE_MEMORY_MB * 1024 * 1024)) * 100,
    ).toFixed(2),
  );
  const counterSnapshot = { ...minuteCounters };
  const counterWindowSeconds = Math.max(
    60,
    (Date.now() - lastMonitorCounterResetAt) / 1000,
  );
  const counterWindowMinutes = counterWindowSeconds / 60;
  const perMinute = (value) =>
    Number((Number(value || 0) / counterWindowMinutes).toFixed(2));
  const topRoutes = [...routeCounters.entries()]
    .map(([route, value]) => ({
      route,
      requests: Number(value.requests || 0),
      errors: Number(value.errors || 0),
      responseBytes: Number(value.responseBytes || 0),
    }))
    .sort(
      (left, right) =>
        right.responseBytes - left.responseBytes ||
        right.requests - left.requests,
    )
    .slice(0, 12);
  const requestCount = counterSnapshot.requests;
  const errorRate = requestCount
    ? Number(((counterSnapshot.errors / requestCount) * 100).toFixed(2))
    : 0;
  const snapshot = {
    at: nowIso(),
    uptimeSeconds: Math.trunc((Date.now() - startedAt) / 1000),
    application: {
      cpuPercent,
      monitorIntervalMinutes: ACTIVE_MONITOR_INTERVAL_MS / 60_000,
      monitorCacheMinutes: MONITOR_CACHE_MS / 60_000,
      memoryRssBytes: memory.rss,
      memoryHeapBytes: memory.heapUsed,
      memoryLimitBytes: INSTANCE_MEMORY_MB * 1024 * 1024,
      memoryPercent,
      sampleWindowSeconds: Number(counterWindowSeconds.toFixed(1)),
      requestsInWindow: requestCount,
      errorsInWindow: counterSnapshot.errors,
      messagesInWindow: counterSnapshot.messages,
      uploadsInWindow: counterSnapshot.uploads,
      uploadFailuresInWindow: counterSnapshot.uploadFailures,
      licenseFailuresInWindow: counterSnapshot.licenseFailures,
      telegramWebhookFailuresInWindow:
        counterSnapshot.telegramWebhookFailures,
      legacyRequestsInWindow: counterSnapshot.legacyRequests,
      fullHistoryReadsInWindow: counterSnapshot.fullHistoryReads,
      fullHistoryMessagesInWindow: counterSnapshot.fullHistoryMessages,
      databaseMediaReadsInWindow: counterSnapshot.databaseMediaReads,
      databaseMediaBytesInWindow: counterSnapshot.databaseMediaBytes,
      topRoutes,
      requestsPerMinute: perMinute(requestCount),
      errorsPerMinute: perMinute(counterSnapshot.errors),
      errorRate,
      averageResponseMs: requestLatencies.length
        ? Number(
            (
              requestLatencies.reduce((sum, value) => sum + value, 0) /
              requestLatencies.length
            ).toFixed(1),
          )
        : 0,
      p95ResponseMs: percentile(requestLatencies, 95),
      messagesPerMinute: perMinute(counterSnapshot.messages),
      uploadsPerMinute: perMinute(counterSnapshot.uploads),
      uploadFailuresPerMinute: perMinute(counterSnapshot.uploadFailures),
      activeUploads,
      sseConnections: sseClients.size,
      onlineTenants: new Set(
        [...sseClients]
          .filter((client) => client.kind === 'tenant_admin')
          .map((client) => client.tenantId),
      ).size,
      onlineVisitors: new Set(
        [...sseClients]
          .filter((client) => client.kind === 'user')
          .map((client) => client.conversationId),
      ).size,
      licenseFailuresPerMinute: perMinute(counterSnapshot.licenseFailures),
      telegramWebhookFailuresPerMinute:
        perMinute(counterSnapshot.telegramWebhookFailures),
      legacyRequestsPerMinute: perMinute(counterSnapshot.legacyRequests),
    },
    database: {
      connected: true,
      queryLatencyMs: databaseSample.latencyMs,
      sizeBytes: Number(database.rows[0]?.database_size || 0),
      activeConnections: Number(
        database.rows[0]?.active_connections || 0,
      ),
      idleConnections: Number(database.rows[0]?.idle_connections || 0),
      poolTotal: pool.totalCount,
      poolIdle: pool.idleCount,
      poolWaiting: pool.waitingCount,
      tables: tables.rows.map((row) => ({
        name: row.relname,
        bytes: Number(row.bytes || 0),
      })),
    },
    business: {
      tenants: Number(business.rows[0]?.tenants || 0),
      visitorsToday: Number(business.rows[0]?.visitors_today || 0),
      conversationsToday: Number(
        business.rows[0]?.conversations_today || 0,
      ),
      messagesToday: Number(business.rows[0]?.messages_today || 0),
      mediaBytes: Number(business.rows[0]?.media_bytes || 0),
      r2DeleteQueue: Number(business.rows[0]?.delete_queue || 0),
      r2Enabled: R2_ENABLED,
      cleanupIntervalMinutes: ACTIVE_CLEANUP_INTERVAL_MS / 60_000,
      cleanupLastRunAt: lastCleanupAt
        ? new Date(lastCleanupAt).toISOString()
        : null,
    },
    provider: {
      render: provider.render,
      neon: provider.neon,
      cloudflareTurn: provider.cloudflareTurn,
    },
    version: (await getPlatformSettings()).currentVersion,
  };
  metricSamples.push(snapshot);
  if (metricSamples.length > 1440) metricSamples.shift();
  lastMonitorSnapshot = snapshot;
  if (persist) {
    await pool.query(
      `INSERT INTO system_metric_samples (metrics) VALUES ($1::jsonb)`,
      [JSON.stringify(snapshot)],
    );
    lastPersistedMonitorAt = Date.now();
  }
  if (persist) {
    for (const key of Object.keys(minuteCounters)) minuteCounters[key] = 0;
    requestLatencies.length = 0;
    routeCounters.clear();
    lastMonitorCounterResetAt = Date.now();
  }
  broadcastSuper({ type: 'monitor-updated', monitor: snapshot });
  if (persist) await evaluateAlerts(snapshot);
  return snapshot;
}

async function getMonitorSnapshotCached({ force = false, persist = false } = {}) {
  const sampledAt = lastMonitorSnapshot?.at
    ? new Date(lastMonitorSnapshot.at).getTime()
    : 0;
  if (
    !force &&
    lastMonitorSnapshot &&
    Date.now() - sampledAt < MONITOR_CACHE_MS
  ) {
    return lastMonitorSnapshot;
  }
  if (activeMonitorPromise) return activeMonitorPromise;
  activeMonitorPromise = collectMonitorSnapshot({ persist })
    .catch((error) => {
      console.error('监控采集失败：', error.message);
      if (persist) handleMonitorFailure(error).catch(() => {});
      if (lastMonitorSnapshot) return lastMonitorSnapshot;
      throw error;
    })
    .finally(() => {
      activeMonitorPromise = null;
    });
  return activeMonitorPromise;
}

function scheduleActiveDatabaseWork(pathname) {
  if (!pathname.startsWith('/api/')) return;
  if (
    pathname === '/api/telegram/webhook' ||
    pathname.startsWith('/api/public/')
  ) return;
  if (
    Date.now() - lastPersistedMonitorAt >= ACTIVE_MONITOR_INTERVAL_MS &&
    Date.now() >= nextMonitorRetryAt &&
    !activeMonitorPromise
  ) {
    setTimeout(() => {
      getMonitorSnapshotCached({ force: true, persist: true }).catch(() => {});
    }, 0).unref();
  }
  if (
    Date.now() - lastCleanupAt >= ACTIVE_CLEANUP_INTERVAL_MS &&
    Date.now() >= nextCleanupRetryAt &&
    !activeMaintenancePromise
  ) {
    activeMaintenancePromise = Promise.resolve()
      .then(() => maybeCleanupExpiredData())
      .finally(() => {
        activeMaintenancePromise = null;
      });
  }
}

async function sendTelegramAlert(text) {
  if (!TELEGRAM_ENABLED) return;
  const settings = await getPlatformSettings().catch(
    () => lastPlatformSettings,
  );
  if (!settings?.telegramGroupId) return;
  await telegramApi('sendMessage', {
    chat_id: settings.telegramGroupId,
    text,
  });
}

async function evaluateAlerts(snapshot) {
  monitorFailureCount = 0;
  nextMonitorRetryAt = 0;
  const settings = await getPlatformSettings();
  const options = settings.alertSettings || {};
  const number = (key, fallback, minimum, maximum) => {
    const value = Number(options[key]);
    return Number.isFinite(value)
      ? Math.min(maximum, Math.max(minimum, value))
      : fallback;
  };
  const cpuThreshold = number('cpuPercent', 85, 20, 100);
  const memoryThreshold = number('memoryPercent', 85, 20, 100);
  const errorThreshold = number('errorRatePercent', 5, 0.1, 100);
  const minimumRequests = number('minimumRequestsPerMinute', 20, 1, 100000);
  const sseThreshold = number('sseCapacityPercent', 85, 20, 100);
  const uploadFailureThreshold = number('uploadFailures', 3, 1, 1000);
  const consecutiveChecks = number('consecutiveChecks', 2, 1, 10);
  const cooldownMinutes = number('cooldownMinutes', 60, 5, 1440);
  const cleanupAlertAfterMinutes = Math.max(
    45,
    Math.ceil((ACTIVE_CLEANUP_INTERVAL_MS * 2) / 60_000),
  );
  const enabled = (code) => options[`${code}Enabled`] !== false;
  const checks = [
    {
      code: 'cpu',
      active:
        enabled('cpu') &&
        snapshot.application.cpuPercent >= cpuThreshold,
      text: `CPU 持续达到 ${snapshot.application.cpuPercent}%`,
    },
    {
      code: 'memory',
      active:
        enabled('memory') &&
        snapshot.application.memoryPercent >= memoryThreshold,
      text: `内存持续达到 ${snapshot.application.memoryPercent}%`,
    },
    {
      code: 'errors',
      active:
        enabled('errors') &&
        snapshot.application.requestsPerMinute >= minimumRequests &&
        snapshot.application.errorRate >= errorThreshold,
      text: `接口错误率达到 ${snapshot.application.errorRate}%`,
    },
    {
      code: 'sse',
      active:
        enabled('sse') &&
        snapshot.application.sseConnections >=
          MAX_SSE_CONNECTIONS * (sseThreshold / 100),
      text: `SSE 连接已达到 ${snapshot.application.sseConnections}/${MAX_SSE_CONNECTIONS}`,
    },
    {
      code: 'r2',
      active:
        enabled('r2') &&
        snapshot.application.uploadFailuresInWindow >=
          uploadFailureThreshold,
      text: `媒体上传失败 ${snapshot.application.uploadFailuresInWindow} 次（当前采样窗口）`,
    },
    {
      code: 'render',
      active:
        enabled('render') &&
        snapshot.provider.render?.configured &&
        snapshot.provider.render?.reachable === false,
      text: 'Render 平台接口连续检测失败',
    },
    {
      code: 'neon',
      active:
        enabled('neon') &&
        snapshot.provider.neon?.configured &&
        snapshot.provider.neon?.reachable === false,
      text: 'Neon 平台接口连续检测失败',
    },
    {
      code: 'cleanup',
      active:
        enabled('cleanup') &&
        Date.now() - (lastCleanupAt || startedAt) >
          cleanupAlertAfterMinutes * 60_000,
      text: `消息与媒体清理任务超过${cleanupAlertAfterMinutes}分钟未成功运行`,
    },
    {
      code: 'telegram',
      active:
        enabled('telegram') &&
        snapshot.application.telegramWebhookFailuresInWindow > 0,
      text: `Telegram Webhook 处理失败 ${snapshot.application.telegramWebhookFailuresInWindow} 次（当前采样窗口）`,
    },
  ];
  for (const check of checks) {
    const previous = alertState.get(check.code) || {
      count: 0,
      lastSentAt: 0,
    };
    previous.count = check.active ? previous.count + 1 : 0;
    if (
      previous.count >= consecutiveChecks &&
      Date.now() - previous.lastSentAt > cooldownMinutes * 60_000
    ) {
      previous.lastSentAt = Date.now();
      await sendTelegramAlert(
        `⚠️ 拓界云客服系统告警\n${check.text}\n时间：${new Date().toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' })}`,
      ).catch(() => {});
    }
    alertState.set(check.code, previous);
  }
}

async function handleMonitorFailure(error) {
  monitorFailureCount += 1;
  nextMonitorRetryAt =
    Date.now() +
    Math.min(
      15 * 60_000,
      30_000 * 2 ** Math.min(monitorFailureCount - 1, 5),
    );
  if (monitorFailureCount !== 2) return;
  await sendTelegramAlert(
    [
      '⚠️ 拓界云客服系统告警',
      '数据库或监控采集连续两次失败',
      `错误：${cleanText(error.message, 300)}`,
      `时间：${new Date().toLocaleString('zh-CN', {
        timeZone: 'Asia/Shanghai',
      })}`,
    ].join('\n'),
  ).catch(() => {});
}

function timezoneParts(date, timeZone) {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  return Object.fromEntries(
    parts
      .filter((part) => part.type !== 'literal')
      .map((part) => [part.type, part.value]),
  );
}

function offsetIsoDate(dateText, offsetDays) {
  return new Date(
    new Date(`${dateText}T12:00:00Z`).getTime() + offsetDays * 86_400_000,
  )
    .toISOString()
    .slice(0, 10);
}

function sampleRequestTotal(sample) {
  const application = sample?.application || {};
  if (Number.isFinite(Number(application.requestsInWindow))) {
    return Number(application.requestsInWindow);
  }
  // 2.0.0 旧样本虽命名为“每分钟”，实际保存的是整个采样窗口总数。
  return Number(application.requestsPerMinute || 0);
}

async function getYesterdaySystemAssessment() {
  const settings = await getPlatformSettings();
  let timeZone = settings.reportTimezone || 'Asia/Shanghai';
  let parts;
  try {
    parts = timezoneParts(new Date(), timeZone);
  } catch {
    timeZone = 'Asia/Shanghai';
    parts = timezoneParts(new Date(), timeZone);
  }
  const today = `${parts.year}-${parts.month}-${parts.day}`;
  const date = offsetIsoDate(today, -1);
  const previousDate = offsetIsoDate(today, -2);
  const result = await pool.query(
    `
      SELECT
        metrics,
        (created_at AT TIME ZONE $3)::date::text AS local_date,
        created_at
      FROM system_metric_samples
      WHERE (created_at AT TIME ZONE $3)::date IN ($1::date,$2::date)
      ORDER BY created_at
    `,
    [previousDate, date, timeZone],
  );
  const samples = result.rows
    .filter((row) => row.local_date === date)
    .map((row) => row.metrics || {});
  const previousSamples = result.rows
    .filter((row) => row.local_date === previousDate)
    .map((row) => row.metrics || {});
  const values = (selector, list = samples) =>
    list
      .map((item) => Number(selector(item)))
      .filter(Number.isFinite);
  const average = (selector, list = samples) => {
    const items = values(selector, list);
    return items.length
      ? items.reduce((sum, value) => sum + value, 0) / items.length
      : 0;
  };
  const maximum = (selector, list = samples) =>
    Math.max(0, ...values(selector, list));
  const latest = samples.at(-1) || {};
  const previousLatest = previousSamples.at(-1) || {};
  const sampleCount = samples.length;
  const sampleIntervalMinutes = Math.max(
    1,
    Math.round(ACTIVE_MONITOR_INTERVAL_MS / 60_000),
  );
  const expectedSamples = Math.ceil(1440 / sampleIntervalMinutes);
  const coveragePercent = Number(
    Math.min(100, (sampleCount / expectedSamples) * 100).toFixed(1),
  );
  const cpuHighMinutes = samples.filter(
    (item) => Number(item.application?.cpuPercent || 0) >= 80,
  ).length * sampleIntervalMinutes;
  const memoryHighMinutes = samples.filter(
    (item) => Number(item.application?.memoryPercent || 0) >= 85,
  ).length * sampleIntervalMinutes;
  const databaseWaitingMinutes = samples.filter(
    (item) => Number(item.database?.poolWaiting || 0) > 0,
  ).length * sampleIntervalMinutes;
  const cpuAverage = Number(
    average((item) => item.application?.cpuPercent).toFixed(1),
  );
  const cpuPeak = Number(
    maximum((item) => item.application?.cpuPercent).toFixed(1),
  );
  const memoryAverage = Number(
    average((item) => item.application?.memoryPercent).toFixed(1),
  );
  const memoryPeak = Number(
    maximum((item) => item.application?.memoryPercent).toFixed(1),
  );
  const responseAverage = Number(
    average((item) => item.application?.averageResponseMs).toFixed(1),
  );
  const response95Peak = Number(
    maximum((item) => item.application?.p95ResponseMs).toFixed(1),
  );
  const errorRatePeak = Number(
    maximum((item) => item.application?.errorRate).toFixed(1),
  );
  const databaseLatencyAverage = Number(
    average((item) => item.database?.queryLatencyMs).toFixed(1),
  );
  const databaseLatencyPeak = Number(
    maximum((item) => item.database?.queryLatencyMs).toFixed(1),
  );
  const databaseBytes = Number(latest.database?.sizeBytes || 0);
  const previousDatabaseBytes = Number(
    previousLatest.database?.sizeBytes || 0,
  );
  const databaseGrowthBytes =
    databaseBytes && previousDatabaseBytes
      ? databaseBytes - previousDatabaseBytes
      : 0;
  const databaseConnectionPeak = maximum(
    (item) => item.database?.activeConnections,
  );
  const databaseWaitingPeak = maximum(
    (item) => item.database?.poolWaiting,
  );
  const totalRequests = samples.reduce(
    (sum, item) => sum + sampleRequestTotal(item),
    0,
  );
  const insufficient = sampleCount < 4;
  let serverStatus = 'healthy';
  if (
    cpuAverage >= 70 ||
    memoryAverage >= 75 ||
    cpuHighMinutes >= 60 ||
    memoryHighMinutes >= 30
  ) {
    serverStatus = 'upgrade';
  } else if (
    cpuPeak >= 90 ||
    memoryPeak >= 90 ||
    response95Peak >= 1000 ||
    errorRatePeak >= 5
  ) {
    serverStatus = 'watch';
  }
  let databaseStatus = 'healthy';
  if (databaseWaitingMinutes >= 5) {
    databaseStatus = 'upgrade';
  } else if (
    databaseWaitingPeak > 0 ||
    databaseLatencyAverage >= 500 ||
    databaseLatencyPeak >= 1000 ||
    databaseConnectionPeak >= Math.max(4, DB_POOL_MAX) ||
    databaseBytes >= 400 * 1024 * 1024 ||
    databaseGrowthBytes >= 100 * 1024 * 1024
  ) {
    databaseStatus = 'watch';
  }
  let status = 'healthy';
  if (insufficient) status = 'insufficient';
  else if ([serverStatus, databaseStatus].includes('upgrade')) status = 'upgrade';
  else if ([serverStatus, databaseStatus].includes('watch')) status = 'watch';
  const recommendation = {
    healthy: '昨天运行平稳，当前服务器和数据库配置可以继续使用，暂时无需升级。',
    watch: '昨天出现短时峰值或容量提醒，当前仍可运行，建议连续观察三天后再决定是否升级。',
    upgrade: '昨天存在持续资源压力，建议优先升级标记为“建议升级”的项目。',
    insufficient: '昨天有效监控样本不足，暂时无法可靠判断是否需要升级，请至少连续运行一整天。',
  }[status];
  return {
    date,
    timeZone,
    status,
    recommendation,
    sampleCount,
    coveragePercent,
    server: {
      status: insufficient ? 'insufficient' : serverStatus,
      cpuAverage,
      cpuPeak,
      cpuHighMinutes,
      memoryAverage,
      memoryPeak,
      memoryHighMinutes,
      totalRequests,
      responseAverage,
      response95Peak,
      errorRatePeak,
      ssePeak: maximum((item) => item.application?.sseConnections),
    },
    database: {
      status: insufficient ? 'insufficient' : databaseStatus,
      sizeBytes: databaseBytes,
      growthBytes: databaseGrowthBytes,
      connectionPeak: databaseConnectionPeak,
      poolWaitingPeak: databaseWaitingPeak,
      waitingMinutes: databaseWaitingMinutes,
      latencyAverage: databaseLatencyAverage,
      latencyPeak: databaseLatencyPeak,
    },
  };
}

async function buildDailyReport(reportDate, timeZone) {
  const monitor =
    lastMonitorSnapshot ||
    (await collectMonitorSnapshot({ persist: false }));
  const [license, business] = await Promise.all([
    pool.query(`
      SELECT
        COUNT(*) FILTER (
          WHERE (created_at AT TIME ZONE $2)::date = $1::date
        )::int AS generated,
        COUNT(*) FILTER (
          WHERE (activated_at AT TIME ZONE $2)::date = $1::date
        )::int AS activated,
        COUNT(*) FILTER (
          WHERE (revoked_at AT TIME ZONE $2)::date = $1::date
        )::int AS revoked
      FROM license_keys
    `, [reportDate, timeZone]),
    pool.query(`
      SELECT
        (SELECT COUNT(*)::int FROM tenants) AS tenants,
        (SELECT COUNT(*)::int FROM tenants
          WHERE (created_at AT TIME ZONE $2)::date=$1::date
        ) AS new_tenants,
        (SELECT COUNT(*)::int FROM tenants
          WHERE (access_expires_at AT TIME ZONE $2)::date=$1::date
        ) AS expired_tenants,
        (SELECT COUNT(*)::int FROM conversations
          WHERE (created_at AT TIME ZONE $2)::date=$1::date
        ) AS visitors,
        (SELECT COUNT(*)::int FROM conversations
          WHERE (updated_at AT TIME ZONE $2)::date=$1::date
        ) AS conversations,
        (SELECT COUNT(*)::int FROM messages
          WHERE (created_at AT TIME ZONE $2)::date=$1::date
        ) AS messages,
        (SELECT COUNT(*)::int FROM attachments
          WHERE (created_at AT TIME ZONE $2)::date=$1::date
        ) AS uploads,
        (SELECT COALESCE(SUM(size),0)::bigint FROM attachments
          WHERE (created_at AT TIME ZONE $2)::date=$1::date
        ) AS upload_bytes
    `, [reportDate, timeZone]),
  ]);
  const samples = await pool.query(`
    SELECT metrics
    FROM system_metric_samples
    WHERE (created_at AT TIME ZONE $2)::date = $1::date
  `, [reportDate, timeZone]);
  const sampleMetrics = samples.rows.map((row) => row.metrics || {});
  const maximum = (selector) =>
    sampleMetrics.reduce(
      (value, item) => Math.max(value, Number(selector(item) || 0)),
      0,
    );
  const average = (selector) =>
    sampleMetrics.length
      ? sampleMetrics.reduce(
          (value, item) => value + Number(selector(item) || 0),
          0,
        ) / sampleMetrics.length
      : 0;
  const totalRequests = sampleMetrics.reduce(
    (sum, item) => sum + sampleRequestTotal(item),
    0,
  );
  const abnormalSamples = sampleMetrics.filter(
    (item) =>
      Number(item.application?.errorRate || 0) >= 5 ||
      item.provider?.render?.reachable === false ||
      item.provider?.neon?.reachable === false,
  ).length;
  const businessRow = business.rows[0] || {};
  const data = {
    date: reportDate,
    timeZone,
    version: monitor.version,
    availabilityPercent: Number(
      Math.min(
        100,
        (sampleMetrics.length /
          Math.ceil(1440 / (ACTIVE_MONITOR_INTERVAL_MS / 60_000))) *
          100,
      ).toFixed(2),
    ),
    sampleCount: sampleMetrics.length,
    totalRequests,
    abnormalSamples,
    cpuAverage: Number(
      average((item) => item.application?.cpuPercent).toFixed(1),
    ),
    cpuPeak: Number(
      maximum((item) => item.application?.cpuPercent).toFixed(1),
    ),
    memoryAverage: Number(
      average((item) => item.application?.memoryPercent).toFixed(1),
    ),
    memoryPeak: Number(
      maximum((item) => item.application?.memoryPercent).toFixed(1),
    ),
    p95Peak: Number(
      maximum((item) => item.application?.p95ResponseMs).toFixed(1),
    ),
    errorRatePeak: Number(
      maximum((item) => item.application?.errorRate).toFixed(1),
    ),
    ssePeak: maximum((item) => item.application?.sseConnections),
    ...monitor.business,
    databaseBytes: monitor.database.sizeBytes,
    databaseConnectionPeak: maximum(
      (item) => item.database?.activeConnections,
    ),
    tenants: Number(businessRow.tenants || 0),
    newTenants: Number(businessRow.new_tenants || 0),
    expiredTenants: Number(businessRow.expired_tenants || 0),
    visitorsToday: Number(businessRow.visitors || 0),
    conversationsToday: Number(businessRow.conversations || 0),
    messagesToday: Number(businessRow.messages || 0),
    uploadsToday: Number(businessRow.uploads || 0),
    uploadBytesToday: Number(businessRow.upload_bytes || 0),
    mediaBytes: monitor.business.mediaBytes,
    r2Enabled: monitor.business.r2Enabled,
    cleanupLastRunAt: monitor.business.cleanupLastRunAt,
    cardsGenerated: Number(license.rows[0]?.generated || 0),
    cardsActivated: Number(license.rows[0]?.activated || 0),
    cardsRevoked: Number(license.rows[0]?.revoked || 0),
  };
  const text = [
    '📊 拓界云每日运行报告',
    `日期：${data.date}`,
    `当前版本：v${data.version}`,
    `采样可用率：${data.availabilityPercent}%（${data.sampleCount}/${Math.ceil(1440 / (ACTIVE_MONITOR_INTERVAL_MS / 60_000))}）`,
    '',
    `CPU：平均 ${data.cpuAverage}%｜峰值 ${data.cpuPeak}%`,
    `内存：平均 ${data.memoryAverage}%｜峰值 ${data.memoryPeak}%`,
    `API：请求 ${data.totalRequests}｜P95 峰值 ${data.p95Peak}ms｜错误率峰值 ${data.errorRatePeak}%`,
    `Neon：${formatBytes(data.databaseBytes)}｜连接峰值 ${data.databaseConnectionPeak}`,
    `SSE：连接峰值 ${data.ssePeak}`,
    '',
    `租户：${data.tenants}｜新增 ${data.newTenants}｜到期 ${data.expiredTenants}`,
    `访客：${data.visitorsToday}｜会话 ${data.conversationsToday}｜消息 ${data.messagesToday}`,
    `媒体：上传 ${data.uploadsToday} 个 / ${formatBytes(data.uploadBytesToday)}｜总占用 ${formatBytes(data.mediaBytes)}`,
    `卡密：生成 ${data.cardsGenerated}｜激活 ${data.cardsActivated}｜禁用 ${data.cardsRevoked}`,
    `清理任务：${data.cleanupLastRunAt || '尚未运行'}`,
    `异常采样：${data.abnormalSamples}`,
  ].join('\n');
  return { data, text };
}

async function buildWeeklyReport(weekStart, weekEnd) {
  const [business, licenses, samples] = await Promise.all([
    pool.query(
      `
        SELECT
          (SELECT COUNT(*)::int FROM tenants
            WHERE created_at >= $1::date AND created_at < $2::date) AS new_tenants,
          (SELECT COUNT(*)::int FROM conversations
            WHERE created_at >= $1::date AND created_at < $2::date) AS visitors,
          (SELECT COUNT(*)::int FROM messages
            WHERE created_at >= $1::date AND created_at < $2::date) AS messages,
          (SELECT COUNT(*)::int FROM attachments
            WHERE created_at >= $1::date AND created_at < $2::date) AS uploads,
          (SELECT COALESCE(SUM(size),0)::bigint FROM attachments
            WHERE created_at >= $1::date AND created_at < $2::date) AS upload_bytes
      `,
      [weekStart, weekEnd],
    ),
    pool.query(
      `
        SELECT
          COUNT(*) FILTER (
            WHERE created_at >= $1::date AND created_at < $2::date
          )::int AS generated,
          COUNT(*) FILTER (
            WHERE activated_at >= $1::date AND activated_at < $2::date
          )::int AS activated,
          COUNT(*) FILTER (
            WHERE revoked_at >= $1::date AND revoked_at < $2::date
          )::int AS revoked
        FROM license_keys
      `,
      [weekStart, weekEnd],
    ),
    pool.query(
      `
        SELECT metrics
        FROM system_metric_samples
        WHERE created_at >= $1::date AND created_at < $2::date
      `,
      [weekStart, weekEnd],
    ),
  ]);
  const rows = samples.rows.map((row) => row.metrics || {});
  const values = (selector) =>
    rows.map((row) => Number(selector(row) || 0));
  const average = (selector) => {
    const list = values(selector);
    return list.length
      ? list.reduce((sum, value) => sum + value, 0) / list.length
      : 0;
  };
  const maximum = (selector) => Math.max(0, ...values(selector));
  const current =
    lastMonitorSnapshot ||
    (await collectMonitorSnapshot({ persist: false }));
  const displayEnd = new Date(
    new Date(`${weekEnd}T00:00:00Z`).getTime() - 86_400_000,
  )
    .toISOString()
    .slice(0, 10);
  const data = {
    weekStart,
    weekEnd: displayEnd,
    weekEndExclusive: weekEnd,
    version: current.version,
    sampleCount: rows.length,
    cpuAverage: Number(
      average((item) => item.application?.cpuPercent).toFixed(1),
    ),
    cpuPeak: Number(
      maximum((item) => item.application?.cpuPercent).toFixed(1),
    ),
    memoryAverage: Number(
      average((item) => item.application?.memoryPercent).toFixed(1),
    ),
    memoryPeak: Number(
      maximum((item) => item.application?.memoryPercent).toFixed(1),
    ),
    p95Peak: Number(
      maximum((item) => item.application?.p95ResponseMs).toFixed(1),
    ),
    errorRatePeak: Number(
      maximum((item) => item.application?.errorRate).toFixed(1),
    ),
    ssePeak: maximum((item) => item.application?.sseConnections),
    newTenants: Number(business.rows[0]?.new_tenants || 0),
    visitors: Number(business.rows[0]?.visitors || 0),
    messages: Number(business.rows[0]?.messages || 0),
    uploads: Number(business.rows[0]?.uploads || 0),
    uploadBytes: Number(business.rows[0]?.upload_bytes || 0),
    cardsGenerated: Number(licenses.rows[0]?.generated || 0),
    cardsActivated: Number(licenses.rows[0]?.activated || 0),
    cardsRevoked: Number(licenses.rows[0]?.revoked || 0),
    databaseBytes: current.database.sizeBytes,
    mediaBytes: current.business.mediaBytes,
  };
  const text = [
    '📈 拓界云每周运行报告',
    `周期：${weekStart} 至 ${displayEnd}`,
    `当前版本：v${data.version}`,
    '',
    `CPU：平均 ${data.cpuAverage}%｜峰值 ${data.cpuPeak}%`,
    `内存：平均 ${data.memoryAverage}%｜峰值 ${data.memoryPeak}%`,
    `API：P95 峰值 ${data.p95Peak}ms｜错误率峰值 ${data.errorRatePeak}%`,
    `SSE：连接峰值 ${data.ssePeak}｜有效采样 ${data.sampleCount}`,
    '',
    `新增租户：${data.newTenants}｜访客 ${data.visitors}｜消息 ${data.messages}`,
    `媒体上传：${data.uploads} 个｜${formatBytes(data.uploadBytes)}`,
    `当前 Neon：${formatBytes(data.databaseBytes)}｜媒体总量 ${formatBytes(data.mediaBytes)}`,
    `卡密：生成 ${data.cardsGenerated}｜激活 ${data.cardsActivated}｜禁用 ${data.cardsRevoked}`,
  ].join('\n');
  return { data, text };
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

async function runScheduledReport() {
  const settings = await getPlatformSettings();
  if (
    (!settings.dailyReportEnabled && !settings.weeklyReportEnabled) ||
    !settings.telegramGroupId ||
    !TELEGRAM_ENABLED
  ) return;
  let parts;
  let reportTimezone = settings.reportTimezone;
  try {
    parts = timezoneParts(new Date(), reportTimezone);
  } catch {
    reportTimezone = 'Asia/Shanghai';
    parts = timezoneParts(new Date(), 'Asia/Shanghai');
  }
  const date = `${parts.year}-${parts.month}-${parts.day}`;
  const currentTime = `${parts.hour}:${parts.minute}`;
  if (currentTime !== settings.reportTime) return;
  if (settings.dailyReportEnabled) {
    const reportDate = new Date(`${date}T12:00:00Z`);
    reportDate.setUTCDate(reportDate.getUTCDate() - 1);
    const reportDateText = reportDate.toISOString().slice(0, 10);
    const claimed = await pool.query(
      `
        INSERT INTO daily_reports (report_date, status)
        VALUES ($1, 'pending')
        ON CONFLICT (report_date) DO NOTHING
        RETURNING report_date
      `,
      [reportDateText],
    );
    if (claimed.rows[0]) {
      try {
        const report = await buildDailyReport(
          reportDateText,
          reportTimezone,
        );
        await telegramApi('sendMessage', {
          chat_id: settings.telegramGroupId,
          text: report.text,
        });
        await pool.query(
          `
            UPDATE daily_reports
            SET status='sent',summary=$2::jsonb,sent_at=NOW(),updated_at=NOW()
            WHERE report_date=$1
          `,
          [reportDateText, JSON.stringify(report.data)],
        );
      } catch (error) {
        await pool.query(
          `
            UPDATE daily_reports
            SET status='failed',error=$2,updated_at=NOW()
            WHERE report_date=$1
          `,
          [reportDateText, cleanText(error.message, 500)],
        );
      }
    }
  }
  const localDay = new Date(`${date}T12:00:00Z`).getUTCDay();
  if (settings.weeklyReportEnabled && localDay === 1) {
    const weekEndDate = new Date(`${date}T00:00:00Z`);
    const weekStartDate = new Date(weekEndDate.getTime() - 7 * 86400_000);
    const weekStart = weekStartDate.toISOString().slice(0, 10);
    const weekEnd = weekEndDate.toISOString().slice(0, 10);
    const claimed = await pool.query(
      `
        INSERT INTO weekly_reports (week_start,week_end,status)
        VALUES ($1,$2,'pending')
        ON CONFLICT (week_start) DO NOTHING
        RETURNING week_start
      `,
      [weekStart, weekEnd],
    );
    if (claimed.rows[0]) {
      try {
        const report = await buildWeeklyReport(weekStart, weekEnd);
        await telegramApi('sendMessage', {
          chat_id: settings.telegramGroupId,
          text: report.text,
        });
        await pool.query(
          `
            UPDATE weekly_reports
            SET status='sent',summary=$2::jsonb,sent_at=NOW(),updated_at=NOW()
            WHERE week_start=$1
          `,
          [weekStart, JSON.stringify(report.data)],
        );
      } catch (error) {
        await pool.query(
          `
            UPDATE weekly_reports
            SET status='failed',error=$2,updated_at=NOW()
            WHERE week_start=$1
          `,
          [weekStart, cleanText(error.message, 500)],
        );
      }
    }
  }
}

async function processExpiryReminders() {
  const result = await pool.query(`
    UPDATE tenants
    SET expiry_reminder_sent_at=NOW(),
        updated_at=NOW()
    WHERE status='active'
      AND access_expires_at > NOW()
      AND access_expires_at <= NOW() + INTERVAL '3 days'
      AND expiry_reminder_sent_at IS NULL
    RETURNING id, access_expires_at
  `);
  for (const tenant of result.rows) {
    const remainingHours = Math.max(
      1,
      Math.ceil(
        (new Date(tenant.access_expires_at).getTime() - Date.now()) /
          3_600_000,
      ),
    );
    broadcast(
      {
        type: 'license-expiry-warning',
        accessExpiresAt: new Date(tenant.access_expires_at).toISOString(),
        dataDeleteAt: new Date(
          new Date(tenant.access_expires_at).getTime() +
            EXPIRED_TENANT_GRACE_DAYS * 86_400_000,
        ).toISOString(),
        graceDays: EXPIRED_TENANT_GRACE_DAYS,
        remainingHours,
        message: `卡密即将到期；若未续费，到期 ${EXPIRED_TENANT_GRACE_DAYS} 天后将自动清除租户数据。`,
        at: nowIso(),
      },
      null,
      tenant.id,
    );
  }
  if (result.rowCount) broadcastSuper({ type: 'tenants-updated' });
  return result.rowCount;
}

function nextReportDelay(settings) {
  const [targetHour, targetMinute] = String(settings.reportTime || '09:00')
    .split(':')
    .map(Number);
  const start = new Date();
  start.setSeconds(0, 0);
  start.setMinutes(start.getMinutes() + 1);
  for (let offset = 0; offset < 2 * 24 * 60; offset += 1) {
    const candidate = new Date(start.getTime() + offset * 60_000);
    try {
      const parts = timezoneParts(
        candidate,
        settings.reportTimezone || 'Asia/Shanghai',
      );
      if (
        Number(parts.hour) === targetHour &&
        Number(parts.minute) === targetMinute
      ) return Math.max(1000, candidate.getTime() - Date.now());
    } catch {
      return 60 * 60_000;
    }
  }
  return 24 * 60 * 60_000;
}

async function scheduleNextReport() {
  if (reportTimer) clearTimeout(reportTimer);
  reportTimer = null;
  const settings = await getPlatformSettings();
  if (
    (!settings.dailyReportEnabled && !settings.weeklyReportEnabled) ||
    !settings.telegramGroupId ||
    !TELEGRAM_ENABLED
  ) return;
  reportTimer = setTimeout(async () => {
    reportTimer = null;
    try {
      await runScheduledReport();
    } catch (error) {
      console.error('Telegram 日报发送失败：', error.message);
    } finally {
      scheduleNextReport().catch(() => {});
    }
  }, nextReportDelay(settings));
  reportTimer.unref();
}

function requestExpiryReminderReschedule() {
  if (expiryReminderRescheduleTimer) return;
  expiryReminderRescheduleTimer = setTimeout(() => {
    expiryReminderRescheduleTimer = null;
    scheduleNextExpiryReminder().catch((error) =>
      console.error('到期提醒调度失败：', error.message),
    );
  }, 250);
  expiryReminderRescheduleTimer.unref();
}

function requestExpiredTenantPurgeReschedule() {
  if (expiredTenantPurgeRescheduleTimer) return;
  expiredTenantPurgeRescheduleTimer = setTimeout(() => {
    expiredTenantPurgeRescheduleTimer = null;
    scheduleNextExpiredTenantPurge().catch((error) =>
      console.error('到期租户清理调度失败：', error.message),
    );
  }, 250);
  expiredTenantPurgeRescheduleTimer.unref();
}

async function scheduleNextExpiryReminder() {
  if (expiryReminderTimer) clearTimeout(expiryReminderTimer);
  expiryReminderTimer = null;
  await processExpiryReminders();
  const result = await pool.query(`
    SELECT MIN(access_expires_at - INTERVAL '3 days') AS remind_at
    FROM tenants
    WHERE status='active'
      AND access_expires_at > NOW()
      AND expiry_reminder_sent_at IS NULL
  `);
  const remindAt = result.rows[0]?.remind_at
    ? new Date(result.rows[0].remind_at).getTime()
    : 0;
  const delay = remindAt
    ? Math.min(
        24 * 60 * 60_000,
        Math.max(1000, remindAt - Date.now() + 1000),
      )
    : 24 * 60 * 60_000;
  expiryReminderTimer = setTimeout(() => {
    scheduleNextExpiryReminder().catch((error) =>
      console.error('到期提醒调度失败：', error.message),
    );
  }, delay);
  expiryReminderTimer.unref();
}

async function scheduleNextExpiredTenantPurge() {
  if (expiredTenantPurgeTimer) clearTimeout(expiredTenantPurgeTimer);
  expiredTenantPurgeTimer = null;
  const result = await pool.query(
    `
      SELECT MIN(
        access_expires_at + ($1::int * INTERVAL '1 day')
      ) AS purge_at
      FROM tenants
    `,
    [EXPIRED_TENANT_GRACE_DAYS],
  );
  const purgeAt = result.rows[0]?.purge_at
    ? new Date(result.rows[0].purge_at).getTime()
    : 0;
  const delay = purgeAt
    ? Math.min(
        24 * 60 * 60_000,
        Math.max(1000, purgeAt - Date.now() + 1000),
      )
    : 24 * 60 * 60_000;
  expiredTenantPurgeTimer = setTimeout(async () => {
    try {
      await maybeCleanupExpiredData(true);
    } catch (error) {
      console.error('到期租户自动清理失败：', error.message);
    } finally {
      scheduleNextExpiredTenantPurge().catch((error) =>
        console.error('到期租户清理调度失败：', error.message),
      );
    }
  }, delay);
  expiredTenantPurgeTimer.unref();
}

function startBackgroundJobs() {
  processObjectDeleteQueue().catch(() => {});
  scheduleLegacySuperKeyBackfill();
  scheduleNextExpiryReminder().catch((error) =>
    console.error('到期提醒调度失败：', error.message),
  );
  scheduleNextExpiredTenantPurge().catch((error) =>
    console.error('到期租户清理调度失败：', error.message),
  );
  scheduleNextReport().catch((error) =>
    console.error('Telegram 报告调度失败：', error.message),
  );
}

function effectiveLicenseStatus(row) {
  if (
    row.status === 'active' &&
    row.expires_at &&
    new Date(row.expires_at).getTime() <= Date.now()
  ) return 'expired';
  return row.status;
}

function publicLicenseRow(row) {
  return {
    id: row.id,
    tenantId: row.tenant_id || null,
    maskedKey: licenseHint(row),
    superMaskedKey: superLicenseHint(row),
    durationCode: row.duration_code,
    durationDays: Number(row.duration_days),
    durationHours: Number(
      LICENSE_DURATIONS[row.duration_code]?.hours ||
        Number(row.duration_days || 1) * 24,
    ),
    durationLabel:
      LICENSE_DURATIONS[row.duration_code]?.label || row.duration_code,
    status: effectiveLicenseStatus(row),
    storedStatus: row.status,
    disableMode: row.disable_mode === 'busy' ? 'busy' : 'notice',
    superUsable: Boolean(
      row.super_key_hash &&
      !['archived', 'superseded'].includes(row.status) &&
      (!row.expires_at || new Date(row.expires_at).getTime() > Date.now()),
    ),
    maxDesktopDevices: Number(
      row.max_desktop_devices || LICENSE_DESKTOP_DEVICE_DEFAULT,
    ),
    maxMobileDevices: Number(
      row.max_mobile_devices || LICENSE_MOBILE_DEVICE_DEFAULT,
    ),
    desktopDevices: Number(row.desktop_devices || 0),
    mobileDevices: Number(row.mobile_devices || 0),
    generator:
      row.generated_by_username ||
      (row.generated_by_distributor_username
        ? `二级代理 · ${row.generated_by_distributor_username}`
        : '') ||
      telegramLicenseCreator(row),
    generatedByDistributorId: row.generated_by_distributor_id || null,
    tenantName: row.tenant_name || '',
    activatedAt: row.activated_at
      ? new Date(row.activated_at).toISOString()
      : null,
    expiresAt: row.expires_at
      ? new Date(row.expires_at).toISOString()
      : null,
    revokedAt: row.revoked_at
      ? new Date(row.revoked_at).toISOString()
      : null,
    archivedAt: row.archived_at
      ? new Date(row.archived_at).toISOString()
      : null,
    lastUsedAt: row.last_used_at
      ? new Date(row.last_used_at).toISOString()
      : null,
    createdAt: new Date(row.created_at).toISOString(),
  };
}

function recordRealtimeChatActivity(
  tenantId,
  conversationId,
  role,
  occurredAt = null,
) {
  if (
    !isUuid(tenantId) ||
    !isUuid(conversationId) ||
    !['user', 'admin'].includes(role)
  ) return;
  const at = occurredAt ? new Date(occurredAt).getTime() : Date.now();
  const timestamp = Number.isFinite(at) ? at : Date.now();
  let tenant = recentChatActivity.get(tenantId);
  if (!tenant) {
    tenant = new Map();
    recentChatActivity.set(tenantId, tenant);
  }
  const activity = tenant.get(conversationId) || { userAt: 0, adminAt: 0 };
  activity[role === 'user' ? 'userAt' : 'adminAt'] = timestamp;
  tenant.set(conversationId, activity);
}

function tenantActiveChatCount(tenantId, onlineVisitorIds = new Set()) {
  const tenant = recentChatActivity.get(tenantId);
  if (!tenant) return 0;
  const cutoff = Date.now() - ACTIVE_CHAT_WINDOW_MS;
  let count = 0;
  for (const [conversationId, activity] of tenant) {
    if (Math.max(activity.userAt || 0, activity.adminAt || 0) < cutoff) {
      tenant.delete(conversationId);
      continue;
    }
    if (
      onlineVisitorIds.has(conversationId) &&
      Number(activity.userAt || 0) >= cutoff &&
      Number(activity.adminAt || 0) >= cutoff
    ) count += 1;
  }
  if (!tenant.size) recentChatActivity.delete(tenantId);
  return count;
}

function getRealtimePresenceSnapshot() {
  const presence = new Map();
  for (const client of sseClients) {
    if (!isUuid(client.tenantId)) continue;
    if (!['tenant_admin', 'user'].includes(client.kind)) continue;
    const item = presence.get(client.tenantId) || {
      tenantId: client.tenantId,
      adminDevices: 0,
      visitorIds: new Set(),
    };
    if (client.kind === 'tenant_admin') item.adminDevices += 1;
    if (client.kind === 'user' && client.conversationId) {
      item.visitorIds.add(client.conversationId);
    }
    presence.set(client.tenantId, item);
  }
  const tenants = [...presence.values()].map((item) => {
    const activeChats = tenantActiveChatCount(item.tenantId, item.visitorIds);
    return {
      tenantId: item.tenantId,
      adminDevices: item.adminDevices,
      onlineVisitors: item.visitorIds.size,
      activeChats,
      chatting: item.adminDevices > 0 && activeChats > 0,
    };
  });
  return {
    onlineTenantCount: tenants.filter((item) => item.adminDevices > 0).length,
    onlineTenantDevices: tenants.reduce(
      (sum, item) => sum + item.adminDevices,
      0,
    ),
    chattingTenantCount: tenants.filter((item) => item.chatting).length,
    onlineVisitors: tenants.reduce(
      (sum, item) => sum + item.onlineVisitors,
      0,
    ),
    tenants,
  };
}

function getDistributorPresenceSnapshot(distributorId) {
  const presence = new Map();
  for (const client of sseClients) {
    if (client.ownerDistributorId !== distributorId) continue;
    if (!isUuid(client.tenantId)) continue;
    if (!['tenant_admin', 'user'].includes(client.kind)) continue;
    const item = presence.get(client.tenantId) || {
      tenantId: client.tenantId,
      adminDevices: 0,
      visitorIds: new Set(),
    };
    if (client.kind === 'tenant_admin') item.adminDevices += 1;
    if (client.kind === 'user' && client.conversationId) {
      item.visitorIds.add(client.conversationId);
    }
    presence.set(client.tenantId, item);
  }
  const tenants = [...presence.values()].map((item) => {
    const activeChats = tenantActiveChatCount(item.tenantId, item.visitorIds);
    return {
      tenantId: item.tenantId,
      adminDevices: item.adminDevices,
      onlineVisitors: item.visitorIds.size,
      activeChats,
      chatting: item.adminDevices > 0 && activeChats > 0,
    };
  });
  return {
    onlineTenants: tenants.filter((item) => item.adminDevices > 0).length,
    chattingTenants: tenants.filter((item) => item.chatting).length,
    tenants,
  };
}

async function getRealtimeTenantPresence() {
  const snapshot = getRealtimePresenceSnapshot();
  const tenantIds = snapshot.tenants.map((item) => item.tenantId);
  const tenantRows = tenantIds.length
    ? (
        await pool.query(
          `SELECT id,name,public_code FROM tenants WHERE id=ANY($1::uuid[])`,
          [tenantIds],
        )
      ).rows
    : [];
  const tenantMeta = new Map(tenantRows.map((row) => [row.id, row]));
  const tenants = snapshot.tenants
    .map((item) => {
      const row = tenantMeta.get(item.tenantId) || {};
      return {
        ...item,
        tenantId: item.tenantId,
        name: row.name || '未命名租户',
        publicCode: row.public_code || '',
      };
    })
    .sort((left, right) =>
      Number(right.chatting) - Number(left.chatting) ||
      right.adminDevices - left.adminDevices ||
      left.name.localeCompare(right.name, 'zh-CN'),
    );
  return {
    ...snapshot,
    tenants,
  };
}

async function getSuperDashboard() {
  if (
    superDashboardCache.value &&
    superDashboardCache.expiresAt > Date.now()
  ) return superDashboardCache.value;
  if (superDashboardCache.promise) return superDashboardCache.promise;
  const request = collectSuperDashboard();
  superDashboardCache.promise = request;
  try {
    const value = await request;
    superDashboardCache.value = value;
    superDashboardCache.expiresAt = Date.now() + 3000;
    return value;
  } finally {
    if (superDashboardCache.promise === request) {
      superDashboardCache.promise = null;
    }
  }
}

async function collectSuperDashboard() {
  const [result, yesterday, presence] = await Promise.all([
    pool.query(`
      WITH
      license_stats AS MATERIALIZED (
        SELECT
          COUNT(*)::int AS total,
          COUNT(*) FILTER (WHERE status='unused')::int AS unused,
          COUNT(*) FILTER (
            WHERE status='active' AND expires_at>NOW()
          )::int AS active,
          COUNT(*) FILTER (
            WHERE status='active' AND expires_at<=NOW()
          )::int AS expired,
          COUNT(*) FILTER (WHERE status='revoked')::int AS revoked,
          COUNT(*) FILTER (
            WHERE status IN ('archived','superseded')
          )::int AS archived
        FROM license_keys
      ),
      conversation_stats AS MATERIALIZED (
        SELECT
          COUNT(*) FILTER (
            WHERE created_at>=date_trunc('day',NOW())
          )::int AS visitors_today,
          COUNT(*) FILTER (
            WHERE updated_at>=date_trunc('day',NOW())
          )::int AS conversations_today
        FROM conversations
      )
      SELECT
        ls.total AS license_total,
        ls.unused AS license_unused,
        ls.active AS license_active,
        ls.expired AS license_expired,
        ls.revoked AS license_revoked,
        ls.archived AS license_archived,
        (SELECT COUNT(*)::int FROM tenants) AS tenants,
        cs.visitors_today,
        cs.conversations_today,
        (SELECT COUNT(*)::int FROM messages
          WHERE created_at>=date_trunc('day',NOW())) AS messages_today,
        (SELECT COALESCE(SUM(size),0)::bigint FROM attachments) +
          (SELECT COALESCE(SUM(size),0)::bigint FROM assets) AS media_bytes
      FROM license_stats ls CROSS JOIN conversation_stats cs
    `),
    getYesterdaySystemAssessment(),
    getRealtimeTenantPresence(),
  ]);
  const row = result.rows[0];
  return {
    licenseTotal: Number(row.license_total || 0),
    licenseUnused: Number(row.license_unused || 0),
    licenseActive: Number(row.license_active || 0),
    licenseExpired: Number(row.license_expired || 0),
    licenseRevoked: Number(row.license_revoked || 0),
    licenseArchived: Number(row.license_archived || 0),
    tenants: Number(row.tenants || 0),
    visitorsToday: Number(row.visitors_today || 0),
    conversationsToday: Number(row.conversations_today || 0),
    messagesToday: Number(row.messages_today || 0),
    mediaBytes: Number(row.media_bytes || 0),
    sseConnections: sseClients.size,
    yesterday,
    presence,
  };
}

async function getSuperLicenses(
  { cursor = null, limit = 2000, search = '', status = '' } = {},
) {
  const decoded = decodeCursor(cursor);
  const keyword = cleanText(search, 120).trim();
  const requestedStatus = [
    'unused',
    'active',
    'expired',
    'revoked',
    'archived',
    'superseded',
  ].includes(status)
    ? status
    : '';
  const result = await pool.query(`
    SELECT
      l.id,l.tenant_id,l.key_prefix,l.key_suffix,
      l.super_key_hash,l.super_key_suffix,
      l.duration_code,l.duration_days,l.status,
      l.disable_mode,
      l.max_desktop_devices,l.max_mobile_devices,
      l.generated_by_admin_id,l.generated_by_distributor_id,
      l.telegram_user_id,l.telegram_username,l.telegram_display_name,
      l.activated_at,l.expires_at,l.revoked_at,l.archived_at,
      l.last_used_at,l.created_at,
      t.name AS tenant_name, sa.username AS generated_by_username,
      d.username AS generated_by_distributor_username,
      COALESCE(device_counts.desktop_devices,0)::int AS desktop_devices,
      COALESCE(device_counts.mobile_devices,0)::int AS mobile_devices
    FROM license_keys l
    LEFT JOIN tenants t ON t.id = l.tenant_id
    LEFT JOIN super_admins sa ON sa.id = l.generated_by_admin_id
    LEFT JOIN distributors d ON d.id = l.generated_by_distributor_id
    LEFT JOIN LATERAL (
      SELECT
        COUNT(*) FILTER (WHERE device_type='desktop') AS desktop_devices,
        COUNT(*) FILTER (WHERE device_type='mobile') AS mobile_devices
      FROM license_devices ld
      WHERE ld.license_id=l.id
        AND ld.access_kind='normal'
        AND ld.revoked_at IS NULL
    ) device_counts ON TRUE
    WHERE (
      $1::timestamptz IS NULL
      OR (l.created_at,l.id) < ($1::timestamptz,$2::uuid)
    )
      AND (
        $3::text=''
        OR ($3='active' AND l.status='active' AND l.expires_at>NOW())
        OR ($3='expired' AND l.status='active' AND l.expires_at<=NOW())
        OR ($3 NOT IN ('active','expired') AND l.status=$3)
      )
      AND (
        $4::text=''
        OR t.name ILIKE '%' || $4 || '%'
        OR COALESCE(sa.username,'') ILIKE '%' || $4 || '%'
        OR COALESCE(d.username,'') ILIKE '%' || $4 || '%'
        OR COALESCE(l.key_suffix,'') ILIKE '%' || $4 || '%'
      )
    ORDER BY l.created_at DESC,l.id DESC
    LIMIT $5
  `, [decoded?.at || null, decoded?.id || null, requestedStatus, keyword, limit]);
  return result.rows.map(publicLicenseRow);
}

async function getSuperLicensePage(options = {}) {
  const limit = Math.min(API_PAGE_MAX, Math.max(1, options.limit || API_PAGE_DEFAULT));
  const rows = await getSuperLicenses({ ...options, limit: limit + 1 });
  const hasMore = rows.length > limit;
  const items = rows.slice(0, limit);
  const last = items.at(-1);
  return {
    items,
    hasMore,
    nextCursor:
      hasMore && last
        ? encodeCursor({ at: last.createdAt, id: last.id })
        : null,
  };
}

async function getSuperTenants(
  { cursor = null, limit = 10000, search = '', status = '' } = {},
) {
  const decoded = decodeCursor(cursor);
  const keyword = cleanText(search, 120).trim();
  const requestedStatus = [
    'active',
    'expired',
    'revoked',
    'archived',
    'superseded',
    'none',
  ].includes(status)
    ? status
    : '';
  const result = await pool.query(`
    WITH tenant_page AS MATERIALIZED (
      SELECT
        t.*,
        l.id AS license_id,
        l.key_prefix,
        l.key_suffix,
        l.duration_code,
        l.duration_days,
        l.expires_at,
        l.status AS license_status,
        l.generated_by_admin_id,
        l.generated_by_distributor_id,
        l.telegram_user_id,
        l.telegram_username,
        l.telegram_display_name,
        sa.username AS generated_by_username,
        d.username AS generated_by_distributor_username,
        owner_d.username AS owner_distributor_username,
        owner_d.display_name AS owner_distributor_display_name,
        tc.retention_hours,
        tc.frontend_template_id,
        ft.name AS frontend_template_name,
        template_history.approved_templates
      FROM tenants t
      LEFT JOIN LATERAL (
        SELECT
          id,key_prefix,key_suffix,duration_code,duration_days,
          expires_at,status,generated_by_admin_id,
          generated_by_distributor_id,telegram_user_id,
          telegram_username,telegram_display_name
        FROM license_keys
        WHERE tenant_id = t.id
        ORDER BY
          CASE WHEN status = 'active' THEN 0 ELSE 1 END,
          created_at DESC
        LIMIT 1
      ) l ON TRUE
      LEFT JOIN super_admins sa ON sa.id = l.generated_by_admin_id
      LEFT JOIN distributors d ON d.id = l.generated_by_distributor_id
      LEFT JOIN distributors owner_d ON owner_d.id = t.owner_distributor_id
      LEFT JOIN tenant_config tc ON tc.tenant_id = t.id
      LEFT JOIN frontend_templates ft ON ft.id = tc.frontend_template_id
      LEFT JOIN LATERAL (
        SELECT jsonb_agg(
          jsonb_build_object(
            'id', history_template.id,
            'name', history_template.name,
            'origin', history_template.origin,
            'status', history_template.status
          )
          ORDER BY
            (history_template.id=tc.frontend_template_id) DESC,
            history.last_selected_at DESC
        ) AS approved_templates
        FROM tenant_frontend_templates history
        JOIN frontend_templates history_template
          ON history_template.id=history.template_id
        WHERE history.tenant_id=t.id
      ) template_history ON TRUE
      WHERE (
        $1::timestamptz IS NULL
        OR (t.updated_at,t.id) < ($1::timestamptz,$2::uuid)
      )
        AND (
          $3::text=''
          OR t.name ILIKE '%' || $3 || '%'
          OR t.note ILIKE '%' || $3 || '%'
          OR t.public_code ILIKE '%' || $3 || '%'
          OR COALESCE(l.key_suffix,'') ILIKE '%' || $3 || '%'
          OR COALESCE(owner_d.username,'') ILIKE '%' || $3 || '%'
          OR COALESCE(owner_d.display_name,'') ILIKE '%' || $3 || '%'
        )
        AND (
          $4::text=''
          OR ($4='active' AND l.status='active' AND l.expires_at>NOW())
          OR ($4='expired' AND l.status='active' AND l.expires_at<=NOW())
          OR ($4='none' AND l.id IS NULL)
          OR ($4 NOT IN ('active','expired','none') AND l.status=$4)
        )
      ORDER BY t.updated_at DESC,t.id DESC
      LIMIT $5
    ),
    today AS MATERIALIZED (
      SELECT
        c.tenant_id,
        COUNT(DISTINCT c.id) FILTER (
          WHERE m.created_at>=date_trunc('day',NOW())
        ) AS visitors,
        COUNT(m.id) FILTER (
          WHERE m.created_at>=date_trunc('day',NOW())
        ) AS messages
      FROM conversations c
      LEFT JOIN messages m ON m.conversation_id=c.id
      WHERE c.tenant_id IN (SELECT id FROM tenant_page)
      GROUP BY c.tenant_id
    ),
    media AS MATERIALIZED (
      SELECT c.tenant_id,COALESCE(SUM(a.size),0)::bigint AS bytes
      FROM conversations c
      JOIN attachments a ON a.conversation_id=c.id
      WHERE c.tenant_id IN (SELECT id FROM tenant_page)
      GROUP BY c.tenant_id
    )
    SELECT
      t.*,
      COALESCE(today.visitors,0)::int AS visitors_today,
      COALESCE(today.messages,0)::int AS messages_today,
      COALESCE(media.bytes,0)::bigint AS media_bytes
    FROM tenant_page t
    LEFT JOIN today ON today.tenant_id=t.id
    LEFT JOIN media ON media.tenant_id=t.id
    ORDER BY t.updated_at DESC,t.id DESC
  `, [
    decoded?.at || null,
    decoded?.id || null,
    keyword,
    requestedStatus,
    limit,
  ]);
  const presenceByTenant = new Map(
    getRealtimePresenceSnapshot().tenants.map((item) => [
      item.tenantId,
      item,
    ]),
  );
  return result.rows.map((row) => ({
    id: row.id,
    publicCode: row.public_code,
    name: row.name || '',
    note: row.note || '',
    status: row.status,
    accessExpiresAt: new Date(row.access_expires_at).toISOString(),
    createdAt: new Date(row.created_at).toISOString(),
    updatedAt: new Date(row.updated_at).toISOString(),
    lastAdminOnlineAt: row.last_admin_online_at
      ? new Date(row.last_admin_online_at).toISOString()
      : null,
    expiryReminderSentAt: row.expiry_reminder_sent_at
      ? new Date(row.expiry_reminder_sent_at).toISOString()
      : null,
    licenseId: row.license_id || null,
    maskedKey: row.license_id
      ? licenseHint(row)
      : '',
    licenseStatus: row.license_id
      ? effectiveLicenseStatus({
          status: row.license_status,
          expires_at: row.expires_at,
        })
      : '',
    licenseDurationCode: row.duration_code || '',
    licenseDurationDays: Number(row.duration_days || 0),
    licenseDurationHours: Number(
      LICENSE_DURATIONS[row.duration_code]?.hours ||
        Number(row.duration_days || 0) * 24,
    ),
    licenseDurationLabel:
      LICENSE_DURATIONS[row.duration_code]?.label || row.duration_code || '',
    licenseExpiresAt: row.expires_at
      ? new Date(row.expires_at).toISOString()
      : null,
    generator:
      row.generated_by_username ||
      (row.generated_by_distributor_username
        ? `二级代理 · ${row.generated_by_distributor_username}`
        : '') ||
      telegramLicenseCreator(row),
    generatedByDistributorId: row.generated_by_distributor_id || null,
    ownerDistributorId: row.owner_distributor_id || null,
    ownerDistributorUsername: row.owner_distributor_username || '',
    ownerDistributorName: row.owner_distributor_display_name || '',
    retentionHours: Number(row.retention_hours || 24),
    frontendTemplateId: row.frontend_template_id || null,
    frontendTemplateName: row.frontend_template_name || '',
    approvedTemplates: Array.isArray(row.approved_templates)
      ? row.approved_templates.map((item) => ({
          id: item.id,
          name: item.name || '',
          origin: item.origin || '',
          status: item.status || '',
        }))
      : [],
    approvedTemplateIds: Array.isArray(row.approved_templates)
      ? row.approved_templates.map((item) => item.id).filter(isUuid)
      : [],
    visitorsToday: Number(row.visitors_today || 0),
    messagesToday: Number(row.messages_today || 0),
    mediaBytes: Number(row.media_bytes || 0),
    onlineDevices: Number(presenceByTenant.get(row.id)?.adminDevices || 0),
    onlineVisitors: Number(
      presenceByTenant.get(row.id)?.onlineVisitors || 0,
    ),
  }));
}

async function getSuperTenantPage(options = {}) {
  const limit = Math.min(API_PAGE_MAX, Math.max(1, options.limit || API_PAGE_DEFAULT));
  const rows = await getSuperTenants({ ...options, limit: limit + 1 });
  const hasMore = rows.length > limit;
  const items = rows.slice(0, limit);
  const last = items.at(-1);
  return {
    items,
    hasMore,
    nextCursor:
      hasMore && last
        ? encodeCursor({ at: last.updatedAt, id: last.id })
        : null,
  };
}

function normalizeDistributorUsername(value) {
  const username = cleanText(value, 40).trim().toLowerCase();
  return /^[a-z0-9_]{3,32}$/.test(username) ? username : '';
}

function normalizeTelegramUsername(value) {
  const username = cleanText(value, 64).trim().replace(/^@+/, '');
  return /^[A-Za-z0-9_]{0,32}$/.test(username) ? username : '';
}

async function ensureDistributorQuotas(distributorId, client = pool) {
  if (!isUuid(distributorId)) return;
  await client.query(
    `
      INSERT INTO distributor_license_quotas (
        distributor_id,duration_code
      )
      SELECT $1,code
      FROM unnest($2::text[]) AS code
      ON CONFLICT (distributor_id,duration_code) DO NOTHING
    `,
    [distributorId, DISTRIBUTOR_DURATION_CODES],
  );
}

async function getDistributorQuotaMap(distributorId, client = pool) {
  const result = await client.query(
    `
      SELECT duration_code,remaining_count,generated_count,updated_at
      FROM distributor_license_quotas
      WHERE distributor_id=$1
      ORDER BY duration_code
    `,
    [distributorId],
  );
  const quotas = {};
  for (const code of DISTRIBUTOR_DURATION_CODES) {
    const row = result.rows.find((item) => item.duration_code === code);
    quotas[code] = {
      remaining: Number(row?.remaining_count || 0),
      generated: Number(row?.generated_count || 0),
      updatedAt: row?.updated_at
        ? new Date(row.updated_at).toISOString()
        : null,
    };
  }
  return quotas;
}

function distributorAccountPayload(row, quotas = {}) {
  return {
    id: row.id,
    username: row.username,
    displayName: row.display_name || row.displayName || '',
    telegramUsername:
      row.telegram_username || row.telegramUsername || '',
    enabled: row.enabled !== false,
    canGenerate: Boolean(row.can_generate ?? row.canGenerate),
    allowedDurationCodes: cleanDurationCodes(
      row.allowed_duration_codes || row.allowedDurationCodes || [],
    ),
    quotas,
    lastLoginAt: row.last_login_at
      ? new Date(row.last_login_at).toISOString()
      : row.lastLoginAt || null,
    createdAt: row.created_at
      ? new Date(row.created_at).toISOString()
      : row.createdAt || null,
  };
}

async function getSuperDistributors() {
  const result = await pool.query(
    `
      WITH license_stats AS MATERIALIZED (
        SELECT
          generated_by_distributor_id AS distributor_id,
          COUNT(*)::int AS license_total,
          COUNT(*) FILTER (WHERE status='unused')::int AS license_unused
        FROM license_keys
        WHERE generated_by_distributor_id IS NOT NULL
        GROUP BY generated_by_distributor_id
      ),
      tenant_stats AS MATERIALIZED (
        SELECT owner_distributor_id AS distributor_id,COUNT(*)::int AS tenant_total
        FROM tenants
        WHERE owner_distributor_id IS NOT NULL
        GROUP BY owner_distributor_id
      )
      SELECT
        d.*,
        sa.username AS created_by_username,
        COALESCE(ls.license_total,0)::int AS license_total,
        COALESCE(ls.license_unused,0)::int AS license_unused,
        COALESCE(ts.tenant_total,0)::int AS tenant_total
      FROM distributors d
      LEFT JOIN super_admins sa ON sa.id=d.created_by_admin_id
      LEFT JOIN license_stats ls ON ls.distributor_id=d.id
      LEFT JOIN tenant_stats ts ON ts.distributor_id=d.id
      ORDER BY d.created_at DESC
    `,
  );
  const distributorIds = result.rows.map((row) => row.id);
  if (!distributorIds.length) return [];
  const quotaResult = await pool.query(
    `
      SELECT distributor_id,duration_code,remaining_count,
             generated_count,updated_at
      FROM distributor_license_quotas
      WHERE distributor_id=ANY($1::uuid[])
    `,
    [distributorIds],
  );
  const quotaMaps = new Map(
    distributorIds.map((id) => [
      id,
      Object.fromEntries(
        DISTRIBUTOR_DURATION_CODES.map((code) => [
          code,
          { remaining: 0, generated: 0, updatedAt: null },
        ]),
      ),
    ]),
  );
  for (const quota of quotaResult.rows) {
    quotaMaps.get(quota.distributor_id)[quota.duration_code] = {
      remaining: Number(quota.remaining_count || 0),
      generated: Number(quota.generated_count || 0),
      updatedAt: quota.updated_at
        ? new Date(quota.updated_at).toISOString()
        : null,
    };
  }
  return result.rows.map((row) => ({
      ...distributorAccountPayload(row, quotaMaps.get(row.id)),
      createdBy: row.created_by_username || '',
      licenseTotal: Number(row.license_total || 0),
      licenseUnused: Number(row.license_unused || 0),
      tenantTotal: Number(row.tenant_total || 0),
    }));
}

function publicDistributorLicenseRow(row, distributorId) {
  return {
    id: row.id,
    tenantId: row.tenant_id || null,
    tenantName: row.tenant_name || '',
    maskedKey: licenseHint(row),
    durationCode: row.duration_code,
    durationDays: Number(row.duration_days),
    durationHours: Number(
      LICENSE_DURATIONS[row.duration_code]?.hours ||
        Number(row.duration_days || 1) * 24,
    ),
    durationLabel:
      LICENSE_DURATIONS[row.duration_code]?.label || row.duration_code,
    status: effectiveLicenseStatus(row),
    activatedAt: row.activated_at
      ? new Date(row.activated_at).toISOString()
      : null,
    expiresAt: row.expires_at
      ? new Date(row.expires_at).toISOString()
      : null,
    revokedAt: row.revoked_at
      ? new Date(row.revoked_at).toISOString()
      : null,
    lastUsedAt: row.last_used_at
      ? new Date(row.last_used_at).toISOString()
      : null,
    createdAt: new Date(row.created_at).toISOString(),
    canDisable: Boolean(
      row.tenant_id &&
      row.owner_distributor_id === distributorId &&
      row.status === 'active' &&
      row.expires_at &&
      new Date(row.expires_at).getTime() > Date.now()
    ),
  };
}

async function getDistributorLicenses(distributorId, options = {}) {
  const maxLimit = options.legacy ? 2000 : API_PAGE_MAX;
  const limit = Math.min(maxLimit, Math.max(1, options.limit || API_PAGE_DEFAULT));
  const cursor = decodeCursor(options.cursor);
  const result = await pool.query(
    `
      SELECT
        l.id,l.tenant_id,l.key_prefix,l.key_suffix,
        l.duration_code,l.duration_days,l.status,
        l.activated_at,l.expires_at,l.revoked_at,l.last_used_at,l.created_at,
        t.name AS tenant_name,t.owner_distributor_id
      FROM license_keys l
      LEFT JOIN tenants t ON t.id=l.tenant_id
      WHERE l.generated_by_distributor_id=$1
        AND (
          $2::timestamptz IS NULL OR
          (l.created_at,l.id) < ($2::timestamptz,$3::uuid)
        )
      ORDER BY l.created_at DESC,l.id DESC
      LIMIT $4
    `,
    [distributorId, cursor?.at || null, cursor?.id || null, limit + 1],
  );
  const hasMore = result.rows.length > limit;
  const items = result.rows.slice(0, limit).map((row) =>
    publicDistributorLicenseRow(row, distributorId),
  );
  const last = items.at(-1);
  return {
    items,
    hasMore,
    nextCursor: hasMore && last
      ? encodeCursor({ at: last.createdAt, id: last.id })
      : null,
  };
}

async function getDistributorTenants(distributorId, options = {}) {
  const maxLimit = options.legacy ? 2000 : API_PAGE_MAX;
  const limit = Math.min(maxLimit, Math.max(1, options.limit || API_PAGE_DEFAULT));
  const cursor = decodeCursor(options.cursor);
  const result = await pool.query(
    `
      SELECT
        t.*,
        l.id AS license_id,l.key_prefix,l.key_suffix,
        l.duration_code,l.status AS license_status,l.activated_at,
        l.expires_at,l.last_used_at,l.revoked_at
      FROM tenants t
      LEFT JOIN LATERAL (
        SELECT *
        FROM license_keys
        WHERE tenant_id=t.id
        ORDER BY
          CASE WHEN status='active' THEN 0 ELSE 1 END,
          created_at DESC
        LIMIT 1
      ) l ON TRUE
      WHERE t.owner_distributor_id=$1
        AND (
          $2::timestamptz IS NULL OR
          (t.updated_at,t.id) < ($2::timestamptz,$3::uuid)
        )
      ORDER BY t.updated_at DESC,t.id DESC
      LIMIT $4
    `,
    [distributorId, cursor?.at || null, cursor?.id || null, limit + 1],
  );
  const hasMore = result.rows.length > limit;
  const presenceByTenant = new Map(
    getDistributorPresenceSnapshot(distributorId).tenants.map((item) => [
      item.tenantId,
      item,
    ]),
  );
  const items = result.rows.slice(0, limit).map((row) => {
    const live = presenceByTenant.get(row.id);
    const onlineDevices = Number(live?.adminDevices || 0);
    const onlineVisitors = Number(live?.onlineVisitors || 0);
    return {
      id: row.id,
      publicCode: row.public_code,
      name: row.name || '',
      note: row.note || '',
      remark: row.distributor_note || '',
      status: row.status,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString(),
      accessExpiresAt: new Date(row.access_expires_at).toISOString(),
      lastAdminOnlineAt: row.last_admin_online_at
        ? new Date(row.last_admin_online_at).toISOString()
        : null,
      licenseId: row.license_id || null,
      maskedKey: row.license_id ? licenseHint(row) : '',
      durationCode: row.duration_code || '',
      licenseStatus: row.license_id ? effectiveLicenseStatus({
        status: row.license_status,
        expires_at: row.expires_at,
      }) : '',
      activatedAt: row.activated_at
        ? new Date(row.activated_at).toISOString()
        : null,
      expiresAt: row.expires_at
        ? new Date(row.expires_at).toISOString()
        : null,
      lastUsedAt: row.last_used_at
        ? new Date(row.last_used_at).toISOString()
        : null,
      onlineDevices,
      onlineVisitors,
      currentlyUsing: onlineDevices > 0,
      canDisable: Boolean(
        row.license_id &&
        row.license_status === 'active' &&
        row.expires_at &&
        new Date(row.expires_at).getTime() > Date.now()
      ),
    };
  });
  const last = items.at(-1);
  return {
    items,
    hasMore,
    nextCursor: hasMore && last
      ? encodeCursor({ at: last.updatedAt, id: last.id })
      : null,
  };
}

async function getDistributorDashboard(distributorId) {
  const [result, quotas] = await Promise.all([
    pool.query(
      `
        SELECT
          COUNT(*)::int AS license_total,
          COUNT(*) FILTER (WHERE status='unused')::int AS license_unused,
          COUNT(*) FILTER (
            WHERE status='active' AND expires_at>NOW()
          )::int AS license_active,
          COUNT(*) FILTER (
            WHERE status='active' AND expires_at<=NOW()
          )::int AS license_expired,
          COUNT(*) FILTER (WHERE status='revoked')::int AS license_revoked,
          (SELECT COUNT(*)::int FROM tenants
           WHERE owner_distributor_id=$1) AS tenant_total
        FROM license_keys
        WHERE generated_by_distributor_id=$1
      `,
      [distributorId],
    ),
    getDistributorQuotaMap(distributorId),
  ]);
  const row = result.rows[0] || {};
  const presence = getDistributorPresenceSnapshot(distributorId);
  return {
    licenseTotal: Number(row.license_total || 0),
    licenseUnused: Number(row.license_unused || 0),
    licenseActive: Number(row.license_active || 0),
    licenseExpired: Number(row.license_expired || 0),
    licenseRevoked: Number(row.license_revoked || 0),
    tenantTotal: Number(row.tenant_total || 0),
    onlineTenants: presence.onlineTenants,
    chattingTenants: presence.chattingTenants,
    quotas,
  };
}

async function handleDistributorLogin(req, res) {
  if (
    !rateLimit(req, res, 'distributor-login', 12, 15 * 60_000) ||
    !rateLimit(req, res, 'distributor-login-global', 60, 60_000, 'global')
  ) return;
  if (!await durableAuthRateLimit(
    req,
    res,
    'distributor-login',
    20,
    15 * 60_000,
  )) return;
  const body = await readJson(req, 32 * 1024);
  const username = normalizeDistributorUsername(body.username);
  const result = username
    ? await pool.query(
        `SELECT * FROM distributors WHERE username=$1`,
        [username],
      )
    : { rows: [] };
  const row = result.rows[0];
  const passwordOk = await verifyPasswordAsync(
    body.password,
    row ? row.password_hash : DUMMY_PASSWORD_HASH,
  );
  if (!row?.enabled || !passwordOk) {
    await writeDistributorAudit(
      req,
      row ? { id: row.id } : null,
      'distributor.login',
      {
        targetType: 'distributor',
        targetId: username,
        result: 'failed',
      },
    ).catch(() => {});
    return sendError(
      res,
      401,
      row && !row.enabled ? '代理账号已停用。' : '账号或密码不正确。',
      'DISTRIBUTOR_LOGIN',
    );
  }
  await pool.query(
    `UPDATE distributors SET last_login_at=NOW(),updated_at=NOW() WHERE id=$1`,
    [row.id],
  );
  const sessionExpiresAt = new Date(Date.now() + 8 * 60 * 60_000);
  const sessionId = await createAuthSession(
    'distributor',
    row.id,
    sessionExpiresAt,
  );
  const token = signTokenUntil(
    {
      kind: 'distributor',
      distributorId: row.id,
      sessionId,
      sessionVersion: Number(row.session_version),
    },
    sessionExpiresAt,
  );
  await writeDistributorAudit(
    req,
    { id: row.id },
    'distributor.login',
    { targetType: 'distributor', targetId: row.id },
  ).catch(() => {});
  return sendJson(res, 200, {
    ok: true,
    token,
    distributor: distributorAccountPayload(
      row,
      await getDistributorQuotaMap(row.id),
    ),
  });
}

async function handleDistributorRoutes(req, res, url, pathname, apiVersion = 1) {
  if (req.method === 'POST' && pathname === '/api/distributor/login') {
    return handleDistributorLogin(req, res);
  }
  const distributor = await authenticateDistributor(req);
  if (!distributor) {
    return sendError(res, 401, '二级代理登录已失效。', 'DISTRIBUTOR_AUTH');
  }

  if (req.method === 'POST' && pathname === '/api/distributor/logout') {
    await revokeAuthSession(
      distributor.sessionId,
      'distributor',
      distributor.id,
    );
    disconnectAuthSession(distributor.sessionId);
    await writeDistributorAudit(req, distributor, 'distributor.logout', {
      targetType: 'distributor',
      targetId: distributor.id,
    }).catch(() => {});
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/api/distributor/bootstrap') {
    const dashboard = await getDistributorDashboard(distributor.id);
    return sendJson(res, 200, {
      ok: true,
      distributor: distributorAccountPayload(distributor, dashboard.quotas),
      dashboard,
    });
  }

  if (req.method === 'GET' && pathname === '/api/distributor/licenses') {
    const page = await getDistributorLicenses(distributor.id, {
      cursor: apiVersion >= 2 ? url.searchParams.get('cursor') : null,
      limit: apiVersion >= 2 ? pageLimit(url) : 2000,
      legacy: apiVersion < 2,
    });
    return sendJson(res, 200, {
      ok: true,
      licenses: page.items,
      page: apiVersion >= 2
        ? { nextCursor: page.nextCursor, hasMore: page.hasMore }
        : undefined,
    });
  }

  if (req.method === 'POST' && pathname === '/api/distributor/licenses') {
    const idempotencyKey = licenseGenerationIdempotencyKey(req);
    if (
      !rateLimit(
        req,
        res,
        'distributor-license-create',
        20,
        60_000,
        distributor.id,
      )
    ) return;
    const body = await readJson(req, 32 * 1024);
    const durationCode = cleanText(body.durationCode, 12);
    const count = Math.min(
      50,
      Math.max(1, Math.trunc(Number(body.count || 1))),
    );
    if (!LICENSE_DURATIONS[durationCode]) {
      return sendError(res, 400, '卡密期限无效。', 'LICENSE_DURATION');
    }
    const requestHash = licenseGenerationRequestHash({ durationCode, count });
    const client = await pool.connect();
    const created = [];
    let before = 0;
    let after = 0;
    let replayed = false;
    try {
      await client.query('BEGIN');
      const accountResult = await client.query(
        `SELECT * FROM distributors WHERE id=$1 FOR UPDATE`,
        [distributor.id],
      );
      const account = accountResult.rows[0];
      if (
        !account?.enabled ||
        Number(account.session_version) !== distributor.sessionVersion
      ) {
        throw requestError(
          '代理登录状态已变化，请重新登录。',
          401,
          'DISTRIBUTOR_AUTH',
        );
      }
      if (!account.can_generate) {
        throw requestError(
          '超级管理员尚未开放卡密生成权限。',
          403,
          'DISTRIBUTOR_GENERATE_DISABLED',
        );
      }
      if (!cleanDurationCodes(account.allowed_duration_codes).includes(durationCode)) {
        throw requestError(
          '超级管理员尚未开放此期限的卡密。',
          403,
          'DISTRIBUTOR_DURATION_DISABLED',
        );
      }
      await ensureDistributorQuotas(distributor.id, client);
      const quotaResult = await client.query(
        `
          SELECT *
          FROM distributor_license_quotas
          WHERE distributor_id=$1 AND duration_code=$2
          FOR UPDATE
        `,
        [distributor.id, durationCode],
      );
      const quota = quotaResult.rows[0];
      before = Number(quota?.remaining_count || 0);
      const generation = await claimLicenseGeneration(client, {
        actorKind: 'distributor',
        actorId: distributor.id,
        idempotencyKey,
        requestHash,
      });
      replayed = generation.replayed;
      if (replayed) {
        created.push(
          ...await replayedLicenseRecords(client, generation.licenseIds),
        );
        after = before;
      } else if (before < count) {
        throw requestError(
          `此期限只剩 ${before} 个额度。`,
          409,
          'DISTRIBUTOR_QUOTA',
        );
      } else {
        created.push(
          ...(await createLicenseRecordsBatch(
            durationCode,
            count,
            { generatedByDistributorId: distributor.id },
            client,
          )),
        );
        after = before - count;
        await client.query(
          `
            UPDATE distributor_license_quotas
            SET remaining_count=$3,
                generated_count=generated_count+$4,
                updated_at=NOW()
            WHERE distributor_id=$1 AND duration_code=$2
          `,
          [distributor.id, durationCode, after, count],
        );
        await client.query(
          `
            INSERT INTO distributor_quota_logs (
              distributor_id,duration_code,action,change_amount,
              balance_before,balance_after,actor_distributor_id,
              reason,metadata
            ) VALUES ($1,$2,'consume',$3,$4,$5,$1,$6,$7::jsonb)
          `,
          [
            distributor.id,
            durationCode,
            -count,
            before,
            after,
            '生成卡密',
            JSON.stringify({
              count,
              licenseIds: created.map((item) => item.row.id),
            }),
          ],
        );
        await completeLicenseGeneration(
          client,
          generation.id,
          created.map((item) => item.row.id),
        );
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      await writeDistributorAudit(
        req,
        distributor,
        'distributor.license.create',
        {
          targetType: 'license_batch',
          targetId: durationCode,
          result: 'failed',
          metadata: { count, code: cleanText(error.code, 80) },
        },
      ).catch(() => {});
      throw error;
    } finally {
      client.release();
    }
    await writeDistributorAudit(
      req,
      distributor,
      'distributor.license.create',
      {
        targetType: 'license_batch',
        targetId: durationCode,
        metadata: { count, quotaBefore: before, quotaAfter: after, replayed },
      },
    );
    broadcastDistributor(
      { type: 'distributor-licenses-updated' },
      distributor.id,
    );
    broadcastDistributor(
      { type: 'distributor-account-updated' },
      distributor.id,
    );
    broadcastSuper({ type: 'licenses-updated' });
    broadcastSuper({ type: 'distributors-updated' });
    return sendJson(res, replayed ? 200 : 201, {
      ok: true,
      idempotentReplay: replayed,
      licenses: created.map((item) => ({
        ...publicDistributorLicenseRow(item.row, distributor.id),
        fullKey: item.licenseKey,
      })),
      quota: { durationCode, remaining: after },
    });
  }

 if (req.method === 'GET' && pathname === '/api/distributor/tenants') {
  const page = await getDistributorTenants(distributor.id, {
    cursor: apiVersion >= 2 ? url.searchParams.get('cursor') : null,
    limit: apiVersion >= 2 ? pageLimit(url) : 2000,
    legacy: apiVersion < 2,
  });
  return sendJson(res, 200, {
    ok: true,
    tenants: page.items,
    page: apiVersion >= 2
      ? { nextCursor: page.nextCursor, hasMore: page.hasMore }
      : undefined,
  });
}

const tenantRemarkMatch = pathname.match(
  /^\/api\/distributor\/tenants\/([0-9a-f-]+)\/remark$/i,
);

if (
  tenantRemarkMatch &&
  isUuid(tenantRemarkMatch[1]) &&
  req.method === 'PATCH'
) {
  if (
    !rateLimit(
      req,
      res,
      'distributor-tenant-remark',
      60,
      60_000,
      distributor.id,
    )
  ) {
    return;
  }

  const tenantId = tenantRemarkMatch[1];
  const body = await readJson(req, 16 * 1024);

  if (typeof body.remark !== 'string') {
    return sendError(
      res,
      400,
      '备注内容格式不正确。',
      'DISTRIBUTOR_TENANT_REMARK_INPUT',
    );
  }

  const remark = cleanText(body.remark, 300);

  const result = await pool.query(
    `
      UPDATE tenants
      SET distributor_note = $3,
          updated_at = NOW()
      WHERE id = $1
        AND owner_distributor_id = $2
      RETURNING id, distributor_note, updated_at
    `,
    [tenantId, distributor.id, remark],
  );

  const row = result.rows[0];

  if (!row) {
    return sendError(
      res,
      404,
      '租户不存在或不属于当前代理。',
      'DISTRIBUTOR_TENANT_NOT_FOUND',
    );
  }

  await writeDistributorAudit(
    req,
    distributor,
    'distributor.tenant.remark.update',
    {
      targetType: 'tenant',
      targetId: tenantId,
      metadata: {
        remarkLength: remark.length,
      },
    },
  );

  broadcastDistributor(
    {
      type: 'distributor-tenants-updated',
    },
    distributor.id,
  );

  broadcastSuper({
    type: 'tenants-updated',
  });

  return sendJson(res, 200, {
    ok: true,
    tenant: {
      id: row.id,
      remark: row.distributor_note || '',
      updatedAt: new Date(row.updated_at).toISOString(),
    },
  });
}

if (req.method === 'GET' && pathname === '/api/distributor/quota-logs') {
    const logLimit = apiVersion >= 2 ? pageLimit(url, 100) : 500;
    const rawCursor = Number(url.searchParams.get('cursor'));
    const logCursor = apiVersion >= 2 && Number.isSafeInteger(rawCursor) && rawCursor > 0
      ? rawCursor
      : null;
    const result = await pool.query(
      `
        SELECT id,duration_code,action,change_amount,balance_before,
               balance_after,reason,created_at
        FROM distributor_quota_logs
        WHERE distributor_id=$1
          AND ($2::bigint IS NULL OR id<$2)
        ORDER BY id DESC
        LIMIT $3
      `,
      [distributor.id, logCursor, apiVersion >= 2 ? logLimit + 1 : logLimit],
    );
    const hasMore = apiVersion >= 2 && result.rows.length > logLimit;
    const logs = result.rows.slice(0, logLimit);
    return sendJson(res, 200, {
      ok: true,
      logs,
      page: apiVersion >= 2
        ? {
            hasMore,
            nextCursor: hasMore ? String(logs.at(-1)?.id || '') : null,
          }
        : undefined,
    });
  }

  const licenseMatch = pathname.match(
    /^\/api\/distributor\/licenses\/([0-9a-f-]+)$/i,
  );
  if (
    licenseMatch &&
    isUuid(licenseMatch[1]) &&
    req.method === 'PATCH'
  ) {
    const body = await readJson(req, 16 * 1024);
    if (body.action !== 'disable') {
      return sendError(
        res,
        400,
        '二级代理只允许禁用自己租户当前使用的卡密。',
        'DISTRIBUTOR_LICENSE_ACTION',
      );
    }
    const licenseId = licenseMatch[1];
    const client = await pool.connect();
    let row;
    try {
      await client.query('BEGIN');
      const result = await client.query(
        `
          SELECT l.*,t.owner_distributor_id,t.status AS tenant_status
          FROM license_keys l
          JOIN tenants t ON t.id=l.tenant_id
          WHERE l.id=$1
            AND t.owner_distributor_id=$2
          FOR UPDATE OF l,t
        `,
        [licenseId, distributor.id],
      );
      row = result.rows[0];
      if (!row) {
        throw requestError(
          '卡密不存在或不属于你的租户。',
          404,
          'NOT_FOUND',
        );
      }
      if (
        row.status !== 'active' ||
        !row.expires_at ||
        new Date(row.expires_at).getTime() <= Date.now()
      ) {
        throw requestError(
          '只有正在有效使用的卡密可以禁用。',
          409,
          'LICENSE_STATE',
        );
      }
        await client.query(
        `
          UPDATE license_keys
          SET status='revoked',disable_mode='notice',
              revoked_at=NOW(),updated_at=NOW()
          WHERE id=$1
        `,
        [licenseId],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    disconnectTenantLicense(
      row.tenant_id,
      licenseId,
      await tenantLicenseDisablePayload('notice'),
    );
    await writeDistributorAudit(
      req,
      distributor,
      'distributor.license.disable',
      { targetType: 'license', targetId: licenseId },
    );
    broadcastDistributor(
      { type: 'distributor-licenses-updated' },
      distributor.id,
    );
    broadcastDistributor(
      { type: 'distributor-tenants-updated' },
      distributor.id,
    );
    broadcastSuper({ type: 'licenses-updated' });
    broadcastSuper({ type: 'tenants-updated' });
    return sendJson(res, 200, { ok: true });
  }

  return sendError(res, 404, '二级代理接口不存在。', 'NOT_FOUND');
}

async function handleSuperLogin(req, res) {
  if (
    !rateLimit(req, res, 'super-login', 10, 15 * 60_000) ||
    !rateLimit(req, res, 'super-login-global', 60, 60_000, 'global')
  ) return;
  if (!await durableAuthRateLimit(
    req,
    res,
    'super-login',
    20,
    15 * 60_000,
  )) return;
  const body = await readJson(req, 32 * 1024);
  const username = cleanText(body.username, 80).toLowerCase();
  const result = await pool.query(
    `SELECT * FROM super_admins WHERE username = $1`,
    [username],
  );
  const row = result.rows[0];
  const passwordOk = await verifyPasswordAsync(
    body.password,
    row ? row.password_hash : DUMMY_PASSWORD_HASH,
  );
  const secret = row?.totp_secret_ciphertext
    ? decryptSecret(row.totp_secret_ciphertext)
    : '';
  if (
    !row?.enabled ||
    !passwordOk ||
    (REQUIRE_SUPER_ADMIN_TOTP && !secret) ||
    (secret && !verifyTotp(secret, body.totp))
  ) {
    await writeAudit(
      req,
      row ? { id: row.id } : null,
      'super.login',
      {
        targetType: 'super_admin',
        targetId: username,
        result: 'failed',
      },
    );
    return sendError(
      res,
      401,
      REQUIRE_SUPER_ADMIN_TOTP && passwordOk
        ? '两步验证码不正确或尚未配置。'
        : '账号或密码不正确。',
      'SUPER_LOGIN',
    );
  }
  await pool.query(
    `UPDATE super_admins SET last_login_at=NOW() WHERE id=$1`,
    [row.id],
  );
  const sessionExpiresAt = new Date(Date.now() + 8 * 60 * 60_000);
  const sessionId = await createAuthSession(
    'super_admin',
    row.id,
    sessionExpiresAt,
  );
  const token = signTokenUntil(
    {
      kind: 'super_admin',
      adminId: row.id,
      sessionId,
      sessionVersion: Number(row.session_version),
      clientOrigin: normalizeOrigin(req.headers.origin),
    },
    sessionExpiresAt,
  );
  res.setHeader('Set-Cookie', sessionCookie(token));
  await writeAudit(
    req,
    { id: row.id },
    'super.login',
    {
      targetType: 'super_admin',
      targetId: row.id,
    },
  );
  return sendJson(res, 200, {
    ok: true,
    token,
    admin: {
      id: row.id,
      username: row.username,
      role: row.role,
      twoFactorEnabled: Boolean(secret),
    },
  });
}

function cleanTenantIds(value) {
  return Array.isArray(value)
    ? [...new Set(value.filter(isUuid))].slice(0, 1000)
    : [];
}

function cleanFeatureEntitlements(value = {}) {
  const scope = ['all', 'selected', 'durations'].includes(value.scope)
    ? value.scope
    : 'all';
  const tenantIds = cleanTenantIds(value.tenantIds);
  const durationCodes = Array.isArray(value.durationCodes)
    ? [...new Set(value.durationCodes)].filter(
        (code) => LICENSE_DURATIONS[code],
      )
    : [];
  if (scope === 'selected' && !tenantIds.length) {
    throw requestError(
      '指定租户功能至少选择一个租户。',
      400,
      'FEATURE_ENTITLEMENT',
    );
  }
  if (scope === 'durations' && !durationCodes.length) {
    throw requestError(
      '按卡密期限开放时至少选择一个期限。',
      400,
      'FEATURE_ENTITLEMENT',
    );
  }
  return { scope, tenantIds, durationCodes };
}

function parseIsoDate(value, allowNull = true) {
  if ((value === null || value === '') && allowNull) return null;
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) {
    throw requestError('日期时间格式无效。', 400, 'INVALID_DATE');
  }
  return date.toISOString();
}

async function syncCurrentReleaseVersion(databaseClient) {
  const latest = await databaseClient.query(`
    SELECT version
    FROM releases
    WHERE scope='all'
    ORDER BY published_at DESC,created_at DESC
    LIMIT 1
  `);
  const currentVersion = latest.rows[0]?.version || APP_VERSION;
  await databaseClient.query(
    `UPDATE platform_settings SET current_version=$1,updated_at=NOW() WHERE id=1`,
    [currentVersion],
  );
  return currentVersion;
}

async function handleSuperRoutes(req, res, url, pathname, apiVersion = 1) {
  if (req.method === 'POST' && pathname === '/api/super/login') {
    return handleSuperLogin(req, res);
  }
  const admin = await authenticateSuper(req);
  if (!admin) {
    if (req.method === 'GET' && pathname === '/api/super/bootstrap') {
      return sendJson(res, 200, {
        ok: true,
        authenticated: false,
      });
    }
    return sendError(res, 401, '超级管理员登录已失效。', 'SUPER_AUTH');
  }

  if (req.method === 'POST' && pathname === '/api/super/logout') {
    res.setHeader('Set-Cookie', sessionCookie('', 0));
    await revokeAuthSession(admin.sessionId, 'super_admin', admin.id);
    disconnectAuthSession(admin.sessionId);
    await writeAudit(req, admin, 'super.logout', {
      targetType: 'super_admin',
      targetId: admin.id,
    });
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/api/super/bootstrap') {
    const [
      dashboard,
      platform,
      templates,
      announcements,
      releases,
      featureCatalog,
      featureFlags,
      tenantResult,
    ] = await Promise.all([
      getSuperDashboard(),
      getPlatformSettings(),
      getTemplateCatalog({ audience: 'super' }),
      pool.query(`
        SELECT a.*,
          (SELECT COUNT(*)::int FROM announcement_reads ar
            WHERE ar.announcement_id=a.id) AS read_count
        FROM announcements a
        ORDER BY a.created_at DESC
        LIMIT 200
      `),
      pool.query(`
        SELECT r.*,
          (SELECT COUNT(*)::int FROM release_reads rr
            WHERE rr.release_id=r.id) AS read_count
        FROM releases r
        ORDER BY r.published_at DESC
        LIMIT 100
      `),
      pool.query(`SELECT * FROM feature_catalog ORDER BY category,name`),
      pool.query(`SELECT * FROM feature_flags ORDER BY code`),
      apiVersion >= 2
        ? getSuperTenantPage({ limit: pageLimit(url) })
        : getSuperTenants(),
    ]);
    return sendJson(res, 200, {
      ok: true,
      authenticated: true,
      admin: {
        id: admin.id,
        username: admin.username,
        role: admin.role,
        lastLoginAt: admin.lastLoginAt,
      },
      dashboard,
      platform,
      templates,
      announcements: announcements.rows,
      releases: releases.rows,
      featureCatalog: featureCatalog.rows,
      featureFlags: featureFlags.rows,
      tenants: apiVersion >= 2 ? tenantResult.items : tenantResult,
      tenantPage:
        apiVersion >= 2
          ? {
              nextCursor: tenantResult.nextCursor,
              hasMore: tenantResult.hasMore,
            }
          : undefined,
      monitor:
        lastMonitorSnapshot ||
        (await getMonitorSnapshotCached({
          persist:
            Date.now() - lastPersistedMonitorAt >=
            ACTIVE_MONITOR_INTERVAL_MS,
        })),
    });
  }

  if (req.method === 'GET' && pathname === '/api/super/distributors') {
    return sendJson(res, 200, {
      ok: true,
      distributors: await getSuperDistributors(),
    });
  }

  if (req.method === 'POST' && pathname === '/api/super/distributors') {
    requireRole(admin, 'manager');
    const body = await readJson(req, 32 * 1024);
    const username = normalizeDistributorUsername(body.username);
    const password = String(body.password || '');
    if (!username) {
      return sendError(
        res,
        400,
        '代理账号必须为3-32位小写字母、数字或下划线。',
        'DISTRIBUTOR_USERNAME',
      );
    }
    if (password.length < 12 || password.length > 128) {
      return sendError(
        res,
        400,
        '代理密码必须为12-128位。',
        'DISTRIBUTOR_PASSWORD',
      );
    }
    const telegramUsername = normalizeTelegramUsername(
      body.telegramUsername,
    );
    if (body.telegramUsername && !telegramUsername) {
      return sendError(
        res,
        400,
        'Telegram 用户名格式不正确。',
        'DISTRIBUTOR_TELEGRAM',
      );
    }
    const distributorId = randomUUID();
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
        await client.query(
        `
          INSERT INTO distributors (
            id,username,display_name,password_hash,telegram_username,
            enabled,can_generate,allowed_duration_codes,created_by_admin_id
          ) VALUES ($1,$2,$3,$4,$5,TRUE,FALSE,'[]'::jsonb,$6)
        `,
        [
          distributorId,
          username,
          cleanText(body.displayName, 80),
          hashPassword(password),
          telegramUsername,
          admin.id,
        ],
      );
      await ensureDistributorQuotas(distributorId, client);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      if (error?.code === '23505') {
        return sendError(
          res,
          409,
          '这个代理账号已经存在。',
          'DISTRIBUTOR_EXISTS',
        );
      }
      throw error;
    } finally {
      client.release();
    }
    await writeAudit(req, admin, 'distributor.create', {
      targetType: 'distributor',
      targetId: distributorId,
      metadata: { username },
    });
    broadcastSuper({ type: 'distributors-updated' });
    return sendJson(res, 201, {
      ok: true,
      distributor: (await getSuperDistributors()).find(
        (item) => item.id === distributorId,
      ),
    });
  }

  const distributorMatch = pathname.match(
    /^\/api\/super\/distributors\/([0-9a-f-]+)(?:\/(quotas|quota-logs))?$/i,
  );
  if (distributorMatch && isUuid(distributorMatch[1])) {
    const distributorId = distributorMatch[1];
    const subresource = distributorMatch[2] || '';
    if (
      req.method === 'GET' &&
      subresource === 'quota-logs'
    ) {
      const result = await pool.query(
        `
          SELECT ql.*,sa.username AS actor_admin_username,
                 d.username AS actor_distributor_username
          FROM distributor_quota_logs ql
          LEFT JOIN super_admins sa ON sa.id=ql.actor_admin_id
          LEFT JOIN distributors d ON d.id=ql.actor_distributor_id
          WHERE ql.distributor_id=$1
          ORDER BY ql.created_at DESC
          LIMIT 1000
        `,
        [distributorId],
      );
      return sendJson(res, 200, { ok: true, logs: result.rows });
    }

    if (req.method === 'PUT' && subresource === 'quotas') {
      requireRole(admin, 'manager');
      const body = await readJson(req, 32 * 1024);
      const requested = body.quotas && typeof body.quotas === 'object'
        ? body.quotas
        : {};
      const reason = cleanText(body.reason, 200) || '超级管理员调整额度';
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const account = await client.query(
          `SELECT id FROM distributors WHERE id=$1 FOR UPDATE`,
          [distributorId],
        );
        if (!account.rows[0]) {
          throw requestError('二级代理不存在。', 404, 'NOT_FOUND');
        }
        await ensureDistributorQuotas(distributorId, client);
        const rows = await client.query(
          `
            SELECT * FROM distributor_license_quotas
            WHERE distributor_id=$1
            FOR UPDATE
          `,
          [distributorId],
        );
        for (const code of DISTRIBUTOR_DURATION_CODES) {
          if (requested[code] === undefined) continue;
          const next = Math.trunc(Number(requested[code]));
          if (!Number.isSafeInteger(next) || next < 0 || next > 1_000_000) {
            throw requestError(
              `${LICENSE_DURATIONS[code].label}额度必须是0-1000000的整数。`,
              400,
              'DISTRIBUTOR_QUOTA',
            );
          }
          const current = rows.rows.find(
            (item) => item.duration_code === code,
          );
          const before = Number(current?.remaining_count || 0);
          if (before === next) continue;
          await client.query(
            `
              UPDATE distributor_license_quotas
              SET remaining_count=$3,updated_at=NOW()
              WHERE distributor_id=$1 AND duration_code=$2
            `,
            [distributorId, code, next],
          );
          await client.query(
            `
              INSERT INTO distributor_quota_logs (
                distributor_id,duration_code,action,change_amount,
                balance_before,balance_after,actor_admin_id,reason
              ) VALUES ($1,$2,'set',$3,$4,$5,$6,$7)
            `,
            [
              distributorId,
              code,
              next - before,
              before,
              next,
              admin.id,
              reason,
            ],
          );
        }
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      await writeAudit(req, admin, 'distributor.quota.update', {
        targetType: 'distributor',
        targetId: distributorId,
        metadata: { reason },
      });
      broadcastDistributor(
        { type: 'distributor-account-updated' },
        distributorId,
      );
      broadcastSuper({ type: 'distributors-updated' });
      return sendJson(res, 200, {
        ok: true,
        quotas: await getDistributorQuotaMap(distributorId),
      });
    }

    if (req.method === 'PATCH' && !subresource) {
      requireRole(admin, 'manager');
      const body = await readJson(req, 32 * 1024);
      const currentResult = await pool.query(
        `SELECT * FROM distributors WHERE id=$1`,
        [distributorId],
      );
      const current = currentResult.rows[0];
      if (!current) {
        return sendError(res, 404, '二级代理不存在。', 'NOT_FOUND');
      }
      const username = body.username === undefined
        ? current.username
        : normalizeDistributorUsername(body.username);
      if (!username) {
        return sendError(
          res,
          400,
          '代理账号格式不正确。',
          'DISTRIBUTOR_USERNAME',
        );
      }
      const telegramUsername = body.telegramUsername === undefined
        ? current.telegram_username
        : normalizeTelegramUsername(body.telegramUsername);
      if (body.telegramUsername && !telegramUsername) {
        return sendError(
          res,
          400,
          'Telegram 用户名格式不正确。',
          'DISTRIBUTOR_TELEGRAM',
        );
      }
      const password = body.password === undefined
        ? ''
        : String(body.password || '');
      if (password && (password.length < 12 || password.length > 128)) {
        return sendError(
          res,
          400,
          '新密码必须为12-128位。',
          'DISTRIBUTOR_PASSWORD',
        );
      }
      const enabled = body.enabled === undefined
        ? Boolean(current.enabled)
        : Boolean(body.enabled);
      const canGenerate = body.canGenerate === undefined
        ? Boolean(current.can_generate)
        : Boolean(body.canGenerate);
      const allowedDurationCodes = body.allowedDurationCodes === undefined
        ? cleanDurationCodes(current.allowed_duration_codes)
        : cleanDurationCodes(body.allowedDurationCodes);
      const invalidateSession = Boolean(
        password || (current.enabled && !enabled),
      );
      try {
        await pool.query(
          `
            UPDATE distributors
            SET username=$2,display_name=$3,telegram_username=$4,
                enabled=$5,can_generate=$6,allowed_duration_codes=$7::jsonb,
                password_hash=$8,
                session_version=session_version+$9,
                updated_at=NOW()
            WHERE id=$1
          `,
          [
            distributorId,
            username,
            body.displayName === undefined
              ? current.display_name
              : cleanText(body.displayName, 80),
            telegramUsername,
            enabled,
            canGenerate,
            JSON.stringify(allowedDurationCodes),
            password ? hashPassword(password) : current.password_hash,
            invalidateSession ? 1 : 0,
          ],
        );
      } catch (error) {
        if (error?.code === '23505') {
          return sendError(
            res,
            409,
            '这个代理账号已经存在。',
            'DISTRIBUTOR_EXISTS',
          );
        }
        throw error;
      }
      await writeAudit(req, admin, 'distributor.update', {
        targetType: 'distributor',
        targetId: distributorId,
        metadata: {
          enabled,
          canGenerate,
          allowedDurationCodes,
          passwordReset: Boolean(password),
        },
      });
      if (invalidateSession) disconnectDistributor(distributorId);
      else {
        broadcastDistributor(
          { type: 'distributor-account-updated' },
          distributorId,
        );
      }
      broadcastSuper({ type: 'distributors-updated' });
      return sendJson(res, 200, {
        ok: true,
        distributor: (await getSuperDistributors()).find(
          (item) => item.id === distributorId,
        ),
      });
    }
  }

  if (req.method === 'GET' && pathname === '/api/super/dashboard') {
    return sendJson(res, 200, {
      ok: true,
      dashboard: await getSuperDashboard(),
    });
  }
  if (req.method === 'GET' && pathname === '/api/super/licenses') {
    const page = apiVersion >= 2
      ? await getSuperLicensePage({
          cursor: url.searchParams.get('cursor'),
          limit: pageLimit(url),
          search: url.searchParams.get('search') || '',
          status: url.searchParams.get('status') || '',
        })
      : null;
    return sendJson(res, 200, {
      ok: true,
      licenses: apiVersion >= 2 ? page.items : await getSuperLicenses(),
      page:
        apiVersion >= 2
          ? { nextCursor: page.nextCursor, hasMore: page.hasMore }
          : undefined,
    });
  }
  if (req.method === 'POST' && pathname === '/api/super/licenses') {
    requireRole(admin, 'manager');
    if (!rateLimit(req, res, 'super-license-create', 10, 60_000, admin.id)) {
      return;
    }
    const idempotencyKey = licenseGenerationIdempotencyKey(req);
    const body = await readJson(req, 32 * 1024);
    const count = Math.min(100, Math.max(1, Math.trunc(Number(body.count || 1))));
    if (!LICENSE_DURATIONS[body.durationCode]) {
      return sendError(res, 400, '卡密时长无效。', 'LICENSE_DURATION');
    }
    const maxDesktopDevices = Math.trunc(
      Number(body.maxDesktopDevices || LICENSE_DESKTOP_DEVICE_DEFAULT),
    );
    const maxMobileDevices = Math.trunc(
      Number(body.maxMobileDevices || LICENSE_MOBILE_DEVICE_DEFAULT),
    );
    if (
      maxDesktopDevices < 1 || maxDesktopDevices > 50 ||
      maxMobileDevices < 1 || maxMobileDevices > 50
    ) {
      return sendError(
        res,
        400,
        '电脑和手机设备上限必须是 1-50 的整数。',
        'DEVICE_LIMIT_INPUT',
      );
    }
    const requestHash = licenseGenerationRequestHash({
      durationCode: body.durationCode,
      count,
      maxDesktopDevices,
      maxMobileDevices,
    });
    const client = await pool.connect();
    let createdLicenses = [];
    let replayed = false;
    try {
      await client.query('BEGIN');
      const generation = await claimLicenseGeneration(client, {
        actorKind: 'super_admin',
        actorId: admin.id,
        idempotencyKey,
        requestHash,
      });
      replayed = generation.replayed;
      createdLicenses = replayed
        ? await replayedLicenseRecords(client, generation.licenseIds)
        : await createLicenseRecordsBatch(
            body.durationCode,
            count,
            {
              generatedByAdminId: admin.id,
              maxDesktopDevices,
              maxMobileDevices,
            },
            client,
          );
      if (!replayed) {
        await completeLicenseGeneration(
          client,
          generation.id,
          createdLicenses.map((item) => item.row.id),
        );
      }
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    const licenses = createdLicenses.map((created) => ({
        ...publicLicenseRow(created.row),
        fullKey: created.licenseKey,
        superKey: created.superLicenseKey,
      }));
    await writeAudit(req, admin, 'license.create', {
      targetType: 'license_batch',
      targetId: body.durationCode,
      metadata: { count, maxDesktopDevices, maxMobileDevices, replayed },
    });
    broadcastSuper({ type: 'licenses-updated' });
    return sendJson(res, replayed ? 200 : 201, {
      ok: true,
      idempotentReplay: replayed,
      licenses,
    });
  }

  if (
    req.method === 'POST' &&
    pathname === '/api/super/licenses/archive-expired'
  ) {
    requireRole(admin, 'manager');
    const cleanup = await maybeCleanupExpiredData(true);
    await writeAudit(req, admin, 'license.cleanup_expired', {
      targetType: 'license_batch',
      metadata: {
        purgedTenants: Number(cleanup?.purgedTenants || 0),
        graceDays: EXPIRED_TENANT_GRACE_DAYS,
      },
    });
    return sendJson(res, 200, {
      ok: true,
      archivedCount: Number(cleanup?.purgedTenants || 0),
      purgedTenants: Number(cleanup?.purgedTenants || 0),
      graceDays: EXPIRED_TENANT_GRACE_DAYS,
    });
  }

  const licenseMatch = pathname.match(
    /^\/api\/super\/licenses\/([0-9a-f-]+)(?:\/(reveal|copy))?$/i,
  );
  if (licenseMatch && isUuid(licenseMatch[1])) {
    const licenseId = licenseMatch[1];
    const action = licenseMatch[2] || '';
    if (req.method === 'POST' && action === 'reveal') {
      requireRole(admin, 'manager');
      if (!rateLimit(req, res, 'super-license-reveal', 10, 15 * 60_000, admin.id)) {
        return;
      }
      const result = await pool.query(
        `SELECT * FROM license_keys WHERE id=$1`,
        [licenseId],
      );
      const row = result.rows[0];
      if (!row) return sendError(res, 404, '卡密不存在。', 'NOT_FOUND');
      const fullKey = decryptLicenseKey(row.key_ciphertext);
      const superKey = await ensureSuperLicenseKey(row);
      if (!fullKey && !superKey) {
        return sendError(res, 409, '此历史卡密无法恢复完整内容。', 'KEY_UNAVAILABLE');
      }
      await writeAudit(req, admin, 'license.reveal', {
        targetType: 'license',
        targetId: licenseId,
      });
      if (!row.super_key_hash && superKey) {
        broadcastSuper({ type: 'licenses-updated' });
      }
      return sendJson(res, 200, {
        ok: true,
        fullKey,
        superKey,
        normalKeyAvailable: Boolean(fullKey),
      });
    }
    if (req.method === 'POST' && action === 'copy') {
      requireRole(admin, 'operations');
      await writeAudit(req, admin, 'license.copy', {
        targetType: 'license',
        targetId: licenseId,
      });
      return sendJson(res, 200, { ok: true });
    }
    if (req.method === 'PATCH' && !action) {
      requireRole(admin, 'operations');
      const body = await readJson(req, 32 * 1024);
      if (body.action === 'deviceLimits') {
        const maxDesktopDevices = Math.trunc(Number(body.maxDesktopDevices));
        const maxMobileDevices = Math.trunc(Number(body.maxMobileDevices));
        if (
          !Number.isInteger(maxDesktopDevices) ||
          !Number.isInteger(maxMobileDevices) ||
          maxDesktopDevices < 1 || maxDesktopDevices > 50 ||
          maxMobileDevices < 1 || maxMobileDevices > 50
        ) {
          return sendError(
            res,
            400,
            '电脑和手机设备上限必须是 1-50 的整数。',
            'DEVICE_LIMIT_INPUT',
          );
        }
        const databaseClient = await pool.connect();
        let row;
        try {
          await databaseClient.query('BEGIN');
          const result = await databaseClient.query(
            `SELECT id,tenant_id FROM license_keys WHERE id=$1 FOR UPDATE`,
            [licenseId],
          );
          row = result.rows[0];
          if (!row) throw requestError('卡密不存在。', 404, 'NOT_FOUND');
          const counts = await databaseClient.query(
            `
              SELECT device_type,COUNT(*)::int AS count
              FROM license_devices
              WHERE license_id=$1 AND access_kind='normal'
                AND revoked_at IS NULL
              GROUP BY device_type
            `,
            [licenseId],
          );
          const activeCounts = Object.fromEntries(
            counts.rows.map((item) => [item.device_type, Number(item.count)]),
          );
          if (
            Number(activeCounts.desktop || 0) > maxDesktopDevices ||
            Number(activeCounts.mobile || 0) > maxMobileDevices
          ) {
            throw requestError(
              '新上限低于当前已登记设备数，请先点击“清空普通卡密设备”。',
              409,
              'DEVICE_LIMIT_BELOW_ACTIVE',
            );
          }
          await databaseClient.query(
            `
              UPDATE license_keys
              SET max_desktop_devices=$2,max_mobile_devices=$3,
                  updated_at=NOW()
              WHERE id=$1
            `,
            [licenseId, maxDesktopDevices, maxMobileDevices],
          );
          await databaseClient.query('COMMIT');
        } catch (error) {
          await databaseClient.query('ROLLBACK');
          throw error;
        } finally {
          databaseClient.release();
        }
        await writeAudit(req, admin, 'license.device_limits', {
          targetType: 'license',
          targetId: licenseId,
          metadata: { maxDesktopDevices, maxMobileDevices },
        });
        broadcastSuper({ type: 'licenses-updated' });
        return sendJson(res, 200, { ok: true });
      }
      if (body.action === 'resetDevices') {
        const databaseClient = await pool.connect();
        let row;
        let deletedCount = 0;
        try {
          await databaseClient.query('BEGIN');
          const result = await databaseClient.query(
            `SELECT id,tenant_id FROM license_keys WHERE id=$1 FOR UPDATE`,
            [licenseId],
          );
          row = result.rows[0];
          if (!row) throw requestError('卡密不存在。', 404, 'NOT_FOUND');
          const deleted = await databaseClient.query(
            `DELETE FROM license_devices WHERE license_id=$1 AND access_kind='normal'`,
            [licenseId],
          );
          deletedCount = deleted.rowCount;
          await databaseClient.query('COMMIT');
        } catch (error) {
          await databaseClient.query('ROLLBACK');
          throw error;
        } finally {
          databaseClient.release();
        }
        if (row?.tenant_id) {
          disconnectTenantLicense(row.tenant_id, licenseId, {
            type: 'device-authorization-reset',
            message: '管理员已清空普通卡密设备，请重新登录登记。',
            at: nowIso(),
          });
        }
        await writeAudit(req, admin, 'license.devices_reset', {
          targetType: 'license',
          targetId: licenseId,
          metadata: { deletedCount },
        });
        broadcastSuper({ type: 'licenses-updated' });
        return sendJson(res, 200, { ok: true, deletedCount });
      }
      if (!['disable', 'restore', 'archive'].includes(body.action)) {
        return sendError(res, 400, '卡密操作无效。', 'LICENSE_ACTION');
      }
      if (
        body.action === 'disable' &&
        body.disableMode !== undefined &&
        !['notice', 'busy'].includes(body.disableMode)
      ) {
        return sendError(
          res,
          400,
          '卡密禁用显示方式无效。',
          'LICENSE_DISABLE_MODE',
        );
      }
      // 兼容短暂滚动升级期间仍在使用旧前端的管理员请求。
      const disableMode = body.disableMode === 'busy' ? 'busy' : 'notice';
      const databaseClient = await pool.connect();
      let row;
      let disconnectPayload = null;
      let disableDisconnectMode = '';
      try {
        await databaseClient.query('BEGIN');
        const result = await databaseClient.query(
          `
            SELECT l.*,t.owner_distributor_id
            FROM license_keys l
            LEFT JOIN tenants t ON t.id=l.tenant_id
            WHERE l.id=$1
            FOR UPDATE OF l
          `,
          [licenseId],
        );
        row = result.rows[0];
        if (!row) {
          throw requestError('卡密不存在。', 404, 'NOT_FOUND');
        }
        if (body.action === 'disable') {
          if (!['unused', 'active'].includes(row.status)) {
            throw requestError(
              '当前状态的卡密不能禁用。',
              409,
              'LICENSE_STATE',
            );
          }
          await databaseClient.query(
            `UPDATE license_keys
             SET status='revoked',disable_mode=$2,
                 revoked_at=NOW(),updated_at=NOW()
             WHERE id=$1`,
            [licenseId, disableMode],
          );
          if (row.tenant_id) {
            disableDisconnectMode = disableMode;
          }
        } else if (body.action === 'restore') {
          if (row.status !== 'revoked') {
            throw requestError(
              '只有已禁用卡密可以恢复。',
              409,
              'LICENSE_STATE',
            );
          }
          if (
            row.expires_at &&
            new Date(row.expires_at).getTime() <= Date.now()
          ) {
            throw requestError(
              '卡密已到期，不能恢复使用。',
              409,
              'TENANT_EXPIRED',
            );
          }
          await databaseClient.query(
            `UPDATE license_keys
             SET status=$2,disable_mode='notice',
                 revoked_at=NULL,updated_at=NOW()
             WHERE id=$1`,
            [licenseId, row.tenant_id ? 'active' : 'unused'],
          );
          if (row.tenant_id) {
            await databaseClient.query(
              `UPDATE tenants SET status='active',updated_at=NOW() WHERE id=$1`,
              [row.tenant_id],
            );
          }
        } else {
          if (!row.tenant_id) {
            throw requestError(
              '未激活卡密应直接删除。',
              409,
              'LICENSE_STATE',
            );
          }
          await databaseClient.query(
            `UPDATE license_keys SET status='archived',archived_at=NOW(),updated_at=NOW() WHERE id=$1`,
            [licenseId],
          );
          await databaseClient.query(
            `UPDATE tenants SET status='suspended',session_version=session_version+1,updated_at=NOW() WHERE id=$1`,
            [row.tenant_id],
          );
          disconnectPayload = {
            type: 'force-logout',
            message: '租户服务已归档。',
            at: nowIso(),
          };
        }
        await databaseClient.query('COMMIT');
      } catch (error) {
        await databaseClient.query('ROLLBACK');
        throw error;
      } finally {
        databaseClient.release();
      }
      if (row.tenant_id && (disconnectPayload || disableDisconnectMode)) {
        if (body.action === 'disable') {
          disconnectTenantLicense(
            row.tenant_id,
            licenseId,
            await tenantLicenseDisablePayload(disableDisconnectMode),
          );
        } else {
          disconnectTenant(row.tenant_id, disconnectPayload);
        }
      }
      await writeAudit(req, admin, `license.${body.action}`, {
        targetType: 'license',
        targetId: licenseId,
        metadata: body.action === 'disable' ? { disableMode } : {},
      });
      broadcastSuper({ type: 'licenses-updated' });
      if (row.tenant_id) broadcastSuper({ type: 'tenants-updated' });
      if (row.generated_by_distributor_id) {
        broadcastSuper({ type: 'distributors-updated' });
      }
      const ownerDistributorId = row.owner_distributor_id ||
        row.generated_by_distributor_id;
      if (ownerDistributorId) {
        broadcastDistributor(
          { type: 'distributor-licenses-updated' },
          ownerDistributorId,
        );
        if (row.tenant_id) {
          broadcastDistributor(
            { type: 'distributor-tenants-updated' },
            ownerDistributorId,
          );
        }
      }
      return sendJson(res, 200, { ok: true });
    }
    if (req.method === 'DELETE' && !action) {
      requireRole(admin, 'manager');
      const deleted = await pool.query(
        `
          DELETE FROM license_keys
          WHERE id=$1 AND status='unused' AND tenant_id IS NULL
          RETURNING id,generated_by_distributor_id
        `,
        [licenseId],
      );
      if (!deleted.rows[0]) {
        return sendError(
          res,
          409,
          '只有未激活卡密可以彻底删除。',
          'LICENSE_STATE',
        );
      }
      await writeAudit(req, admin, 'license.delete', {
        targetType: 'license',
        targetId: licenseId,
      });
      broadcastSuper({ type: 'licenses-updated' });
      if (deleted.rows[0].generated_by_distributor_id) {
        broadcastDistributor(
          { type: 'distributor-licenses-updated' },
          deleted.rows[0].generated_by_distributor_id,
        );
        broadcastSuper({ type: 'distributors-updated' });
      }
      return sendJson(res, 200, { ok: true });
    }
  }

  if (req.method === 'GET' && pathname === '/api/super/tenants') {
    const page = apiVersion >= 2
      ? await getSuperTenantPage({
          cursor: url.searchParams.get('cursor'),
          limit: pageLimit(url),
          search: url.searchParams.get('search') || '',
          status: url.searchParams.get('status') || '',
        })
      : null;
    return sendJson(res, 200, {
      ok: true,
      tenants: apiVersion >= 2 ? page.items : await getSuperTenants(),
      page:
        apiVersion >= 2
          ? { nextCursor: page.nextCursor, hasMore: page.hasMore }
          : undefined,
    });
  }
  const tenantMatch = pathname.match(
    /^\/api\/super\/tenants\/([0-9a-f-]+)$/i,
  );
  if (tenantMatch && isUuid(tenantMatch[1]) && req.method === 'PATCH') {
    requireRole(admin, 'operations');
    const tenantId = tenantMatch[1];
    const body = await readJson(req, 64 * 1024);
    const tenantOwnerResult = await pool.query(
      `SELECT t.owner_distributor_id,tc.frontend_template_id
       FROM tenants t
       LEFT JOIN tenant_config tc ON tc.tenant_id=t.id
       WHERE t.id=$1`,
      [tenantId],
    );
    if (!tenantOwnerResult.rows[0]) {
      return sendError(res, 404, '租户不存在。', 'NOT_FOUND');
    }
   const oldOwnerDistributorId =
  tenantOwnerResult.rows[0].owner_distributor_id;
const currentFrontendTemplateId =
  tenantOwnerResult.rows[0].frontend_template_id || DEFAULT_TEMPLATE_ID;
let nextOwnerDistributorId = oldOwnerDistributorId;

if (body.action === 'assignDistributor') {
  requireRole(admin, 'manager');

  const requestedDistributorId = cleanText(
    body.distributorId,
    80,
  ) || null;

  if (
    requestedDistributorId &&
    !isUuid(requestedDistributorId)
  ) {
    return sendError(
      res,
      400,
      '二级代理账号无效。',
      'DISTRIBUTOR_ID',
    );
  }

  if (requestedDistributorId) {
    const distributorResult = await pool.query(
      `
        SELECT id,enabled
        FROM distributors
        WHERE id=$1
      `,
      [requestedDistributorId],
    );

    const targetDistributor = distributorResult.rows[0];

    if (!targetDistributor) {
      return sendError(
        res,
        404,
        '二级代理不存在。',
        'DISTRIBUTOR_NOT_FOUND',
      );
    }

    if (
      !targetDistributor.enabled &&
      targetDistributor.id !== oldOwnerDistributorId
    ) {
      return sendError(
        res,
        409,
        '不能把租户划给已停用的代理。',
        'DISTRIBUTOR_DISABLED',
      );
    }
  }

  await pool.query(
    `
      UPDATE tenants
      SET owner_distributor_id=$2,
          updated_at=NOW()
      WHERE id=$1
    `,
    [tenantId, requestedDistributorId],
  );

  nextOwnerDistributorId = requestedDistributorId;
} else if (body.action === 'forceLogout') {
      await pool.query(
        `UPDATE tenants SET session_version=session_version+1,updated_at=NOW() WHERE id=$1`,
        [tenantId],
      );
      disconnectTenant(tenantId, {
        type: 'force-logout',
        message: '管理员已要求重新登录。',
        at: nowIso(),
      });
    } else if (body.action === 'suspend') {
      await pool.query(
        `UPDATE tenants SET status='suspended',session_version=session_version+1,updated_at=NOW() WHERE id=$1`,
        [tenantId],
      );
      disconnectTenant(tenantId, {
        type: 'force-logout',
        message: '租户服务已暂停。',
        at: nowIso(),
      });
    } else if (body.action === 'resume') {
      const activeLicense = await pool.query(
        `
          SELECT id
          FROM license_keys
          WHERE tenant_id=$1 AND status='active' AND expires_at>NOW()
          LIMIT 1
        `,
        [tenantId],
      );
      if (!activeLicense.rows[0]) {
        return sendError(res, 409, '没有可恢复的有效卡密。', 'LICENSE_STATE');
      }
      await pool.query(
        `UPDATE tenants SET status='active',updated_at=NOW() WHERE id=$1`,
        [tenantId],
      );
    } else {
      const retentionHours = Number(body.retentionHours);
      let approvedTemplateIds = null;
      if (
        body.retentionHours !== undefined &&
        !RETENTION_OPTIONS.has(retentionHours)
      ) {
        return sendError(res, 400, '消息保存时间无效。', 'RETENTION');
      }
      if (
        body.frontendTemplateId !== undefined &&
        !isUuid(body.frontendTemplateId)
      ) {
        return sendError(res, 400, '用户端模板无效。', 'FRONTEND_TEMPLATE');
      }
      if (body.frontendTemplateId !== undefined) {
        const selectedTemplate = await pool.query(
          `
            SELECT id,status
            FROM frontend_templates
            WHERE id=$1
              AND (
                status='testing'
                OR (
                  status='enabled'
                  AND (
                    selection_closed=FALSE
                    OR EXISTS (
                      SELECT 1
                      FROM tenant_frontend_templates history
                      WHERE history.tenant_id=$2
                        AND history.template_id=frontend_templates.id
                    )
                  )
                )
              )
          `,
          [body.frontendTemplateId, tenantId],
        );
        if (!selectedTemplate.rows[0]) {
          return sendError(
            res,
            400,
            '该用户端模板不存在或已停用。',
            'FRONTEND_TEMPLATE',
          );
        }
        if (selectedTemplate.rows[0].status === 'testing') {
          await pool.query(
            `
              UPDATE frontend_templates
              SET test_tenant_ids = CASE
                    WHEN test_tenant_ids @> $2::jsonb THEN test_tenant_ids
                    ELSE test_tenant_ids || $2::jsonb
                  END,
                  updated_at=NOW()
              WHERE id=$1
            `,
            [body.frontendTemplateId, JSON.stringify([tenantId])],
          );
        }
      }
      if (body.approvedTemplateIds !== undefined) {
        if (!Array.isArray(body.approvedTemplateIds)) {
          return sendError(
            res,
            400,
            '历史模板白名单格式无效。',
            'FRONTEND_TEMPLATE_HISTORY',
          );
        }
        approvedTemplateIds = cleanTenantIds(body.approvedTemplateIds);
        const selectedId = body.frontendTemplateId === undefined
          ? currentFrontendTemplateId
          : body.frontendTemplateId;
        if (isUuid(selectedId) && !approvedTemplateIds.includes(selectedId)) {
          approvedTemplateIds.push(selectedId);
        }
        const approvedTemplates = await pool.query(
          `
            SELECT id,status
            FROM frontend_templates
            WHERE id=ANY($1::uuid[])
              AND status IN ('enabled','testing')
          `,
          [approvedTemplateIds],
        );
        if (approvedTemplates.rows.length !== approvedTemplateIds.length) {
          return sendError(
            res,
            400,
            '历史模板中包含不存在或已紧急停用的项目。',
            'FRONTEND_TEMPLATE_HISTORY',
          );
        }
        const testingIds = approvedTemplates.rows
          .filter((item) => item.status === 'testing')
          .map((item) => item.id);
        if (testingIds.length) {
          await pool.query(
            `
              UPDATE frontend_templates
              SET test_tenant_ids = CASE
                    WHEN test_tenant_ids @> $2::jsonb THEN test_tenant_ids
                    ELSE test_tenant_ids || $2::jsonb
                  END,
                  updated_at=NOW()
              WHERE id=ANY($1::uuid[])
            `,
            [testingIds, JSON.stringify([tenantId])],
          );
        }
      }
      const selectedTemplateId = body.frontendTemplateId === undefined
        ? currentFrontendTemplateId
        : body.frontendTemplateId;
      const databaseClient = await pool.connect();
      try {
        await databaseClient.query('BEGIN');
        await databaseClient.query(
          `
            UPDATE tenants
            SET name=COALESCE($2,name),
                note=COALESCE($3,note),
                updated_at=NOW()
            WHERE id=$1
          `,
          [
            tenantId,
            body.name === undefined ? null : cleanText(body.name, 80),
            body.note === undefined ? null : cleanText(body.note, 500),
          ],
        );
        await databaseClient.query(
          `
            UPDATE tenant_config
            SET retention_hours=COALESCE($2,retention_hours),
                frontend_template_id=COALESCE($3,frontend_template_id),
                updated_at=NOW()
            WHERE tenant_id=$1
          `,
          [
            tenantId,
            body.retentionHours === undefined ? null : retentionHours,
            body.frontendTemplateId === undefined
              ? null
              : body.frontendTemplateId,
          ],
        );
        if (approvedTemplateIds) {
          await databaseClient.query(
            `
              WITH desired(template_id) AS (
                SELECT UNNEST($2::uuid[])
              ), upserted AS (
                INSERT INTO tenant_frontend_templates (
                  tenant_id,template_id,first_selected_at,last_selected_at
                )
                SELECT $1,template_id,NOW(),NOW()
                FROM desired
                ON CONFLICT (tenant_id,template_id)
                DO UPDATE SET last_selected_at=NOW()
                RETURNING template_id
              )
              DELETE FROM tenant_frontend_templates history
              WHERE history.tenant_id=$1
                AND NOT (history.template_id=ANY($2::uuid[]))
            `,
            [tenantId, approvedTemplateIds],
          );
        } else {
          await rememberTenantFrontendTemplate(
            databaseClient,
            tenantId,
            selectedTemplateId,
          );
        }
        await databaseClient.query('COMMIT');
      } catch (error) {
        await databaseClient.query('ROLLBACK');
        throw error;
      } finally {
        databaseClient.release();
      }
      broadcast({ type: 'settings-updated' }, null, tenantId);
    }
   invalidateTenantCaches(tenantId);
	   await writeAudit(
  req,
  admin,
  body.action === 'assignDistributor'
    ? 'tenant.assign_distributor'
    : 'tenant.update',
  {
    targetType: 'tenant',
    targetId: tenantId,
    metadata: {
      action: body.action || 'settings',
      frontendTemplateId:
        body.frontendTemplateId || currentFrontendTemplateId,
      approvedTemplateIds: Array.isArray(body.approvedTemplateIds)
        ? cleanTenantIds(body.approvedTemplateIds)
        : undefined,
      fromDistributorId: oldOwnerDistributorId || null,
      toDistributorId: nextOwnerDistributorId || null,
    },
  },
);

broadcastSuper({ type: 'tenants-updated' });

if (body.action === 'assignDistributor') {
  broadcastSuper({ type: 'distributors-updated' });
  for (const liveClient of sseClients) {
    if (liveClient.tenantId === tenantId) {
      liveClient.ownerDistributorId = nextOwnerDistributorId;
    }
  }
}

for (
  const distributorId of new Set(
    [
      oldOwnerDistributorId,
      nextOwnerDistributorId,
    ].filter((id) => isUuid(id)),
  )
) {
  broadcastDistributor(
    { type: 'distributor-tenants-updated' },
    distributorId,
  );
  scheduleDistributorPresenceUpdate(distributorId);
}

return sendJson(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/api/super/announcements') {
    const result = await pool.query(`
      SELECT a.*,
        (SELECT COUNT(*)::int FROM announcement_reads ar
          WHERE ar.announcement_id=a.id) AS read_count
      FROM announcements a
      ORDER BY a.created_at DESC
    `);
    return sendJson(res, 200, { ok: true, announcements: result.rows });
  }
  if (req.method === 'POST' && pathname === '/api/super/announcements') {
    requireRole(admin, 'operations');
    const body = await readJson(req, 128 * 1024);
    const type = ['normal','important','maintenance','version','incident']
      .includes(body.type) ? body.type : 'normal';
    const scope = body.scope === 'selected' ? 'selected' : 'all';
    const tenantIds = cleanTenantIds(body.tenantIds);
    if (scope === 'selected' && !tenantIds.length) {
      return sendError(
        res,
        400,
        '定向公告至少选择一个租户。',
        'ANNOUNCEMENT_SCOPE',
      );
    }
    const displayMode = ['banner','modal','both'].includes(body.displayMode)
      ? body.displayMode : 'banner';
    const id = randomUUID();
    await pool.query(
      `
        INSERT INTO announcements (
          id,type,title,content,scope,tenant_ids,starts_at,ends_at,
          display_mode,force_modal,created_by
        ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9,$10,$11)
      `,
      [
        id,
        type,
        cleanText(body.title, 120) || '平台公告',
        cleanText(body.content, 5000),
        scope,
        JSON.stringify(tenantIds),
        parseIsoDate(body.startsAt || new Date().toISOString(), false),
        parseIsoDate(body.endsAt),
        displayMode,
        Boolean(body.forceModal),
        admin.id,
      ],
    );
    await writeAudit(req, admin, 'announcement.publish', {
      targetType: 'announcement',
      targetId: id,
    });
    publishEvent(
      { type: 'announcement-updated', announcementId: id },
      { targetKind: 'tenant_admin' },
    );
    return sendJson(res, 201, { ok: true, id });
  }
  const announcementMatch = pathname.match(
    /^\/api\/super\/announcements\/([0-9a-f-]+)$/i,
  );
  if (
    announcementMatch &&
    isUuid(announcementMatch[1]) &&
    req.method === 'PATCH'
  ) {
    requireRole(admin, 'operations');
    const body = await readJson(req, 128 * 1024);
    const type = body.type === undefined
      ? null
      : ['normal','important','maintenance','version','incident'].includes(body.type)
        ? body.type : 'normal';
    const scope = body.scope === undefined
      ? null
      : body.scope === 'selected' ? 'selected' : 'all';
    const tenantIds = body.tenantIds === undefined
      ? null
      : cleanTenantIds(body.tenantIds);
    if (scope === 'selected' && !tenantIds?.length) {
      return sendError(
        res,
        400,
        '定向公告至少选择一个租户。',
        'ANNOUNCEMENT_SCOPE',
      );
    }
    const displayMode = body.displayMode === undefined
      ? null
      : ['banner','modal','both'].includes(body.displayMode)
        ? body.displayMode : 'banner';
    await pool.query(
      `
        UPDATE announcements
        SET type=COALESCE($2,type),
            title=COALESCE($3,title),
            content=COALESCE($4,content),
            scope=COALESCE($5,scope),
            tenant_ids=COALESCE($6::jsonb,tenant_ids),
            starts_at=COALESCE($7,starts_at),
            ends_at=CASE WHEN $8::boolean THEN $9 ELSE ends_at END,
            display_mode=COALESCE($10,display_mode),
            force_modal=COALESCE($11,force_modal),
            updated_at=NOW()
        WHERE id=$1
      `,
      [
        announcementMatch[1],
        type,
        body.title === undefined ? null : cleanText(body.title, 120),
        body.content === undefined ? null : cleanText(body.content, 5000),
        scope,
        tenantIds === null ? null : JSON.stringify(tenantIds),
        body.startsAt === undefined ? null : parseIsoDate(body.startsAt, false),
        body.endsAt !== undefined,
        body.endsAt === undefined ? null : parseIsoDate(body.endsAt),
        displayMode,
        body.forceModal === undefined ? null : Boolean(body.forceModal),
      ],
    );
    await writeAudit(req, admin, 'announcement.update', {
      targetType: 'announcement',
      targetId: announcementMatch[1],
    });
    publishEvent(
      {
        type: 'announcement-updated',
        announcementId: announcementMatch[1],
      },
      { targetKind: 'tenant_admin' },
    );
    return sendJson(res, 200, { ok: true });
  }
  if (
    announcementMatch &&
    isUuid(announcementMatch[1]) &&
    req.method === 'DELETE'
  ) {
    requireRole(admin, 'operations');
    await pool.query(
      `
        UPDATE announcements
        SET active=FALSE,retracted_at=NOW(),updated_at=NOW()
        WHERE id=$1
      `,
      [announcementMatch[1]],
    );
    await writeAudit(req, admin, 'announcement.retract', {
      targetType: 'announcement',
      targetId: announcementMatch[1],
    });
    publishEvent(
      {
        type: 'announcement-retracted',
        announcementId: announcementMatch[1],
      },
      { targetKind: 'tenant_admin' },
    );
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/api/super/releases') {
    const result = await pool.query(`
      SELECT r.*,
        (SELECT COUNT(*)::int FROM release_reads rr
          WHERE rr.release_id=r.id) AS read_count
      FROM releases r
      ORDER BY r.published_at DESC
    `);
    return sendJson(res, 200, { ok: true, releases: result.rows });
  }
  if (req.method === 'POST' && pathname === '/api/super/releases') {
    requireRole(admin, 'operations');
    const body = await readJson(req, 256 * 1024);
    const version = cleanText(body.version, 40);
    if (!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version)) {
      return sendError(res, 400, '版本号格式应类似 1.8.2。', 'VERSION');
    }
    const id = randomUUID();
    const scope = body.scope === 'selected' ? 'selected' : 'all';
    const tenantIds = cleanTenantIds(body.tenantIds);
    if (scope === 'selected' && !tenantIds.length) {
      return sendError(
        res,
        400,
        '定向版本至少选择一个租户。',
        'RELEASE_SCOPE',
      );
    }
    await pool.query(
      `
        INSERT INTO releases (
          id,version,title,new_features,improvements,fixes,known_issues,
          scope,tenant_ids,force_modal,published_at,created_by
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb,$10,$11,$12)
      `,
      [
        id,
        version,
        cleanText(body.title, 120) || `v${version} 更新`,
        cleanText(body.newFeatures, 10000),
        cleanText(body.improvements, 10000),
        cleanText(body.fixes, 10000),
        cleanText(body.knownIssues, 10000),
        scope,
        JSON.stringify(tenantIds),
        Boolean(body.forceModal),
        parseIsoDate(body.publishedAt || new Date().toISOString(), false),
        admin.id,
      ],
    );
    if (scope === 'all') {
      await pool.query(
        `UPDATE platform_settings SET current_version=$1,updated_at=NOW() WHERE id=1`,
        [version],
      );
      invalidatePlatformCache();
    }
    await writeAudit(req, admin, 'release.publish', {
      targetType: 'release',
      targetId: id,
      metadata: { version },
    });
    if (scope === 'all') {
      publishEvent(
        { type: 'release-published', releaseId: id, version },
        { targetKind: 'tenant_admin' },
      );
    } else {
      for (const tenantId of tenantIds) {
        publishEvent(
          { type: 'release-published', releaseId: id, version },
          { tenantId, targetKind: 'tenant_admin' },
        );
      }
    }
    broadcastSuper({
      type: 'release-published',
      releaseId: id,
      version,
    });
    return sendJson(res, 201, { ok: true, id });
  }

  const releaseMatch = pathname.match(
    /^\/api\/super\/releases\/([0-9a-f-]+)$/i,
  );
  if (
    releaseMatch &&
    isUuid(releaseMatch[1]) &&
    ['PATCH', 'DELETE'].includes(req.method)
  ) {
    requireRole(admin, 'operations');
    const releaseId = releaseMatch[1];
    const body =
      req.method === 'PATCH' ? await readJson(req, 256 * 1024) : null;
    let updatedRelease = null;
    let deletedRelease = null;
    let currentVersion = APP_VERSION;
    const databaseClient = await pool.connect();
    try {
      await databaseClient.query('BEGIN');
      const existingResult = await databaseClient.query(
        `SELECT * FROM releases WHERE id=$1 FOR UPDATE`,
        [releaseId],
      );
      const existing = existingResult.rows[0];
      if (!existing) {
        await databaseClient.query('ROLLBACK');
        return sendError(res, 404, '版本记录不存在。', 'RELEASE_NOT_FOUND');
      }

      if (req.method === 'PATCH') {
        const version = cleanText(body.version ?? existing.version, 40);
        if (!/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version)) {
          await databaseClient.query('ROLLBACK');
          return sendError(
            res,
            400,
            '版本号格式应类似 1.8.2。',
            'VERSION',
          );
        }
        const duplicate = await databaseClient.query(
          `SELECT 1 FROM releases WHERE version=$1 AND id<>$2 LIMIT 1`,
          [version, releaseId],
        );
        if (duplicate.rowCount) {
          await databaseClient.query('ROLLBACK');
          return sendError(
            res,
            409,
            '该版本号已经存在，请使用其他版本号。',
            'VERSION_EXISTS',
          );
        }
        const scope = body.scope === 'selected' ? 'selected' : 'all';
        const tenantIds = cleanTenantIds(body.tenantIds);
        if (scope === 'selected' && !tenantIds.length) {
          await databaseClient.query('ROLLBACK');
          return sendError(
            res,
            400,
            '定向版本至少选择一个租户。',
            'RELEASE_SCOPE',
          );
        }
        const updated = await databaseClient.query(
          `
            UPDATE releases
            SET version=$2,title=$3,new_features=$4,improvements=$5,
                fixes=$6,known_issues=$7,scope=$8,tenant_ids=$9::jsonb,
                force_modal=$10
            WHERE id=$1
            RETURNING *
          `,
          [
            releaseId,
            version,
            cleanText(body.title, 120) || `v${version} 更新`,
            cleanText(body.newFeatures, 10000),
            cleanText(body.improvements, 10000),
            cleanText(body.fixes, 10000),
            cleanText(body.knownIssues, 10000),
            scope,
            JSON.stringify(tenantIds),
            Boolean(body.forceModal),
          ],
        );
        if (body.resetReads) {
          await databaseClient.query(
            `DELETE FROM release_reads WHERE release_id=$1`,
            [releaseId],
          );
        }
        updatedRelease = updated.rows[0];
        updatedRelease.previous_scope = existing.scope;
        updatedRelease.previous_tenant_ids = existing.tenant_ids;
      } else {
        deletedRelease = existing;
        await databaseClient.query(`DELETE FROM releases WHERE id=$1`, [releaseId]);
      }

      currentVersion = await syncCurrentReleaseVersion(databaseClient);
      await databaseClient.query('COMMIT');
    } catch (error) {
      await databaseClient.query('ROLLBACK').catch(() => {});
      throw error;
    } finally {
      databaseClient.release();
    }
    invalidatePlatformCache();

    const release = updatedRelease || deletedRelease;
    const previousTenantIds = cleanTenantIds(
      updatedRelease?.previous_tenant_ids || release.tenant_ids,
    );
    const currentTenantIds = cleanTenantIds(updatedRelease?.tenant_ids || []);
    const notifyAll =
      release.scope === 'all' || updatedRelease?.previous_scope === 'all';
    const event = {
      type: 'release-published',
      action: updatedRelease ? 'updated' : 'deleted',
      releaseId,
      version: updatedRelease?.version || release.version,
      currentVersion,
    };
    if (notifyAll) {
      publishEvent(event, { targetKind: 'tenant_admin' });
    } else {
      const affectedTenantIds = [
        ...new Set([...previousTenantIds, ...currentTenantIds]),
      ];
      for (const tenantId of affectedTenantIds) {
        publishEvent(event, { tenantId, targetKind: 'tenant_admin' });
      }
    }
    broadcastSuper(event);
    await writeAudit(
      req,
      admin,
      updatedRelease ? 'release.update' : 'release.delete',
      {
        targetType: 'release',
        targetId: releaseId,
        metadata: {
          version: updatedRelease?.version || release.version,
          currentVersion,
        },
      },
    );
    return sendJson(res, 200, {
      ok: true,
      release: updatedRelease || undefined,
      currentVersion,
    });
  }

  if (req.method === 'GET' && pathname === '/api/super/features') {
    const result = await pool.query(
      `SELECT * FROM feature_catalog ORDER BY category,name`,
    );
    return sendJson(res, 200, { ok: true, features: result.rows });
  }
  if (req.method === 'POST' && pathname === '/api/super/features') {
    requireRole(admin, 'operations');
    const body = await readJson(req, 64 * 1024);
    const requestedCode = cleanText(body.code, 80).toLowerCase();
    if (requestedCode && !/^[a-z][a-z0-9_]{2,79}$/.test(requestedCode)) {
      return sendError(res, 400, '功能代码格式无效。', 'FEATURE_CODE');
    }
    const code =
      requestedCode ||
      `feature_${Date.now().toString(36)}_${randomBytes(3).toString('hex')}`;
    const name = cleanText(body.name, 80);
    if (!name) {
      return sendError(res, 400, '请填写功能名称。', 'FEATURE_NAME');
    }
    const entitlements = cleanFeatureEntitlements(body.entitlements);
    const id = randomUUID();
    await pool.query(
      `
        INSERT INTO feature_catalog (
          id,code,name,description,category,icon,public_visible,status,entitlements
        ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9::jsonb)
      `,
      [
        id,
        code,
        name,
        cleanText(body.description, 1000),
        cleanText(body.category, 80) || '其他',
        cleanText(body.icon, 50) || 'sparkles',
        body.publicVisible !== false,
        ['normal','testing','maintenance','coming'].includes(body.status)
          ? body.status : 'normal',
        JSON.stringify(entitlements),
      ],
    );
    await writeAudit(req, admin, 'feature.create', {
      targetType: 'feature',
      targetId: id,
    });
    invalidateTenantCaches();
    publishEvent(
      { type: 'feature-catalog-updated' },
      { targetKind: 'tenant_admin' },
    );
    publishEvent(
      { type: 'feature-catalog-updated' },
      { targetKind: 'user' },
    );
    broadcastSuper({ type: 'feature-catalog-updated' });
    return sendJson(res, 201, { ok: true, id });
  }
  const featureMatch = pathname.match(
    /^\/api\/super\/features\/([0-9a-f-]+)$/i,
  );
  if (featureMatch && isUuid(featureMatch[1]) && req.method === 'PATCH') {
    requireRole(admin, 'operations');
    const body = await readJson(req, 64 * 1024);
    if (body.name !== undefined && !cleanText(body.name, 80)) {
      return sendError(res, 400, '请填写功能名称。', 'FEATURE_NAME');
    }
    const entitlements = body.entitlements === undefined
      ? null
      : cleanFeatureEntitlements(body.entitlements);
    await pool.query(
      `
        UPDATE feature_catalog
        SET name=COALESCE($2,name),
            description=COALESCE($3,description),
            category=COALESCE($4,category),
            icon=COALESCE($5,icon),
            public_visible=COALESCE($6,public_visible),
            status=COALESCE($7,status),
            entitlements=COALESCE($8::jsonb,entitlements),
            updated_at=NOW()
        WHERE id=$1
      `,
      [
        featureMatch[1],
        body.name === undefined ? null : cleanText(body.name, 80),
        body.description === undefined
          ? null : cleanText(body.description, 1000),
        body.category === undefined ? null : cleanText(body.category, 80),
        body.icon === undefined ? null : cleanText(body.icon, 50),
        body.publicVisible === undefined ? null : Boolean(body.publicVisible),
        body.status === undefined ? null :
          (['normal','testing','maintenance','coming'].includes(body.status)
            ? body.status : 'normal'),
        entitlements === null ? null : JSON.stringify(entitlements),
      ],
    );
    await writeAudit(req, admin, 'feature.update', {
      targetType: 'feature',
      targetId: featureMatch[1],
    });
    invalidateTenantCaches();
    invalidateTenantEntryCaches();
    publishEvent(
      { type: 'feature-catalog-updated' },
      { targetKind: 'tenant_admin' },
    );
    publishEvent(
      { type: 'feature-catalog-updated' },
      { targetKind: 'user' },
    );
    broadcastSuper({ type: 'feature-catalog-updated' });
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/api/super/flags') {
    const result = await pool.query(`SELECT * FROM feature_flags ORDER BY code`);
    return sendJson(res, 200, { ok: true, flags: result.rows });
  }
  if (
    ['POST', 'PUT'].includes(req.method) &&
    pathname === '/api/super/flags'
  ) {
    requireRole(admin, 'manager');
    const body = await readJson(req, 64 * 1024);
    const code = cleanText(body.code, 80).toLowerCase();
    if (!/^[a-z][a-z0-9_]{2,79}$/.test(code)) {
      return sendError(res, 400, '功能开关代码格式无效。', 'FLAG_CODE');
    }
    const exists = await pool.query(
      `SELECT 1 FROM feature_catalog WHERE code=$1`,
      [code],
    );
    if (!exists.rows[0] || !SUPPORTED_FEATURE_FLAGS.has(code)) {
      return sendError(
        res,
        409,
        '该功能尚未在后端实现开关钩子，不能创建无效开关。',
        'FLAG_UNSUPPORTED',
      );
    }
    const scope = ['super','selected','all'].includes(body.scope)
      ? body.scope
      : 'super';
    const tenantIds = cleanTenantIds(body.tenantIds);
    if (scope === 'selected' && !tenantIds.length) {
      return sendError(
        res,
        400,
        '定向功能开关至少选择一个租户。',
        'FLAG_SCOPE',
      );
    }
    await pool.query(
      `
        INSERT INTO feature_flags (
          code,name,description,enabled,scope,tenant_ids,
          starts_at,ends_at,updated_by
        ) VALUES ($1,$2,$3,$4,$5,$6::jsonb,$7,$8,$9)
        ON CONFLICT (code) DO UPDATE SET
          name=EXCLUDED.name,
          description=EXCLUDED.description,
          enabled=EXCLUDED.enabled,
          scope=EXCLUDED.scope,
          tenant_ids=EXCLUDED.tenant_ids,
          starts_at=EXCLUDED.starts_at,
          ends_at=EXCLUDED.ends_at,
          updated_by=EXCLUDED.updated_by,
          updated_at=NOW()
      `,
      [
        code,
        cleanText(body.name, 80) || code,
        cleanText(body.description, 1000),
        Boolean(body.enabled),
        scope,
        JSON.stringify(tenantIds),
        parseIsoDate(body.startsAt),
        parseIsoDate(body.endsAt),
        admin.id,
      ],
    );
    await writeAudit(req, admin, 'feature_flag.update', {
      targetType: 'feature_flag',
      targetId: code,
    });
    invalidateTenantCaches();
    publishEvent(
      { type: 'feature-flags-updated' },
      { targetKind: 'tenant_admin' },
    );
    publishEvent(
      { type: 'feature-flags-updated' },
      { targetKind: 'user' },
    );
    return sendJson(res, 200, { ok: true });
  }

  if (req.method === 'GET' && pathname === '/api/super/templates') {
    return sendJson(res, 200, {
      ok: true,
      templates: await getTemplateCatalog({ audience: 'super' }),
    });
  }
  if (req.method === 'POST' && pathname === '/api/super/templates') {
    requireRole(admin, 'operations');
    const body = await readJson(req, 64 * 1024);
    let parsed;
    try {
      parsed = parseTemplateFetchTarget(cleanText(body.baseUrl, 500));
    } catch {
      return sendError(res, 400, '模板必须使用有效 HTTPS 地址。', 'TEMPLATE_URL');
    }
    parsed.hash = '';
    const baseUrl = parsed.toString();
    const entryHost = tenantEntryHostFromNetlifyUrl(baseUrl);
    const netlifySiteId = normalizeNetlifySiteId(body.netlifySiteId);
    if (body.netlifySiteId && !netlifySiteId) {
      return sendError(
        res,
        400,
        'Netlify Site ID 格式无效。',
        'NETLIFY_SITE_ID',
      );
    }
    const id = randomUUID();
    const isDefault = Boolean(body.isDefault);
    const status = isDefault
      ? 'enabled'
      : ['testing','enabled'].includes(body.status)
        ? body.status
        : 'testing';
    const client = await pool.connect();
    try {
      await client.query('BEGIN');
      await client.query(
        `SELECT pg_advisory_xact_lock(hashtext('tenant-entry-host-registry'))`,
      );
      if (entryHost) {
        await assertTemplateEntryHostAvailable(client, entryHost, id);
      }
      if (isDefault) {
        await client.query(
          `UPDATE frontend_templates SET is_default=FALSE WHERE is_default=TRUE`,
        );
      }
      await client.query(
        `
          INSERT INTO frontend_templates (
            id,name,base_url,origin,netlify_site_id,entry_host,
            client_version,min_backend_version,
            status,selection_closed,sort_order,recommended,is_default,
            test_tenant_ids
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,FALSE,$10,$11,$12,$13::jsonb)
        `,
        [
          id,
          cleanText(body.name, 80) || parsed.hostname,
          baseUrl,
          parsed.origin,
          netlifySiteId,
          entryHost,
          cleanText(body.clientVersion, 30) || APP_VERSION,
          cleanText(body.minBackendVersion, 30) || APP_VERSION,
          status,
          Math.trunc(Number(body.sortOrder || 0)),
          Boolean(body.recommended),
          isDefault,
          JSON.stringify(cleanTenantIds(body.testTenantIds)),
        ],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
    invalidateApprovedOrigins();
    await refreshApprovedOrigins(true);
    await writeAudit(req, admin, 'template.create', {
      targetType: 'frontend_template',
      targetId: id,
      metadata: { origin: parsed.origin },
    });
    invalidateTenantCaches();
    publishEvent(
      { type: 'frontend_catalog_updated' },
      { targetKind: 'tenant_admin' },
    );
    broadcastSuper({ type: 'frontend_catalog_updated' });
    return sendJson(res, 201, { ok: true, id });
  }
  if (
    req.method === 'POST' &&
    pathname === '/api/super/templates/validate'
  ) {
    requireRole(admin, 'operations');
    if (
      !rateLimit(
        req,
        res,
        'template-validate',
        20,
        10 * 60_000,
        admin.id,
      )
    ) return;
    const body = await readJson(req, 32 * 1024);
    const baseUrl = cleanText(body.baseUrl, 500);
    const minimumVersion =
      cleanText(body.minBackendVersion, 30) || APP_VERSION;
    let fetched;
    try {
      fetched = await fetchTemplateHtml(baseUrl);
    } catch (error) {
      await writeAudit(req, admin, 'template.validate', {
        targetType: 'frontend_template',
        targetId: baseUrl,
        result: 'failed',
        metadata: { error: cleanText(error.message, 300) },
      });
      return sendJson(res, 200, {
        ok: true,
        validation: {
          reachable: false,
          status: 0,
          clientVersion: '',
          apiBase: '',
          contractVersion: '',
          contractReady: false,
          missingMarkers: [],
          compatible: false,
          message: cleanText(error.message, 300),
        },
      });
    }
    const contract = extractTemplateContract(fetched.html);
    const reachable =
      fetched.status >= 200 &&
      fetched.status < 300 &&
      /(?:text\/html|application\/xhtml\+xml)/i.test(fetched.contentType);
    const apiMatches =
      contract.apiBase === PUBLIC_API_BASE;
    const backendCompatible =
      compareVersions(APP_VERSION, minimumVersion) >= 0;
    const compatible =
      reachable &&
      Boolean(contract.clientVersion) &&
      contract.contractReady &&
      apiMatches &&
      backendCompatible;
    const message = compatible
      ? '模板接口契约、后端域名和版本要求均通过。'
      : !reachable
        ? '模板页面无法正常返回 HTML。'
        : !contract.clientVersion
          ? '未识别到用户端版本。'
          : !contract.contractReady
            ? '模板缺少必要接口或 SSE 契约。'
            : !apiMatches
              ? `模板连接的后端不是 ${PUBLIC_API_BASE}。`
              : `当前后端 v${APP_VERSION} 低于模板要求 v${minimumVersion}。`;
    await writeAudit(req, admin, 'template.validate', {
      targetType: 'frontend_template',
      targetId: baseUrl,
      result: compatible ? 'success' : 'failed',
      metadata: {
        finalUrl: fetched.finalUrl,
        status: fetched.status,
        clientVersion: contract.clientVersion,
        contractVersion: contract.contractVersion,
        missingMarkers: contract.missingMarkers,
      },
    });
    return sendJson(res, 200, {
      ok: true,
      validation: {
        reachable,
        status: fetched.status,
        finalUrl: fetched.finalUrl,
        clientVersion: contract.clientVersion,
        apiBase: contract.apiBase,
        contractVersion: contract.contractVersion,
        contractReady: contract.contractReady,
        missingMarkers: contract.missingMarkers,
        backendCompatible,
        compatible,
        message,
      },
    });
  }
  const templateMatch = pathname.match(
    /^\/api\/super\/templates\/([0-9a-f-]+)(?:\/(cover))?$/i,
  );
  if (templateMatch && isUuid(templateMatch[1])) {
    const templateId = templateMatch[1];
    if (req.method === 'POST' && templateMatch[2] === 'cover') {
      requireRole(admin, 'operations');
      if (
        !rateLimit(
          req,
          res,
          'template-cover-upload',
          12,
          10 * 60_000,
          admin.id,
        )
      ) return;
      const data = await prepareImageUpload(req, {
        maxBytes: MAX_COVER_BYTES,
        width: 1200,
        height: 750,
      });
      const current = await pool.query(
        `SELECT cover_asset_id FROM frontend_templates WHERE id=$1`,
        [templateId],
      );
      if (!current.rows[0]) {
        return sendError(res, 404, '模板不存在。', 'NOT_FOUND');
      }
      const asset = await saveAsset({
        kind: 'template_cover',
        filename: 'template-cover.webp',
        mime: 'image/webp',
        data,
      });
      await pool.query(
        `UPDATE frontend_templates SET cover_asset_id=$2,updated_at=NOW() WHERE id=$1`,
        [templateId, asset.id],
      );
      if (current.rows[0].cover_asset_id) {
        await deleteAsset(current.rows[0].cover_asset_id, null);
      }
      await writeAudit(req, admin, 'template.cover', {
        targetType: 'frontend_template',
        targetId: templateId,
      });
      publishEvent(
        { type: 'frontend_catalog_updated' },
        { targetKind: 'tenant_admin' },
      );
      broadcastSuper({ type: 'frontend_catalog_updated' });
      return sendJson(res, 201, {
        ok: true,
        coverUrl: `${PUBLIC_API_BASE}/api/public/assets/${asset.id}`,
      });
    }
    if (req.method === 'PATCH' && !templateMatch[2]) {
      requireRole(admin, 'operations');
      const body = await readJson(req, 64 * 1024);
      let baseUrl = null;
      let origin = null;
      let netlifySiteId = null;
      let entryHost = null;
      if (body.baseUrl !== undefined) {
        try {
          const parsed = parseTemplateFetchTarget(
            cleanText(body.baseUrl, 500),
          );
          parsed.hash = '';
          baseUrl = parsed.toString();
          origin = parsed.origin;
          entryHost = tenantEntryHostFromNetlifyUrl(baseUrl);
        } catch {
          return sendError(res, 400, '模板必须使用有效 HTTPS 地址。', 'TEMPLATE_URL');
        }
      }
      if (body.netlifySiteId !== undefined) {
        netlifySiteId = normalizeNetlifySiteId(body.netlifySiteId);
        if (body.netlifySiteId && !netlifySiteId) {
          return sendError(
            res,
            400,
            'Netlify Site ID 格式无效。',
            'NETLIFY_SITE_ID',
          );
        }
      }
      const status = body.status === undefined
        ? null
        : ['testing','enabled','disabled'].includes(body.status)
          ? body.status : 'disabled';
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const current = await client.query(
          `
            SELECT id,status,is_default,selection_closed,entry_host
            FROM frontend_templates
            WHERE id=$1
            FOR UPDATE
          `,
          [templateId],
        );
        if (!current.rows[0]) {
          throw requestError('模板不存在。', 404, 'NOT_FOUND');
        }
        if (entryHost && entryHost !== current.rows[0].entry_host) {
          await client.query(
            `SELECT pg_advisory_xact_lock(hashtext('tenant-entry-host-registry'))`,
          );
          await storeTemplateEntryAlias(
            client,
            templateId,
            current.rows[0].entry_host,
          );
          await assertTemplateEntryHostAvailable(client, entryHost, templateId);
          await client.query(
            `DELETE FROM frontend_template_entry_aliases
             WHERE hostname=$1 AND template_id=$2`,
            [entryHost, templateId],
          );
        }
        let nextStatus = status;
        let selectionClosed = null;
        let migrateToTemplateId = null;
        if (status === 'disabled') {
          if (current.rows[0].is_default) {
            throw requestError(
              '默认模板不能直接停用，请先将其他模板设为默认。',
              409,
              'DEFAULT_TEMPLATE',
            );
          }
          const disableMode = ['newOnly','migrate','emergency'].includes(
            body.disableMode,
          )
            ? body.disableMode
            : isUuid(body.migrateToTemplateId)
              ? 'migrate'
              : 'newOnly';
          if (disableMode === 'newOnly') {
            nextStatus = current.rows[0].status === 'disabled'
              ? 'enabled'
              : current.rows[0].status;
            selectionClosed = true;
          } else {
            if (isUuid(body.migrateToTemplateId)) {
              migrateToTemplateId = body.migrateToTemplateId;
            } else if (disableMode === 'emergency') {
              const fallback = await client.query(
                `
                  SELECT id
                  FROM frontend_templates
                  WHERE is_default=TRUE
                    AND status='enabled'
                    AND selection_closed=FALSE
                    AND id<>$1
                `,
                [templateId],
              );
              migrateToTemplateId = fallback.rows[0]?.id || null;
            }
            if (!isUuid(migrateToTemplateId)) {
              throw requestError(
                '迁移或紧急停用时必须选择可用的目标模板。',
                400,
                'TEMPLATE_MIGRATION',
              );
            }
            const fallback = await client.query(
              `
                SELECT id
                FROM frontend_templates
                WHERE id=$1
                  AND id<>$2
                  AND status='enabled'
                  AND selection_closed=FALSE
              `,
              [migrateToTemplateId, templateId],
            );
            if (!fallback.rows[0]) {
              throw requestError(
                '目标模板不存在或不可选择。',
                400,
                'TEMPLATE_MIGRATION',
              );
            }
            nextStatus = 'disabled';
            selectionClosed = true;
            await client.query(
              `
                WITH migrated AS (
                  UPDATE tenant_config
                  SET frontend_template_id=$2,updated_at=NOW()
                  WHERE frontend_template_id=$1
                  RETURNING tenant_id
                )
                INSERT INTO tenant_frontend_templates (
                  tenant_id,template_id,first_selected_at,last_selected_at
                )
                SELECT tenant_id,$2,NOW(),NOW()
                FROM migrated
                ON CONFLICT (tenant_id,template_id)
                DO UPDATE SET last_selected_at=NOW()
              `,
              [templateId, migrateToTemplateId],
            );
          }
        } else if (status === 'enabled' || status === 'testing') {
          selectionClosed = false;
        }
        const makeDefault = body.isDefault === true;
        if (makeDefault) {
          nextStatus = 'enabled';
          selectionClosed = false;
          await client.query(
            `UPDATE frontend_templates SET is_default=FALSE WHERE is_default=TRUE`,
          );
        }
        await client.query(
          `
            UPDATE frontend_templates
            SET name=COALESCE($2,name),
                base_url=COALESCE($3,base_url),
                origin=COALESCE($4,origin),
                netlify_site_id=COALESCE($5,netlify_site_id),
                entry_host=COALESCE($6,entry_host),
                client_version=COALESCE($7,client_version),
                min_backend_version=COALESCE($8,min_backend_version),
                status=COALESCE($9,status),
                selection_closed=COALESCE($10,selection_closed),
                sort_order=COALESCE($11,sort_order),
                recommended=COALESCE($12,recommended),
                is_default=CASE WHEN $13::boolean THEN TRUE ELSE is_default END,
                test_tenant_ids=COALESCE($14::jsonb,test_tenant_ids),
                updated_at=NOW()
            WHERE id=$1
          `,
          [
            templateId,
            body.name === undefined ? null : cleanText(body.name, 80),
            baseUrl,
            origin,
            netlifySiteId,
            entryHost,
            body.clientVersion === undefined
              ? null : cleanText(body.clientVersion, 30),
            body.minBackendVersion === undefined
              ? null : cleanText(body.minBackendVersion, 30),
            nextStatus,
            selectionClosed,
            body.sortOrder === undefined
              ? null : Math.trunc(Number(body.sortOrder || 0)),
            body.recommended === undefined
              ? null : Boolean(body.recommended),
            makeDefault,
            body.testTenantIds === undefined
              ? null
              : JSON.stringify(cleanTenantIds(body.testTenantIds)),
          ],
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      invalidateTenantCaches();
      invalidateTenantEntryCaches();
      invalidateApprovedOrigins();
      await refreshApprovedOrigins(true);
      await writeAudit(req, admin, 'template.update', {
        targetType: 'frontend_template',
        targetId: templateId,
      });
      publishEvent(
        { type: 'frontend_catalog_updated' },
        { targetKind: 'tenant_admin' },
      );
      broadcastSuper({ type: 'frontend_catalog_updated' });
      return sendJson(res, 200, { ok: true });
    }
  }

  if (req.method === 'GET' && pathname === '/api/super/audit') {
    const auditLimit = apiVersion >= 2 ? pageLimit(url, 100) : 1000;
    const rawCursor = Number(url.searchParams.get('cursor'));
    const auditCursor =
      apiVersion >= 2 && Number.isSafeInteger(rawCursor) && rawCursor > 0
        ? rawCursor
        : null;
    const result = await pool.query(`
      SELECT
        al.*,
        COALESCE(
          sa.username,
          CASE WHEN d.username IS NOT NULL
            THEN '二级代理 · ' || d.username
            ELSE NULL
          END,
          CASE WHEN actor_tenant.id IS NOT NULL
            THEN '租户 · ' || COALESCE(NULLIF(actor_tenant.name,''),actor_tenant.public_code)
            ELSE NULL
          END,
          '系统任务'
        ) AS username,
        CASE
          WHEN sa.id IS NOT NULL THEN 'super_admin'
          WHEN d.id IS NOT NULL THEN 'distributor'
          WHEN actor_tenant.id IS NOT NULL THEN 'tenant'
          ELSE 'system'
        END AS actor_type,
        actor_tenant.name AS actor_tenant_name,
        actor_tenant.public_code AS actor_tenant_code,
        actor_tenant.note AS actor_tenant_note,
        actor_license.key_prefix AS actor_license_prefix,
        actor_license.key_suffix AS actor_license_suffix,
        actor_license.duration_code AS actor_license_duration_code,
        actor_license.status AS actor_license_status,
        actor_license.expires_at AS actor_license_expires_at
      FROM audit_logs al
      LEFT JOIN super_admins sa ON sa.id=al.actor_admin_id
      LEFT JOIN distributors d ON d.id=al.actor_distributor_id
      LEFT JOIN tenants actor_tenant ON actor_tenant.id=al.actor_tenant_id
      LEFT JOIN license_keys actor_license ON actor_license.id=al.actor_license_id
      WHERE ($1::bigint IS NULL OR al.id < $1)
        AND al.risk_level IN ('high','critical')
      ORDER BY al.id DESC
      LIMIT $2
    `, [auditCursor, apiVersion >= 2 ? auditLimit + 1 : auditLimit]);
    const hasMore = apiVersion >= 2 && result.rows.length > auditLimit;
    const logs = result.rows.slice(0, auditLimit);
    return sendJson(res, 200, {
      ok: true,
      logs,
      page:
        apiVersion >= 2
          ? {
              hasMore,
              nextCursor: hasMore ? String(logs.at(-1)?.id || '') : null,
            }
          : undefined,
    });
  }
  if (req.method === 'GET' && pathname === '/api/super/monitor') {
    const forceRefresh = url.searchParams.get('refresh') === '1';
    if (
      forceRefresh &&
      !rateLimit(req, res, 'super-monitor-refresh', 6, 60_000, admin.id)
    ) return;
    return sendJson(res, 200, {
      ok: true,
      monitor: await getMonitorSnapshotCached({
        force: forceRefresh,
        persist:
          Date.now() - lastPersistedMonitorAt >=
          ACTIVE_MONITOR_INTERVAL_MS,
      }),
    });
  }
  if (req.method === 'GET' && pathname === '/api/super/platform') {
    return sendJson(res, 200, {
      ok: true,
      platform: await getPlatformSettings(),
    });
  }
  if (req.method === 'PUT' && pathname === '/api/super/platform') {
    requireRole(admin, 'manager');
    const body = await readJson(req, 64 * 1024);
    const reportTime = cleanText(body.reportTime, 5);
    if (body.reportTime !== undefined && !/^(?:[01]\d|2[0-3]):[0-5]\d$/.test(reportTime)) {
      return sendError(res, 400, '日报时间格式无效。', 'REPORT_TIME');
    }
    if (body.reportTimezone !== undefined) {
      try {
        new Intl.DateTimeFormat('en', {
          timeZone: cleanText(body.reportTimezone, 80),
        }).format();
      } catch {
        return sendError(res, 400, '时区名称无效。', 'TIMEZONE');
      }
    }
    let customerServiceTelegram = null;
    if (body.customerServiceTelegram !== undefined) {
      const username = cleanText(body.customerServiceTelegram, 80)
        .trim()
        .replace(/^@+/, '');
      if (!/^[A-Za-z0-9_]{5,32}$/.test(username)) {
        return sendError(
          res,
          400,
          '平台客服用户名必须是 5-32 位 Telegram 用户名。',
          'CUSTOMER_SERVICE_TELEGRAM',
        );
      }
      customerServiceTelegram = `@${username}`;
    }
    await pool.query(
      `
        UPDATE platform_settings
        SET brand_name=COALESCE($1,brand_name),
            support_telegram=COALESCE($2,support_telegram),
            customer_service_telegram=COALESCE($3,customer_service_telegram),
            telegram_group_id=COALESCE($4,telegram_group_id),
            report_time=COALESCE($5,report_time),
            report_timezone=COALESCE($6,report_timezone),
            daily_report_enabled=COALESCE($7,daily_report_enabled),
            weekly_report_enabled=COALESCE($8,weekly_report_enabled),
            alert_settings=COALESCE($9::jsonb,alert_settings),
            updated_at=NOW()
        WHERE id=1
      `,
      [
        body.brandName === undefined ? null : cleanText(body.brandName, 80),
        body.supportTelegram === undefined
          ? null : cleanText(body.supportTelegram, 80),
        body.customerServiceTelegram === undefined
          ? null : customerServiceTelegram,
        body.telegramGroupId === undefined
          ? null : cleanText(body.telegramGroupId, 80),
        body.reportTime === undefined ? null : reportTime,
        body.reportTimezone === undefined
          ? null : cleanText(body.reportTimezone, 80),
        body.dailyReportEnabled === undefined
          ? null : Boolean(body.dailyReportEnabled),
        body.weeklyReportEnabled === undefined
          ? null : Boolean(body.weeklyReportEnabled),
        body.alertSettings === undefined
          ? null : JSON.stringify(body.alertSettings),
      ],
    );
    await writeAudit(req, admin, 'platform.update', {
      targetType: 'platform',
      targetId: '1',
    });
    invalidatePlatformCache();
    scheduleNextReport().catch(() => {});
    broadcastSuper({ type: 'platform-updated' });
    publishEvent(
      { type: 'platform-updated' },
      { targetKind: 'tenant_admin' },
    );
    return sendJson(res, 200, {
      ok: true,
      platform: await getPlatformSettings(),
    });
  }

  const superAdminsRoute =
    pathname === '/api/super/admins' ||
    /^\/api\/super\/admins\/[0-9a-f-]+$/i.test(pathname);
  if (superAdminsRoute) {
    return sendError(
      res,
      403,
      '管理员账号只能通过服务器环境变量配置。',
      'ENV_MANAGED_ADMINS',
    );
  }

  return sendError(res, 404, '超级管理员接口不存在。', 'NOT_FOUND');
}

async function getReadinessStatus() {
  if (
    readinessCache.value &&
    readinessCache.expiresAt > Date.now()
  ) {
    return readinessCache.value;
  }
  if (readinessCache.promise) return readinessCache.promise;

  const readinessPromise = pool.query(`
    SELECT
      NOW() AS now,
      EXISTS(
        SELECT 1 FROM super_admins WHERE enabled=TRUE LIMIT 1
      ) AS super_admin_ready
  `).then((result) => ({
    superAdminReady: Boolean(result.rows[0]?.super_admin_ready),
    databaseTime: new Date(result.rows[0].now).toISOString(),
  }));
  readinessCache.promise = readinessPromise;
  try {
    const value = await readinessPromise;
    readinessCache.value = value;
    readinessCache.expiresAt = Date.now() + READINESS_CACHE_MS;
    return value;
  } finally {
    if (readinessCache.promise === readinessPromise) {
      readinessCache.promise = null;
    }
  }
}

async function router(req, res, parsedRequestUrl = null) {
  setCommonHeaders(req, res);

  const url = parsedRequestUrl || parseRequestUrl(req.url);
  if (!url) {
    return sendError(res, 400, '请求地址格式无效。', 'INVALID_URL');
  }
  const rawPathname = url.pathname.replace(/\/+$/, '') || '/';

  if (req.method === 'GET' && rawPathname === '/health/live') {
    return sendJson(res, 200, {
      ok: true,
      service: 'tuojie-cloud-service',
      version: APP_VERSION,
      databaseCheck: false,
      at: nowIso(),
    });
  }

  if (req.method === 'GET' && rawPathname === '/health') {
    return sendJson(res, 200, {
      ok: true,
      service: 'tuojie-cloud-service',
      version: APP_VERSION,
      database: 'neon-postgresql',
      mediaStorage: R2_ENABLED ? 'cloudflare-r2' : 'postgres-fallback',
      defaultRetentionHours: RETENTION_HOURS,
      telegramBotEnabled: TELEGRAM_ENABLED,
      databaseCheck: false,
      readinessEndpoint: '/health/ready',
      at: nowIso(),
    });
  }

  if (req.method === 'GET' && rawPathname === '/health/ready') {
    const readiness = await getReadinessStatus();
    return sendJson(res, 200, {
      ok: true,
      service: 'tuojie-cloud-service',
      version: APP_VERSION,
      database: 'neon-postgresql',
      mediaStorage: R2_ENABLED ? 'cloudflare-r2' : 'postgres-fallback',
      telegramBotEnabled: TELEGRAM_ENABLED,
      superAdminReady: readiness.superAdminReady,
      databaseTime: readiness.databaseTime,
      cacheSeconds: READINESS_CACHE_MS / 1000,
    });
  }

  await refreshBlockedIpCache();
  const ipAddress = requestIp(req);
  if (ipIsBlocked(ipAddress)) {
    return sendError(res, 403, '此网络地址已被管理员禁止访问。', 'IP_BLOCKED');
  }
  const suspicious = suspiciousRequest(req, rawPathname);
  if (suspicious) {
    scheduleSecurityAnomaly({
      kind: suspicious.kind,
      req,
      severity: 'critical',
      count: 1,
      threshold: 1,
      details: { path: rawPathname, reason: suspicious.reason },
    });
    return sendError(res, 404, '资源不存在。', 'NOT_FOUND');
  }
  if (
    rawPathname.startsWith('/api/') &&
    rawPathname !== '/api/telegram/webhook' &&
    !rateLimit(req, res, 'api-request', 360, 60_000)
  ) return;

  await refreshApprovedOrigins();

  const origin = req.headers.origin;
  if (origin && !originAllowed(origin)) {
    const userPayload = authenticate(req, 'user');
    const requestOrigin = normalizeOrigin(origin);
    const tokenOrigin = normalizeOrigin(userPayload?.clientOrigin);
    if (
      userPayload &&
      requestOrigin &&
      tokenOrigin &&
      !timingSafeTextEqual(requestOrigin, tokenOrigin)
    ) {
      observeConfirmedUserOriginReuse(req, userPayload, rawPathname, {
        requestOrigin,
        tokenOrigin,
      });
    }
    return sendError(res, 403, '来源域名未被允许。', 'ORIGIN');
  }

  if (req.method === 'OPTIONS') {
    res.statusCode = 204;
    return res.end();
  }

  const normalizedPath = normalizeApiPath(rawPathname);
  const apiVersion = normalizedPath.apiVersion;
  const pathname = normalizedPath.pathname;
  if (
    REQUIRE_CLOUDFLARE &&
    rawPathname.startsWith('/api/') &&
    rawPathname !== '/api/telegram/webhook' &&
    (!req.headers['cf-ray'] || !requestNetworkContext(req).trustedCloudflare)
  ) {
    return sendError(res, 403, '请求必须通过 Cloudflare。', 'CLOUDFLARE_REQUIRED');
  }

  if (
    apiVersion === 1 &&
    pathname.startsWith('/api/') &&
    pathname !== '/api/telegram/webhook' &&
    !pathname.startsWith('/api/public/') &&
    !requireLegacyApi(res, apiVersion)
  ) return;

  if (
    req.method === 'GET' &&
    pathname === '/api/public/tenant-entry/resolve'
  ) {
    const gatewaySecret = String(
      req.headers['x-tenant-entry-gateway-secret'] || '',
    );
    if (
      !TENANT_ENTRY_ENABLED ||
      !gatewaySecret ||
      !timingSafeTextEqual(gatewaySecret, TENANT_ENTRY_GATEWAY_SECRET)
    ) {
      return sendError(res, 404, '资源不存在。', 'NOT_FOUND');
    }
    const resolved = await resolveTenantEntryUpstream(
      url.searchParams.get('host'),
    );
    if (!resolved) {
      return sendError(res, 404, '模板入口不可用。', 'ENTRY_NOT_FOUND');
    }
    return sendJson(res, 200, { ok: true, ...resolved });
  }

  if (
    req.method === 'GET' &&
    pathname.startsWith('/api/public/assets/')
  ) {
    const assetId = safeDecodeURIComponent(
      pathname.slice('/api/public/assets/'.length),
    );
    if (!isUuid(assetId)) {
      return sendError(res, 404, '资源不存在。', 'NOT_FOUND');
    }
    const result = await pool.query(
      `SELECT * FROM assets WHERE id=$1 AND kind <> 'reply_image'`,
      [assetId],
    );
    const row = result.rows[0];
    if (!row) return sendError(res, 404, '资源不存在。', 'NOT_FOUND');
    const data = await readStoredRow(row);
    if (!data) return sendError(res, 404, '资源不存在。', 'NOT_FOUND');
    res.statusCode = 200;
    res.setHeader('Content-Type', row.mime);
    res.setHeader('Content-Length', String(data.length));
    res.setHeader('Cache-Control', 'public, max-age=86400, immutable');
    return res.end(data);
  }

  if (pathname.startsWith('/api/super/')) {
    return handleSuperRoutes(req, res, url, pathname, apiVersion);
  }

  if (pathname.startsWith('/api/distributor/')) {
    return handleDistributorRoutes(req, res, url, pathname, apiVersion);
  }

  if (req.method === 'POST' && pathname === '/api/telegram/webhook') {
    if (!TELEGRAM_ENABLED) return sendError(res,404,'Telegram 机器人未启用。','NOT_FOUND');
    const secret=String(req.headers['x-telegram-bot-api-secret-token']||'');
    if (!timingSafeTextEqual(secret,TELEGRAM_WEBHOOK_SECRET)) return sendError(res,403,'Webhook 校验失败。','TELEGRAM_SECRET');
    const update=await readJson(req,512*1024);
    const updateId=Number(update.update_id);
    if (Number.isSafeInteger(updateId)) {
      const claimed=await pool.query(`INSERT INTO telegram_updates(update_id) VALUES($1) ON CONFLICT DO NOTHING RETURNING update_id`,[updateId]);
      if (!claimed.rows[0]) return sendJson(res,200,{ok:true});
    }
    try {
      await processTelegramUpdate(update);
    } catch(error) {
      console.error('Telegram 更新处理失败：',error);
      minuteCounters.telegramWebhookFailures += 1;
      if (Number.isSafeInteger(updateId)) {
        await pool.query(
          `DELETE FROM telegram_updates WHERE update_id=$1`,
          [updateId],
        ).catch(() => {});
      }
      return sendError(res,500,'Telegram 更新处理失败，请重新发送指令。','TELEGRAM_PROCESSING');
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
    if (
      !rateLimit(req, res, 'new-session', 20, 60_000) ||
      !rateLimit(req, res, 'new-session-global', 600, 60_000, 'global')
    ) return;
    const body = await readJson(req, 64 * 1024);
    const tenant = await getTenantByCode(body.tenantCode);
    if (!tenant) {
      return sendError(res, 404, '用户端入口无效。', 'TENANT_NOT_FOUND');
    }
    if (tenantAccessIssue(tenant)) {
      return sendTenantAccessError(res, tenant, 'user');
    }
    const [config, featureFlags] = await Promise.all([
      getConfig(tenant.id),
      getTenantFeatureStates(tenant.id),
    ]);
    const requestOrigin = normalizeOrigin(req.headers.origin);
    if (body.clientTemplateId && !isUuid(body.clientTemplateId)) {
      return sendError(res, 400, '用户端模板标识无效。', 'CLIENT_TEMPLATE');
    }
    if (REQUIRE_CLIENT_TEMPLATE_ID && !body.clientTemplateId) {
      return sendError(
        res,
        403,
        '当前用户端缺少受信任的模板标识。',
        'CLIENT_TEMPLATE',
      );
    }
    const approvedOrigins = tenantApprovedOriginSummary(config);
    if (STRICT_CLIENT_ORIGIN && !approvedOrigins) {
      return sendError(
        res,
        503,
        '租户尚未配置有效的用户端来源，请联系管理员。',
        'CLIENT_ORIGIN_CONFIG',
      );
    }
    if (STRICT_CLIENT_ORIGIN && !requestOrigin) {
      return sendError(
        res,
        403,
        '浏览器没有提供可验证的页面来源，请从商家客服入口重新打开。',
        'CLIENT_ORIGIN_MISSING',
      );
    }
    const originApproved = findTenantApprovedFrontend(config, requestOrigin);
    let template = findTenantApprovedFrontend(
      config,
      requestOrigin,
      body.clientTemplateId,
    );
    if (STRICT_CLIENT_ORIGIN && !originApproved) {
      observeBehaviorCounter(req, {
        kind: 'template-origin-mismatch',
        key: securityFingerprint([
          tenant.id,
          requestOrigin,
          approvedOrigins,
        ]),
        limit: ANOMALY_ORIGIN_MISMATCH_LIMIT,
        severity: 'warning',
        tenantId: tenant.id,
        details: {
          path: pathname,
          requestOrigin,
          approvedOrigin: approvedOrigins,
        },
      });
      return sendError(
        res,
        403,
        '此页面来源不是该租户当前批准的用户端。',
        'CLIENT_ORIGIN',
      );
    }
    if (!STRICT_CLIENT_ORIGIN && !template) {
      template = findTenantApprovedFrontendByTemplate(
        config,
        body.clientTemplateId,
      ) || (config.approvedFrontends || []).find((item) =>
        item.id === config.settings.frontendTemplateId) || null;
    }
    if (!template) {
      return sendError(
        res,
        403,
        '当前用户端未通过该租户批准，或模板已被平台停用。',
        'CLIENT_TEMPLATE',
      );
    }
    const resolvedClientTemplateId = template.id;
    let conversationId = null;
    let visitorKey = cleanText(body.visitorKey, 200);
    if (visitorKey && !body.forceNew) {
      const existing = await pool.query(
        `
          SELECT id
          FROM conversations
          WHERE tenant_id=$1 AND visitor_key_hash=$2
        `,
        [tenant.id, hashVisitorKey(visitorKey)],
      );
      conversationId = existing.rows[0]?.id || null;
    }
    let created = false;
    if (!conversationId) {
      const capacityResult = await pool.query(
        `SELECT 1 FROM conversations
         WHERE tenant_id=$1
         LIMIT 1 OFFSET $2`,
        [tenant.id, MAX_CONVERSATIONS - 1],
      );
      if (capacityResult.rows[0]) {
        return sendError(
          res,
          503,
          '当前会话过多，请稍后再试。',
          'CONVERSATION_LIMIT',
        );
      }
      conversationId = randomUUID();
      visitorKey = randomBytes(24).toString('base64url');
      created = true;
      const visitorName =
        cleanText(body.name, 40) || `访客 ${conversationId.slice(0, 6)}`;
      const location = cloudflareVisitorLocation(req);
      const downlink = Number(body.downlinkMbps);
      const rtt = Number(body.rttMs);
      const databaseClient = await pool.connect();
      try {
        await databaseClient.query('BEGIN');
        await databaseClient.query(`
          INSERT INTO conversations(
            id,tenant_id,visitor_key_hash,visitor_name,ip_address,ip_location,
            timezone,device_type,device_label,entry_source,user_agent,referrer_url,
            network_type,network_effective_type,downlink_mbps,rtt_ms,save_data,
            client_template_id,client_version,last_seen_at
          ) VALUES(
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,
            $13,$14,$15,$16,$17,$18,$19,NOW()
          )
        `, [
          conversationId,
          tenant.id,
          hashVisitorKey(visitorKey),
          visitorName,
          cleanText(requestIp(req), 100),
          location.location,
          location.timezone,
          cleanText(body.deviceType, 30),
          cleanText(body.deviceLabel, 100),
          cleanText(body.entrySource, 80),
          cleanText(body.userAgent, 500),
          cleanText(body.referrerUrl, 500),
          cleanText(body.networkType, 30),
          cleanText(body.networkEffectiveType, 30),
          Number.isFinite(downlink)
            ? Math.max(0, Math.min(10000, downlink))
            : null,
          Number.isFinite(rtt)
            ? Math.max(0, Math.min(120000, Math.trunc(rtt)))
            : null,
          typeof body.saveData === 'boolean' ? body.saveData : null,
          resolvedClientTemplateId,
          cleanText(body.clientVersion, 30),
        ]);
        if (config.settings?.welcomeText) {
          await databaseClient.query(
            `
              INSERT INTO messages(
                id,conversation_id,role,source,type,text,expires_at
              ) VALUES(
                $1,$2,'admin','auto','text',$3,
                NOW() + ($4::text || ' hours')::interval
              )
            `,
            [
              randomUUID(),
              conversationId,
              cleanText(config.settings.welcomeText, 2000),
              Number(config.settings.retentionHours || 24),
            ],
          );
          await databaseClient.query(
            `UPDATE conversations SET updated_at=NOW() WHERE id=$1`,
            [conversationId],
          );
        }
        await databaseClient.query('COMMIT');
      } catch (error) {
        await databaseClient.query('ROLLBACK');
        throw error;
      } finally {
        databaseClient.release();
      }
    } else {
      await touchConversation(conversationId, body, req, tenant.id);
    }
    const conversation = apiVersion >= 2
      ? await getConversationMessagePage(
          conversationId,
          tenant.id,
          { limit: pageLimit(url) },
        )
      : await getPublicConversation(
          conversationId,
          pool,
          tenant.id,
        );
    if (created) {
      broadcast(
        {
          type: 'conversation-created',
          conversation: {
            ...conversation,
            messages: undefined,
            latestMessage: conversation.messages.at(-1) || null,
          },
        },
        conversationId,
        tenant.id,
      );
      observeBehaviorCounter(req, {
        kind: 'visitor-session-ip',
        key: `${tenant.id}:${requestIp(req)}`,
        limit: ANOMALY_VISITOR_IP_LIMIT,
        tenantId: tenant.id,
        conversationId,
        details: { path: pathname },
      });
      observeBehaviorCounter(req, {
        kind: 'visitor-session-tenant',
        key: tenant.id,
        limit: ANOMALY_VISITOR_TENANT_LIMIT,
        tenantId: tenant.id,
        conversationId,
        details: { path: pathname },
      });
    }
    return sendJson(res, 201, {
      ok: true,
      tenant: {
        publicCode: tenant.public_code,
        accessExpiresAt: new Date(tenant.access_expires_at).toISOString(),
      },
      visitorKey,
      token: signTokenUntil(
        {
          kind: 'user',
          tenantId: tenant.id,
          conversationId,
          visitorKey,
          sessionVersion: Number(tenant.session_version || 1),
          clientOrigin: requestOrigin,
          clientTemplateId: resolvedClientTemplateId,
        },
        tenant.access_expires_at,
      ),
      conversation,
      settings: config.settings,
      featureFlags,
    });
  }

  if (req.method === 'GET' && pathname === '/api/events') {
    const rawPayload = authenticate(req);
    const hasSuperCredential = Boolean(
      parseCookies(req)[SESSION_COOKIE] ||
      rawPayload?.kind === 'super_admin',
    );
    const superAdmin = hasSuperCredential
      ? await authenticateSuper(req)
      : null;
    const distributorAccount = rawPayload?.kind === 'distributor'
      ? await authenticateDistributor(req)
      : null;
    const payload = superAdmin
      ? {
          ...rawPayload,
          kind: 'super_admin',
          adminId: superAdmin.id,
          sessionId: superAdmin.sessionId,
        }
      : distributorAccount
        ? {
            ...rawPayload,
            kind: 'distributor',
            distributorId: distributorAccount.id,
          }
        : rawPayload?.kind === 'super_admin' ||
            rawPayload?.kind === 'distributor'
          ? null
          : rawPayload;
    if (
      !payload ||
      !['user', 'tenant_admin', 'super_admin', 'distributor'].includes(
        payload.kind,
      )
    ) {
      return sendError(res, 401, '登录已失效。', 'AUTH');
    }
    if (
      payload.kind === 'user' &&
      await rejectInvalidUserTokenOrigin(req, res, payload, pathname)
    ) return;

    let tenant = null;
    if (!['super_admin', 'distributor'].includes(payload.kind)) {
      tenant =
        payload.kind === 'tenant_admin'
          ? await getTenantForAdminToken(payload)
          : await getTenantById(payload.tenantId);
      if (!tenant && payload.kind === 'tenant_admin') {
        const tenantState = await getTenantById(payload.tenantId);
        if (tenantAccessIssue(tenantState) === 'LICENSE_REVOKED') {
          return sendTenantAccessError(res, tenantState, 'admin');
        }
        return sendError(
          res,
          401,
          '此后台登录已被新的登录或续费卡密替换，请重新登录。',
          'LICENSE_REPLACED',
        );
      }
      if (tenantAccessIssue(tenant)) {
        return sendTenantAccessError(
          res,
          tenant,
          payload.kind === 'tenant_admin' ? 'admin' : 'user',
        );
      }
      if (
        payload.kind === 'user' &&
        Number(payload.sessionVersion || 0) !==
          Number(tenant.session_version || 1)
      ) {
        return sendError(
          res,
          401,
          '访客会话已被管理员重置。',
          'FORCE_LOGOUT',
        );
      }
    }
    if (payload.kind === 'user') {
      if (
        !isUuid(payload.conversationId) ||
        !cleanText(payload.visitorKey, 200)
      ) {
        return sendError(res, 401, '会话已失效。', 'AUTH');
      }
      if (apiVersion < 2) {
        const conversation = await getConversationRow(
          payload.conversationId,
          pool,
          false,
          payload.tenantId,
        );
        if (!conversation || !authorizeConversation(payload, conversation)) {
          return sendError(res, 401, '会话已失效。', 'AUTH');
        }
        await touchConversation(conversation.id, {}, req, payload.tenantId);
      }
    }
    const connectionIdentity =
      payload.kind === 'super_admin'
        ? payload.adminId
        : payload.kind === 'distributor'
          ? payload.distributorId
        : payload.kind === 'tenant_admin'
          ? `${payload.tenantId}:${payload.licenseId}`
          : `${payload.tenantId}:${payload.conversationId}`;
    if (
      !rateLimit(
        req,
        res,
        'sse-connect',
        60,
        60_000,
        connectionIdentity,
      )
    ) return;
    const sameConnections = [...sseClients].filter(
      (client) =>
        client.kind === payload.kind &&
        (payload.kind === 'super_admin'
          ? client.adminId === payload.adminId
          : payload.kind === 'distributor'
            ? client.distributorId === payload.distributorId
          : client.tenantId === payload.tenantId) &&
        (payload.kind === 'tenant_admin'
          ? client.licenseId === payload.licenseId
          : payload.kind === 'user'
            ? client.conversationId === payload.conversationId
            : true),
    ).length;
    const perSessionLimit =
      payload.kind === 'super_admin'
        ? 3
        : payload.kind === 'distributor'
          ? 3
        : payload.kind === 'tenant_admin'
          ? 6
          : 4;
    if (
      sseClients.size >= MAX_SSE_CONNECTIONS ||
      sameConnections >= perSessionLimit
    ) {
      return sendError(res, 503, '实时连接数量已达上限，请稍后重试。', 'SSE_LIMIT');
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
      apiVersion,
      tenantId: payload.tenantId,
      conversationId: payload.conversationId || null,
      licenseId: payload.licenseId || null,
      accessKind:
        payload.kind === 'tenant_admin'
          ? tenantAdminAccessKind(payload)
          : 'normal',
      deviceHash: cleanText(payload.deviceHash, 100),
      adminId: payload.adminId || null,
      distributorId: payload.distributorId || null,
      sessionId: payload.sessionId || null,
      ownerDistributorId: tenant?.owner_distributor_id || null,
      accessExpiresAt:
        ['super_admin', 'distributor'].includes(payload.kind)
          ? Number(payload.exp || 0) * 1000 ||
            Date.now() + 8 * 60 * 60_000
          : new Date(tenant.access_expires_at).getTime(),
    };
    sseClients.add(client);
    if (['tenant_admin', 'user'].includes(payload.kind)) {
      scheduleSuperPresenceUpdate();
      scheduleDistributorPresenceUpdate(tenant?.owner_distributor_id);
    }
    replayEvents(
      client,
      req.headers['last-event-id'] || url.searchParams.get('lastEventId'),
    );
    sendSse(
      res,
      {
        type: 'connected',
        at: nowIso(),
        eventId: nextEventId,
        apiVersion,
      },
      nextEventId++,
    );
    if (payload.kind === 'tenant_admin') {
      await pool.query(
        `
          UPDATE tenants
          SET last_admin_online_at=NOW()
          WHERE id=$1
            AND (
              last_admin_online_at IS NULL
              OR last_admin_online_at < NOW() - INTERVAL '1 minute'
            )
        `,
        [payload.tenantId],
      );
    }
    if (payload.kind === 'user') {
      publishEvent(
        {
          type: 'visitor-presence',
          conversationId: payload.conversationId,
          online: true,
          at: nowIso(),
        },
        {
          tenantId: payload.tenantId,
          conversationId: payload.conversationId,
          targetKind: 'tenant_admin',
        },
      );
    }
    req.on('close', () => {
      const removed = sseClients.delete(client);
      if (
        removed &&
        ['tenant_admin', 'user'].includes(payload.kind)
      ) {
        scheduleSuperPresenceUpdate();
        scheduleDistributorPresenceUpdate(tenant?.owner_distributor_id);
      }
      if (payload.kind !== 'user') return;
      setTimeout(() => {
        if (
          conversationHasLiveVisitor(
            payload.conversationId,
            payload.tenantId,
          )
        ) return;
        publishEvent(
          {
            type: 'visitor-presence',
            conversationId: payload.conversationId,
            online: false,
            at: nowIso(),
          },
          {
            tenantId: payload.tenantId,
            conversationId: payload.conversationId,
            targetKind: 'tenant_admin',
          },
        );
      }, 400).unref();
    });
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
    if (await rejectInvalidUserTokenOrigin(req, res, payload, pathname)) return;

    const tenant = await getTenantById(payload.tenantId);
    if (tenantAccessIssue(tenant)) return sendTenantAccessError(res,tenant,'user');
    if (
      Number(payload.sessionVersion || 0) !==
      Number(tenant.session_version || 1)
    ) {
      return sendError(
        res,
        401,
        '访客会话已被管理员重置。',
        'FORCE_LOGOUT',
      );
    }
    const requiresStoredConversation =
      apiVersion < 2 ||
      (req.method === 'POST' && pathname === '/api/user/uploads');
    const conversation = requiresStoredConversation
      ? await getConversationRow(
          payload.conversationId,
          pool,
          false,
          payload.tenantId,
        )
      : {
          id: payload.conversationId,
          tenant_id: payload.tenantId,
          visitor_key_hash: hashVisitorKey(payload.visitorKey),
        };
    if (!conversation || !authorizeConversation(payload, conversation)) return sendError(res,401,'访客会话不存在。','AUTH');
    if (apiVersion < 2) {
      await touchConversation(conversation.id,{},req,payload.tenantId);
    }

    if (req.method === 'GET' && pathname === '/api/user/conversation') {
      const [publicConversation, config, featureFlags] = await Promise.all([
        apiVersion >= 2
          ? getConversationMessagePage(
              conversation.id,
              payload.tenantId,
              {
                cursor: url.searchParams.get('before'),
                limit: pageLimit(url),
              },
            )
          : getPublicConversation(conversation.id, pool, payload.tenantId),
        getConfig(payload.tenantId),
        getTenantFeatureStates(payload.tenantId),
      ]);
      if (!publicConversation) {
        return sendError(
          res,
          401,
          '访客会话不存在。',
          'CONVERSATION_DELETED',
        );
      }
      return sendJson(res, 200, {
        ok: true,
        conversation: publicConversation,
        settings: config.settings,
        featureFlags,
      });
    }

    if (req.method === 'GET' && pathname === '/api/user/realtime-config') {
      return sendJson(res, 200, {
        ok: true,
        ...(await realtimeConfig(`user:${payload.tenantId}:${conversation.id}`)),
      });
    }

    if (req.method === 'POST' && pathname === '/api/user/push/subscribe') {
      if (!rateLimit(
        req,
        res,
        'push-subscribe',
        12,
        10 * 60_000,
        `${payload.tenantId}:${conversation.id}`,
        {
          tenantId: payload.tenantId,
          conversationId: conversation.id,
        },
      )) return;
      const body = await readJson(req, 32 * 1024);
      await savePushSubscription(payload, body, req);
      return sendJson(res, 201, { ok: true });
    }

    if (req.method === 'DELETE' && pathname === '/api/user/push/subscribe') {
      const body = await readJson(req, 16 * 1024);
      await removePushSubscription(payload, body);
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'GET' && pathname === '/api/user/pending-call') {
      const call = await getPendingCall(
        url.searchParams.get('callId'),
        payload.tenantId,
        conversation.id,
      );
      return sendJson(res, 200, { ok: true, call });
    }

    if (req.method === 'POST' && pathname === '/api/user/call-signal') {
      if (!rateLimit(
        req,
        res,
        'user-call-signal',
        240,
        60_000,
        `${payload.tenantId}:${conversation.id}`,
        {
          tenantId: payload.tenantId,
          conversationId: conversation.id,
        },
      )) return;
      const signal = parseCallSignal(await readJson(req, 256 * 1024));
      if (signal.action === 'offer') {
        const saved = await savePendingCallOffer(
          payload.tenantId,
          conversation.id,
          signal,
          'user',
        );
        publishCallLogUpdate(saved.call);
        if (saved.busy) {
          publishEvent(
            {
              type: 'call-signal',
              conversationId: conversation.id,
              from: 'system',
              action: 'busy',
              callId: signal.callId,
              mode: signal.mode,
              at: nowIso(),
            },
            {
              tenantId: payload.tenantId,
              conversationId: conversation.id,
              targetKind: 'user',
            },
          );
          return sendJson(res, 200, {
            ok: true,
            busy: true,
            call: publicCallSession(saved.call),
          });
        }
        publishEvent(
          {
            type: 'call-signal',
            conversationId: conversation.id,
            from: 'user',
            ...signal,
            at: nowIso(),
          },
          {
            tenantId: payload.tenantId,
            conversationId: conversation.id,
            targetKind: 'tenant_admin',
          },
        );
        return sendJson(res, 200, {
          ok: true,
          busy: false,
          call: publicCallSession(saved.call),
        });
      }
      if (signal.action === 'claim') {
        const claimed = await claimPendingCall(
          signal.callId,
          payload.tenantId,
          conversation.id,
          'user',
          signal.deviceId,
        );
        if (!claimed.accepted) {
          return sendError(
            res,
            409,
            '这次来电已由其他设备处理。',
            'CALL_ALREADY_HANDLED',
          );
        }
        publishCallControl(claimed.call, {
          action: 'claimed',
          handledByDeviceId: signal.deviceId,
          handledByKind: 'user',
        });
        return sendJson(res, 200, { ok: true, accepted: true });
      }
      if (signal.action === 'answer') {
        const answered = await answerPendingCall(
          signal.callId,
          payload.tenantId,
          conversation.id,
          'user',
          signal.deviceId,
        );
        if (!answered.accepted) {
          return sendError(
            res,
            409,
            '这次来电已由其他设备处理。',
            'CALL_ALREADY_HANDLED',
          );
        }
        publishCallLogUpdate(answered.call);
      } else if (signal.action === 'connected') {
        const connectedCall = await markPendingCallConnected(
          signal.callId,
          payload.tenantId,
          conversation.id,
          'user',
          signal.deviceId,
        );
        if (connectedCall) publishCallLogUpdate(connectedCall);
        return sendJson(res, 200, { ok: true });
      } else if (['hangup','reject','busy','timeout','failed'].includes(signal.action)) {
        const finished = await finishPendingCall(
          signal.callId,
          payload.tenantId,
          conversation.id,
          signal.action,
          'user',
          signal.deviceId,
          signal.reason,
        );
        if (!finished.accepted) {
          return sendJson(res, 200, {
            ok: true,
            alreadyHandled: true,
            call: publicCallSession(finished.call),
          });
        }
        publishCallLogUpdate(finished.call);
        publishCallControl(finished.call, {
          action: 'resolved',
          handledByDeviceId: signal.deviceId,
          handledByKind: 'user',
        });
      }
      publishEvent(
        {
          type: 'call-signal',
          conversationId: conversation.id,
          from: 'user',
          ...signal,
          at: nowIso(),
        },
        {
          tenantId: payload.tenantId,
          conversationId: conversation.id,
          targetKind: 'tenant_admin',
        },
      );
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && pathname === '/api/user/read') {
      const receipt = await markConversationRead(
        conversation.id,
        payload.tenantId,
        'user',
      );
      return sendJson(res, 200, { ok: true, ...receipt });
    }

    if (req.method === 'PATCH' && pathname === '/api/user/presence') {
      const body = await readJson(req, 32 * 1024);
      const updated = await touchConversation(
        conversation.id,
        body,
        req,
        payload.tenantId,
      );
      if (updated) {
        publishEvent(
          {
            type: 'summary-updated',
            conversation: conversationBase(updated),
          },
          {
            tenantId: payload.tenantId,
            conversationId: conversation.id,
            targetKind: 'tenant_admin',
          },
        );
      }
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && pathname === '/api/user/uploads') {
      return handleUpload(req, res, payload, conversation);
    }

    if (req.method === 'POST' && pathname === '/api/user/messages') {
      if (
        !rateLimit(
          req,
          res,
          'user-message',
          40,
          60_000,
          `${payload.tenantId}:${conversation.id}`,
          {
            tenantId: payload.tenantId,
            conversationId: conversation.id,
          },
        )
      ) return;
      const body = await readJson(req);
      const result = await createUserMessage(
        conversation.id,
        body,
        payload.tenantId,
        { includeConversation: apiVersion < 2 },
      );
      const messageIncrement = Math.max(1, result.messages?.length || 1);
      observeBehaviorCounter(req, {
        kind: 'message-conversation',
        key: `${payload.tenantId}:${conversation.id}`,
        limit: ANOMALY_MESSAGE_CONVERSATION_LIMIT,
        tenantId: payload.tenantId,
        conversationId: conversation.id,
        increment: messageIncrement,
        details: { path: pathname },
      });
      observeBehaviorCounter(req, {
        kind: 'message-tenant',
        key: payload.tenantId,
        limit: ANOMALY_MESSAGE_TENANT_LIMIT,
        tenantId: payload.tenantId,
        conversationId: conversation.id,
        increment: messageIncrement,
        details: { path: pathname },
      });
      await broadcastMessageResult(
        result,
        'user-message',
        conversation.id,
        payload.tenantId,
        apiVersion,
      );
      return sendJson(res, 201, {
        ok: true,
        message: result.message,
        messages: result.messages,
        autoReply: result.autoReply,
        autoReplies: result.autoReplies || (result.autoReply ? [result.autoReply] : []),
        conversation: result.conversation,
      });
    }
  }

  if (pathname.startsWith('/api/admin/')) {
    const payload = authenticate(req, 'tenant_admin');
    if (!payload) {
      return sendError(res, 401, '后台登录已失效。', 'AUTH');
    }
    const activeTenant = await getTenantForAdminToken(payload);
    if (!activeTenant) {
      const tenantState = await getTenantById(payload.tenantId);
      if (tenantAccessIssue(tenantState) === 'LICENSE_REVOKED') {
        return sendTenantAccessError(res, tenantState, 'admin');
      }
      return sendError(
        res,
        401,
        '此后台登录已被新的续费卡密替换，请重新登录。',
        'LICENSE_REPLACED',
      );
    }
    if (tenantAccessIssue(activeTenant)) {
      return sendTenantAccessError(res,activeTenant,'admin');
    }

    if (req.method === 'POST' && pathname === '/api/admin/logout') {
      await revokeAuthSession(
        payload.sessionId,
        'tenant_admin',
        payload.tenantId,
      );
      disconnectAuthSession(payload.sessionId);
      await writeAudit(req, null, 'tenant.logout', {
        targetType: 'tenant',
        targetId: payload.tenantId,
        actorTenantId: payload.tenantId,
        actorLicenseId: payload.licenseId,
      }).catch(() => {});
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'GET' && pathname === '/api/admin/bootstrap') {
      const tenant = activeTenant;
      const [conversationResult, config, templates, notices, visitorGroups] = await Promise.all([
        apiVersion >= 2
          ? getAllSummariesPage(payload.tenantId, {
              limit: pageLimit(url),
            })
          : getAllSummaries(payload.tenantId),
        getConfig(payload.tenantId),
        getTemplateCatalog({ tenantId: payload.tenantId }),
        getTenantNotices(payload.tenantId),
        getVisitorGroups(payload.tenantId),
      ]);
      return sendJson(res, 200, {
        ok: true,
        tenant: publicTenant(tenant),
        conversations:
          apiVersion >= 2 ? conversationResult.items : conversationResult,
        conversationPage:
          apiVersion >= 2
            ? {
                nextCursor: conversationResult.nextCursor,
                hasMore: conversationResult.hasMore,
                totals: conversationResult.totals,
              }
            : undefined,
        cannedReplies: config.cannedReplies,
        autoReplies: config.autoReplies,
        settings: config.settings,
        templates,
        visitorGroups,
        entryUrl: tenantEntryUrl(config.settings, tenant.public_code),
        qrEntryUrl: tenantEntryUrl(config.settings, tenant.public_code),
        ...notices,
      });
    }

    if (req.method === 'GET' && pathname === '/api/admin/conversations') {
      const page = apiVersion >= 2
        ? await getAllSummariesPage(payload.tenantId, {
            cursor: url.searchParams.get('cursor'),
            limit: pageLimit(url),
            search: url.searchParams.get('search') || '',
            groupId: url.searchParams.get('groupId') || '',
          })
        : null;
      const conversations = apiVersion >= 2
        ? page.items
        : await getAllSummaries(payload.tenantId);
      return sendJson(res, 200, {
        ok: true,
        tenant: publicTenant(activeTenant),
        conversations,
        page:
          apiVersion >= 2
            ? {
                nextCursor: page.nextCursor,
                hasMore: page.hasMore,
                totals: page.totals,
              }
            : undefined,
      });
    }

    if (req.method === 'GET' && pathname === '/api/admin/visitor-groups') {
      return sendJson(res, 200, {
        ok: true,
        visitorGroups: await getVisitorGroups(payload.tenantId),
      });
    }

    if (req.method === 'POST' && pathname === '/api/admin/visitor-groups') {
      if (
        !rateLimit(
          req,
          res,
          'visitor-group-write',
          60,
          60_000,
          payload.tenantId,
        )
      ) return;
      const body = await readJson(req, 32 * 1024);
      const name = cleanVisitorGroupName(body.name);
      if (!name) {
        return sendError(
          res,
          400,
          '请输入分组名称。',
          'VISITOR_GROUP_NAME',
        );
      }
      const databaseClient = await pool.connect();
      let groupId = '';
      try {
        await databaseClient.query('BEGIN');
        await databaseClient.query(
          `SELECT id FROM tenants WHERE id=$1 FOR UPDATE`,
          [payload.tenantId],
        );
        const countResult = await databaseClient.query(
          `SELECT COUNT(*)::int AS count FROM visitor_groups WHERE tenant_id=$1`,
          [payload.tenantId],
        );
        if (Number(countResult.rows[0]?.count || 0) >= MAX_VISITOR_GROUPS_PER_TENANT) {
          throw requestError(
            `每个租户最多创建 ${MAX_VISITOR_GROUPS_PER_TENANT} 个访客分组。`,
            409,
            'VISITOR_GROUP_LIMIT',
          );
        }
        groupId = randomUUID();
        await databaseClient.query(
          `
            INSERT INTO visitor_groups (id,tenant_id,name)
            VALUES ($1,$2,$3)
          `,
          [groupId, payload.tenantId, name],
        );
        await databaseClient.query('COMMIT');
      } catch (error) {
        await databaseClient.query('ROLLBACK').catch(() => {});
        if (error.code === '23505') {
          return sendError(
            res,
            409,
            '已经存在同名访客分组。',
            'VISITOR_GROUP_DUPLICATE',
          );
        }
        throw error;
      } finally {
        databaseClient.release();
      }
      await writeTenantAudit(req, payload, 'tenant.visitor_group.create', {
        targetType: 'visitor_group',
        targetId: groupId,
        metadata: { name },
      }).catch(() => {});
      const visitorGroups = await getVisitorGroups(payload.tenantId);
      broadcast(
        { type: 'visitor-groups-updated', visitorGroups },
        null,
        payload.tenantId,
      );
      return sendJson(res, 201, { ok: true, visitorGroups });
    }

    const visitorGroupMatch = pathname.match(
      /^\/api\/admin\/visitor-groups\/([0-9a-f-]+)$/i,
    );
    if (visitorGroupMatch && isUuid(visitorGroupMatch[1])) {
      const visitorGroupId = visitorGroupMatch[1];
      if (
        ['PATCH', 'DELETE'].includes(req.method) &&
        !rateLimit(
          req,
          res,
          'visitor-group-write',
          60,
          60_000,
          payload.tenantId,
        )
      ) return;
      if (req.method === 'PATCH') {
        const body = await readJson(req, 32 * 1024);
        const name = cleanVisitorGroupName(body.name);
        if (!name) {
          return sendError(
            res,
            400,
            '请输入分组名称。',
            'VISITOR_GROUP_NAME',
          );
        }
        let updated;
        try {
          updated = await pool.query(
            `
              UPDATE visitor_groups
              SET name=$3,updated_at=NOW()
              WHERE id=$1 AND tenant_id=$2
              RETURNING id
            `,
            [visitorGroupId, payload.tenantId, name],
          );
        } catch (error) {
          if (error.code === '23505') {
            return sendError(
              res,
              409,
              '已经存在同名访客分组。',
              'VISITOR_GROUP_DUPLICATE',
            );
          }
          throw error;
        }
        if (!updated.rows[0]) {
          return sendError(res, 404, '访客分组不存在。', 'NOT_FOUND');
        }
        await writeTenantAudit(req, payload, 'tenant.visitor_group.update', {
          targetType: 'visitor_group',
          targetId: visitorGroupId,
          metadata: { name },
        }).catch(() => {});
        const visitorGroups = await getVisitorGroups(payload.tenantId);
        broadcast(
          { type: 'visitor-groups-updated', visitorGroups },
          null,
          payload.tenantId,
        );
        return sendJson(res, 200, { ok: true, visitorGroups });
      }
      if (req.method === 'DELETE') {
        const deleted = await pool.query(
          `
            DELETE FROM visitor_groups
            WHERE id=$1 AND tenant_id=$2
            RETURNING name
          `,
          [visitorGroupId, payload.tenantId],
        );
        if (!deleted.rows[0]) {
          return sendError(res, 404, '访客分组不存在。', 'NOT_FOUND');
        }
        await writeTenantAudit(req, payload, 'tenant.visitor_group.delete', {
          targetType: 'visitor_group',
          targetId: visitorGroupId,
          metadata: { name: deleted.rows[0].name },
        }).catch(() => {});
        const visitorGroups = await getVisitorGroups(payload.tenantId);
        broadcast(
          {
            type: 'visitor-groups-updated',
            visitorGroups,
            deletedGroupId: visitorGroupId,
          },
          null,
          payload.tenantId,
        );
        return sendJson(res, 200, { ok: true, visitorGroups });
      }
    }

    if (req.method === 'GET' && pathname === '/api/admin/config') {
      const [config, templates, notices] = await Promise.all([
        getConfig(payload.tenantId),
        getTemplateCatalog({ tenantId: payload.tenantId }),
        getTenantNotices(payload.tenantId),
      ]);
      return sendJson(res, 200, {
        ok: true,
        cannedReplies: config.cannedReplies,
        autoReplies: config.autoReplies,
        settings: config.settings,
        templates,
        entryUrl: tenantEntryUrl(
          config.settings,
          activeTenant.public_code,
        ),
        qrEntryUrl: tenantEntryUrl(config.settings, activeTenant.public_code),
        ...notices,
      });
    }

    if (req.method === 'GET' && pathname === '/api/admin/realtime-config') {
      return sendJson(res, 200, {
        ok: true,
        ...(await realtimeConfig(`admin:${payload.tenantId}:${payload.adminId}`)),
      });
    }

    if (req.method === 'GET' && pathname === '/api/admin/pending-call') {
      return sendJson(res, 200, {
        ok: true,
        call: await getPendingAdminCall(payload.tenantId),
      });
    }

    if (req.method === 'PUT' && pathname === '/api/admin/settings') {
      const body = await readJson(req, 512 * 1024);
      const tenant = activeTenant;
      const current = await getConfig(payload.tenantId);
      const validated = await validateAdminSettings(
        body,
        current,
        payload.tenantId,
      );
      const databaseClient = await pool.connect();
      try {
        await databaseClient.query('BEGIN');
        await databaseClient.query(
          `
            UPDATE tenant_config
            SET canned_replies = $1::jsonb,
                auto_replies = $2::jsonb,
                settings = $3::jsonb,
                frontend_template_id = $4,
                retention_hours = $5,
                updated_at = NOW()
            WHERE tenant_id = $6
          `,
          [
            JSON.stringify(validated.cannedReplies),
            JSON.stringify(validated.autoReplies),
            JSON.stringify(validated.settings),
            validated.frontendTemplateId,
            validated.retentionHours,
            payload.tenantId,
          ],
        );
        await rememberTenantFrontendTemplate(
          databaseClient,
          payload.tenantId,
          validated.frontendTemplateId,
        );
        if (validated.applyRetentionToExisting) {
          await databaseClient.query(
            `
              UPDATE messages m
              SET expires_at = m.created_at + ($2::text || ' hours')::interval
              FROM conversations c
              WHERE m.conversation_id = c.id
                AND c.tenant_id = $1
            `,
            [payload.tenantId, validated.retentionHours],
          );
          await databaseClient.query(
            `
              UPDATE attachments a
              SET expires_at = m.expires_at
              FROM messages m
              JOIN conversations c ON c.id = m.conversation_id
              WHERE m.attachment_id = a.id
                AND c.tenant_id = $1
            `,
            [payload.tenantId],
          );
        }
        await databaseClient.query('COMMIT');
      } catch (error) {
        await databaseClient.query('ROLLBACK');
        throw error;
      } finally {
        databaseClient.release();
      }
      await writeTenantAudit(req, payload, 'tenant.config.update', {
        targetType: 'tenant',
        targetId: payload.tenantId,
        metadata: {
          retentionHours: validated.retentionHours,
          frontendTemplateId: validated.frontendTemplateId,
          applyRetentionToExisting: validated.applyRetentionToExisting,
        },
      }).catch((error) =>
        console.error('租户设置审计写入失败：', error.message),
      );
      invalidateTenantCaches(payload.tenantId);
      const updated = await getConfig(payload.tenantId);
      broadcast(
        { type: 'settings-updated', settings: updated.settings },
        null,
        payload.tenantId,
      );
      return sendJson(res, 200, {
        ok: true,
        cannedReplies: updated.cannedReplies,
        autoReplies: updated.autoReplies,
        settings: updated.settings,
        entryUrl: tenantEntryUrl(updated.settings, tenant.public_code),
        qrEntryUrl: tenantEntryUrl(updated.settings, tenant.public_code),
      });
    }

    if (
      req.method === 'POST' &&
      pathname === '/api/admin/brand/avatar'
    ) {
      await requireTenantFeature('tenant_branding', payload.tenantId);
      if (
        !rateLimit(
          req,
          res,
          'tenant-avatar-upload',
          12,
          10 * 60_000,
          payload.tenantId,
          { tenantId: payload.tenantId, licenseId: payload.licenseId },
        )
      ) return;
      const data = await prepareImageUpload(req, {
        maxBytes: MAX_AVATAR_BYTES,
        width: 512,
        height: 512,
      });
      const current = await getConfig(payload.tenantId);
      const oldAssetId = cleanText(current.settings.avatarAssetId, 80);
      const asset = await saveAsset({
        tenantId: payload.tenantId,
        kind: 'brand_avatar',
        filename: 'brand-avatar.webp',
        mime: 'image/webp',
        data,
      });
      await pool.query(
        `
          UPDATE tenant_config
          SET settings=jsonb_set(
                COALESCE(settings,'{}'::jsonb),
                '{avatarAssetId}',
                to_jsonb($2::text),
                true
              ),
              updated_at=NOW()
          WHERE tenant_id=$1
        `,
        [payload.tenantId, asset.id],
      );
      if (isUuid(oldAssetId)) {
        await deleteAsset(oldAssetId, payload.tenantId);
      }
      invalidateTenantCaches(payload.tenantId);
      await writeTenantAudit(req, payload, 'tenant.avatar.update', {
        targetType: 'tenant',
        targetId: payload.tenantId,
      }).catch((error) =>
        console.error('租户头像审计写入失败：', error.message),
      );
      const settings = (await getConfig(payload.tenantId)).settings;
      broadcast(
        { type: 'settings-updated', settings },
        null,
        payload.tenantId,
      );
      return sendJson(res, 201, {
        ok: true,
        avatarAssetId: asset.id,
        avatarUrl: `${PUBLIC_API_BASE}/api/public/assets/${asset.id}`,
        settings,
      });
    }

    if (
      req.method === 'DELETE' &&
      pathname === '/api/admin/brand/avatar'
    ) {
      await requireTenantFeature('tenant_branding', payload.tenantId);
      const current = await getConfig(payload.tenantId);
      const oldAssetId = cleanText(current.settings.avatarAssetId, 80);
      await pool.query(
        `
          UPDATE tenant_config
          SET settings=settings - 'avatarAssetId',updated_at=NOW()
          WHERE tenant_id=$1
        `,
        [payload.tenantId],
      );
      if (isUuid(oldAssetId)) {
        await deleteAsset(oldAssetId, payload.tenantId);
      }
      invalidateTenantCaches(payload.tenantId);
      await writeTenantAudit(req, payload, 'tenant.avatar.delete', {
        targetType: 'tenant',
        targetId: payload.tenantId,
      }).catch((error) =>
        console.error('租户头像审计写入失败：', error.message),
      );
      broadcast(
        { type: 'settings-updated' },
        null,
        payload.tenantId,
      );
      return sendJson(res, 200, { ok: true });
    }

    if (req.method === 'POST' && pathname === '/api/admin/qr/logo') {
      if (
        !rateLimit(
          req,
          res,
          'tenant-qr-logo-upload',
          12,
          10 * 60_000,
          payload.tenantId,
          { tenantId: payload.tenantId, licenseId: payload.licenseId },
        )
      ) return;
      const data = await prepareQrLogoUpload(req);
      const current = await getConfig(payload.tenantId);
      const oldAssetId = cleanText(current.settings.qrLogoAssetId, 80);
      const asset = await saveAsset({
        tenantId: payload.tenantId,
        kind: 'qr_logo',
        filename: 'qr-logo.webp',
        mime: 'image/webp',
        data,
      });
      await pool.query(
        `
          UPDATE tenant_config
          SET settings=jsonb_set(
                COALESCE(settings,'{}'::jsonb),
                '{qrLogoAssetId}',
                to_jsonb($2::text),
                true
              ),
              updated_at=NOW()
          WHERE tenant_id=$1
        `,
        [payload.tenantId, asset.id],
      );
      if (isUuid(oldAssetId)) {
        await deleteAsset(oldAssetId, payload.tenantId);
      }
      invalidateTenantCaches(payload.tenantId);
      const settings = (await getConfig(payload.tenantId)).settings;
      broadcast(
        { type: 'settings-updated', settings },
        null,
        payload.tenantId,
      );
      await writeTenantAudit(req, payload, 'tenant.qr_logo.update', {
        targetType: 'tenant',
        targetId: payload.tenantId,
      }).catch(() => {});
      return sendJson(res, 201, {
        ok: true,
        qrLogoAssetId: asset.id,
        qrLogoUrl: `${PUBLIC_API_BASE}/api/public/assets/${asset.id}`,
        settings,
      });
    }

    if (req.method === 'DELETE' && pathname === '/api/admin/qr/logo') {
      const current = await getConfig(payload.tenantId);
      const oldAssetId = cleanText(current.settings.qrLogoAssetId, 80);
      await pool.query(
        `
          UPDATE tenant_config
          SET settings=settings - 'qrLogoAssetId',updated_at=NOW()
          WHERE tenant_id=$1
        `,
        [payload.tenantId],
      );
      if (isUuid(oldAssetId)) {
        await deleteAsset(oldAssetId, payload.tenantId);
      }
      invalidateTenantCaches(payload.tenantId);
      const settings = (await getConfig(payload.tenantId)).settings;
      broadcast(
        { type: 'settings-updated', settings },
        null,
        payload.tenantId,
      );
      await writeTenantAudit(req, payload, 'tenant.qr_logo.delete', {
        targetType: 'tenant',
        targetId: payload.tenantId,
      }).catch(() => {});
      return sendJson(res, 200, { ok: true, settings });
    }

    if (
      req.method === 'GET' &&
      pathname.startsWith('/api/admin/reply-images/')
    ) {
      await requireAnyTenantFeature(
        ['auto_reply', 'media_album'],
        payload.tenantId,
      );
      const assetId = safeDecodeURIComponent(
        pathname.slice('/api/admin/reply-images/'.length),
      );
      if (!isUuid(assetId)) {
        return sendError(res, 404, '回复图片不存在。', 'NOT_FOUND');
      }
      const result = await pool.query(
        `
          SELECT *
          FROM assets
          WHERE id=$1 AND tenant_id=$2 AND kind='reply_image'
        `,
        [assetId, payload.tenantId],
      );
      const row = result.rows[0];
      if (!row) return sendError(res, 404, '回复图片不存在。', 'NOT_FOUND');
      const data = await readStoredRow(row);
      if (!Buffer.isBuffer(data)) {
        return sendError(res, 404, '回复图片不存在。', 'NOT_FOUND');
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', row.mime);
      res.setHeader('Content-Length', String(data.length));
      res.setHeader('Cache-Control', 'private, max-age=300');
      res.setHeader('Content-Disposition', 'inline; filename="reply-image.webp"');
      return res.end(data);
    }

    if (req.method === 'POST' && pathname === '/api/admin/reply-images') {
      await requireAnyTenantFeature(
        ['auto_reply', 'media_album'],
        payload.tenantId,
      );
      if (
        !rateLimit(
          req,
          res,
          'tenant-reply-image-upload',
          30,
          10 * 60_000,
          payload.tenantId,
          { tenantId: payload.tenantId, licenseId: payload.licenseId },
        )
      ) return;
      const data = await prepareImageUpload(req, {
        maxBytes: MAX_IMAGE_BYTES,
        width: 1600,
        height: 1600,
        fit: 'inside',
      });
      const asset = await saveAsset({
        tenantId: payload.tenantId,
        kind: 'reply_image',
        filename: 'reply-image.webp',
        mime: 'image/webp',
        data,
      });
      await writeTenantAudit(req, payload, 'tenant.reply-image.upload', {
        targetType: 'asset',
        targetId: asset.id,
      }).catch(() => {});
      return sendJson(res, 201, { ok: true, assetId: asset.id });
    }

    if (req.method === 'POST' && pathname === '/api/admin/qr-incident') {
      if (
        !rateLimit(
          req,
          res,
          'qr-incident',
          30,
          30 * 60_000,
          payload.tenantId,
        )
      ) return;
      const body = await readJson(req, 16 * 1024);
      const config = await getConfig(payload.tenantId);
      const templateId = cleanText(
        body.templateId || config.settings.frontendTemplateId,
        80,
      );
      if (!isUuid(templateId)) {
        return sendError(
          res,
          400,
          '用户端模板无效。',
          'FRONTEND_TEMPLATE',
        );
      }
      const templateResult = await pool.query(
        `
          SELECT id,name,base_url,entry_host,netlify_site_id
          FROM frontend_templates
          WHERE id=$1
            AND (
              (
                status='enabled'
                AND (
                  selection_closed=FALSE
                  OR EXISTS (
                    SELECT 1 FROM tenant_config selected
                    WHERE selected.tenant_id=$2
                      AND selected.frontend_template_id=frontend_templates.id
                  )
                )
              )
              OR (
                status='testing'
                AND EXISTS (
                  SELECT 1
                  FROM jsonb_array_elements_text(test_tenant_ids) allowed(id)
                  WHERE allowed.id=$2::text
                )
              )
            )
        `,
        [templateId, payload.tenantId],
      );
      const template = templateResult.rows[0];
      if (!template) {
        return sendError(
          res,
          404,
          '用户端模板不可用。',
          'FRONTEND_TEMPLATE',
        );
      }
      const incident = await createQrIncidentReport(activeTenant, template, {
        licenseId: payload.licenseId,
      });
      await writeTenantAudit(req, payload, 'tenant.qr_incident.report', {
        targetType: 'frontend_template',
        targetId: template.id,
        metadata: { incidentId: incident.id, duplicate: incident.duplicate },
      }).catch(() => {});
      return sendJson(res, incident.duplicate ? 200 : 201, {
        ok: true,
        incidentId: incident.id,
        duplicate: incident.duplicate,
        status: incident.status,
        clickCount: incident.clickCount,
        requiresAdminReview: incident.requiresAdminReview,
        oldDomain: incident.oldDomain || null,
        newDomain: incident.newDomain || null,
        error: incident.error || null,
      });
    }

    if (req.method === 'GET' && pathname === '/api/admin/qr') {
      if (
        !rateLimit(
          req,
          res,
          'tenant-qr-render',
          30,
          60_000,
          payload.tenantId,
          { tenantId: payload.tenantId, licenseId: payload.licenseId },
        )
      ) return;
      const config = await getConfig(payload.tenantId);
      // 二维码编码当前模板的自有域名入口，并用 tenant 参数识别租户。
      // Netlify 仅作为隐藏源站；模板入口域名变更后需要重新保存二维码。
      const entryUrl = tenantEntryUrl(config.settings, activeTenant.public_code);
      // plain=1 只返回二维码主体（仍保留租户上传的中心图片）。
      // 新版租户后台会在浏览器 Canvas 中绘制中文文字，避免服务器缺少中文字体时出现方框乱码。
      const plainQr = url.searchParams.get('plain') === '1';
      const topText = plainQr ? '' : config.settings.qrTopText || '';
      const bottomText = plainQr
        ? ''
        : config.settings.qrBottomText !== undefined
          ? config.settings.qrBottomText
          : DEFAULT_QR_BOTTOM_TEXT;
      const cacheHash = createHash('sha256').update(JSON.stringify([
        entryUrl,
        plainQr,
        topText,
        bottomText,
        config.settings.qrLogoAssetId || '',
      ])).digest('base64url');
      const qrCacheKey = `${payload.tenantId}:${cacheHash}`;
      let image = cacheGet(tenantQrImageCache, qrCacheKey);
      if (!image) {
        const logoData = await readTenantQrLogo(
          payload.tenantId,
          config.settings.qrLogoAssetId,
        ).catch(() => null);
        image = await buildTenantQrImage(entryUrl, {
          topText,
          bottomText,
          logoData,
        });
        makeRoomInExpiringMap(
          tenantQrImageCache,
          MAX_TENANT_QR_CACHE,
          Date.now(),
          (item) => item.expiresAt,
        );
        cacheSet(
          tenantQrImageCache,
          qrCacheKey,
          image,
          TENANT_QR_CACHE_MS,
        );
      }
      res.statusCode = 200;
      res.setHeader('Content-Type', 'image/png');
      res.setHeader('Content-Length', String(image.length));
      res.setHeader('Cache-Control', 'no-store');
      res.setHeader(
        'Content-Disposition',
        'inline; filename="tuojie-entry-qr.png"',
      );
      return res.end(image);
    }

    if (req.method === 'GET' && pathname === '/api/admin/notices') {
      return sendJson(res, 200, {
        ok: true,
        ...(await getTenantNotices(payload.tenantId)),
      });
    }
    const announcementRead = pathname.match(
      /^\/api\/admin\/announcements\/([0-9a-f-]+)\/read$/i,
    );
    if (
      req.method === 'POST' &&
      announcementRead &&
      isUuid(announcementRead[1])
    ) {
      await pool.query(
        `
          INSERT INTO announcement_reads (announcement_id,tenant_id)
          SELECT id,$2 FROM announcements WHERE id=$1
          ON CONFLICT (announcement_id,tenant_id)
          DO UPDATE SET read_at=NOW()
        `,
        [announcementRead[1], payload.tenantId],
      );
      return sendJson(res, 200, { ok: true });
    }
    const releaseRead = pathname.match(
      /^\/api\/admin\/releases\/([0-9a-f-]+)\/read$/i,
    );
    if (
      req.method === 'POST' &&
      releaseRead &&
      isUuid(releaseRead[1])
    ) {
      await pool.query(
        `
          INSERT INTO release_reads (release_id,tenant_id)
          SELECT id,$2 FROM releases WHERE id=$1
          ON CONFLICT (release_id,tenant_id)
          DO UPDATE SET read_at=NOW()
        `,
        [releaseRead[1], payload.tenantId],
      );
      return sendJson(res, 200, { ok: true });
    }

    const messageActionMatch = pathname.match(
      /^\/api\/admin\/conversations\/([0-9a-f-]+)\/messages\/([0-9a-f-]+)(?:\/(recall))?$/i,
    );
    if (
      messageActionMatch &&
      isUuid(messageActionMatch[1]) &&
      isUuid(messageActionMatch[2])
    ) {
      const conversationId = messageActionMatch[1];
      const messageId = messageActionMatch[2];
      const conversation = await getConversationRow(
        conversationId,
        pool,
        false,
        payload.tenantId,
      );
      if (!conversation) {
        return sendError(res, 404, '会话不存在。', 'NOT_FOUND');
      }
      await requireTenantFeature('message_actions', payload.tenantId);
      if (req.method === 'DELETE' && !messageActionMatch[3]) {
        const deleted = await deleteAdminMessage(
          conversationId,
          messageId,
          payload.tenantId,
          apiVersion,
        );
        await writeTenantAudit(req, payload, 'tenant.message.delete', {
          targetType: 'message',
          targetId: messageId,
          metadata: { conversationId },
        }).catch(() => {});
        return sendJson(res, 200, {
          ok: true,
          ...deleted,
        });
      }
      if (
        req.method === 'POST' &&
        messageActionMatch[3] === 'recall'
      ) {
        const recalled = await recallAdminMessage(
          conversationId,
          messageId,
          payload.tenantId,
          apiVersion,
        );
        await writeTenantAudit(req, payload, 'tenant.message.recall', {
          targetType: 'message',
          targetId: messageId,
          metadata: { conversationId },
        }).catch(() => {});
        return sendJson(res, 200, {
          ok: true,
          ...recalled,
        });
      }
    }

    const match = pathname.match(
      /^\/api\/admin\/conversations\/([^/]+)(?:\/(messages|uploads|read|call))?$/,
    );

    if (match) {
      const conversationId = safeDecodeURIComponent(match[1]);
      const action = match[2] || '';
      if (!isUuid(conversationId)) {
        return sendError(res, 404, '会话不存在。', 'NOT_FOUND');
      }
      const useScopedV2Conversation =
        apiVersion >= 2 &&
        (
          (req.method === 'GET' && !action) ||
          (req.method === 'POST' && ['messages','call'].includes(action))
        );
      const conversation = useScopedV2Conversation
        ? { id: conversationId, tenant_id: payload.tenantId }
        : await getConversationRow(
            conversationId,
            pool,
            false,
            payload.tenantId,
          );

      if (!conversation || !authorizeConversation(payload, conversation)) {
        return sendError(res, 404, '会话不存在。', 'NOT_FOUND');
      }

      if (req.method === 'GET' && !action) {
        const readReceipt = await markConversationRead(
          conversationId,
          payload.tenantId,
          'admin',
        );
        const publicConversation = apiVersion >= 2
          ? await getConversationMessagePage(
              conversationId,
              payload.tenantId,
              {
                cursor: url.searchParams.get('before'),
                limit: pageLimit(url),
              },
            )
          : await getPublicConversation(
              conversationId,
              pool,
              payload.tenantId,
            );
        if (!publicConversation) {
          return sendError(res, 404, '会话不存在。', 'NOT_FOUND');
        }
        if (readReceipt.messageIds.length) {
          const summary = await getConversationSummaryById(
            conversationId,
            payload.tenantId,
          );
          if (summary) {
            broadcast(
              { type: 'summary-updated', conversation: summary },
              conversationId,
              payload.tenantId,
            );
          }
        }
        return sendJson(res, 200, {
          ok: true,
          conversation: publicConversation,
        });
      }

      if (req.method === 'POST' && action === 'read') {
        const receipt = await markConversationRead(
          conversationId,
          payload.tenantId,
          'admin',
        );
        return sendJson(res, 200, { ok: true, ...receipt });
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
        let visitorGroupId = conversation.visitor_group_id || null;
        if (body.visitorGroupId !== undefined) {
          if (body.visitorGroupId === null || body.visitorGroupId === '') {
            visitorGroupId = null;
          } else if (!isUuid(body.visitorGroupId)) {
            return sendError(
              res,
              400,
              '访客分组无效。',
              'VISITOR_GROUP_INVALID',
            );
          } else {
            const visitorGroup = await pool.query(
              `SELECT id FROM visitor_groups WHERE id=$1 AND tenant_id=$2`,
              [body.visitorGroupId, payload.tenantId],
            );
            if (!visitorGroup.rows[0]) {
              return sendError(
                res,
                404,
                '访客分组不存在。',
                'VISITOR_GROUP_NOT_FOUND',
              );
            }
            visitorGroupId = visitorGroup.rows[0].id;
          }
        }

        await pool.query(
          `
            UPDATE conversations
            SET status = $2,
                visitor_name = $3,
                visitor_note = $4,
                visitor_group_id = $5,
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $6
          `,
          [
            conversationId,
            status,
            visitorName,
            visitorNote,
            visitorGroupId,
            payload.tenantId,
          ],
        );
        const changedFields = [];
        if (status !== conversation.status) changedFields.push('status');
        if (visitorName !== conversation.visitor_name) changedFields.push('visitorName');
        if (visitorNote !== (conversation.visitor_note || '')) changedFields.push('visitorNote');
        const visitorGroupChanged =
          visitorGroupId !== (conversation.visitor_group_id || null);
        if (visitorGroupChanged) changedFields.push('visitorGroupId');
        if (changedFields.length) {
          await writeTenantAudit(req, payload, 'tenant.conversation.update', {
            targetType: 'conversation',
            targetId: conversationId,
            metadata: {
              changedFields,
              status,
              visitorName,
              hasVisitorNote: Boolean(visitorNote),
              visitorGroupId,
            },
          }).catch(() => {});
        }

        const summary = await getConversationSummaryById(
          conversationId,
          payload.tenantId,
        );
        let publicConversation = summary;
        if (apiVersion >= 2) {
          if (summary) {
            broadcastVersion(
              { type: 'summary-updated', conversation: summary },
              2,
              conversationId,
              payload.tenantId,
            );
          }
          if (hasLegacyConversationClient(conversationId, payload.tenantId)) {
            const legacyConversation = await getPublicConversation(
              conversationId,
              pool,
              payload.tenantId,
            );
            if (legacyConversation) {
              broadcastVersion(
                { type: 'conversation-updated', conversation: legacyConversation },
                1,
                conversationId,
                payload.tenantId,
              );
            }
          }
        } else {
          publicConversation = await getPublicConversation(
            conversationId,
            pool,
            payload.tenantId,
          );
          broadcastVersion(
            { type: 'conversation-updated', conversation: publicConversation },
            1,
            conversationId,
            payload.tenantId,
          );
        }
        let updatedVisitorGroups;
        if (visitorGroupChanged) {
          updatedVisitorGroups = await getVisitorGroups(payload.tenantId);
          broadcast(
            {
              type: 'visitor-groups-updated',
              visitorGroups: updatedVisitorGroups,
            },
            null,
            payload.tenantId,
          );
        }
        return sendJson(res, 200, {
          ok: true,
          conversation: publicConversation,
          visitorGroups: updatedVisitorGroups,
        });
      }

      if (req.method === 'DELETE' && !action) {
        const databaseClient = await pool.connect();
        try {
          await databaseClient.query('BEGIN');
          const stored = await databaseClient.query(
            `
              SELECT a.object_key
              FROM attachments a
              WHERE a.conversation_id=$1
                AND a.object_key IS NOT NULL
            `,
            [conversationId],
          );
          await queueObjectDeletes(
            stored.rows.map((row) => row.object_key),
            databaseClient,
          );
          await databaseClient.query(
            `DELETE FROM conversations WHERE id=$1 AND tenant_id=$2`,
            [conversationId, payload.tenantId],
          );
          await databaseClient.query('COMMIT');
        } catch (error) {
          await databaseClient.query('ROLLBACK');
          throw error;
        } finally {
          databaseClient.release();
        }
        processObjectDeleteQueue().catch(() => {});
        broadcast(
          { type: 'conversation-deleted', conversationId },
          conversationId,
          payload.tenantId,
        );
        await writeTenantAudit(req, payload, 'tenant.conversation.delete', {
          targetType: 'conversation',
          targetId: conversationId,
          metadata: {
            visitorName: cleanText(conversation.visitor_name, 40),
          },
        }).catch(() => {});
        if (conversation.visitor_group_id) {
          const visitorGroups = await getVisitorGroups(payload.tenantId);
          broadcast(
            { type: 'visitor-groups-updated', visitorGroups },
            null,
            payload.tenantId,
          );
        }
        return sendJson(res, 200, { ok: true });
      }

      if (req.method === 'POST' && action === 'call') {
        if (!rateLimit(
          req,
          res,
          'admin-call-signal',
          240,
          60_000,
          `${payload.tenantId}:${conversationId}`,
          {
            tenantId: payload.tenantId,
            conversationId,
          },
        )) return;
        const signal = parseCallSignal(await readJson(req, 256 * 1024));
        if (signal.action === 'offer') {
          const saved = await savePendingCallOffer(
            payload.tenantId,
            conversationId,
            signal,
            'admin',
          );
          publishCallLogUpdate(saved.call);
          if (saved.busy) {
            publishEvent(
              {
                type: 'call-signal',
                conversationId,
                from: 'system',
                action: 'busy',
                callId: signal.callId,
                mode: signal.mode,
                at: nowIso(),
              },
              {
                tenantId: payload.tenantId,
                conversationId,
                targetKind: 'tenant_admin',
              },
            );
            return sendJson(res, 200, {
              ok: true,
              busy: true,
              call: publicCallSession(saved.call),
            });
          }
          publishEvent(
            {
              type: 'call-signal',
              conversationId,
              from: 'admin',
              ...signal,
              at: nowIso(),
            },
            {
              tenantId: payload.tenantId,
              conversationId,
              targetKind: 'user',
            },
          );
          if (saved.isNew) {
            queueMicrotask(() => {
              sendConversationCallNotification(
                payload.tenantId,
                conversationId,
                signal,
              ).catch((error) =>
                console.error('视频/语音来电推送失败：', error.message),
              );
            });
          }
          return sendJson(res, 200, {
            ok: true,
            busy: false,
            call: publicCallSession(saved.call),
          });
        }
        if (signal.action === 'claim') {
          const claimed = await claimPendingCall(
            signal.callId,
            payload.tenantId,
            conversationId,
            'admin',
            signal.deviceId,
          );
          if (!claimed.accepted) {
            return sendError(
              res,
              409,
              '这次来电已由其他设备处理。',
              'CALL_ALREADY_HANDLED',
            );
          }
          publishCallControl(claimed.call, {
            action: 'claimed',
            handledByDeviceId: signal.deviceId,
            handledByKind: 'admin',
          });
          return sendJson(res, 200, { ok: true, accepted: true });
        }
        if (signal.action === 'answer') {
          const answered = await answerPendingCall(
            signal.callId,
            payload.tenantId,
            conversationId,
            'admin',
            signal.deviceId,
          );
          if (!answered.accepted) {
            return sendError(
              res,
              409,
              '这次来电已由其他设备处理。',
              'CALL_ALREADY_HANDLED',
            );
          }
          publishCallLogUpdate(answered.call);
        } else if (signal.action === 'connected') {
          const connectedCall = await markPendingCallConnected(
            signal.callId,
            payload.tenantId,
            conversationId,
            'admin',
            signal.deviceId,
          );
          if (connectedCall) publishCallLogUpdate(connectedCall);
          return sendJson(res, 200, { ok: true });
        } else if (['hangup','reject','busy','timeout','failed'].includes(signal.action)) {
          const finished = await finishPendingCall(
            signal.callId,
            payload.tenantId,
            conversationId,
            signal.action,
            'admin',
            signal.deviceId,
            signal.reason,
          );
          if (!finished.accepted) {
            return sendJson(res, 200, {
              ok: true,
              alreadyHandled: true,
              call: publicCallSession(finished.call),
            });
          }
          publishCallLogUpdate(finished.call);
          publishCallControl(finished.call, {
            action: 'resolved',
            handledByDeviceId: signal.deviceId,
            handledByKind: 'admin',
          });
        }
        publishEvent(
          {
            type: 'call-signal',
            conversationId,
            from: 'admin',
            ...signal,
            at: nowIso(),
          },
          {
            tenantId: payload.tenantId,
            conversationId,
            targetKind: 'user',
          },
        );
        return sendJson(res, 200, { ok: true });
      }

      if (req.method === 'POST' && action === 'uploads') {
        return handleUpload(req, res, payload, conversation);
      }

      if (req.method === 'POST' && action === 'messages') {
        if (
          !rateLimit(
            req,
            res,
            'admin-message',
            100,
            60_000,
            `${payload.tenantId}:${conversationId}`,
          )
        ) return;
        const body = await readJson(req);
        const result = await createAdminMessage(
          conversationId,
          body,
          payload.tenantId,
          { includeConversation: apiVersion < 2 },
        );
        await broadcastMessageResult(
          result,
          'admin-message',
          conversationId,
          payload.tenantId,
          apiVersion,
        );
        return sendJson(res, 201, {
          ok: true,
          message: result.message,
          messages: result.messages,
          conversation: result.conversation,
        });
      }
    }
  }

  if (req.method === 'GET' && pathname.startsWith('/api/media/')) {
    const payload = authenticate(req);
    if (!payload) {
      return sendError(res, 401, '没有权限读取媒体。', 'AUTH');
    }
    if (
      payload.kind === 'user' &&
      await rejectInvalidUserTokenOrigin(req, res, payload, pathname)
    ) return;

    const attachmentId = safeDecodeURIComponent(
      pathname.slice('/api/media/'.length),
    );
    if (!isUuid(attachmentId)) {
      return sendError(res, 404, '媒体不存在。', 'NOT_FOUND');
    }
    let result = await pool.query(
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
    let row = result.rows[0];
    if (!row && ['user', 'tenant_admin'].includes(payload.kind)) {
      const scopeId = payload.kind === 'user'
        ? payload.conversationId
        : payload.tenantId;
      if (isUuid(scopeId)) {
        result = await pool.query(
          `
            SELECT
              a.*,
              m.conversation_id,
              c.visitor_key_hash,
              c.tenant_id,
              c.visitor_name,
              c.status,
              c.unread_admin,
              c.unread_user,
              c.created_at AS conversation_created_at,
              c.updated_at AS conversation_updated_at
            FROM assets a
            JOIN messages m ON m.asset_id = a.id
            JOIN conversations c ON c.id = m.conversation_id
            WHERE a.id = $1
              AND a.kind = 'reply_image'
              AND m.recalled_at IS NULL
              AND (
                ($2 = 'user' AND m.conversation_id = $3)
                OR ($2 = 'tenant_admin' AND c.tenant_id = $3)
              )
            ORDER BY m.created_at DESC
            LIMIT 1
          `,
          [attachmentId, payload.kind, scopeId],
        );
        row = result.rows[0];
      }
    }
    if (!row) return sendError(res, 404, '媒体不存在。', 'NOT_FOUND');

    const conversationForAuth = {
      id: row.conversation_id,
      tenant_id: row.tenant_id,
      visitor_key_hash: row.visitor_key_hash,
    };
    if (!authorizeConversation(payload, conversationForAuth)) {
      return sendError(res, 403, '没有权限读取媒体。', 'FORBIDDEN');
    }
    const tenant =
      payload.kind === 'tenant_admin'
        ? await getTenantForAdminToken(payload)
        : await getTenantById(row.tenant_id);
    if (!tenant && payload.kind === 'tenant_admin') {
      const tenantState = await getTenantById(payload.tenantId);
      if (tenantAccessIssue(tenantState) === 'LICENSE_REVOKED') {
        return sendTenantAccessError(res, tenantState, 'admin');
      }
      return sendError(res, 401, '后台登录已失效。', 'LICENSE_REPLACED');
    }
    if (tenantAccessIssue(tenant)) {
      return sendTenantAccessError(
        res,
        tenant,
        payload.kind === 'tenant_admin' ? 'admin' : 'user',
      );
    }

    const data = await readStoredRow(row);
    if (!Buffer.isBuffer(data)) {
      return sendError(res, 404, '媒体不存在。', 'NOT_FOUND');
    }

    res.statusCode = 200;
    res.setHeader('Content-Type', row.mime);
    res.setHeader('Content-Length', String(data.length));
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader(
      'Content-Disposition',
      `inline; filename="${ALLOWED_VIDEO_TYPES.has(row.mime) ? 'video' : ALLOWED_AUDIO_TYPES.has(row.mime) ? 'audio' : 'image'}"`,
    );
    return res.end(data);
  }

  return sendError(res, 404, '接口不存在。', 'NOT_FOUND');
}

const server = http.createServer((req, res) => {
  const requestStartedAt = performance.now();
  const requestId = randomUUID();
  const traceId = requestTraceId(req);
  const context = {
    requestId,
    traceId,
    sqlCount: 0,
    sqlDurationMs: 0,
  };
  res.setHeader('X-Request-ID', requestId);
  res.setHeader('X-Trace-ID', traceId);
  const requestUrl = parseRequestUrl(req.url);
  if (!requestUrl) {
    setCommonHeaders(req, res);
    sendError(res, 400, '请求地址格式无效。', 'INVALID_URL');
    return;
  }
  const rawRequestPath = requestUrl.pathname.replace(/\/+$/, '') || '/';
  const requestPath = normalizeApiPath(rawRequestPath).pathname;
  minuteCounters.requests += 1;
  if (
    rawRequestPath.startsWith('/api/') &&
    !rawRequestPath.startsWith('/api/v2/') &&
    rawRequestPath !== '/api/v2' &&
    rawRequestPath !== '/api/telegram/webhook' &&
    !rawRequestPath.startsWith('/api/public/') &&
    rawRequestPath !== '/api/public'
  ) {
    minuteCounters.legacyRequests += 1;
  }
  res.once('finish', () => {
    const duration = performance.now() - requestStartedAt;
    requestLatencies.push(duration);
    if (requestLatencies.length > 5000) {
      requestLatencies.splice(0, requestLatencies.length - 5000);
    }
    if (res.statusCode >= 400) minuteCounters.errors += 1;
    let routeKey = monitoredRouteKey(req.method, rawRequestPath);
    if (!routeCounters.has(routeKey) && routeCounters.size >= 200) {
      routeKey = `${String(req.method || 'GET').toUpperCase()} /api/:other`;
    }
    const routeMetric = routeCounters.get(routeKey) || {
      requests: 0,
      errors: 0,
      responseBytes: 0,
    };
    routeMetric.requests += 1;
    if (res.statusCode >= 400) routeMetric.errors += 1;
    routeMetric.responseBytes += Number(res.getHeader('Content-Length') || 0);
    routeCounters.set(routeKey, routeMetric);
    if (duration >= SLOW_API_MS || res.statusCode >= 400) {
      const logger = res.statusCode >= 500 ? console.error : console.warn;
      logger(JSON.stringify({
        event: res.statusCode >= 400 ? 'api_request_error' : 'slow_api_request',
        requestId,
        traceId,
        method: String(req.method || 'GET').toUpperCase(),
        route: routeKey,
        status: res.statusCode,
        durationMs: Number(duration.toFixed(1)),
        sqlCount: context.sqlCount,
        sqlDurationMs: Number(context.sqlDurationMs.toFixed(1)),
        responseBytes: Number(res.getHeader('Content-Length') || 0),
      }));
    }
    if (res.statusCode < 500) scheduleActiveDatabaseWork(requestPath);
  });
  requestContext.run(context, () => {
    router(req, res, requestUrl).catch((error) => {
      console.error(JSON.stringify({
        event: 'request_handler_error',
        requestId,
        traceId,
        route: monitoredRouteKey(req.method, rawRequestPath),
        errorName: cleanText(error?.name, 80),
        errorCode: cleanText(error?.code, 80),
        message: cleanText(error?.message, 300),
      }));
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
});

server.requestTimeout = 90_000;
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
startBackgroundJobs();

server.listen(PORT, HOST, () => {
  console.log(`拓界云客服 v${APP_VERSION} 已启动：http://${HOST}:${PORT}`);
  console.log(`媒体存储：${R2_ENABLED ? 'Cloudflare R2' : 'PostgreSQL 兼容模式'}`);
  console.log(`Telegram 发卡机器人：${TELEGRAM_ENABLED ? '已启用' : '未启用'}`);
});
