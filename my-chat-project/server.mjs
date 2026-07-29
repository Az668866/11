import http from 'node:http';
import https from 'node:https';
import { lookup as dnsLookup } from 'node:dns';
import { isIP } from 'node:net';
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomUUID,
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

const { Pool } = pg;

const PORT = Number(process.env.PORT || 10000);
const HOST = process.env.HOST || '0.0.0.0';
const DATABASE_URL = String(process.env.DATABASE_URL || '').trim();
const TOKEN_SECRET_TEXT = process.env.TOKEN_SECRET || '';
const PUBLIC_API_BASE = String(
  process.env.PUBLIC_API_BASE || 'https://api.ykf000.com',
).replace(/\/+$/, '');
const APP_VERSION = String(process.env.APP_VERSION || '1.8.1').trim();
const SUPPORT_TELEGRAM = String(
  process.env.SUPPORT_TELEGRAM || '@YingYingUu',
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
const COOKIE_DOMAIN = String(process.env.COOKIE_DOMAIN || '').trim();
const COOKIE_SECURE = process.env.COOKIE_SECURE !== 'false';
const REQUIRE_CLOUDFLARE = process.env.REQUIRE_CLOUDFLARE === 'true';
const CLOUDFLARE_ORIGIN_SECRET = String(
  process.env.CLOUDFLARE_ORIGIN_SECRET || '',
);
const RENDER_API_KEY = String(process.env.RENDER_API_KEY || '').trim();
const RENDER_SERVICE_ID = String(process.env.RENDER_SERVICE_ID || '').trim();
const NEON_API_KEY = String(process.env.NEON_API_KEY || '').trim();
const NEON_PROJECT_ID = String(process.env.NEON_PROJECT_ID || '').trim();
const NEON_ORG_ID = String(process.env.NEON_ORG_ID || '').trim();
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
const MAX_IMAGE_BYTES =
  envNumber('MAX_IMAGE_MB', 8, 1, 16) * 1024 * 1024;
const MAX_VIDEO_BYTES =
  envNumber('MAX_VIDEO_MB', 25, 1, 50) * 1024 * 1024;
const MAX_AVATAR_BYTES = 2 * 1024 * 1024;
const MAX_COVER_BYTES = 5 * 1024 * 1024;
const MAX_ALBUM_IMAGES = 9;
const MAX_CONCURRENT_UPLOADS = Math.trunc(
  envNumber('MAX_CONCURRENT_UPLOADS', 4, 1, 8),
);
const MAX_CONVERSATIONS = Math.trunc(
  envNumber('MAX_CONVERSATIONS', 1000, 10, 10_000),
);
const MAX_MESSAGES_PER_CONVERSATION = Math.trunc(
  envNumber('MAX_MESSAGES_PER_CONVERSATION', 500, 100, 5000),
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


if (!STATIC_ALLOWED_ORIGINS.length) {
  throw new Error(
    'ALLOWED_ORIGINS 必须设置，例如：https://user.example.com,https://admin.example.com',
  );
}

if (TOKEN_SECRET_TEXT.length < 32) {
  throw new Error('TOKEN_SECRET 必须设置，且至少32个字符。');
}
if (Boolean(SUPER_ADMIN_USERNAME) !== Boolean(SUPER_ADMIN_PASSWORD)) {
  throw new Error(
    'SUPER_ADMIN_USERNAME 和 SUPER_ADMIN_PASSWORD 必须同时设置。',
  );
}
if (SUPER_ADMIN_PASSWORD && SUPER_ADMIN_PASSWORD.length < 12) {
  throw new Error('SUPER_ADMIN_PASSWORD 必须至少12位。');
}
if (
  SUPER_ADMIN_TOTP_SECRET &&
  !/^[A-Z2-7]{16,128}$/.test(SUPER_ADMIN_TOTP_SECRET)
) {
  throw new Error('SUPER_ADMIN_TOTP_SECRET 必须是有效的 Base32 密钥。');
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
const LICENSE_ENCRYPTION_KEY = createHash('sha256')
  .update(TOKEN_SECRET)
  .digest();
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
const DEFAULT_USER_SITE_URL = 'https://zxkf.netlify.app/';
const DEFAULT_TEMPLATE_ID = '11111111-1111-4111-8111-111111111111';
const RETENTION_OPTIONS = new Set([1, 6, 12, 24, 72, 168]);
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
const eventHistory = [];
const requestLatencies = [];
const minuteCounters = {
  requests: 0,
  errors: 0,
  messages: 0,
  uploads: 0,
  uploadFailures: 0,
  licenseFailures: 0,
  telegramWebhookFailures: 0,
};
const metricSamples = [];
const alertState = new Map();
let approvedOriginCache = new Set(STATIC_ALLOWED_ORIGINS);
let approvedOriginCacheExpiresAt = 0;
let nextEventId = 1;
let lastCleanupAt = 0;
let cleanupPromise = null;
let activeUploads = 0;
let metricTimer = null;
let reportTimer = null;
let lastCpuUsage = process.cpuUsage();
let lastCpuSampleAt = process.hrtime.bigint();
let lastMonitorSnapshot = null;
let lastPlatformSettings = null;
let monitorFailureCount = 0;
let startedAt = Date.now();
let providerMetricsCache = {
  expiresAt: 0,
  render: null,
  neon: null,
};

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
      avatarAssetId: '',
      welcomeText: '您好，欢迎咨询。您可以发送文字、图片或视频，我们会尽快回复。',
      onlineStatusText: '客服在线',
      pageTitle: '在线客服',
      autoReplyEnabled: true,
      defaultAutoReplyEnabled: true,
      defaultAutoReply: '消息已收到，客服看到后会尽快回复。',
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
        duration_code TEXT NOT NULL CHECK (duration_code IN ('1d','7d','30d','180d','365d')),
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
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS session_version INTEGER NOT NULL DEFAULT 1`);
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS last_admin_online_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE tenants ADD COLUMN IF NOT EXISTS expiry_reminder_sent_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS generated_by_admin_id UUID`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS archived_at TIMESTAMPTZ`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS assets (
        id UUID PRIMARY KEY,
        tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
        kind TEXT NOT NULL CHECK (kind IN ('brand_avatar','template_cover')),
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
      CREATE TABLE IF NOT EXISTS frontend_templates (
        id UUID PRIMARY KEY,
        name TEXT NOT NULL,
        base_url TEXT NOT NULL,
        origin TEXT NOT NULL,
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
      INSERT INTO frontend_templates (
        id, name, base_url, origin, client_version, min_backend_version,
        status, sort_order, recommended, is_default
      ) VALUES ($1, '拓界经典版', $2, $3, $4, $4, 'enabled', 10, TRUE, TRUE)
      ON CONFLICT (id) DO NOTHING
    `, [
      DEFAULT_TEMPLATE_ID,
      DEFAULT_USER_SITE_URL,
      new URL(DEFAULT_USER_SITE_URL).origin,
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
      CREATE TABLE IF NOT EXISTS platform_settings (
        id SMALLINT PRIMARY KEY CHECK (id = 1),
        brand_name TEXT NOT NULL DEFAULT '拓界云客服',
        current_version TEXT NOT NULL DEFAULT '1.8.1',
        support_telegram TEXT NOT NULL DEFAULT '@YingYingUu',
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
      INSERT INTO platform_settings (
        id, current_version, support_telegram
      ) VALUES (1, $1, $2)
      ON CONFLICT (id) DO NOTHING
    `, [APP_VERSION, SUPPORT_TELEGRAM]);

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
      CREATE INDEX IF NOT EXISTS audit_logs_created_idx
      ON audit_logs (created_at DESC)
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
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS telegram_username TEXT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS telegram_display_name TEXT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS key_ciphertext TEXT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS telegram_update_id BIGINT`);
    await client.query(`ALTER TABLE license_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ`);

    await client.query(`
      CREATE TABLE IF NOT EXISTS attachments (
        id UUID PRIMARY KEY,
        conversation_id UUID NOT NULL REFERENCES conversations(id) ON DELETE CASCADE,
        filename TEXT NOT NULL,
        mime TEXT NOT NULL CHECK (mime IN (
          'image/jpeg','image/png','image/webp','image/gif',
          'video/mp4','video/webm','video/quicktime'
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
        type TEXT NOT NULL CHECK (type IN ('text','image','video')),
        text TEXT NOT NULL DEFAULT '',
        attachment_id UUID UNIQUE REFERENCES attachments(id) ON DELETE CASCADE,
        album_id UUID,
        album_position SMALLINT NOT NULL DEFAULT 0 CHECK (album_position BETWEEN 0 AND 9),
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        CHECK (
          (type = 'text' AND attachment_id IS NULL AND length(text) > 0)
          OR
          (type IN ('image','video') AND attachment_id IS NOT NULL)
        )
      )
    `);

    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS album_id UUID`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS album_position SMALLINT NOT NULL DEFAULT 0`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS read_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS recalled_at TIMESTAMPTZ`);
    await client.query(`ALTER TABLE messages ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ`);
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
                AND type IN ('image','video')
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
    await client.query(`CREATE INDEX IF NOT EXISTS license_keys_created_at_idx ON license_keys (created_at DESC)`);
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
      CREATE INDEX IF NOT EXISTS messages_unread_idx
      ON messages (conversation_id, role, created_at)
      WHERE read_at IS NULL
    `);
    await client.query(`
      CREATE INDEX IF NOT EXISTS messages_created_at_idx
      ON messages (created_at)
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
            WHEN retention_hours IN (1,6,12,24,72,168) THEN retention_hours
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
    if (SUPER_ADMIN_USERNAME && SUPER_ADMIN_PASSWORD) {
      await client.query(`
        INSERT INTO super_admins (
          id, username, password_hash, role, totp_secret_ciphertext
        ) VALUES ($1, $2, $3, 'owner', $4)
        ON CONFLICT (username) DO NOTHING
      `, [
        randomUUID(),
        SUPER_ADMIN_USERNAME.toLowerCase(),
        hashPassword(SUPER_ADMIN_PASSWORD),
        SUPER_ADMIN_TOTP_SECRET
          ? encryptSecret(SUPER_ADMIN_TOTP_SECRET)
          : null,
      ]);
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

async function cleanupExpiredData() {
  const client = await pool.connect();
  const objectKeys = [];

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
    await client.query(`DELETE FROM audit_logs WHERE created_at < NOW() - INTERVAL '7 days'`);
    await client.query(`DELETE FROM system_metric_samples WHERE created_at < NOW() - INTERVAL '7 days'`);
    await queueObjectDeletes(objectKeys, client);

    await client.query('COMMIT');
    lastCleanupAt = Date.now();
    await processObjectDeleteQueue();

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
    /(?:^|[^A-Z0-9])(VIP(?:[\s_-]*[A-Z2-9]{5}){4})(?=$|[^A-Z0-9])/,
  )?.[1];
  if (embedded) {
    const raw = embedded.replace(/[^A-Z2-9]/g, '').slice(3);
    return `VIP-${raw.match(/.{5}/g).join('-')}`;
  }
  return source.replace(/[\s_]+/g, '-').replace(/-+/g, '-');
}
function hashLicenseKey(value) {
  return createHmac('sha256', TOKEN_SECRET)
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

function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(String(password), salt, 64);
  return `scrypt$${salt.toString('base64url')}$${hash.toString('base64url')}`;
}

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
    'SameSite=None',
    `Max-Age=${Math.max(0, Math.trunc(maxAge))}`,
  ];
  if (COOKIE_SECURE) parts.push('Secure');
  if (COOKIE_DOMAIN) parts.push(`Domain=${COOKIE_DOMAIN}`);
  return parts.join('; ');
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
  return row
    ? `${row.key_prefix || 'VIP'}-•••••-•••••-•••••-${row.key_suffix || '?????'}`
    : '';
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

async function authenticateSuper(req) {
  const token =
    parseCookies(req)[SESSION_COOKIE] ||
    (process.env.NODE_ENV === 'test' ? getBearer(req) : '');
  const payload = verifyToken(token);
  if (
    payload?.kind !== 'super_admin' ||
    !isUuid(payload.adminId) ||
    !Number.isInteger(payload.sessionVersion)
  ) return null;
  const result = await pool.query(
    `
      SELECT id, username, role, enabled, session_version, last_login_at
      FROM super_admins
      WHERE id = $1
    `,
    [payload.adminId],
  );
  const admin = result.rows[0];
  if (
    !admin?.enabled ||
    Number(admin.session_version) !== payload.sessionVersion
  ) return null;
  return {
    id: admin.id,
    username: admin.username,
    role: admin.role,
    lastLoginAt: admin.last_login_at
      ? new Date(admin.last_login_at).toISOString()
      : null,
  };
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

async function writeAudit(
  req,
  admin,
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
        actor_admin_id, action, target_type, target_id,
        ip_address, result, metadata
      ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb)
    `,
    [
      admin?.id || null,
      cleanText(action, 100),
      cleanText(targetType, 80),
      cleanText(targetId, 160),
      cleanText(requestIp(req), 100),
      cleanText(result, 30) || 'success',
      JSON.stringify(metadata || {}),
    ],
  );
}

function normalizeOrigin(origin) {
  return String(origin || '').trim().replace(/\/$/, '');
}

function isPublicAddress(address) {
  const version = isIP(address);
  if (version === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 0 && c === 2) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      (a === 198 && b === 51 && c === 100) ||
      (a === 203 && b === 0 && c === 113) ||
      a >= 224
    );
  }
  if (version === 6) {
    const value = address.toLowerCase();
    if (value.startsWith('::ffff:')) {
      return isPublicAddress(value.slice(7));
    }
    return !(
      value === '::' ||
      value === '::1' ||
      /^f[cd]/.test(value) ||
      /^fe[89ab]/.test(value) ||
      value.startsWith('ff') ||
      value.startsWith('2001:db8:')
    );
  }
  return false;
}

// 模板检测会访问管理员填写的网址，因此 DNS 必须锁定到公网地址以阻断 SSRF。
function fetchTemplateHtml(inputUrl, redirectCount = 0) {
  return new Promise((resolve, reject) => {
    let target;
    try {
      target = new URL(inputUrl);
      if (
        target.protocol !== 'https:' ||
        target.username ||
        target.password ||
        (target.port && target.port !== '443')
      ) {
        throw new Error();
      }
    } catch {
      reject(requestError('只能检测标准 HTTPS 用户端地址。', 400, 'TEMPLATE_URL'));
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
  const contractReady = [
    '/api/user/session',
    '/api/user/conversation',
    '/api/events',
    'CLIENT_TEMPLATE_ID',
    'Last-Event-ID',
  ].every((marker) => String(html).includes(marker));
  return {
    clientVersion: cleanText(clientVersion, 30),
    apiBase: cleanText(apiBase, 300).replace(/\/+$/, ''),
    contractReady,
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
      SELECT origin
      FROM frontend_templates
      WHERE status IN ('testing','enabled')
    `);
    for (const row of result.rows) {
      const origin = normalizeOrigin(row.origin);
      if (origin) origins.add(origin);
    }
  } catch (error) {
    if (!approvedOriginCache.size) throw error;
  }
  approvedOriginCache = origins;
  approvedOriginCacheExpiresAt = Date.now() + 60_000;
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
    'Authorization,Content-Type,X-File-Name,Last-Event-ID',
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

function normalizeIp(value) {
  let ip = String(value || '').trim();
  if (ip.startsWith('[') && ip.includes(']')) ip = ip.slice(1, ip.indexOf(']'));
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (/^\d{1,3}(?:\.\d{1,3}){3}:\d+$/.test(ip)) {
    ip = ip.slice(0, ip.lastIndexOf(':'));
  }
  return isIP(ip) ? ip : '';
}

function requestIp(req) {
  const candidates = REQUIRE_CLOUDFLARE
    ? [req.headers['cf-connecting-ip']]
    : [
        req.headers['cf-connecting-ip'],
        req.headers['true-client-ip'],
        req.headers['x-real-ip'],
        ...String(req.headers['x-forwarded-for'] || '')
          .split(',')
          .map((item) => item.trim()),
        req.socket.remoteAddress,
      ];
  for (const candidate of candidates) {
    const ip = normalizeIp(candidate);
    if (ip) return ip;
  }
  return 'unknown';
}

function cloudflareVisitorLocation(req) {
  const countryCode = cleanText(req.headers['cf-ipcountry'], 8).toUpperCase();
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
  const parts = [
    country,
    cleanText(req.headers['cf-region'], 100),
    cleanText(req.headers['cf-ipcity'], 100),
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
    timezone: cleanText(req.headers['cf-timezone'], 80),
  };
}

function rateLimit(req, res, name, max, windowMs, identity = '') {
  const key = `${name}:${identity || requestIp(req)}`;
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

  if (mime === 'video/mp4' || mime === 'video/quicktime') {
    return data.length >= 12 && data.subarray(4, 8).toString('ascii') === 'ftyp';
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

async function queueObjectDeletes(objectKeys, client = pool) {
  const unique = [...new Set(objectKeys.filter(Boolean))];
  for (const objectKey of unique) {
    await client.query(
      `
        INSERT INTO r2_delete_queue (object_key)
        VALUES ($1)
        ON CONFLICT (object_key) DO NOTHING
      `,
      [objectKey],
    );
  }
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
  for (const row of result.rows) {
    try {
      await r2.send(
        new DeleteObjectCommand({
          Bucket: R2_BUCKET,
          Key: row.object_key,
        }),
      );
      await pool.query(`DELETE FROM r2_delete_queue WHERE id = $1`, [row.id]);
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
  const storedInR2 = await putObject(objectKey, data, mime);
  const result = await pool.query(
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
}

async function deleteAsset(assetId, tenantId = undefined) {
  if (!isUuid(assetId)) return;
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

async function prepareImageUpload(req, { maxBytes, width, height }) {
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
        fit: 'cover',
        position: 'attention',
      })
      .webp({ quality: 84, effort: 4 })
      .toBuffer();
  } catch {
    throw requestError('图片无法解析或尺寸异常。', 415, 'IMAGE_INVALID');
  }
}

async function readStoredRow(row) {
  if (!row) return null;
  if (row.storage === 'r2') return readObject(row.object_key);
  return Buffer.isBuffer(row.data) ? row.data : null;
}

function publicMessage(row) {
  return {
    id: row.id,
    role: row.role,
    source: row.source || 'manual',
    type: row.type,
    text: row.text || '',
    attachmentId: row.attachment_id || null,
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
}

async function getConfig(tenantId, client = pool) {
  if (!tenantId) throw new Error('缺少租户标识。');
  const result = await client.query(
    `
      SELECT
        tc.canned_replies,
        tc.auto_replies,
        tc.settings,
        tc.retention_hours,
        tc.frontend_template_id,
        ft.name AS frontend_template_name,
        ft.base_url AS frontend_base_url
      FROM tenant_config tc
      LEFT JOIN frontend_templates ft ON ft.id = tc.frontend_template_id
      WHERE tc.tenant_id = $1
    `,
    [tenantId],
  );
  if (!result.rows[0]) {
    await createTenantConfig(tenantId, client);
    return getConfig(tenantId, client);
  }
  return {
    cannedReplies: result.rows[0].canned_replies || [],
    autoReplies: result.rows[0].auto_replies || [],
    settings: {
      ...(result.rows[0].settings || {}),
      retentionHours: Number(result.rows[0].retention_hours || 24),
      frontendTemplateId:
        result.rows[0].frontend_template_id || DEFAULT_TEMPLATE_ID,
      frontendTemplateName:
        result.rows[0].frontend_template_name || '拓界经典版',
      frontendBaseUrl:
        result.rows[0].frontend_base_url || DEFAULT_USER_SITE_URL,
    },
  };
}

async function getTemplateCatalog(
  { audience = 'tenant', tenantId = '' } = {},
  client = pool,
) {
  const isSuper = audience === 'super';
  const result = await client.query(
    `
      SELECT
        ft.id, ft.name, ft.base_url, ft.origin, ft.cover_asset_id,
        ft.client_version, ft.min_backend_version, ft.status,
        ft.selection_closed, ft.sort_order, ft.recommended, ft.is_default,
        ft.test_tenant_ids,
        (
          SELECT COUNT(*)::int
          FROM tenant_config tc
          WHERE tc.frontend_template_id = ft.id
        ) AS usage_count
      FROM frontend_templates ft
      WHERE $1::boolean
         OR (
           ft.status = 'enabled'
           AND (
             ft.selection_closed = FALSE
             OR EXISTS (
               SELECT 1
               FROM tenant_config selected
               WHERE selected.tenant_id = $2::uuid
                 AND selected.frontend_template_id = ft.id
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
  return result.rows.map((row) => ({
    id: row.id,
    name: row.name,
    baseUrl: row.base_url,
    displayUrl: row.base_url.replace(/^https:\/\//i, '').replace(/\/$/, ''),
    origin: row.origin,
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
    testTenantIds: Array.isArray(row.test_tenant_ids)
      ? row.test_tenant_ids
      : [],
    usageCount: Number(row.usage_count || 0),
  }));
}

function tenantEntryUrl(settings, publicCode) {
  const base = settings?.frontendBaseUrl || DEFAULT_USER_SITE_URL;
  const url = new URL(base);
  url.searchParams.set('tenant', publicCode);
  return url.toString();
}

async function getPlatformSettings(client = pool) {
  try {
    const result = await client.query(
      `SELECT * FROM platform_settings WHERE id = 1`,
    );
    const row = result.rows[0] || {};
    lastPlatformSettings = {
      brandName: row.brand_name || '拓界云客服',
      currentVersion: row.current_version || APP_VERSION,
      supportTelegram: row.support_telegram || SUPPORT_TELEGRAM,
      telegramGroupId: row.telegram_group_id || '',
      reportTime: row.report_time || '09:00',
      reportTimezone: row.report_timezone || 'Asia/Shanghai',
      dailyReportEnabled: Boolean(row.daily_report_enabled),
      weeklyReportEnabled: Boolean(row.weekly_report_enabled),
      alertSettings: row.alert_settings || {},
    };
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
  return Object.fromEntries(
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
        ORDER BY created_at DESC, id DESC
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
      ORDER BY created_at ASC, album_position ASC, id ASC
    `,
    [id, MAX_MESSAGES_PER_CONVERSATION],
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

async function validateAdminSettings(body, current, tenantId) {
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
                FROM tenant_config selected
                WHERE selected.tenant_id = $2
                  AND selected.frontend_template_id = frontend_templates.id
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
  if (event.targetKind && client.kind !== event.targetKind) return false;
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
    targetKind = null,
    keepHistory = true,
  } = {},
) {
  const event = {
    id: nextEventId++,
    payload: { ...payload, eventId: nextEventId - 1 },
    conversationId,
    tenantId,
    targetKind,
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

function broadcastSuper(payload) {
  publishEvent(payload, { targetKind: 'super_admin' });
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
  await requireTenantFeature('media_album', payload.tenantId);

  const rateIdentity = `${payload.kind}:${payload.tenantId}:${conversation.id}`;
  if (!rateLimit(req, res, 'upload', 30, 60_000, rateIdentity)) return;

  const mime = String(req.headers['content-type'] || '')
    .split(';')[0]
    .trim()
    .toLowerCase();
  const isImage = ALLOWED_IMAGE_TYPES.has(mime);
  const isVideo = ALLOWED_VIDEO_TYPES.has(mime);

  if (!isImage && !isVideo) {
    return sendError(
      res,
      415,
      '仅支持 JPG、PNG、WEBP、GIF 图片，以及 MP4、WEBM、MOV 视频。',
      'MEDIA_TYPE',
    );
  }

  const maxBytes = isVideo ? MAX_VIDEO_BYTES : MAX_IMAGE_BYTES;
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
    req.headers['x-file-name'] || `${isVideo ? 'video' : 'image'}-${attachmentId}`,
  );
  const objectKey = mediaObjectKey(
    payload.tenantId,
    conversation.id,
    attachmentId,
    mime,
  );
  let storedInR2 = false;
  try {
    storedInR2 = await putObject(objectKey, data, mime);
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
        storedInR2 ? null : data,
        storedInR2 ? 'r2' : 'database',
        storedInR2 ? objectKey : null,
        retentionHours,
      ],
    );
    minuteCounters.uploads += 1;
    return sendJson(res, 201, {
      ok: true,
      attachment: publicAttachment(result.rows[0]),
      mediaType: isVideo ? 'video' : 'image',
    });
  } catch (error) {
    minuteCounters.uploadFailures += 1;
    if (storedInR2) await queueObjectDeletes([objectKey]).catch(() => {});
    throw error;
  }
}

function requestError(message, statusCode, code) {
  const error = new Error(message);
  error.statusCode = statusCode;
  error.code = code;
  return error;
}

function parseMessageInput(body = {}) {
  const requestedType = cleanText(body.type, 20) || 'text';
  if (!['text', 'image', 'video'].includes(requestedType)) {
    throw requestError('消息类型无效。', 400, 'INVALID_MESSAGE_TYPE');
  }

  const text = cleanText(body.text, 4000);
  if (requestedType === 'text') {
    if (!text) throw requestError('消息不能为空。', 400, 'EMPTY_MESSAGE');
    return { type: 'text', text, attachmentIds: [] };
  }

  const inputIds = Array.isArray(body.attachmentIds)
    ? body.attachmentIds
    : [body.attachmentId];
  const attachmentIds = inputIds
    .map((value) => cleanText(value, 80))
    .filter(Boolean);

  if (
    !attachmentIds.length ||
    attachmentIds.some((id) => !isUuid(id)) ||
    new Set(attachmentIds).size !== attachmentIds.length
  ) {
    throw requestError('媒体附件无效。', 400, 'INVALID_ATTACHMENT');
  }
  if (requestedType === 'image' && attachmentIds.length > MAX_ALBUM_IMAGES) {
    throw requestError(
      `一次最多发送 ${MAX_ALBUM_IMAGES} 张图片。`,
      400,
      'ALBUM_LIMIT',
    );
  }
  if (requestedType === 'video' && attachmentIds.length !== 1) {
    throw requestError('一次只能发送一个视频。', 400, 'VIDEO_LIMIT');
  }

  return { type: requestedType, text, attachmentIds };
}

async function getTenantRetentionHours(tenantId, client = pool) {
  const result = await client.query(
    `SELECT retention_hours FROM tenant_config WHERE tenant_id = $1`,
    [tenantId],
  );
  const hours = Number(result.rows[0]?.retention_hours || 24);
  return RETENTION_OPTIONS.has(hours) ? hours : 24;
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
    return type === 'image'
      ? ALLOWED_IMAGE_TYPES.has(mime)
      : ALLOWED_VIDEO_TYPES.has(mime);
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
) {
  const albumId =
    type === 'image' && attachmentIds.length > 1 ? randomUUID() : null;
  const rows = [];
  for (let index = 0; index < attachmentIds.length; index += 1) {
    const result = await client.query(
      `
        INSERT INTO messages (
          id, conversation_id, role, source, type, text, attachment_id,
          album_id, album_position, expires_at
        )
        VALUES (
          $1,$2,$3,'manual',$4,$5,$6,$7,$8,
          NOW() + ($9::text || ' hours')::interval
        )
        RETURNING *
      `,
      [
        randomUUID(),
        conversationId,
        role,
        type,
        index === 0 ? text : '',
        attachmentIds[index],
        albumId,
        index,
        retentionHours,
      ],
    );
    rows.push(result.rows[0]);
  }
  await client.query(
    `
      UPDATE attachments
      SET linked_at = NOW(),
          expires_at = NOW() + ($2::text || ' hours')::interval
      WHERE id = ANY($1::uuid[])
    `,
    [attachmentIds, retentionHours],
  );
  return rows;
}

async function createUserMessage(conversationId, body, tenantId) {
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

    const input = parseMessageInput(body);
    if (input.type !== 'text') {
      await requireTenantFeature('media_album', tenantId, client);
    }
    const retentionHours = await getTenantRetentionHours(tenantId, client);
    let messageRows;
    if (input.type === 'text') {
      const result = await client.query(
        `
          INSERT INTO messages (
            id, conversation_id, role, source, type, text, expires_at
          )
          VALUES (
            $1,$2,'user','manual','text',$3,
            NOW() + ($4::text || ' hours')::interval
          )
          RETURNING *
        `,
        [randomUUID(), conversationId, input.text, retentionHours],
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
      );
    }

    await client.query(
      `
        UPDATE conversations
        SET unread_admin = unread_admin + 1, updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
      `,
      [conversationId, tenantId],
    );

    let autoReplyRow = null;
    if (input.type === 'text') {
      const config = await getConfig(conversation.tenant_id, client);
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
      const replyText =
        cooldownPassed &&
        (await tenantFeatureEnabled('auto_reply', tenantId, client))
        ? matchAutoReply(config, input.text)
        : '';

      if (replyText) {
        const autoResult = await client.query(
          `
            INSERT INTO messages (
              id, conversation_id, role, source, type, text, expires_at
            )
            VALUES (
              $1,$2,'admin','auto','text',$3,
              NOW() + ($4::text || ' hours')::interval
            )
            RETURNING *
          `,
          [randomUUID(), conversationId, replyText, retentionHours],
        );
        autoReplyRow = autoResult.rows[0];
        await client.query(
          `
            UPDATE conversations
            SET unread_user = unread_user + 1,
                last_auto_reply_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND tenant_id = $2
          `,
          [conversationId, tenantId],
        );
      }
    }

    await client.query('COMMIT');
    minuteCounters.messages +=
      messageRows.length + (autoReplyRow ? 1 : 0);
    const publicConversation = await getPublicConversation(
      conversationId,
      pool,
      conversation.tenant_id,
    );
    const messages = messageRows.map(publicMessage);
    return {
      message: messages[0],
      messages,
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

    const input = parseMessageInput(body);
    if (input.type !== 'text') {
      await requireTenantFeature('media_album', tenantId, client);
    }
    const retentionHours = await getTenantRetentionHours(tenantId, client);
    let messageRows;
    if (input.type === 'text') {
      const result = await client.query(
        `
          INSERT INTO messages (
            id, conversation_id, role, source, type, text, expires_at
          )
          VALUES (
            $1,$2,'admin','manual','text',$3,
            NOW() + ($4::text || ' hours')::interval
          )
          RETURNING *
        `,
        [randomUUID(), conversationId, input.text, retentionHours],
      );
      messageRows = [result.rows[0]];
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
      );
    }

    await client.query(
      `
        UPDATE conversations
        SET unread_user = unread_user + 1, updated_at = NOW()
        WHERE id = $1 AND tenant_id = $2
      `,
      [conversationId, tenantId],
    );

    await client.query('COMMIT');
    minuteCounters.messages += messageRows.length;
    const publicConversation = await getPublicConversation(
      conversationId,
      pool,
      conversation.tenant_id,
    );
    const messages = messageRows.map(publicMessage);
    return {
      message: messages[0],
      messages,
      conversation: publicConversation,
    };
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
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

async function deleteAdminMessage(conversationId, messageId, tenantId) {
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
  const conversation = await getPublicConversation(
    conversationId,
    pool,
    tenantId,
  );
  broadcast(
    {
      type: 'message-deleted',
      conversationId,
      messageIds,
      conversation,
    },
    conversationId,
    tenantId,
  );
  return { messageIds, conversation };
}

async function recallAdminMessage(conversationId, messageId, tenantId) {
  const client = await pool.connect();
  const objectKeys = [];
  let messageIds = [];
  let recalledMessageId = '';
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
    await client.query(
      `
        UPDATE messages
        SET type = 'text',
            text = '客服已撤回了一条消息',
            attachment_id = NULL,
            album_id = NULL,
            album_position = 0,
            recalled_at = NOW()
        WHERE id = $1
      `,
      [recalledMessageId],
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
  const conversation = await getPublicConversation(
    conversationId,
    pool,
    tenantId,
  );
  const message = conversation.messages.find(
    (item) => item.id === recalledMessageId,
  );
  broadcast(
    {
      type: 'message-recalled',
      conversationId,
      messageIds,
      message,
      conversation,
    },
    conversationId,
    tenantId,
  );
  return { messageIds, message, conversation };
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
  if (!isUuid(payload?.tenantId) || !isUuid(payload?.licenseId)) return null;
  const result = await client.query(
    `
      SELECT t.*
      FROM tenants t
      JOIN license_keys l
        ON l.id = $2
       AND l.tenant_id = t.id
       AND l.status = 'active'
      WHERE t.id = $1
        AND t.session_version = $3
    `,
    [
      payload.tenantId,
      payload.licenseId,
      Number(payload.sessionVersion || 0),
    ],
  );
  return result.rows[0] || null;
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
          ? `你的卡密已被禁用，如有疑问请联系 Telegram ${SUPPORT_TELEGRAM}。`
          : '该客服服务已停用，请联系商家。',
      code: issue,
      supportTelegram: SUPPORT_TELEGRAM,
    });
  }
  return sendError(
    res,
    403,
    audience === 'admin'
      ? '卡密已到期，请购买新卡密续费。'
      : '该客服服务已到期，请联系商家续费。',
    issue === 'TENANT_NOT_FOUND' ? 'TENANT_NOT_FOUND' : 'TENANT_EXPIRED',
  );
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
  await pool.query(
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
}

async function createLicenseRecord(durationCode, metadata = {}) {
  const duration = LICENSE_DURATIONS[durationCode];
  if (!duration) throw new Error('卡密时长无效。');
  const updateId = Number(metadata.telegramUpdateId);
  const telegramUpdateId = Number.isSafeInteger(updateId) ? updateId : null;

  async function existingForUpdate() {
    if (telegramUpdateId == null) return null;
    const result = await pool.query(
      `SELECT * FROM license_keys WHERE telegram_update_id = $1`,
      [telegramUpdateId],
    );
    const row = result.rows[0];
    if (!row) return null;
    const licenseKey = decryptLicenseKey(row.key_ciphertext);
    if (!licenseKey) {
      throw new Error('此发卡请求已经处理，卡密已激活或不再可重复显示。');
    }
    return {
      licenseKey,
      row,
      duration: LICENSE_DURATIONS[row.duration_code] || duration,
    };
  }

  const existing = await existingForUpdate();
  if (existing) return existing;

  for (let attempt = 0; attempt < 5; attempt += 1) {
    const licenseKey = generateLicenseKey();
    try {
      const result = await pool.query(
        `
          INSERT INTO license_keys (
            id, key_hash, key_ciphertext, key_prefix, key_suffix,
            duration_code, duration_days,
            telegram_chat_id, telegram_user_id, telegram_username,
            telegram_display_name, telegram_update_id, generated_by_admin_id
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)
          RETURNING *
        `,
        [randomUUID(), hashLicenseKey(licenseKey), encryptLicenseKey(licenseKey),
         'VIP', licenseKey.slice(-5), durationCode, duration.days,
         cleanText(metadata.telegramChatId, 50),
         cleanText(metadata.telegramUserId, 50),
         cleanText(metadata.telegramUsername, 64),
         cleanText(metadata.telegramDisplayName, 120),
         telegramUpdateId,
         isUuid(metadata.generatedByAdminId)
           ? metadata.generatedByAdminId
           : null],
      );
      return { licenseKey, row: result.rows[0], duration };
    } catch (error) {
      if (error?.code !== '23505') throw error;
      const duplicateUpdate = await existingForUpdate();
      if (duplicateUpdate) return duplicateUpdate;
      if (attempt === 4) throw error;
    }
  }
  throw new Error('生成卡密失败。');
}

async function handleTenantLogin(req, res) {
  if (!rateLimit(req, res, 'tenant-login', 15, 10 * 60_000)) return;
  const body = await readJson(req, 64 * 1024);
  const key = normalizeLicenseKey(body.licenseKey);
  if (!/^VIP-[A-Z2-9]{5}(?:-[A-Z2-9]{5}){3}$/.test(key)) {
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
  try {
    await client.query('BEGIN');
    const result = await client.query(`SELECT * FROM license_keys WHERE key_hash = $1 FOR UPDATE`, [hashLicenseKey(key)]);
    license = result.rows[0];
    if (!license) {
      minuteCounters.licenseFailures += 1;
      const error = new Error('卡密不存在或输入错误。'); error.statusCode = 401; error.code = 'LICENSE_INVALID'; throw error;
    }
    if (license.status === 'revoked') {
      const error = new Error('此卡密已被停用，请联系平台。'); error.statusCode = 403; error.code = 'LICENSE_REVOKED'; throw error;
    }
    if (license.status === 'superseded') {
      const error = new Error('此卡密已被续费卡替换，请使用最新卡密。'); error.statusCode = 403; error.code = 'LICENSE_REPLACED'; throw error;
    }
    if (license.status === 'archived') {
      const error = new Error('此卡密已归档并停止使用，请联系平台。'); error.statusCode = 403; error.code = 'LICENSE_ARCHIVED'; throw error;
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
        `UPDATE license_keys SET tenant_id=$2,status='active',key_ciphertext=COALESCE(key_ciphertext,$4),activated_at=NOW(),expires_at=$3,last_used_at=NOW(),updated_at=NOW() WHERE id=$1`,
        [license.id, tenantId, expiry.toISOString(), encryptLicenseKey(key)],
      );
      license = { ...license, tenant_id: tenantId, status: 'active', expires_at: expiry };
    } else {
      tenant = await getTenantById(license.tenant_id, client, true);
      if (!tenant) {
        const error = new Error('租户账户不存在，请联系平台。'); error.statusCode = 409; error.code = 'LICENSE_STATE'; throw error;
      }
      const accessIssue = tenantAccessIssue(tenant);
      if (accessIssue === 'LICENSE_REVOKED') {
        throw requestError(
          `你的卡密已被禁用，如有疑问请联系 Telegram ${SUPPORT_TELEGRAM}。`,
          403,
          'LICENSE_REVOKED',
        );
      }
      if (accessIssue === 'TENANT_EXPIRED') {
        const error = new Error('卡密已到期，请购买新卡密续费。'); error.statusCode = 403; error.code = 'TENANT_EXPIRED'; error.expiresAt = new Date(tenant.access_expires_at).toISOString(); throw error;
      }
      await client.query(
        `UPDATE license_keys SET key_ciphertext=COALESCE(key_ciphertext,$2),last_used_at=NOW(),updated_at=NOW() WHERE id=$1`,
        [license.id, encryptLicenseKey(key)],
      );
    }
    await client.query('COMMIT');
  } catch (error) {
    await client.query('ROLLBACK');
    await writeAudit(req, null, 'tenant.login', {
      targetType: 'tenant',
      targetId: license?.tenant_id || '',
      result: 'failed',
      metadata: { code: cleanText(error.code || 'ERROR', 80) },
    }).catch(() => {});
    if (error.code === 'TENANT_EXPIRED') {
      return sendJson(res, error.statusCode, { ok:false,error:error.message,code:error.code,expiresAt:error.expiresAt });
    }
    throw error;
  } finally { client.release(); }
  const config = await getConfig(tenant.id);
  await writeAudit(req, null, 'tenant.login', {
    targetType: 'tenant',
    targetId: tenant.id,
  }).catch(() => {});
  return sendJson(res, 200, {
    ok: true,
    token: signTokenUntil({
      kind:'tenant_admin',
      tenantId:tenant.id,
      licenseId:license.id,
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
      `
        UPDATE tenants
        SET status='active',
            access_expires_at=$2,
            expiry_reminder_sent_at=NULL,
            updated_at=NOW()
        WHERE id=$1
        RETURNING *
      `,
      [tenant.id, newExpiry.toISOString()],
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
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
  updateTenantConnectionsAfterRenewal(tenant.id, newExpiry, newLicense.id);
  return sendJson(res, 200, {
    ok:true,
    token: signTokenUntil({
      kind:'tenant_admin',
      tenantId:tenant.id,
      licenseId:newLicense.id,
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

async function sendAllLicenses(chatId, message) {
  const result = await pool.query(`
    SELECT
      key_ciphertext, key_prefix, key_suffix, duration_code, duration_days, status,
      telegram_user_id, telegram_username, telegram_display_name,
      activated_at, expires_at, revoked_at, created_at
    FROM license_keys
    ORDER BY created_at DESC, id DESC
  `);
  const rows = result.rows;
  const lines = [
    `📋 当前共有 ${rows.length} 张卡密`,
    '⚠️ 以下包含完整卡密，请勿转发到非授权群。',
    '',
  ];
  rows.forEach((row, index) => {
    const fullKey = decryptLicenseKey(row.key_ciphertext);
    const expiry =
      row.status === 'unused'
        ? `首次登录后 ${row.duration_days} 天`
        : formatTelegramDate(row.expires_at);
    lines.push(
      `${index + 1}. ${fullKey || `${licenseHint(row)}（历史卡密可按尾号禁用）`} · ${telegramLicenseStatus(row)}`,
      `生成者：${telegramLicenseCreator(row)}`,
      `生成：${formatTelegramDate(row.created_at)}｜到期：${expiry}`,
      ...(row.revoked_at
        ? [`禁用：${formatTelegramDate(row.revoked_at)}`]
        : []),
      '',
    );
  });
  await sendTelegramChunks(chatId, lines, message);
}

async function processTelegramUpdate(update) {
  const message = update?.message;
  const callback = update?.callback_query;

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
    const revokeMatch = raw.match(
      /^(?:\/revoke(?:@[A-Za-z0-9_]+)?|禁用卡密)\s+(.+)$/i,
    );
    const isList =
      raw === '查看卡密' ||
      raw === '查看所有卡密' ||
      ['/licenses', '/keys'].includes(command);

    if (!isHelp && !isGenerate && !revokeMatch && !isList) return;

    if (!telegramOperatorAllowed(chat, userId)) {
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text: '⛔ 当前用户或群组未被授权使用此机器人。',
        ...telegramThread(message),
      });
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
          '查看卡密：发送“查看卡密”或 /licenses',
        ].join('\n'),
        ...telegramThread(message),
      });
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
          const displayKey =
            (hasFullKey ? key : decryptLicenseKey(row.key_ciphertext)) ||
            licenseHint(row);
          if (row.status === 'revoked') {
            text = `此卡密已经被禁用：${displayKey}`;
          } else {
            await client.query(
              `UPDATE license_keys
               SET status='revoked',
                   key_ciphertext=COALESCE(key_ciphertext,$2),
                   revoked_at=NOW(),
                   updated_at=NOW()
               WHERE id=$1`,
              [row.id, hasFullKey ? encryptLicenseKey(key) : null],
            );
            if (row.tenant_id && row.status === 'active') {
              await client.query(
                `UPDATE tenants
                 SET status='suspended',
                     session_version=session_version+1,
                     updated_at=NOW()
                 WHERE id=$1`,
                [row.tenant_id],
              );
              revokedTenantId = row.tenant_id;
            }
            text = `✅ 已禁用卡密：${displayKey}`;
          }
        }
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      if (revokedTenantId) {
        disconnectTenant(revokedTenantId, {
          type: 'license-revoked',
          message:
            `你的卡密已被禁用，如有疑问请联系 Telegram ${SUPPORT_TELEGRAM}。`,
          supportTelegram: SUPPORT_TELEGRAM,
          at: nowIso(),
        });
      }
      await telegramApi('sendMessage', {
        chat_id: chatId,
        text,
        ...telegramThread(message),
      });
      return;
    }

    if (isList) {
      await sendAllLicenses(chatId, message);
      return;
    }
  }

  if (callback?.data?.startsWith('license:')) {
    const chat = callback.message?.chat;
    const chatId = chat?.id;
    const userId = callback.from?.id;
    const code = callback.data.slice(8);

    if (!telegramOperatorAllowed(chat, userId)) {
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

    await telegramApi('answerCallbackQuery', {
      callback_query_id: callback.id,
      text: '正在生成卡密…',
    }).catch(() => {});

    const created = await createLicenseRecord(code, {
      telegramChatId: chatId,
      telegramUserId: userId,
      telegramUsername: callback.from?.username || '',
      telegramDisplayName: telegramDisplayName(callback.from),
      telegramUpdateId: update.update_id,
    });

    const resultText = [
      `✅ ${created.duration.label}已生成`,
      '',
      `卡密：${created.licenseKey}`,
      `有效时长：首次登录后台后 ${created.duration.days} 天`,
      '',
      '请确认钱包收款成功后，再把卡密发给客户。',
      '客户首次登录后会自动创建独立后台和专属用户端入口。',
    ].join('\n');
    await telegramApi('sendMessage', {
      chat_id: chatId,
      text: resultText,
      reply_markup: {
        inline_keyboard: [
          [
            {
              text: '📋 点击复制全部内容',
              copy_text: { text: resultText },
            },
          ],
        ],
      },
      ...telegramThread(callback.message),
    });
    const selectionMessageId = callback.message?.message_id;
    if (selectionMessageId) {
      await telegramApi('deleteMessage', {
        chat_id: chatId,
        message_id: selectionMessageId,
      }).catch(async () => {
        await telegramApi('editMessageReplyMarkup', {
          chat_id: chatId,
          message_id: selectionMessageId,
          reply_markup: { inline_keyboard: [] },
        }).catch(() => {});
      });
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

async function fetchProviderMetrics() {
  if (providerMetricsCache.expiresAt > Date.now()) {
    return providerMetricsCache;
  }
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
  };
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
  const queryStartedAt = performance.now();
  const [database, tables, business, provider] = await Promise.all([
    pool.query(`
      SELECT
        pg_database_size(current_database())::bigint AS database_size,
        COUNT(*) FILTER (WHERE state = 'active')::int AS active_connections,
        COUNT(*) FILTER (WHERE state = 'idle')::int AS idle_connections
      FROM pg_stat_activity
      WHERE datname = current_database()
    `),
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
  const memory = process.memoryUsage();
  const cpuPercent = sampleCpuPercent();
  const memoryPercent = Number(
    Math.min(
      100,
      (memory.rss / (INSTANCE_MEMORY_MB * 1024 * 1024)) * 100,
    ).toFixed(2),
  );
  const requestCount = minuteCounters.requests;
  const errorRate = requestCount
    ? Number(((minuteCounters.errors / requestCount) * 100).toFixed(2))
    : 0;
  const snapshot = {
    at: nowIso(),
    uptimeSeconds: Math.trunc((Date.now() - startedAt) / 1000),
    application: {
      cpuPercent,
      memoryRssBytes: memory.rss,
      memoryHeapBytes: memory.heapUsed,
      memoryLimitBytes: INSTANCE_MEMORY_MB * 1024 * 1024,
      memoryPercent,
      requestsPerMinute: requestCount,
      errorsPerMinute: minuteCounters.errors,
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
      messagesPerMinute: minuteCounters.messages,
      uploadsPerMinute: minuteCounters.uploads,
      uploadFailuresPerMinute: minuteCounters.uploadFailures,
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
      licenseFailuresPerMinute: minuteCounters.licenseFailures,
      telegramWebhookFailuresPerMinute:
        minuteCounters.telegramWebhookFailures,
    },
    database: {
      connected: true,
      queryLatencyMs: Number((performance.now() - queryStartedAt).toFixed(1)),
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
      cleanupLastRunAt: lastCleanupAt
        ? new Date(lastCleanupAt).toISOString()
        : null,
    },
    provider: {
      render: provider.render,
      neon: provider.neon,
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
  }
  for (const key of Object.keys(minuteCounters)) minuteCounters[key] = 0;
  requestLatencies.length = 0;
  broadcastSuper({ type: 'monitor-updated', monitor: snapshot });
  await evaluateAlerts(snapshot);
  return snapshot;
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
        snapshot.application.uploadFailuresPerMinute >=
          uploadFailureThreshold,
      text: `媒体上传连续失败 ${snapshot.application.uploadFailuresPerMinute} 次`,
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
        lastCleanupAt > 0 &&
        Date.now() - lastCleanupAt > 15 * 60_000,
      text: '消息与媒体清理任务超过15分钟未成功运行',
    },
    {
      code: 'telegram',
      active:
        enabled('telegram') &&
        snapshot.application.telegramWebhookFailuresPerMinute > 0,
      text: `Telegram Webhook 处理失败 ${snapshot.application.telegramWebhookFailuresPerMinute} 次`,
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
    (sum, item) =>
      sum + Number(item.application?.requestsPerMinute || 0),
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
      Math.min(100, (sampleMetrics.length / 1440) * 100).toFixed(2),
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
    `采样可用率：${data.availabilityPercent}%（${data.sampleCount}/1440）`,
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
        remainingHours,
        at: nowIso(),
      },
      null,
      tenant.id,
    );
  }
  if (result.rowCount) broadcastSuper({ type: 'tenants-updated' });
  return result.rowCount;
}

function startBackgroundJobs() {
  setInterval(() => maybeCleanupExpiredData(), 5 * 60_000).unref();
  setInterval(
    () => processObjectDeleteQueue().catch(() => {}),
    5 * 60_000,
  ).unref();
  processExpiryReminders().catch(() => {});
  setInterval(
    () => processExpiryReminders().catch(() => {}),
    60 * 60_000,
  ).unref();
  metricTimer = setInterval(
    () =>
      collectMonitorSnapshot().catch((error) => {
        console.error('监控采集失败：', error.message);
        handleMonitorFailure(error).catch(() => {});
      }),
    60_000,
  );
  metricTimer.unref();
  reportTimer = setInterval(
    () =>
      runScheduledReport().catch((error) =>
        console.error('Telegram 日报发送失败：', error.message),
      ),
    60_000,
  );
  reportTimer.unref();
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
    durationCode: row.duration_code,
    durationDays: Number(row.duration_days),
    status: effectiveLicenseStatus(row),
    storedStatus: row.status,
    generator:
      row.generated_by_username ||
      telegramLicenseCreator(row),
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

async function getSuperDashboard() {
  const result = await pool.query(`
    SELECT
      (SELECT COUNT(*)::int FROM license_keys) AS license_total,
      (SELECT COUNT(*)::int FROM license_keys WHERE status = 'unused') AS license_unused,
      (SELECT COUNT(*)::int FROM license_keys
        WHERE status = 'active' AND expires_at > NOW()) AS license_active,
      (SELECT COUNT(*)::int FROM license_keys
        WHERE status = 'active' AND expires_at <= NOW()) AS license_expired,
      (SELECT COUNT(*)::int FROM license_keys WHERE status = 'revoked') AS license_revoked,
      (SELECT COUNT(*)::int FROM license_keys
        WHERE status IN ('archived','superseded')) AS license_archived,
      (SELECT COUNT(*)::int FROM tenants) AS tenants,
      (SELECT COUNT(*)::int FROM conversations
        WHERE created_at >= date_trunc('day', NOW())) AS visitors_today,
      (SELECT COUNT(*)::int FROM conversations
        WHERE updated_at >= date_trunc('day', NOW())) AS conversations_today,
      (SELECT COUNT(*)::int FROM messages
        WHERE created_at >= date_trunc('day', NOW())) AS messages_today,
      (SELECT COALESCE(SUM(size),0)::bigint FROM attachments) +
        (SELECT COALESCE(SUM(size),0)::bigint FROM assets) AS media_bytes
  `);
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
  };
}

async function getSuperLicenses() {
  const result = await pool.query(`
    SELECT
      l.*, t.name AS tenant_name, sa.username AS generated_by_username
    FROM license_keys l
    LEFT JOIN tenants t ON t.id = l.tenant_id
    LEFT JOIN super_admins sa ON sa.id = l.generated_by_admin_id
    ORDER BY l.created_at DESC
    LIMIT 2000
  `);
  return result.rows.map(publicLicenseRow);
}

async function getSuperTenants() {
  const result = await pool.query(`
    SELECT
      t.*,
      l.id AS license_id,
      l.key_prefix,
      l.key_suffix,
      l.expires_at,
      l.status AS license_status,
      l.generated_by_admin_id,
      sa.username AS generated_by_username,
      tc.retention_hours,
      tc.frontend_template_id,
      ft.name AS frontend_template_name,
      COALESCE(today.visitors,0)::int AS visitors_today,
      COALESCE(today.messages,0)::int AS messages_today,
      COALESCE(media.bytes,0)::bigint AS media_bytes
    FROM tenants t
    LEFT JOIN LATERAL (
      SELECT *
      FROM license_keys
      WHERE tenant_id = t.id
      ORDER BY
        CASE WHEN status = 'active' THEN 0 ELSE 1 END,
        created_at DESC
      LIMIT 1
    ) l ON TRUE
    LEFT JOIN super_admins sa ON sa.id = l.generated_by_admin_id
    LEFT JOIN tenant_config tc ON tc.tenant_id = t.id
    LEFT JOIN frontend_templates ft ON ft.id = tc.frontend_template_id
    LEFT JOIN LATERAL (
      SELECT
        COUNT(DISTINCT c.id) FILTER (
          WHERE m.created_at >= date_trunc('day',NOW())
        ) AS visitors,
        COUNT(m.id) FILTER (
          WHERE m.created_at >= date_trunc('day',NOW())
        ) AS messages
      FROM conversations c
      LEFT JOIN messages m ON m.conversation_id = c.id
      WHERE c.tenant_id = t.id
    ) today ON TRUE
    LEFT JOIN LATERAL (
      SELECT COALESCE(SUM(a.size),0) AS bytes
      FROM conversations c
      JOIN attachments a ON a.conversation_id = c.id
      WHERE c.tenant_id = t.id
    ) media ON TRUE
    ORDER BY t.updated_at DESC
  `);
  return result.rows.map((row) => ({
    id: row.id,
    publicCode: row.public_code,
    name: row.name || '',
    note: row.note || '',
    status: row.status,
    accessExpiresAt: new Date(row.access_expires_at).toISOString(),
    createdAt: new Date(row.created_at).toISOString(),
    lastAdminOnlineAt: row.last_admin_online_at
      ? new Date(row.last_admin_online_at).toISOString()
      : null,
    expiryReminderSentAt: row.expiry_reminder_sent_at
      ? new Date(row.expiry_reminder_sent_at).toISOString()
      : null,
    licenseId: row.license_id || null,
    maskedKey: row.license_id ? licenseHint(row) : '',
    licenseStatus: row.license_status || '',
    generator: row.generated_by_username || 'Telegram/历史记录',
    retentionHours: Number(row.retention_hours || 24),
    frontendTemplateId: row.frontend_template_id || null,
    frontendTemplateName: row.frontend_template_name || '',
    visitorsToday: Number(row.visitors_today || 0),
    messagesToday: Number(row.messages_today || 0),
    mediaBytes: Number(row.media_bytes || 0),
    onlineDevices: [...sseClients].filter(
      (client) =>
        client.kind === 'tenant_admin' && client.tenantId === row.id,
    ).length,
  }));
}

async function handleSuperLogin(req, res) {
  if (!rateLimit(req, res, 'super-login', 10, 15 * 60_000)) return;
  const body = await readJson(req, 32 * 1024);
  const username = cleanText(body.username, 80).toLowerCase();
  const result = await pool.query(
    `SELECT * FROM super_admins WHERE username = $1`,
    [username],
  );
  const row = result.rows[0];
  const passwordOk = row
    ? verifyPassword(body.password, row.password_hash)
    : verifyPassword(body.password, hashPassword('invalid-password'));
  const secret = row?.totp_secret_ciphertext
    ? decryptSecret(row.totp_secret_ciphertext)
    : '';
  if (
    !row?.enabled ||
    !passwordOk ||
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
      secret && passwordOk ? '两步验证码不正确。' : '账号或密码不正确。',
      'SUPER_LOGIN',
    );
  }
  await pool.query(
    `UPDATE super_admins SET last_login_at=NOW() WHERE id=$1`,
    [row.id],
  );
  const token = signToken(
    {
      kind: 'super_admin',
      adminId: row.id,
      sessionVersion: Number(row.session_version),
    },
    8 * 60 * 60,
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

async function handleSuperRoutes(req, res, url, pathname) {
  if (req.method === 'POST' && pathname === '/api/super/login') {
    return handleSuperLogin(req, res);
  }
  const admin = await authenticateSuper(req);
  if (!admin) {
    res.setHeader('Set-Cookie', sessionCookie('', 0));
    return sendError(res, 401, '超级管理员登录已失效。', 'SUPER_AUTH');
  }

  if (req.method === 'POST' && pathname === '/api/super/logout') {
    res.setHeader('Set-Cookie', sessionCookie('', 0));
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
    ]);
    return sendJson(res, 200, {
      ok: true,
      admin,
      dashboard,
      platform,
      templates,
      announcements: announcements.rows,
      releases: releases.rows,
      featureCatalog: featureCatalog.rows,
      featureFlags: featureFlags.rows,
      monitor:
        lastMonitorSnapshot ||
        (await collectMonitorSnapshot({ persist: false })),
    });
  }

  if (req.method === 'GET' && pathname === '/api/super/dashboard') {
    return sendJson(res, 200, {
      ok: true,
      dashboard: await getSuperDashboard(),
    });
  }
  if (req.method === 'GET' && pathname === '/api/super/licenses') {
    return sendJson(res, 200, {
      ok: true,
      licenses: await getSuperLicenses(),
    });
  }
  if (req.method === 'POST' && pathname === '/api/super/licenses') {
    requireRole(admin, 'operations');
    const body = await readJson(req, 32 * 1024);
    const count = Math.min(100, Math.max(1, Math.trunc(Number(body.count || 1))));
    if (!LICENSE_DURATIONS[body.durationCode]) {
      return sendError(res, 400, '卡密时长无效。', 'LICENSE_DURATION');
    }
    const licenses = [];
    for (let index = 0; index < count; index += 1) {
      const created = await createLicenseRecord(body.durationCode, {
        generatedByAdminId: admin.id,
      });
      licenses.push({
        ...publicLicenseRow(created.row),
        fullKey: created.licenseKey,
      });
    }
    await writeAudit(req, admin, 'license.create', {
      targetType: 'license_batch',
      targetId: body.durationCode,
      metadata: { count },
    });
    broadcastSuper({ type: 'licenses-updated' });
    return sendJson(res, 201, { ok: true, licenses });
  }

  const licenseMatch = pathname.match(
    /^\/api\/super\/licenses\/([0-9a-f-]+)(?:\/(reveal|copy))?$/i,
  );
  if (licenseMatch && isUuid(licenseMatch[1])) {
    const licenseId = licenseMatch[1];
    const action = licenseMatch[2] || '';
    if (req.method === 'POST' && action === 'reveal') {
      requireRole(admin, 'operations');
      const result = await pool.query(
        `SELECT * FROM license_keys WHERE id=$1`,
        [licenseId],
      );
      const row = result.rows[0];
      if (!row) return sendError(res, 404, '卡密不存在。', 'NOT_FOUND');
      const fullKey = decryptLicenseKey(row.key_ciphertext);
      if (!fullKey) {
        return sendError(res, 409, '此历史卡密无法恢复完整内容。', 'KEY_UNAVAILABLE');
      }
      await writeAudit(req, admin, 'license.reveal', {
        targetType: 'license',
        targetId: licenseId,
      });
      return sendJson(res, 200, { ok: true, fullKey });
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
      if (!['disable', 'restore', 'archive'].includes(body.action)) {
        return sendError(res, 400, '卡密操作无效。', 'LICENSE_ACTION');
      }
      const databaseClient = await pool.connect();
      let row;
      let disconnectPayload = null;
      try {
        await databaseClient.query('BEGIN');
        const result = await databaseClient.query(
          `SELECT * FROM license_keys WHERE id=$1 FOR UPDATE`,
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
            `UPDATE license_keys SET status='revoked',revoked_at=NOW(),updated_at=NOW() WHERE id=$1`,
            [licenseId],
          );
          if (row.tenant_id) {
            await databaseClient.query(
              `UPDATE tenants SET status='suspended',session_version=session_version+1,updated_at=NOW() WHERE id=$1`,
              [row.tenant_id],
            );
            disconnectPayload = {
              type: 'license-revoked',
              message: `你的卡密已被禁用，如有疑问请联系 Telegram ${SUPPORT_TELEGRAM}。`,
              supportTelegram: SUPPORT_TELEGRAM,
              at: nowIso(),
            };
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
            `UPDATE license_keys SET status=$2,revoked_at=NULL,updated_at=NOW() WHERE id=$1`,
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
      if (row.tenant_id && disconnectPayload) {
        disconnectTenant(row.tenant_id, disconnectPayload);
      }
      await writeAudit(req, admin, `license.${body.action}`, {
        targetType: 'license',
        targetId: licenseId,
      });
      broadcastSuper({ type: 'licenses-updated' });
      return sendJson(res, 200, { ok: true });
    }
    if (req.method === 'DELETE' && !action) {
      requireRole(admin, 'manager');
      const deleted = await pool.query(
        `
          DELETE FROM license_keys
          WHERE id=$1 AND status='unused' AND tenant_id IS NULL
          RETURNING id
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
      return sendJson(res, 200, { ok: true });
    }
  }

  if (req.method === 'GET' && pathname === '/api/super/tenants') {
    return sendJson(res, 200, {
      ok: true,
      tenants: await getSuperTenants(),
    });
  }
  const tenantMatch = pathname.match(
    /^\/api\/super\/tenants\/([0-9a-f-]+)$/i,
  );
  if (tenantMatch && isUuid(tenantMatch[1]) && req.method === 'PATCH') {
    requireRole(admin, 'operations');
    const tenantId = tenantMatch[1];
    const body = await readJson(req, 64 * 1024);
    if (body.action === 'forceLogout') {
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
                OR (status='enabled' AND selection_closed=FALSE)
              )
          `,
          [body.frontendTemplateId],
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
      await pool.query(
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
      await pool.query(
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
      broadcast({ type: 'settings-updated' }, null, tenantId);
    }
    await writeAudit(req, admin, 'tenant.update', {
      targetType: 'tenant',
      targetId: tenantId,
      metadata: { action: body.action || 'settings' },
    });
    broadcastSuper({ type: 'tenants-updated' });
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

  if (req.method === 'GET' && pathname === '/api/super/features') {
    const result = await pool.query(
      `SELECT * FROM feature_catalog ORDER BY category,name`,
    );
    return sendJson(res, 200, { ok: true, features: result.rows });
  }
  if (req.method === 'POST' && pathname === '/api/super/features') {
    requireRole(admin, 'operations');
    const body = await readJson(req, 64 * 1024);
    const code = cleanText(body.code, 80).toLowerCase();
    if (!/^[a-z][a-z0-9_]{2,79}$/.test(code)) {
      return sendError(res, 400, '功能代码格式无效。', 'FEATURE_CODE');
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
        cleanText(body.name, 80) || code,
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
    publishEvent(
      { type: 'feature-catalog-updated' },
      { targetKind: 'tenant_admin' },
    );
    publishEvent(
      { type: 'feature-catalog-updated' },
      { targetKind: 'user' },
    );
    return sendJson(res, 201, { ok: true, id });
  }
  const featureMatch = pathname.match(
    /^\/api\/super\/features\/([0-9a-f-]+)$/i,
  );
  if (featureMatch && isUuid(featureMatch[1]) && req.method === 'PATCH') {
    requireRole(admin, 'operations');
    const body = await readJson(req, 64 * 1024);
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
    publishEvent(
      { type: 'feature-catalog-updated' },
      { targetKind: 'tenant_admin' },
    );
    publishEvent(
      { type: 'feature-catalog-updated' },
      { targetKind: 'user' },
    );
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
      parsed = new URL(cleanText(body.baseUrl, 500));
      if (parsed.protocol !== 'https:') throw new Error();
    } catch {
      return sendError(res, 400, '模板必须使用有效 HTTPS 地址。', 'TEMPLATE_URL');
    }
    parsed.hash = '';
    const baseUrl = parsed.toString();
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
      if (isDefault) {
        await client.query(
          `UPDATE frontend_templates SET is_default=FALSE WHERE is_default=TRUE`,
        );
      }
      await client.query(
        `
          INSERT INTO frontend_templates (
            id,name,base_url,origin,client_version,min_backend_version,
            status,selection_closed,sort_order,recommended,is_default,
            test_tenant_ids
          ) VALUES ($1,$2,$3,$4,$5,$6,$7,FALSE,$8,$9,$10,$11::jsonb)
        `,
        [
          id,
          cleanText(body.name, 80) || parsed.hostname,
          baseUrl,
          parsed.origin,
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
          contractReady: false,
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
        contractReady: contract.contractReady,
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
      if (body.baseUrl !== undefined) {
        try {
          const parsed = new URL(cleanText(body.baseUrl, 500));
          if (parsed.protocol !== 'https:') throw new Error();
          parsed.hash = '';
          baseUrl = parsed.toString();
          origin = parsed.origin;
        } catch {
          return sendError(res, 400, '模板必须使用有效 HTTPS 地址。', 'TEMPLATE_URL');
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
            SELECT id,status,is_default,selection_closed
            FROM frontend_templates
            WHERE id=$1
            FOR UPDATE
          `,
          [templateId],
        );
        if (!current.rows[0]) {
          throw requestError('模板不存在。', 404, 'NOT_FOUND');
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
                UPDATE tenant_config
                SET frontend_template_id=$2,updated_at=NOW()
                WHERE frontend_template_id=$1
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
                client_version=COALESCE($5,client_version),
                min_backend_version=COALESCE($6,min_backend_version),
                status=COALESCE($7,status),
                selection_closed=COALESCE($8,selection_closed),
                sort_order=COALESCE($9,sort_order),
                recommended=COALESCE($10,recommended),
                is_default=CASE WHEN $11::boolean THEN TRUE ELSE is_default END,
                test_tenant_ids=COALESCE($12::jsonb,test_tenant_ids),
                updated_at=NOW()
            WHERE id=$1
          `,
          [
            templateId,
            body.name === undefined ? null : cleanText(body.name, 80),
            baseUrl,
            origin,
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
    const result = await pool.query(`
      SELECT al.*, sa.username
      FROM audit_logs al
      LEFT JOIN super_admins sa ON sa.id=al.actor_admin_id
      ORDER BY al.created_at DESC
      LIMIT 1000
    `);
    return sendJson(res, 200, { ok: true, logs: result.rows });
  }
  if (req.method === 'GET' && pathname === '/api/super/monitor') {
    return sendJson(res, 200, {
      ok: true,
      monitor:
        lastMonitorSnapshot ||
        (await collectMonitorSnapshot({ persist: false })),
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
    await pool.query(
      `
        UPDATE platform_settings
        SET brand_name=COALESCE($1,brand_name),
            support_telegram=COALESCE($2,support_telegram),
            telegram_group_id=COALESCE($3,telegram_group_id),
            report_time=COALESCE($4,report_time),
            report_timezone=COALESCE($5,report_timezone),
            daily_report_enabled=COALESCE($6,daily_report_enabled),
            weekly_report_enabled=COALESCE($7,weekly_report_enabled),
            alert_settings=COALESCE($8::jsonb,alert_settings),
            updated_at=NOW()
        WHERE id=1
      `,
      [
        body.brandName === undefined ? null : cleanText(body.brandName, 80),
        body.supportTelegram === undefined
          ? null : cleanText(body.supportTelegram, 80),
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

  if (req.method === 'GET' && pathname === '/api/super/admins') {
    requireRole(admin, 'manager');
    const result = await pool.query(`
      SELECT id,username,role,enabled,last_login_at,created_at
      FROM super_admins
      ORDER BY created_at
    `);
    return sendJson(res, 200, { ok: true, admins: result.rows });
  }
  if (req.method === 'POST' && pathname === '/api/super/admins') {
    requireRole(admin, 'owner');
    const body = await readJson(req, 32 * 1024);
    const username = cleanText(body.username, 80).toLowerCase();
    if (!/^[a-z0-9_.-]{3,80}$/.test(username)) {
      return sendError(res, 400, '管理员账号格式无效。', 'ADMIN_USERNAME');
    }
    if (String(body.password || '').length < 12) {
      return sendError(res, 400, '管理员密码至少需要12位。', 'ADMIN_PASSWORD');
    }
    const role = ['manager','operations','support','readonly'].includes(body.role)
      ? body.role : 'readonly';
    const id = randomUUID();
    await pool.query(
      `
        INSERT INTO super_admins (
          id,username,password_hash,role,totp_secret_ciphertext
        ) VALUES ($1,$2,$3,$4,$5)
      `,
      [
        id,
        username,
        hashPassword(body.password),
        role,
        body.totpSecret
          ? encryptSecret(
              cleanText(body.totpSecret, 128).replace(/\s+/g, '').toUpperCase(),
            )
          : null,
      ],
    );
    await writeAudit(req, admin, 'super_admin.create', {
      targetType: 'super_admin',
      targetId: id,
      metadata: { role },
    });
    return sendJson(res, 201, { ok: true, id });
  }
  const superAdminMatch = pathname.match(
    /^\/api\/super\/admins\/([0-9a-f-]+)$/i,
  );
  if (
    superAdminMatch &&
    isUuid(superAdminMatch[1]) &&
    req.method === 'PATCH'
  ) {
    requireRole(admin, 'owner');
    const targetId = superAdminMatch[1];
    const body = await readJson(req, 32 * 1024);
    const current = await pool.query(
      `SELECT id,role,enabled FROM super_admins WHERE id=$1`,
      [targetId],
    );
    if (!current.rows[0]) {
      return sendError(res, 404, '管理员不存在。', 'NOT_FOUND');
    }
    if (targetId === admin.id && body.enabled === false) {
      return sendError(res, 409, '不能停用当前登录账号。', 'ADMIN_SELF');
    }
    const nextRole = body.role === undefined
      ? null
      : ['owner','manager','operations','support','readonly'].includes(body.role)
        ? body.role : 'readonly';
    const removesOwner =
      current.rows[0].role === 'owner' &&
      (nextRole && nextRole !== 'owner' || body.enabled === false);
    if (removesOwner) {
      const owners = await pool.query(
        `SELECT COUNT(*)::int AS count FROM super_admins WHERE role='owner' AND enabled=TRUE`,
      );
      if (Number(owners.rows[0].count) <= 1) {
        return sendError(res, 409, '必须至少保留一个启用的所有者。', 'LAST_OWNER');
      }
    }
    if (body.password !== undefined && String(body.password).length < 12) {
      return sendError(res, 400, '管理员密码至少需要12位。', 'ADMIN_PASSWORD');
    }
    const encryptedTotp = body.clearTotp
      ? null
      : body.totpSecret === undefined
        ? undefined
        : encryptSecret(
            cleanText(body.totpSecret, 128)
              .replace(/\s+/g, '')
              .toUpperCase(),
          );
    await pool.query(
      `
        UPDATE super_admins
        SET role=COALESCE($2,role),
            enabled=COALESCE($3,enabled),
            password_hash=COALESCE($4,password_hash),
            totp_secret_ciphertext=CASE
              WHEN $5::boolean THEN $6
              ELSE totp_secret_ciphertext
            END,
            session_version=session_version+1,
            updated_at=NOW()
        WHERE id=$1
      `,
      [
        targetId,
        nextRole,
        body.enabled === undefined ? null : Boolean(body.enabled),
        body.password === undefined ? null : hashPassword(body.password),
        encryptedTotp !== undefined,
        encryptedTotp === undefined ? null : encryptedTotp,
      ],
    );
    await writeAudit(req, admin, 'super_admin.update', {
      targetType: 'super_admin',
      targetId,
      metadata: {
        role: nextRole,
        enabled:
          body.enabled === undefined ? current.rows[0].enabled : Boolean(body.enabled),
      },
    });
    return sendJson(res, 200, { ok: true });
  }

  return sendError(res, 404, '超级管理员接口不存在。', 'NOT_FOUND');
}

async function router(req, res) {
  maybeCleanupExpiredData();
  await refreshApprovedOrigins();
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
  if (
    REQUIRE_CLOUDFLARE &&
    pathname.startsWith('/api/') &&
    pathname !== '/api/telegram/webhook' &&
    (
      !req.headers['cf-ray'] ||
      !timingSafeTextEqual(
        req.headers['x-tuojie-origin-secret'],
        CLOUDFLARE_ORIGIN_SECRET,
      )
    )
  ) {
    return sendError(res, 403, '请求必须通过 Cloudflare。', 'CLOUDFLARE_REQUIRED');
  }

  if (req.method === 'GET' && pathname === '/health') {
    const dbResult = await pool.query('SELECT NOW() AS now');
    return sendJson(res, 200, {
      ok: true,
      service: 'tuojie-cloud-service',
      version: APP_VERSION,
      database: 'neon-postgresql',
      mediaStorage: R2_ENABLED ? 'cloudflare-r2' : 'postgres-fallback',
      defaultRetentionHours: RETENTION_HOURS,
      telegramBotEnabled: TELEGRAM_ENABLED,
      superAdminReady: Boolean(
        (await pool.query(`SELECT 1 FROM super_admins WHERE enabled=TRUE LIMIT 1`))
          .rows[0],
      ),
      databaseTime: new Date(dbResult.rows[0].now).toISOString(),
    });
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
      `SELECT * FROM assets WHERE id=$1`,
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
    return handleSuperRoutes(req, res, url, pathname);
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
    if (!rateLimit(req, res, 'new-session', 20, 60_000)) return;
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
    const selectedTemplateId = config.settings.frontendTemplateId;
    if (
      !isUuid(selectedTemplateId) ||
      (body.clientTemplateId &&
        body.clientTemplateId !== selectedTemplateId)
    ) {
      return sendError(
        res,
        403,
        '此链接不是该租户当前选择的用户端。',
        'CLIENT_TEMPLATE',
      );
    }
    const template = await pool.query(
      `
        SELECT id
        FROM frontend_templates
        WHERE id=$1
          AND ($2::text = '' OR origin=$2)
          AND (
            status='enabled'
            OR (
              status='testing'
              AND EXISTS (
                SELECT 1
                FROM jsonb_array_elements_text(test_tenant_ids) allowed(id)
                WHERE allowed.id=$3::text
              )
            )
          )
      `,
      [selectedTemplateId, requestOrigin, tenant.id],
    );
    if (!template.rows[0]) {
      return sendError(
        res,
        403,
        '当前用户端未通过平台批准，或租户已切换其他模板。',
        'CLIENT_TEMPLATE',
      );
    }
    const resolvedClientTemplateId = template.rows[0].id;
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
      const countResult = await pool.query(
        `SELECT COUNT(*)::int AS count FROM conversations WHERE tenant_id=$1`,
        [tenant.id],
      );
      if (countResult.rows[0].count >= MAX_CONVERSATIONS) {
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
          Number.isFinite(downlink) ? downlink : null,
          Number.isFinite(rtt) ? Math.trunc(rtt) : null,
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
    const conversation = await getPublicConversation(
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
        },
        tenant.access_expires_at,
      ),
      conversation,
      settings: config.settings,
      featureFlags,
    });
  }

  if (req.method === 'GET' && pathname === '/api/events') {
    const superAdmin = parseCookies(req)[SESSION_COOKIE]
      ? await authenticateSuper(req)
      : null;
    const payload = superAdmin
      ? {
          kind: 'super_admin',
          adminId: superAdmin.id,
        }
      : authenticate(req);
    if (
      !payload ||
      !['user', 'tenant_admin', 'super_admin'].includes(payload.kind)
    ) {
      return sendError(res, 401, '登录已失效。', 'AUTH');
    }

    let tenant = null;
    if (payload.kind !== 'super_admin') {
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
      const conversation = await getConversationRow(payload.conversationId, pool, false, payload.tenantId);
      if (!conversation || !authorizeConversation(payload, conversation)) return sendError(res,401,'会话已失效。','AUTH');
      await touchConversation(conversation.id,{},req,payload.tenantId);
    }
    const connectionIdentity =
      payload.kind === 'super_admin'
        ? payload.adminId
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
      tenantId: payload.tenantId,
      conversationId: payload.conversationId || null,
      licenseId: payload.licenseId || null,
      adminId: payload.adminId || null,
      accessExpiresAt:
        payload.kind === 'super_admin'
          ? Date.now() + 8 * 60 * 60_000
          : new Date(tenant.access_expires_at).getTime(),
    };
    sseClients.add(client);
    replayEvents(
      client,
      req.headers['last-event-id'] || url.searchParams.get('lastEventId'),
    );
    sendSse(
      res,
      { type: 'connected', at: nowIso(), eventId: nextEventId },
      nextEventId++,
    );
    if (payload.kind === 'tenant_admin') {
      await pool.query(
        `UPDATE tenants SET last_admin_online_at=NOW() WHERE id=$1`,
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
      sseClients.delete(client);
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
    const conversation = await getConversationRow(payload.conversationId, pool, false, payload.tenantId);
    if (!conversation || !authorizeConversation(payload, conversation)) return sendError(res,401,'访客会话不存在。','AUTH');
    await touchConversation(conversation.id,{},req,payload.tenantId);

    if (req.method === 'GET' && pathname === '/api/user/conversation') {
      const [publicConversation, config, featureFlags] = await Promise.all([
        getPublicConversation(conversation.id, pool, payload.tenantId),
        getConfig(payload.tenantId),
        getTenantFeatureStates(payload.tenantId),
      ]);
      return sendJson(res, 200, {
        ok: true,
        conversation: publicConversation,
        settings: config.settings,
        featureFlags,
      });
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
      await touchConversation(
        conversation.id,
        body,
        req,
        payload.tenantId,
      );
      const updated = await getConversationRow(
        conversation.id,
        pool,
        false,
        payload.tenantId,
      );
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
        )
      ) return;
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
        messages: result.messages,
        autoReply: result.autoReply,
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

    if (req.method === 'GET' && pathname === '/api/admin/bootstrap') {
      const tenant = activeTenant;
      const [conversations, config, templates, notices] = await Promise.all([
        getAllSummaries(payload.tenantId),
        getConfig(payload.tenantId),
        getTemplateCatalog({ tenantId: payload.tenantId }),
        getTenantNotices(payload.tenantId),
      ]);
      return sendJson(res, 200, {
        ok: true,
        tenant: publicTenant(tenant),
        conversations,
        cannedReplies: config.cannedReplies,
        autoReplies: config.autoReplies,
        settings: config.settings,
        templates,
        entryUrl: tenantEntryUrl(config.settings, tenant.public_code),
        ...notices,
      });
    }

    if (req.method === 'GET' && pathname === '/api/admin/conversations') {
      const conversations = await getAllSummaries(payload.tenantId);
      return sendJson(res, 200, {
        ok: true,
        tenant: publicTenant(activeTenant),
        conversations,
      });
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
        ...notices,
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
      await writeAudit(req, null, 'tenant.config.update', {
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
      });
    }

    if (
      req.method === 'POST' &&
      pathname === '/api/admin/brand/avatar'
    ) {
      await requireTenantFeature('tenant_branding', payload.tenantId);
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
      await writeAudit(req, null, 'tenant.avatar.update', {
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
      await writeAudit(req, null, 'tenant.avatar.delete', {
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

    if (req.method === 'GET' && pathname === '/api/admin/qr') {
      const config = await getConfig(payload.tenantId);
      const previewTemplateId = cleanText(
        url.searchParams.get('templateId'),
        80,
      );
      let entrySettings = config.settings;
      if (previewTemplateId) {
        if (!isUuid(previewTemplateId)) {
          return sendError(res, 400, '用户端模板无效。', 'FRONTEND_TEMPLATE');
        }
        const template = await pool.query(
          `
            SELECT id,base_url
            FROM frontend_templates
            WHERE id=$1
              AND (
                status='enabled'
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
          [previewTemplateId, payload.tenantId],
        );
        if (!template.rows[0]) {
          return sendError(res, 404, '用户端模板不可用。', 'FRONTEND_TEMPLATE');
        }
        entrySettings = {
          ...entrySettings,
          frontendBaseUrl: template.rows[0].base_url,
        };
      }
      const entryUrl = tenantEntryUrl(entrySettings, activeTenant.public_code);
      const image = await QRCode.toBuffer(entryUrl, {
        type: 'png',
        width: 720,
        margin: 3,
        errorCorrectionLevel: 'M',
        color: { dark: '#121827', light: '#ffffff' },
      });
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
        return sendJson(res, 200, {
          ok: true,
          ...(await deleteAdminMessage(
            conversationId,
            messageId,
            payload.tenantId,
          )),
        });
      }
      if (
        req.method === 'POST' &&
        messageActionMatch[3] === 'recall'
      ) {
        return sendJson(res, 200, {
          ok: true,
          ...(await recallAdminMessage(
            conversationId,
            messageId,
            payload.tenantId,
          )),
        });
      }
    }

    const match = pathname.match(
      /^\/api\/admin\/conversations\/([^/]+)(?:\/(messages|uploads|read))?$/,
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
        await markConversationRead(
          conversationId,
          payload.tenantId,
          'admin',
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
                        : publicConversation.messages.at(-1).type === 'video'
                          ? publicConversation.messages.at(-1).text || '[视频]'
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
        const result = await createAdminMessage(conversationId, body, payload.tenantId);
        broadcast(
          {
            type: 'conversation-updated',
            trigger: 'admin-message',
            conversation: result.conversation,
          },
          conversationId,
          payload.tenantId,
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

    const attachmentId = safeDecodeURIComponent(
      pathname.slice('/api/media/'.length),
    );
    if (!isUuid(attachmentId)) {
      return sendError(res, 404, '媒体不存在。', 'NOT_FOUND');
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
      `inline; filename="${ALLOWED_VIDEO_TYPES.has(row.mime) ? 'video' : 'image'}"`,
    );
    return res.end(data);
  }

  return sendError(res, 404, '接口不存在。', 'NOT_FOUND');
}

const server = http.createServer((req, res) => {
  const requestStartedAt = performance.now();
  minuteCounters.requests += 1;
  res.once('finish', () => {
    const duration = performance.now() - requestStartedAt;
    requestLatencies.push(duration);
    if (requestLatencies.length > 5000) {
      requestLatencies.splice(0, requestLatencies.length - 5000);
    }
    if (res.statusCode >= 400) minuteCounters.errors += 1;
  });
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
collectMonitorSnapshot().catch((error) =>
  console.error('首次监控采集失败：', error.message),
);

server.listen(PORT, HOST, () => {
  console.log(`拓界云客服 v${APP_VERSION} 已启动：http://${HOST}:${PORT}`);
  console.log(`媒体存储：${R2_ENABLED ? 'Cloudflare R2' : 'PostgreSQL 兼容模式'}`);
  console.log(`Telegram 发卡机器人：${TELEGRAM_ENABLED ? '已启用' : '未启用'}`);
});
