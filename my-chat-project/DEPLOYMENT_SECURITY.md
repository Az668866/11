# 生产部署安全清单

本清单是上线门禁，不是建议项。任何标为“必须”的项目未完成时，不要把包部署到正式环境。

## 一、升级前必须完成

1. 为 PostgreSQL/Neon 创建可恢复快照，并实际确认恢复权限与最近一次恢复演练时间。
2. 保留当前后端、前端部署包以及当前全部环境变量的加密备份；不要把密钥写入工单、聊天或仓库。
3. 保持单实例运行。当前 SSE、在线状态和部分事件广播是进程内状态，在接入共享事件总线前不得横向扩容。
4. 在独立数据库分支运行 `npm run test:integration`，再按 `load/README.md` 从 100 并发逐级压测。真实数据库集成回归和必要容量验证未通过时不得上线。

## 二、数据保护密钥迁移（顺序不可改变）

旧版本用 `TOKEN_SECRET` 同时保护令牌、卡密、TOTP 和加密语音。新版本将持久化数据改由 `DATA_PROTECTION_SECRET` 保护，目的是允许以后轮换令牌密钥而不损坏数据。

首次升级必须执行：

1. 读取正式环境当前 `TOKEN_SECRET` 的真实值，不生成新值。
2. 新增 `DATA_PROTECTION_SECRET`，其值必须与升级前的 `TOKEN_SECRET` 完全相同。
3. 保持原 `TOKEN_SECRET` 不变，先部署新后端。
4. 等待 `/health/ready` 返回 200，并确认启动日志没有 `data_protection_secret_fallback` 或密钥不匹配错误。
5. 验证一张历史卡密登录、管理员 TOTP 和一条历史语音读取。
6. 只有上述验证完成后，才可以在单独维护窗口轮换 `TOKEN_SECRET`。轮换会让所有现有令牌立即失效，所有管理员、代理和租户需重新登录。

新后端会把不可逆校验标记写入 `data_protection_state`。以后误填或误轮换 `DATA_PROTECTION_SECRET` 时，服务会在同步管理员凭据和处理业务前停止启动。不得删除该表绕过保护，也不得轮换 `DATA_PROTECTION_SECRET`；若确需轮换，必须另做带校验的全量数据重加密迁移。

## 三、环境变量与账号

- `TOKEN_SECRET`：至少 32 位高熵随机值，只用于令牌及短期安全状态。
- `DATA_PROTECTION_SECRET`：至少 32 位；首次升级必须复制旧 `TOKEN_SECRET`，以后固定不变。
- `SUPER_ADMIN_PASSWORD`、`SUPER_ADMIN_PASSWORD_2`：至少 8 位且唯一，建议使用数字、大小写字母和符号组合，禁止复用个人密码。
- `SUPER_ADMIN_TOTP_SECRET` 与 `REQUIRE_SUPER_ADMIN_TOTP=true`：正式环境必须配置。若有第二个环境变量管理员，也必须单独配置其 TOTP。
- 环境变量中的 owner 管理员是权威名单；不在该名单中的旧 owner 会被停用并撤销会话。部署前核对两个可用的应急管理员。
- `COOKIE_DOMAIN` 保持空值，使用 Host-only Cookie；`COOKIE_SECURE=true`。
- `LEGACY_API_ENABLED=false`、`STRICT_CLIENT_ORIGIN=true`、`REQUIRE_CLIENT_TEMPLATE_ID=true`。
- Telegram 启用时必须同时设置 webhook secret、显式用户白名单；群内敏感操作还必须命中显式群白名单。群管理员身份本身不授予平台权限。
- R2、TURN、Web Push、Telegram、Render、Neon、Cloudflare 密钥分别使用最小权限账号，不得复用。

## 四、网络边界

1. 全站只允许 HTTPS；Netlify 响应头包含一年 HSTS、CSP、`frame-ancestors 'none'`、`nosniff` 和严格 Referrer Policy。
2. `ALLOWED_ORIGINS` 只填写实际管理端域名；用户模板来源由后台模板表加载。不得使用 `*` 或允许任意凭据来源。
3. 先在 Cloudflare 配置源站 secret、Worker/Transform Rule 和阻止直连的规则，验证健康检查与 Telegram webhook 例外，再把 `REQUIRE_CLOUDFLARE=true`。保持 false 只适用于尚未完成源站保护的预发布环境。
4. 数据库和 R2 不暴露公网管理入口；部署账号只拥有应用需要的数据库权限。
5. `/health` 仅做存活检查；负载均衡就绪检查使用 `/health/ready`。不要把管理员账号、连接串或密钥写入健康检查输出。

## 五、数据库与容量

- 新增表：`auth_sessions`、`auth_attempt_limits`、`license_generation_requests`、`data_protection_state`；均为增量创建，不删除现有业务表。
- 首次启动必须等待迁移事务提交后再放量。启动失败时保持旧实例服务，不要反复重启绕过错误。
- 每实例连接池为 `DB_POOL_MAX`。总连接上限必须满足：实例数 × 池大小 + 运维连接 < 数据库最大连接数的 80%。当前只批准 1 个应用实例。
- 卡密、余额、订单、权限和通话状态不得加最终一致缓存。现有配置缓存只用于低变化非敏感数据。
- 保持 `MAX_SSE_CONNECTIONS`、上传并发和媒体大小限制；容量不足应通过压测和架构设计解决，不能直接删除保护阈值。

## 六、可观测性和告警

应用会输出结构化 `requestId`、路由、状态、耗时、SQL 次数、SQL 总耗时、慢 SQL 摘要和错误码，不记录 SQL 参数、Authorization、Cookie、Token 或完整卡密。生产日志平台必须继续执行字段脱敏与最小权限访问。

至少配置以下告警：5xx/429 异常增长、P95/P99、进程 CPU/RSS/重启、数据库连接/CPU/锁等待/慢查询、R2/TURN/Telegram 超时、异常登录、权限失败、卡密生成/查看/禁用/兑换，以及备份失败。`SLOW_API_MS=1000`、`SLOW_QUERY_MS=500` 可作为初始阈值，压测后再按证据调整。

## 七、部署和验收顺序

1. 冻结写操作，创建快照并记录当前包/环境变量校验值。
2. 按“数据保护密钥迁移”设置环境变量，部署后端。
3. 确认 `/health/live`、`/health/ready`、迁移日志和关键历史数据。
4. 部署超级管理员、代理、租户后台，再部署各用户端；不能只替换 HTML，必须上传站点完整目录。
5. 所有旧特权令牌会因为缺少数据库会话 ID 而失效，这是预期安全行为；重新登录验证 MFA。
6. 执行管理员/代理/租户、卡密、消息、上传、通知、语音/视频通话、移动端与桌面端冒烟回归。
7. 观察至少一个业务高峰周期；发生权限、卡密、数据一致性或密钥错误时立即按 `ROLLBACK.md` 回滚。
