# 租户独占入口 Worker

此 Worker 根据访问域名向 Render 后端查询租户入口，再反向代理对应的 Netlify 用户端模板。浏览器地址栏始终保留租户独占的 HTTPS 域名。

每个租户的每个可用模板会自动拥有一个域名。入口轮换后，未被访问平台拦截的旧域名会自动跳转到最新域名；如果旧域名在请求到达 Worker 前已经被微信拦截，则必须使用租户后台新生成的二维码。

## Cloudflare 配置

1. 创建一个 Worker，将 `worker.js` 作为代码部署。
2. 普通变量：
   - `BACKEND_API_BASE=https://api.ykf000.com`
   - `RESERVED_HOSTS=api.ykf000.com,go.ykf000.com,www.ykf000.com,ykf000.com`
   - `RESOLVE_CACHE_SECONDS=30`
3. Secret：`TENANT_ENTRY_GATEWAY_SECRET`，必须与 Render 同名环境变量完全一致。
4. DNS 添加一条橙色云泛解析：`A  *  192.0.2.1`。
5. Worker 路由添加：`*.ykf000.com/*`。
6. 为已有精确服务添加“不运行 Worker”的更具体路由，或把这些域名加入 `RESERVED_HOSTS`：
   - `api.ykf000.com/*`
   - `go.ykf000.com/*`
   - `www.ykf000.com/*`
7. 测试一个数据库已分配的入口域名，确认 HTTPS、页面资源、聊天连接、图片和通话功能正常。

不要把 `TENANT_ENTRY_GATEWAY_SECRET` 写进 Git 或普通变量。
