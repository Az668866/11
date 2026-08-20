# Strix 复测说明

本机检查日期：2026-08-20

本机当前没有 Docker/Podman、没有 Strix 命令，也没有 OpenAI、Anthropic、Gemini 或 OpenRouter 模型 API Key。开源版 Strix 依赖容器运行时和模型提供方密钥，因此本次无法启动真实 Strix 代理扫描。

本次已先完成同范围白盒审计、依赖审计、密钥模式扫描、动态代码模式扫描与 109 项自动化回归，结果记录在《修复与安全检查报告_2026-08-20.md》。

补齐 Docker Desktop、Strix 和模型密钥后，在本源码目录执行：

```powershell
strix -n -t ./ --scan-mode standard --max-budget 10
```

建议先在本地隔离测试数据库运行，不要把生产数据库、生产卡密、生产 Telegram Token 或生产管理员密码交给测试代理。Strix 结果默认保存在当前目录下的 `strix_runs`，复测后应逐项人工确认再合并修复。

