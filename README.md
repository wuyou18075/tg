# 流量汇报（Telegram + Cloudflare）

## 一键部署（参考）

```bash
# 1. 创建 D1 数据库
wrangler d1 create traffic-db
# 把返回的 database_id 填入 wrangler.toml

# 2. 配置密钥
wrangler secret put REPORT_TOKEN    # agent 上报 cftoken，生成命令时会引用
wrangler secret put DASH_PASSWORD   # 看板登录密码

# 3. 部署
wrangler deploy
```

> D1 表结构会在 Worker 首次请求时自动创建，无需手动执行 schema.sql。

## 使用流程

### 1. 打开看板
访问 `https://traffic-dashboard.xxx.workers.dev/`，用 `DASH_PASSWORD` 登录。

### 2. 设置 → 保存 TG 配置
在看板点「设置」标签，填入：
- **Telegram Bot Token** 和 **Chat ID**（TG 日报用）
- 可选修改 **TG 汇报时间**（默认 `20:00:00`）和 **CF 汇报 cron**（默认 `0 * * * *` 每小时）

### 3. 添加 VPS
切回「看板」标签，点「＋ 添加 VPS」→ 输入机器 ID（如 `hk-1`）→ 点「生成命令」→ 复制命令 → 在目标 VPS 上执行即可。

生成的命令示例：

```bash
ttoken='123456:ABC...' tid='-1001234567890' ttime='20:00:00' \
cftime='0 * * * *' \
cfurl='https://traffic-dashboard.xxx.workers.dev/api/report' \
cftoken='your-report-token' \
mid='hk-1' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

## 参数说明

| 变量 | 含义 | 默认 |
|------|------|------|
| `ttoken` | Telegram Bot Token | 页面设置 |
| `tid` | Telegram Chat ID | 页面设置 |
| `ttime` | TG 汇报时间 `HH:MM:SS` | `20:00:00` |
| `cftime` | CF 汇报 cron（5 段） | `0 * * * *` |
| `cfurl` | Worker 上报地址 | 自动生成 |
| `cftoken` | 上报 Bearer Token | `REPORT_TOKEN` secret |
| `mid` | 机器 ID | 生成时输入 |

## 看板功能

- 密码登录（HttpOnly Cookie，7 天）
- 历史曲线（Chart.js，今日入/出/合计 GB，支持 24h～30d）
- 机器列表 + 在线状态（2h 内有上报为在线）
- 配置面板（ttoken/tid/ttime/cftime 保存到 D1）
- 添加 VPS 一键生成命令，直接复制到机器执行

## 运维

```bash
systemctl status traffic-telegram-report.timer
systemctl status traffic-telegram-report-cf.timer
journalctl -u traffic-telegram-report.service -u traffic-telegram-report-cf.service
bash sum.sh --uninstall
```
