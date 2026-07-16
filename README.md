# CF 看板 (vps-cf-tg)

多 VPS 流量看板：Cloudflare Worker + D1 集中存储，VPS 定时上报，支持 Web 看板、历史曲线、TG 汇总、离线告警。

[![部署到 Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wuyou18075/tg)

---

## 两种用法

| 方案 | 适用 | 需要 CF | 需要看板 | 消息怎么发 |
|------|------|--------|---------|-----------|
| **方案一：仅 TG 日报** | 只想在 TG 收每台 VPS 流量日报 | ❌ | ❌ | VPS 直接发 TG |
| **方案二：CF 看板** | 要 Web 看板、多机管理、历史曲线、离线告警 | ✅ | ✅ | 看板统一发 TG 汇总 |

---

## 方案一：仅 TG 日报（VPS 独立，无需 Cloudflare）

每台 VPS 自己定时把 vnStat 流量发到你的 Telegram，不依赖 Worker / D1 / 看板。

### 参数

在 VPS（Debian 13）上用环境变量传参：

| 参数 | 含义 | 格式 / 示例 | 必填 |
|------|------|------------|------|
| `t_token` | TG 机器人 Token | `123456789:ABCdef...`（BotFather 创建后获得） | ✅ |
| `t_id` | 聊天/群 ID | `-1001234567890`（群为负，个人为正） | ✅ |
| `t_time` | 每天发送时间 | `HH:MM:SS`，默认 `20:00:00` | ❌ |

获取 Token / ID：

1. Telegram 找 [@BotFather](https://t.me/BotFather) → `/newbot` → 拿到 `t_token`
2. 把机器人拉进群或私聊它一条消息，访问 `https://api.telegram.org/bot<你的t_token>/getUpdates` → 取 `chat.id` 作为 `t_id`

### 安装

```bash
t_token='123456789:ABCdef...' t_id='-1001234567890' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

自定义时间：`t_time='09:30:00'`。

### 运维

```bash
systemctl status traffic-telegram-report.timer   # 定时器
systemctl start  traffic-telegram-report.service # 立即发一次
journalctl -u traffic-telegram-report.service    # 日志
```

> 方案一**不涉及** `access_token`、Cloudflare——VPS 只和你的 Telegram 机器人通信。

---

## 方案二·A：GitHub Actions 部署（默认，自动建 D1）

日常更新代码用这条。Actions 会**自动查找/创建 D1**，无需手填 `database_id`。

### 1. 配 GitHub Secrets

仓库 → Settings → Secrets and variables → Actions：

| Secret | 说明 |
|--------|------|
| `CLOUDFLARE_API_TOKEN` | CF API Token（需含 Workers Scripts:Edit、D1:Edit） |
| `CLOUDFLARE_ACCOUNT_ID` | CF 账号 ID |

### 2. 选部署来源 `.deploy-mode`

仓库根 `.deploy-mode` 文件写一个词：

| 内容 | 谁部署 | 说明 |
|------|--------|------|
| `github`（默认） | GitHub Actions | 自动建/找 D1，部署 Worker |
| `cf` | Cloudflare Workers Builds | Actions 自动跳过 |

改完 `git push` 即切换。

### 3. 加业务变量

CF Dashboard → Worker `cf-tg-web` → Settings → Variables → **添加加密变量**（不是明文）：

| 变量 | 说明 |
|------|------|
| `PASSWORD` | 看板登录密码（必填） |
| `SESSION_SECRET` | 可选。会话 Cookie 签名密钥；不填则用 `PASSWORD`。建议单独设随机长串：改登录密码时不必全员重新登录；轮换 `SESSION_SECRET` 可强制全部下线 |
| `TG_TOKEN` | TG 机器人 Token（可选） |
| `TG_ID` | TG Chat ID（可选） |

> 加密变量 `wrangler deploy` 不会删；明文变量会被清。所以一定加成 Encrypted。
>
> **会话失效：** 改 `SESSION_SECRET`（或未单独设置时改 `PASSWORD`）会使已有登录 Cookie 失效，需重新登录。
### 4. push 部署

```bash
git push origin main
```

Actions 流程：查找 D1 `tg-cf-web` → 不存在则创建 → 写 UUID → `wrangler deploy`。D1 表首次访问自动建。

---

## 方案二·B：CF 看板一键部署（新用户备选）

点按钮，Cloudflare 打开部署表单：

[![部署到 Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wuyou18075/tg)

表单参数（建成**加密变量**，可在 Dashboard 改）：

| 参数 | 必填 | 含义 | 来源 |
|------|------|------|------|
| `PASSWORD` | ✅ | 看板登录密码 | 自己设 |
| `SESSION_SECRET` | ❌ | 会话签名密钥（建议随机长串） | 自己设；不填则用 PASSWORD |
| `TG_TOKEN` | ❌ | TG 机器人 Token（发汇总用） | BotFather |
| `TG_ID` | ❌ | TG 聊天/群 ID | getUpdates 取 |
| D1 数据库 | 自动 | 存机器/历史/token | CF 自动创建并绑定 |

部署后：打开 Worker 地址 → 用 `PASSWORD` 登录 → 「添加 VPS」生成安装命令。

---

## 通信规则

三条链路，各自认证：

```
① 定时上报   VPS ──每小时──▶ Worker /api/report     （该机 access_token, Bearer）
② 获取流量   Worker ──TCP签名──▶ VPS :19840/force-report（该机 access_token, Bearer+HMAC）
③ TG 汇总    Worker ──▶ Telegram Bot API             （TG_TOKEN 机器人 Token）
```

| 链路 | 凭证 | 频率 |
|------|------|------|
| ① 上报 | 该机 `access_token` | 每小时（`cf_time` 可改） |
| ② 获取流量 | 该机 `access_token` | 手动点按钮 |
| ③ TG 汇总 | `TG_TOKEN` | 手动 / 定时 |

要点：

- **无长连接、无轮询**，平时只有 ① 主动上报。
- **② 需回调可达**：VPS 放行回调端口（默认 `19840`，添加/更新 VPS 弹框可改）。
- **`access_token` 每台独立**，互不相同；泄露一台只换那台。
- **`TG_TOKEN` 只用于发 TG 消息**，与上报鉴权无关。

---

## access_token 说明

- **每台 VPS 一个**，看板「添加 VPS」时生成，存 D1 `vps_tokens`。
- 上报（VPS→Worker）和获取流量推送（Worker→VPS）都用它。
- **看板默认不展示完整 token**：「更新注册」只显示前缀；生成命令时由服务端写入安装脚本。需要覆盖密钥时可粘贴新值或勾选轮换。
- **自动轮换**（无需重装）：
  - VPS 端：`/usr/local/sbin/traffic-telegram-report --rotate-token` → 下次上报自动切换。
  - Web 端：「更新注册」勾「轮换新密钥」→ VPS 下次上报自动同步新 token。

---

## 看板功能

- **机器列表**：今日/本月流量、累积在线、状态；**多选批量**删除/加入TG/移出TG；**只看在线**筛选 + 按流量/在线时长排序。
- **总流量统计**：日内折线 / 周报(近7天) / 月报(近30天) / 年报(近12月)；入站/出站勾选。
- **单机流量统计**：每行「流量统计」弹窗。
- **获取流量**：弹窗显示每台推送结果，自动刷新列表（全部成功或 30 秒停；无全局高频轮询）。
- **TG 汇报**：内置卡片/今日排行/详细三个模板，可编辑、新建、预览；设置时间定时发，或「立即汇报」。
- **TG 状态徽章**：顶部显示 TG 配置状态，点击校验。
- **离线告警**：机器离线 TG 通知一次（发送成功才记标），重新在线清标记。
- **登录日志**：每次登录记录 + 成功发 TG 通知；**同 IP 15 分钟内失败 ≥8 次锁定**。
- **密码门**：未配 `PASSWORD` 拦在登录页并提示。

---

## Agent 参数

| 变量 | 含义 | 默认 / 说明 |
|------|------|-------------|
| `t_token` | TG Bot Token | 仅 TG 日报需要 |
| `t_id` | TG Chat ID | 仅 TG 日报需要 |
| `t_time` | TG 日报时间 | `20:00:00` |
| `m_id` | 机器 ID（支持中文，1-64 字） | 看板添加时输入 |
| `cf_url` | Worker 上报地址 | 看板生成 |
| `access_token` | VPS 访问密钥 | 看板生成，每台独立 |
| `cf_time` | CF 上报 cron | `0 * * * *`（每小时） |
| `cb_port` | 回调端口 | `19840`（可改，需放行） |

### `cf_time` 与调用次数

VPS 按 `cf_time` 向 Worker `/api/report` 上报。**越密 → 图表（尤其「日内」）越细，但 CF 请求与 D1 写入越多。**

| cron 示例 | 含义 | 约调用/台/天 |
|-----------|------|----------------|
| `0 * * * *` | 每小时（默认） | 24 |
| `0 */2 * * *` | 每 2 小时 | 12 |
| `0 */6 * * *` | 每 6 小时 | 4 |
| `0 20 * * *` | 每天 20:00 | 1 |

周报/月报/年报看的是「当日/当月累计快照」，一般 **每小时或每 2～6 小时** 足够；只有要看日内小时折线时才需要更密。手动「获取流量」可随时补点，不必把 cron 打到分钟级。

Worker 侧 cron 为 **每小时** 一次：离线检测 + 到点 TG 汇总 + 每日清理 90 天前历史。

---

## 安全要点

- 登录：`PASSWORD` 必填；失败按 IP 限流；Cookie 带过期时间，签名密钥优先 `SESSION_SECRET`。
- 回调：`force-report` 需 **Bearer + HMAC + 时间窗 + nonce**；旧版 soft-accept 已废弃，**已装 VPS 请用最新 `sum.sh` 更新注册/重装回调**。
- Token：看板默认不回传完整 `access_token`；安装命令内仍含密钥，勿发到公开群。

---

## 排查

### 回调服务

```bash
ss -lntp | grep 19840                                  # 看监听
systemctl status traffic-telegram-report-cb.service    # 回调服务
systemctl restart traffic-telegram-report-cb.service   # 改 conf 后必须 restart
journalctl -u traffic-telegram-report-cb.service -n 50 # 日志（含 hmac mismatch / nonce replay）
```

HMAC 失败会返回 401（`bad signature` / `timestamp skew` / `nonce replay`），不会 soft-accept。
### systemctl 217/USER

旧 unit 把多条配置写一行。用最新 `sum.sh` 更新注册重装即可。

---

## 卸载（VPS 端）

```bash
bash /usr/local/sbin/traffic-telegram-report --uninstall
```

保留 vnStat 数据库。
