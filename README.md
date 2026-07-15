# 流量汇报（Telegram + Cloudflare）

[![部署到 Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wuyou18075/tg)

---

## 快速入门：仅 Telegram 日报（无需 Cloudflare）

只想每天在 Telegram 收 VPS 流量日报、不需要 Web 看板时，在 Debian 13 上执行：

```bash
t_token='123456:ABC...' t_id='-1001234567890' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

自定义发送时间：

```bash
t_token='...' t_id='...' t_time='09:30:00' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

运维：

```bash
systemctl status traffic-telegram-report.timer
systemctl start traffic-telegram-report.service
journalctl -u traffic-telegram-report.service
```

---

## 完整方案：Telegram + Cloudflare 看板

需要 Web 看板、多机集中管理、历史曲线时，按下面步骤部署。

> 推荐流程：**先删掉旧 Worker / 旧 D1（如有）→ 新建 D1 → 部署 Worker → Dashboard 绑定 D1 与密钥**。

### 第 1 步：创建 D1 数据库

打开 [dash.cloudflare.com](https://dash.cloudflare.com) → **Workers & Pages** → **D1** → **创建数据库**：

- 名称：`traffic-db`
- 区域：自动

记下数据库 **ID**（UUID，绑定用）。

### 第 2 步：部署 Worker（任选一种）

**方式 A：一键部署按钮**

1. 点上方「部署到 Cloudflare Workers」
2. 授权 GitHub 与 Cloudflare
3. 部署完成后继续第 3 步绑定 D1

**方式 B：Dashboard 手动粘贴**

1. **Workers & Pages** → **创建** → **Worker** → 部署
2. 编辑代码，粘贴本仓库 [`cf-worker-example.js`](cf-worker-example.js)
3. 保存并部署

**方式 C：GitHub Actions / Cloudflare Builds**

仓库已配置 `wrangler.toml`（`name = "cf-tg-web"`）与 `.github/workflows/deploy.yml`。  
**不要把 `database_id` 写进仓库**；D1 一律在 Dashboard 绑定（见第 3 步）。

若用 GitHub Actions，在仓库 Secrets 配置：

| 密钥 | 说明 |
|------|------|
| `CLOUDFLARE_API_TOKEN` | Workers 部署权限 |
| `CLOUDFLARE_ACCOUNT_ID` | 账号 ID |

若用 Cloudflare Workers Builds 连接本仓库：Deploy command 用默认 `npx wrangler deploy` 即可；同样**不要**在 `wrangler.toml` 里写无效 `database_id`。

### 第 3 步：绑定 D1

Worker 详情 → **设置** → **绑定** → 添加 **D1 数据库**：

- 变量名：`DB`（必须是 `DB`）
- 数据库：选刚创建的 `traffic-db`
- 保存

### 第 4 步：加密变量

**设置** → **变量** → **加密变量**：

| 变量名 | 值 | 说明 |
|--------|----|------|
| `PASSWORD` | 看板登录密码 | 访问 Web 看板必填 |
| `TG_TOKEN` | 任意长字符串（可选） | 兼容旧版全局上报密码；新版 VPS 使用独立 token |
| `TG_ID` | Chat ID（可选） | TG 汇总目标；也可在看板「设置」页填写 |

保存后回到代码页再点一次 **部署**（让绑定与变量生效）。

### 第 5 步：打开看板

```
https://cf-tg-web.你的子域.workers.dev/
```

用 `PASSWORD` 登录。D1 表结构会在首次请求时自动创建。

---

## 使用流程

### 1. 设置 TG 汇总（可选）

看板顶部 **设置**：

- Telegram Bot Token
- Telegram Chat ID（若已设 `TG_ID` 环境变量可省略）
- TG 汇报时间 `HH:MM:SS`（默认 `20:00:00`，看板侧汇总时间参考）
- CF 汇报 cron（生成安装命令时使用，默认 `0 * * * *`）

### 2. 添加 VPS

**看板** → **＋ 添加 VPS** → 输入机器 ID（如 `hk-1`）→ 生成并复制命令。

生成的命令类似：

```bash
m_id='hk-1' \
cf_token='vps-独立token' \
cf_url='https://cf-tg-web.xxx.workers.dev/api/report' \
cf_time='0 * * * *' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

> 命令**不含** `t_token`/`t_id`：VPS 只上报 Cloudflare；TG 汇总由看板统一发送。

在 Debian 13 上粘贴执行即可。

### 3. 查看数据

- 表格：今日/本月入站出站
- 点击行切换曲线（24h / 3d / 7d / 30d）
- 2 小时内有上报标为在线

---

## Agent 参数

| 变量 | 含义 | 默认 / 说明 |
|------|------|-------------|
| `t_token` | Telegram Bot Token | 仅 TG 日报需要 |
| `t_id` | Telegram Chat ID | 仅 TG 日报需要 |
| `t_time` | TG 日报时间 `HH:MM:SS` | `20:00:00` |
| `cf_url` | Worker 上报地址 `https://.../api/report` | 看板生成 |
| `cf_token` | 上报 Bearer Token | 看板为每台 VPS 生成独立 token |
| `cf_time` | CF 上报 cron（5 段） | `0 * * * *` |
| `m_id` | 机器 ID | 看板添加时输入 |

规则：

- **仅 TG**：提供 `t_token` + `t_id`
- **仅 CF**：提供 `cf_url` + `cf_token` + `m_id`
- **双通道**：两组都提供
- 两组都缺会报错退出

### cf_time 示例

- `0 * * * *` — 每小时
- `0 */6 * * *` — 每 6 小时
- `0 20 * * *` — 每天 20:00
- `30 8 * * 1-5` — 工作日 08:30

---

## Agent 运维

```bash
systemctl status traffic-telegram-report.timer         # TG 定时器
systemctl status traffic-telegram-report-cf.timer      # CF 定时器

systemctl start traffic-telegram-report.service        # 立即发 TG
systemctl start traffic-telegram-report-cf.service     # 立即 CF 上报

journalctl -u traffic-telegram-report.service
journalctl -u traffic-telegram-report-cf.service

# 卸载（保留 vnStat）
bash /path/to/sum.sh --uninstall
```

---

## 删除旧部署后重新部署清单

1. Cloudflare 删除旧 Worker（如 `cf-tg-web` / `traffic-dashboard`）
2. 如需清空数据：删除旧 D1 `traffic-db` 后新建同名库
3. 按上文第 2～4 步重新部署并绑定 `DB` + `PASSWORD`
4. 打开看板登录 → 设置 TG → 添加 VPS → 在机器上重跑安装命令

仓库内 **不包含** 真实 `database_id`，避免 CI/Builds 把占位符当 UUID 导致 `10021` 错误。
