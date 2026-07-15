### 适用环境

- 系统：**Debian 13**
- 架构：amd64 / arm64

## 快速入门：仅 Telegram 日报（无需 Cloudflare）

如果你的需求只是每天在 Telegram 收到 VPS 流量日报，**不需要看板/Web 页面**，可以跳过整个 Cloudflare 部署流程，只需在 VPS 上运行一条命令即可。

### 用法

在 VPS 上直接粘贴执行以下命令（替换其中的 Token 和 Chat ID）：

```bash
t_token='123456:ABC...' t_id='-1001234567890' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

Agent 会自动：
1. 安装 vnStat、jq 等依赖
2. 配置当前默认网卡
3. 设置 systemd 定时器（默认每天 **20:00** 发一次 TG 日报）
4. 立即发送一条测试消息

> 如果需要自定义发送时间，加 `t_time` 参数：
> ```bash
> t_token='...' t_id='...' t_time='09:30:00' \
>   bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
> ```

完成后可随时查看状态：
```bash
systemctl status traffic-telegram-report.timer   # TG 定时器状态
systemctl start traffic-telegram-report.service   # 立即手动发送
journalctl -u traffic-telegram-report.service     # 最近一次发送日志
```

---

## 完整方案：Telegram + Cloudflare 看板

如需 Web 看板、多机集中管理、历史曲线图表，请按以下步骤部署 Cloudflare Worker。

[![部署到 Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wuyou18075/tg)

> 点击上方按钮，授权后自动拉取本仓库代码部署到 Cloudflare Workers。
> **部署完成后**，还需手动绑定 D1 数据库和添加密钥（见下方步骤 1/4/5）。

**☝️ 点击一键部署按钮后，继续看下方第 1、4、5 步配置 D1 和密钥。**

---

## 部署（Cloudflare Dashboard）

### 第 1 步：创建 D1 数据库

打开 [dash.cloudflare.com](https://dash.cloudflare.com) → 左侧 **Workers & Pages** → **D1** → **创建数据库**：

- 数据库名称：`traffic-db`
- 区域：自动
- 点击「创建」

创建后记下该数据库的 **ID**（一串 UUID），下一步要用。

### 第 2 步：创建 Worker（二选一）

**方式 A：一键部署按钮** ✅ 推荐
1. 点击上方「部署到 Cloudflare Workers」按钮
2. 授权 GitHub 和 Cloudflare
3. 完成后自动生成 Worker，继续第 3 步绑定 D1

**方式 B：手动创建**
1. 左侧 **Workers & Pages** → **创建应用程序** → **Worker** → **部署**
2. 点「编辑代码」，**全选删除**默认代码
3. 打开本仓库的 [`cf-worker-example.js`](cf-worker-example.js)，全选复制，粘贴进去
4. 点「**保存并部署**」

### 第 3 步：绑定 D1 数据库

1. 在 Worker 详情页，点「**设置**」→「**绑定**」
2. 点「添加绑定」→ 选择 **D1 数据库**
3. 变量名称：`DB`
4. 选择你刚创建的 `traffic-db`
5. 点「保存」

### 第 4 步：添加加密变量（密钥）

1. 继续在「**设置**」→「**变量**」
2. 往下找到「**加密变量**」，添加两条：

| 变量名 | 值 | 说明 |
|--------|----|------|
| `TG_TOKEN` | 任意字符串，如 `my-token-2024` | VPS 上报密码（cf_token），生成命令时引用 |
| `PASSWORD` | 你的看板登录密码 | 访问看板时需要输入 |
| `TG_ID` | TG 汇总接收 Chat ID | TG 汇总的目标会话 ID，也可在设置页配置 |

3. 勾选「加密」→ 点「保存」

### 第 5 步：部署生效

回到 Worker 的「代码」页，点「**部署**」按钮。稍等几秒，即可访问：

```
https://traffic-dashboard.你的子域.workers.dev/
```

用刚才设置的 `PASSWORD` 登录。

> D1 表结构会在首次请求时由 Worker 自动创建，无需额外操作。

---

## 使用流程

### 1. 打开看板

访问你的 Worker 地址，用 `PASSWORD` 登录。

### 2. 设置 → 保存 TG 配置

点顶部导航栏「**设置**」，填入：

- **Telegram Bot Token** — Bot 的 Token（@BotFather 创建）  
- **Telegram Chat ID** — 接收日报的会话 ID（数字，可带负号）  
- **TG 汇报时间** — 每天哪个时间发 TG，格式 `HH:MM:SS`，默认 `20:00:00`  
- **CF 汇报 cron** — 向本 Worker 上报的频率，默认 `0 * * * *`（每小时）

点「保存设置」。

### 3. 添加 VPS

切回「**看板**」标签页，点「**＋ 添加 VPS**」：

1. 输入机器 ID，如 `hk-1` / `jp-2` / `us-west`
2. 点「生成命令」
3. 点「复制命令」

复制出的命令类似：

```bash
t_token='123456:ABC...' t_id='-1001234567890' t_time='20:00:00' \
cf_time='0 * * * *' \
cf_url='https://traffic-dashboard.xxx.workers.dev/api/report' \
cf_token='my-token-2024' \
m_id='hk-1' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

在目标 VPS（Debian 13）上直接粘贴执行，Agent 会自动安装并开始上报。

### 4. 查看数据

- 看板自动显示所有机器的今日/本月入站出站流量
- 点击表格行切换曲线图
- 曲线图支持 24h / 3d / 7d / 30d 范围
- 2 小时内有上报的机器标为「在线」

---

## 自动部署（Push 即部署）

如果你习惯用 GitHub Actions，也可以实现「push 到 main → 自动部署到 Cloudflare」。

### 配置 GitHub Secrets

在 GitHub 仓库 → Settings → Secrets and variables → Actions → 添加：

| 密钥名 | 值 |
|--------|----|
| `CLOUDFLARE_API_TOKEN` | Cloudflare API Token（权限：Workers + D1） |
| `CLOUDFLARE_ACCOUNT_ID` | 你的 Cloudflare Account ID |
| `CLOUDFLARE_D1_ID` | 你创建的 `traffic-db` 数据库 ID |

配置完成后，每次 `git push origin main` 会自动触发部署。

---

## Agent 参数说明

| 变量 | 含义 | 默认 |
|------|------|------|
| `t_token` | Telegram Bot Token | 页面设置 |
| `t_id` | Telegram Chat ID | 页面设置 |
| `t_time` | TG 汇报时间 `HH:MM:SS` | `20:00:00` |
| `cf_time` | CF 汇报 cron（5 段） | `0 * * * *` |
| `cf_url` | Worker 上报地址 | 自动生成 |
| `cf_token` | 上报 Bearer Token | `TG_TOKEN` secret |
| `m_id` | 机器 ID | 生成时输入 |

### cf_time 示例

- `0 * * * *` — 每小时
- `0 */6 * * *` — 每 6 小时
- `0 20 * * *` — 每天 20:00
- `30 8 * * 1-5` — 工作日 08:30

---

## Agent 运维命令

```bash
systemctl status traffic-telegram-report.timer         # TG 定时器
systemctl status traffic-telegram-report-cf.timer      # CF 定时器

systemctl start traffic-telegram-report.service        # 立即发 TG
systemctl start traffic-telegram-report-cf.s
