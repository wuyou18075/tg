# 流量汇报（Telegram + Cloudflare）

一键部署（纯网页操作，无需本地安装任何工具）。

---

## 部署（Cloudflare Dashboard）

### 第 1 步：创建 D1 数据库

打开 [dash.cloudflare.com](https://dash.cloudflare.com) → 左侧 **Workers & Pages** → **D1** → **创建数据库**：

- 数据库名称：`traffic-db`
- 区域：自动
- 点击「创建」

创建后记下该数据库的 **ID**（一串 UUID），下一步要用。

### 第 2 步：创建 Worker

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
| `REPORT_TOKEN` | 任意字符串，如 `my-token-2024` | Agent 上报所用的 cftoken，生成 VPS 命令时会引用 |
| `DASH_PASSWORD` | 你的看板登录密码 | 访问看板时需要输入 |

3. 勾选「加密」→ 点「保存」

### 第 5 步：部署生效

回到 Worker 的「代码」页，点「**部署**」按钮。稍等几秒，即可访问：

```
https://traffic-dashboard.你的子域.workers.dev/
```

用刚才设置的 `DASH_PASSWORD` 登录。

> D1 表结构会在首次请求时由 Worker 自动创建，无需额外操作。

---

## 使用流程

### 1. 打开看板

访问你的 Worker 地址，用 `DASH_PASSWORD` 登录。

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
ttoken='123456:ABC...' tid='-1001234567890' ttime='20:00:00' \
cftime='0 * * * *' \
cfurl='https://traffic-dashboard.xxx.workers.dev/api/report' \
cftoken='my-token-2024' \
mid='hk-1' \
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
| `ttoken` | Telegram Bot Token | 页面设置 |
| `tid` | Telegram Chat ID | 页面设置 |
| `ttime` | TG 汇报时间 `HH:MM:SS` | `20:00:00` |
| `cftime` | CF 汇报 cron（5 段） | `0 * * * *` |
| `cfurl` | Worker 上报地址 | 自动生成 |
| `cftoken` | 上报 Bearer Token | `REPORT_TOKEN` secret |
| `mid` | 机器 ID | 生成时输入 |

### cftime 示例

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
systemctl start traffic-telegram-report-cf.service     # 立即报 CF

journalctl -u traffic-telegram-report.service -u traffic-telegram-report-cf.service

bash sum.sh --uninstall                                # 卸载（保留 vnStat）
```

---

## 文件说明

| 文件 | 作用 |
|------|------|
| `sum.sh` | VPS 侧一键安装脚本（含 Agent 报告程序） |
| `cf-worker-example.js` | Cloudflare Worker 主程序（看板 + API + 自动建表） |
| `schema.sql` | D1 表结构参考（Worker 自动执行，无需手动跑） |
| `wrangler.toml` | wrangler 部署配置 |
| `.github/workflows/deploy.yml` | GitHub Actions 自动部署配置 |
