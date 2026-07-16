# CF 看板(vps-cf-tg)

[![部署到 Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wuyou18075/tg)

本项目支持两种独立用法，按需选择：

| 方案 | 适用 | 需要 Cloudflare | 需要看板 | 消息怎么发 |
|------|------|----------------|----------|-----------|
| **方案一：仅 TG 日报** | 只想在 TG 收每台 VPS 流量日报 | ❌ 不需要 | ❌ 不需要 | VPS 直接发 TG |
| **方案二：CF 看板** | 要 Web 看板、多机集中管理、历史曲线 | ✅ 需要 | ✅ 需要 | 看板统一发 TG 汇总 |

> 两种方案的 TG 凭证是同一个 Bot（`t_token` / `TG_TOKEN` 都是 BotFather 给的 Bot Token）。方案一 VPS 独立运行，不依赖任何 Web 服务。

---

## 方案一：仅 TG 日报（VPS 独立使用，无需 Cloudflare）

每台 VPS 自己定时把 vnStat 流量发到你的 Telegram，不需要 Worker / D1 / 看板。适合只想要日报、不想搭 Web 的场景。

### 参数说明

在 VPS（Debian 13）上用环境变量传参：

| 参数 | 含义 | 格式 / 示例 | 必填 |
|------|------|------------|------|
| `t_token` | TG 机器人 Token | `123456789:ABCdef...`（BotFather 创建机器人后获得） | ✅ |
| `t_id` | 聊天/群 ID | `-1001234567890`（群为负数，个人为正数） | ✅ |
| `t_time` | 每天发送时间 | `HH:MM:SS`，默认 `20:00:00` | ❌ |

获取 Token / ID：
1. 在 Telegram 找 [@BotFather](https://t.me/BotFather) → `/newbot` → 拿到 `t_token`
2. 把机器人拉进群（或私聊它发一条消息），再访问 `https://api.telegram.org/bot<你的t_token>/getUpdates` → 从返回里拿 `chat.id` 作为 `t_id`

### 一键安装

```bash
t_token='123456789:ABCdef...' t_id='-1001234567890' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

自定义发送时间（例如每天 09:30）：

```bash
t_token='...' t_id='...' t_time='09:30:00' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

脚本会自动：安装 vnStat → 配置默认网卡 → 注册 systemd 定时任务 → 立即发一条测试消息。

### 运维命令

```bash
systemctl status traffic-telegram-report.timer   # 定时器状态
systemctl start  traffic-telegram-report.service # 立即发一次
journalctl -u traffic-telegram-report.service    # 看日志
```

### 卸载

```bash
bash /usr/local/sbin/traffic-telegram-report --uninstall 2>/dev/null || bash sum.sh --uninstall
```

> 方案一**不涉及** `access_token`、`cf_url`、Cloudflare——VPS 只和你自己的 Telegram 机器人通信。

---

## 方案二·A：CF 看板一键部署（新用户推荐）

点下方按钮，Cloudflare 会打开部署表单：

[![部署到 Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wuyou18075/tg)

表单里会让你填：

- `PASSWORD`：看板登录密码（必填，自己设）
- `TG_TOKEN` / `TG_ID`：可选，TG 机器人 Token 与 Chat ID（用于看板发 TG 汇总）
- D1 数据库：CF 自动创建并绑定，无需手动建

填完 Deploy 即可。所有变量自动创建为**加密变量**，后续部署不会删。部署完打开 Worker 地址用 `PASSWORD` 登录，再到看板「添加 VPS」生成每台机器的安装命令（含独立 `access_token`）。

> 已部署用户日常更新代码用 git push（见方案二·B），不必重复一键部署。

## 方案二·B：CF 看板完整部署（手动/CI）

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

**方式 C：GitHub Actions / Cloudflare Builds（二选一，用 `.deploy-mode` 切换）**

仓库已配置 `wrangler.toml`（`name = "cf-tg-web"`）与 `.github/workflows/deploy.yml`。  
`database_id` 已写进 `wrangler.toml`（持久绑定 D1，见第 3 步）。

在仓库根 `.deploy-mode` 文件里写一个词决定由谁部署：

| `.deploy-mode` 内容 | 谁部署 | 你要做的 |
|--------------------|--------|----------|
| `github`（默认） | GitHub Actions | CF 面板 **断开** Workers Builds（避免重复部署） |
| `cf` | Cloudflare Workers Builds | 无需额外操作；GitHub Actions 会自动跳过 |

切换方法：改 `.deploy-mode` 的值 → `git push` → 去对应平台开/关另一条。  
两种方式都**只部署代码 + D1**，不碰加密变量。

若用 GitHub Actions，在仓库 **Settings → Secrets and variables → Actions** 配置：

| 密钥 | 必填 | 说明 |
|------|------|------|
| `CLOUDFLARE_API_TOKEN` | 是 | Workers 部署权限 |
| `CLOUDFLARE_ACCOUNT_ID` | 是 | 账号 ID |

> 看板密码 / `TG_*` 等 **业务变量不要放 GitHub**，统一在 Cloudflare Dashboard 加为 **加密变量**（见第 4 步）。`deploy.yml` 只部署代码与 D1 绑定，不读写、不覆盖、不删除加密变量。

若用 Cloudflare Workers Builds 连接本仓库：Deploy command 用默认 `npx wrangler deploy` 即可；同样**不要**在 `wrangler.toml` 里写无效 `database_id`。Builds 不会自动同步加密变量，需在 Dashboard 手动配置（见第 4 步）。

### 第 3 步：绑定 D1（必做，且要写进 wrangler.toml）

Dashboard 绑定 **不够**：若用 Git / Workers Builds 部署，`wrangler.toml` 里没有 `database_id` 时，**每次部署可能冲掉 `env.DB`**，页面会报「D1 未绑定」。

**推荐（持久）：**

1. 打开 D1 库（如 `tg-cf-web`）→ 复制 **数据库 ID**（UUID）
2. 编辑仓库 `wrangler.toml`：

```toml
[[d1_databases]]
binding = "DB"
database_name = "tg-cf-web"
database_id = "你的-UUID"
```

3. `git push` 再部署

**临时：** Dashboard → Worker → 设置 → 绑定 → D1，变量名 `DB`，然后对该 Worker **再点一次部署**（只绑不定部署会仍无 `env.DB`）。

### 第 4 步：加密变量（必做，否则看板无法登录）

> ⚠️ **务必加为「加密变量（Secret）」，不是「明文变量」。**  
> `wrangler deploy` 不会动加密变量；但会清掉未在 `wrangler.toml` 声明的明文变量。所以只有加密变量能跨部署保留。

Cloudflare Dashboard → 你的 Worker `cf-tg-web` → **设置** → **变量** → **添加加密变量**：

| 变量名 | 值 | 说明 |
|--------|----|------|
| `PASSWORD` | 看板登录密码 | 访问 Web 看板必填 |
| `TG_BOT_TOKEN` | Bot Token（可选） | 页面未填时用于 TG 汇总 |
| `TG_ID` | Chat ID（可选） | 页面未填时用于 TG 汇总 |
| `TG_TOKEN` | TG 机器人 Token（可选） | VPS 用它给 TG 发消息（Bot Token，如 `123456:ABC...`）。与上报鉴权无关 |

加完后**无需再部署**——加密变量保存即对线上 Worker 立即生效。

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

**看板** → **＋ 添加 VPS** → 输入机器 ID（如 `香港-1` / `hk-1`，支持中文）→ 生成并复制命令。

生成的命令类似：

```bash
m_id='香港-1' \
access_token='看板生成的访问密钥' \
cf_url='https://cf-tg-web.xxx.workers.dev/api/report' \
cf_time='0 * * * *' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

> 命令**不含** `t_token`/`t_id`：VPS 用 `access_token` 上报 Cloudflare；TG 汇总由看板统一发送。

在 Debian 13 上粘贴执行即可。

### 3. 查看数据

- 顶部 **TG 状态徽章**：未配置(灰)/配置不完整(黄)/不可用(红)/待验证(蓝)/正常(绿)，点一下真实校验 Bot Token 与 Chat ID
- 表格：今日/本月入站出站、**累积在线时长**（上报间隔≤2h 计入；在线时含距上次上报）；2 小时内有上报标为在线
- **总流量统计**（页面中部）：全部机器合计，**日/月**切换；**入站/出站**勾选筛选；柱为堆叠（蓝入+绿出=合计高度）
- 每行 **流量统计**（单机弹窗同交互）/ **更新注册** / **删除**
- **获取流量**：弹窗显示每台推送成功/失败/跳过，并自动每 2 秒刷新列表；**全部成功立即停**，**最多 30 秒**后舍弃仍未上报的机器并停止刷新；需 VPS 公网回调；安装/开机仍立即上报一次。裸 IP 回调由 Worker 经 TCP Socket 推送（绕过 CF fetch 的 1003）；需放行回调端口（默认 19840）

---

## Agent 参数

| 变量 | 含义 | 默认 / 说明 |
|------|------|-------------|
| `t_token` | Telegram Bot Token | 仅 TG 日报需要 |
| `t_id` | Telegram Chat ID | 仅 TG 日报需要 |
| `t_time` | TG 日报时间 `HH:MM:SS` | `20:00:00` |
| `cf_url` | Worker 上报地址 `https://.../api/report` | 看板生成 |
| `access_token` | 上报与回调的访问密钥 | 看板「添加 VPS」生成，VPS 用它上报/验证 |
| `cf_time` | CF 上报 cron（5 段） | `0 * * * *` |
| `m_id` | 机器 ID（支持中文，1-64 字） | 看板添加时输入 |

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

## 排查 systemctl 启动失败（217/USER）

若 `systemctl start traffic-telegram-report-cf.service` 报 `status=217/USER`，且 journal 有 `Failed to parse NoNewPrivileges=true; PrivateDevices=...`：  
是旧版 unit 把多条配置写在同一行。用最新 `sum.sh` **更新注册**重装即可；或手动：

```bash
# 直接跑上报（不经过有问题的 unit）
/usr/local/sbin/traffic-telegram-report --cf

# 修好 unit 后
systemctl daemon-reload
systemctl start traffic-telegram-report-cf.service
```

## 排查「获取流量」失败

> **重要：** 回调服务进程会缓存 token。仅改 conf 不 `restart` 时，获取流量会一直 401。安装脚本已改为 `systemctl restart …-cb.service`；手动修复：
> ```bash
> systemctl restart traffic-telegram-report-cb.service
> journalctl -u traffic-telegram-report-cb.service -n 10 --no-pager
> ```


结果弹窗「说明」列会写具体原因。常见：

| 说明关键词 | 处理 |
|-----------|------|
| CF 1003 / 直连 IP | 确认已部署含 TCP sockets 的最新 Worker |
| 建连失败 / 超时 | VPS 放行回调端口（默认 **19840**）；`systemctl status traffic-telegram-report-cb` |
| 无 HTTP 响应 | 端口被其它进程占用，或回调服务未正常监听 |
| 401 / token mismatch / unauthorized | 看板推送 token 与 VPS `CF_TOKEN` 不一致。部署最新 Worker 后：等该机**再上报一次**会自动同步；或 **更新注册** 整段重跑。若 VPS 用的是全局 `TG_TOKEN`，推送也会自动回退使用它 |
| no_callback_url | 机器未登记回调 → 用含 `cf_url` 的安装命令重装/更新 |

在 VPS 本机自测回调：

```bash
# 看监听
ss -lntp | grep 19840
# 看服务日志
journalctl -u traffic-telegram-report-cb.service -n 50 --no-pager
```

若弹窗报「TCP 已连接但无 HTTP 响应」：多半是旧版回调脚本在异常时不回包，或 Worker 过早关连接。请：

1. 部署最新 Worker（含 TCP 读写修复）
2. 在 VPS 上更新回调脚本（任选）

```bash
# 方式 A：用看板「更新注册」生成的命令重装（推荐）
# 方式 B：拉取仓库最新 sum.sh 后重装
bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh') --  # 需带原有 m_id/cf_* 环境变量
```

本机快速验证（应返回 JSON）：

```bash
# 用错误 token 应返回 401 JSON，而不是空连接
curl -sv -X POST http://127.0.0.1:19840/force-report -d '{}' -H 'Content-Type: application/json' | head
```

## Agent 运维

```bash
systemctl status traffic-telegram-report.timer         # TG 定时器
systemctl status traffic-telegram-report-cf.timer      # CF 定时器

systemctl start traffic-telegram-report.service        # 立即发 TG
systemctl start traffic-telegram-report-cf.service     # 立即 CF 上报
systemctl status traffic-telegram-report-cb.service    # 回调监听（获取流量）

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
                   