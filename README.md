# 流量汇报（Telegram + 可选 Cloudflare）

## 仅 Telegram（默认每天 20:00:00）

```bash
ttoken='BOT_TOKEN' tid='CHAT_ID' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

## 自定义 TG 时间

```bash
ttoken='...' tid='...' ttime='23:00:00' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

## Telegram + Cloudflare（CF 每小时上报）

```bash
ttoken='...' tid='...' ttime='20:00:00' \
cftime='0 * * * *' \
cfurl='https://your-worker.example.workers.dev/api/report' \
cftoken='your-secret' \
mid='hk-1' \
  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')
```

### 参数说明

| 变量 | 含义 | 默认 |
|------|------|------|
| `ttoken` | Telegram Bot Token | 交互输入 |
| `tid` | Telegram Chat ID | 交互输入 |
| `ttime` | **TG** 汇报时间，`HH:MM:SS` | `20:00:00` |
| `cftime` | **CF** 汇报 cron（5 段） | 空=不启用 CF |
| `cfurl` | CF Worker 上报 URL（启用 CF 时必填） | — |
| `cftoken` | 上报 Bearer Token | — |
| `mid` | 机器 ID，如 `hk-1` | — |

### cftime 示例

- `0 * * * *` — 每小时整点
- `0 */6 * * *` — 每 6 小时
- `0 20 * * *` — 每天 20:00
- `30 8 * * 1-5` — 工作日 08:30
- `*/15 * * * *` — 每 15 分钟

### 运维

```bash
systemctl status traffic-telegram-report.timer      # TG 定时
systemctl status traffic-telegram-report-cf.timer   # CF 定时
systemctl start traffic-telegram-report.service     # 立即发 TG
systemctl start traffic-telegram-report-cf.service  # 立即报 CF
journalctl -u traffic-telegram-report.service -u traffic-telegram-report-cf.service
bash sum.sh --uninstall
```

### CF 上报 JSON

```json
{
  "machine_id": "hk-1",
  "hostname": "vps",
  "interface": "eth0",
  "ts": 1720000000,
  "date": { "year": 2026, "month": 7, "day": 15 },
  "today": { "rx": 1, "tx": 2, "total": 3 },
  "month": { "rx": 4, "tx": 5, "total": 9 }
}
```

请求头：`Authorization: Bearer <cftoken>`，`X-Machine-Id: <mid>`。  
Worker 示例见 `cf-worker-example.js`。
