/**
 * Cloudflare Worker：多机流量中心
 * - D1 自动初始化（无需手动执行 schema.sql）
 * - 密码登录看板 + 配置面板（ttoken/tid/ttime/cftime）
 * - 添加 VPS 按钮生成一键命令
 * - D1 历史曲线 + Chart.js
 *
 * 部署：
 *   1. wrangler d1 create traffic-db
 *   2. wrangler secret put REPORT_TOKEN   # agent 上报用，也是 cftoken
 *   3. wrangler secret put DASH_PASSWORD  # 看板登录密码
 *   4. 填入 wrangler.toml 的 database_id 后 wrangler deploy
 *
 * wrangler.toml：
 *   name = "traffic-dashboard"
 *   main = "cf-worker-example.js"
 *   compatibility_date = "2024-11-01"
 *   [[d1_databases]]
 *   binding = "DB"
 *   database_name = "traffic-db"
 *   database_id = "粘贴你的 D1 ID"
 */

const SESSION_TTL = 60 * 60 * 24 * 7;
const COOKIE_NAME = "dash_session";

// ─── 工具函数 ───

const json = (data, status = 200, extra = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...extra },
  });

const html = (body, status = 200, extra = {}) =>
  new Response(body, {
    status,
    headers: { "content-type": "text/html; charset=utf-8", ...extra },
  });

function gb(n) {
  return ((Number(n) || 0) / 1e9).toFixed(3) + "GB";
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function reportAuth(req, env) {
  const h = req.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return !!(env.REPORT_TOKEN && m && m[1] === env.REPORT_TOKEN);
}

// ─── 会话 ───

function parseCookies(req) {
  const raw = req.headers.get("cookie") || "";
  const out = {};
  for (const part of raw.split(";")) {
    const i = part.indexOf("=");
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function makeSessionToken(env) {
  const rnd = crypto.randomUUID() + crypto.randomUUID();
  const sig = await sha256Hex(`${rnd}:${env.DASH_PASSWORD || ""}:dash`);
  return `${rnd}.${sig}`;
}

async function verifySessionToken(token, env) {
  if (!token || !env.DASH_PASSWORD) return false;
  const i = token.lastIndexOf(".");
  if (i < 0) return false;
  const rnd = token.slice(0, i);
  const sig = token.slice(i + 1);
  const expect = await sha256Hex(`${rnd}:${env.DASH_PASSWORD}:dash`);
  return sig === expect && rnd.length >= 32;
}

function sessionCookie(token, maxAge = SESSION_TTL) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function requireDash(req, env) {
  if (!env.DASH_PASSWORD) return true;
  return verifySessionToken(parseCookies(req)[COOKIE_NAME], env);
}

// ─── D1 自动初始化 ───

async function ensureSchema(env) {
  if (!env.DB) return;
  await env.DB.batch([
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS machines (
        machine_id TEXT PRIMARY KEY, hostname TEXT, interface TEXT,
        last_ts INTEGER, today_rx INTEGER, today_tx INTEGER,
        month_rx INTEGER, month_tx INTEGER, updated_at INTEGER
      )`
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT, machine_id TEXT NOT NULL,
        ts INTEGER NOT NULL, today_rx INTEGER, today_tx INTEGER,
        month_rx INTEGER, month_tx INTEGER
      )`
    ),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS idx_snap_mid_ts ON snapshots(machine_id, ts)`
    ),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS config (
        key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER
      )`
    ),
  ]);
}

// ─── 数据操作 ───

async function upsertReport(env, rec) {
  const mid = rec.machine_id;
  const ts = Number(rec.ts) || Math.floor(Date.now() / 1000);
  const today = rec.today || {};
  const month = rec.month || {};
  const now = Math.floor(Date.now() / 1000);

  await env.DB.prepare(
    `INSERT INTO machines (machine_id, hostname, interface, last_ts, today_rx, today_tx, month_rx, month_tx, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(machine_id) DO UPDATE SET
       hostname=excluded.hostname, interface=excluded.interface,
       last_ts=excluded.last_ts, today_rx=excluded.today_rx, today_tx=excluded.today_tx,
       month_rx=excluded.month_rx, month_tx=excluded.month_tx, updated_at=excluded.updated_at`
  ).bind(mid, rec.hostname || "", rec.interface || "", ts,
    Number(today.rx) || 0, Number(today.tx) || 0,
    Number(month.rx) || 0, Number(month.tx) || 0, now
  ).run();

  // 节流：同一机器 5 分钟内只写 1 条历史
  const last = await env.DB.prepare(
    `SELECT ts FROM snapshots WHERE machine_id = ? ORDER BY ts DESC LIMIT 1`
  ).bind(mid).first();
  if (!last || ts - Number(last.ts) >= 300) {
    await env.DB.prepare(
      `INSERT INTO snapshots (machine_id, ts, today_rx, today_tx, month_rx, month_tx)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(mid, ts, Number(today.rx) || 0, Number(today.tx) || 0,
      Number(month.rx) || 0, Number(month.tx) || 0
    ).run();
  }

  // 清理 90 天前
  await env.DB.prepare(`DELETE FROM snapshots WHERE ts < ?`).bind(now - 90 * 86400).run();
}

async function listMachines(env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM machines ORDER BY last_ts DESC`
  ).all();
  return (results || []).map((r) => ({
    machine_id: r.machine_id, hostname: r.hostname, interface: r.interface, ts: r.last_ts,
    today: { rx: r.today_rx || 0, tx: r.today_tx || 0, total: (r.today_rx || 0) + (r.today_tx || 0) },
    month: { rx: r.month_rx || 0, tx: r.month_tx || 0, total: (r.month_rx || 0) + (r.month_tx || 0) },
    updated_at: r.updated_at,
  }));
}

async function getHistory(env, mid, hours) {
  const since = Math.floor(Date.now() / 1000) - hours * 3600;
  const { results } = await env.DB.prepare(
    `SELECT ts, today_rx, today_tx, month_rx, month_tx
     FROM snapshots WHERE machine_id = ? AND ts >= ? ORDER BY ts ASC`
  ).bind(mid, since).all();
  return results || [];
}

async function getConfig(env) {
  if (!env.DB) return {};
  const { results } = await env.DB.prepare(`SELECT key, value FROM config`).all();
  const cfg = {};
  for (const r of results || []) cfg[r.key] = r.value;
  return cfg;
}

async function saveConfig(env, data) {
  if (!env.DB) return;
  const now = Math.floor(Date.now() / 1000);
  const keys = ["ttoken", "tid", "ttime", "cftime"];
  const stmts = keys
    .filter((k) => data[k] !== undefined)
    .map((k) =>
      env.DB.prepare(
        `INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
      ).bind(k, String(data[k]), now)
    );
  if (stmts.length) await env.DB.batch(stmts);
}

// ─── 生成一键命令 ───

async function generateCommand(env, request, mid) {
  const cfg = await getConfig(env);
  const url = new URL(request.url);
  const cfurl = url.origin + "/api/report";
  const cftoken = env.REPORT_TOKEN || "";
  const ttoken = cfg.ttoken || "";
  const tid = cfg.tid || "";
  const ttime = cfg.ttime || "20:00:00";
  const cftime = cfg.cftime || "0 * * * *";

  if (!ttoken) return { ok: false, error: "请先在设置页面配置 ttoken（Telegram Bot Token）" };
  if (!tid) return { ok: false, error: "请先在设置页面配置 tid（Telegram Chat ID）" };
  if (!cftoken) return { ok: false, error: "缺少 REPORT_TOKEN 环境变量，请执行 wrangler secret put REPORT_TOKEN" };
  if (!/^[A-Za-z0-9._:-]{1,64}$/.test(mid)) return { ok: false, error: "机器 ID 应为 1-64 位字母数字及 ._-: 组合" };

  const cmd = `ttoken='${ttoken}' tid='${tid}' ttime='${ttime}' \\\ncftime='${cftime}' \\\ncfurl='${cfurl}' \\\ncftoken='${cftoken}' \\\nmid='${mid}' \\\n  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')`;

  return { ok: true, command: cmd, machine_id: mid };
}

// ─── 登录页 ───

function loginPage(err = "") {
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · 流量看板</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:system-ui,sans-serif;background:#0b1220;color:#e8eefc}
.card{width:min(360px,92vw);background:#121a2b;border:1px solid #243049;border-radius:14px;padding:28px 24px;box-shadow:0 12px 40px #0006}
h1{font-size:18px;margin:0 0 6px}
p{margin:0 0 18px;color:#8aa0c6;font-size:13px}
label{display:block;font-size:12px;color:#9fb3d9;margin-bottom:6px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #33415f;background:#0b1220;color:#e8eefc;margin-bottom:14px;outline:none}
input:focus{border-color:#3b82f6}
button{width:100%;padding:10px 12px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}
.err{color:#fca5a5;font-size:13px;margin-bottom:10px;min-height:1.2em}
</style>
<div class="card">
  <h1>流量看板</h1>
  <p>请输入管理密码</p>
  <div class="err">${err ? esc(err) : ""}</div>
  <form method="post" action="/login">
    <label for="pw">密码</label>
    <input id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
    <button type="submit">登录</button>
  </form>
</div>`;
}

// ─── 主看板（SPA） ───

function dashboardPage() {
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>流量看板</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:system-ui,sans-serif;background:#0b1220;color:#e8eefc}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid #1e2a42;background:#0e1628}
header h1{font-size:18px;margin:0}
.nav{display:flex;gap:4px;margin-left:16px}
.nav a{color:#8aa0c6;text-decoration:none;padding:6px 12px;border-radius:8px;font-size:13px;cursor:pointer}
.nav a.active,.nav a:hover{background:#1a2740;color:#e8eefc}
.muted{color:#8aa0c6;font-size:13px}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
select,button{background:#121a2b;color:#e8eefc;border:1px solid #33415f;border-radius:8px;padding:8px 10px;font-size:13px;outline:none}
button{cursor:pointer}
button:active{opacity:.8}
button.primary{background:#3b82f6;border-color:#3b82f6;font-weight:600}
button.primary:hover{background:#2563eb}
button.danger{background:#dc2626;border-color:#dc2626}
button.green{background:#16a34a;border-color:#16a34a;font-weight:600}
main{padding:16px 20px 40px;max-width:1200px;margin:0 auto}
.page{display:none}
.page.active{display:block}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:16px}
.card{background:#121a2b;border:1px solid #243049;border-radius:12px;padding:14px}
.card .label{font-size:12px;color:#8aa0c6}
.card .val{font-size:20px;font-weight:700;margin-top:6px}
.panel{background:#121a2b;border:1px solid #243049;border-radius:12px;padding:14px;margin-bottom:16px}
.panel h2{font-size:14px;margin:0 0 12px;color:#9fb3d9;font-weight:600}
.chart-wrap{position:relative;height:280px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:10px 8px;border-bottom:1px solid #243049;text-align:left}
th{color:#9fb3d9;font-weight:600}
tr{cursor:pointer}
tr.active{background:#1a2740}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;background:#1e3a5f;color:#93c5fd}
.badge.off{background:#3f1d1d;color:#fca5a5}
/* 设置页 */
.settings-form{max-width:520px}
.settings-form label{display:block;font-size:12px;color:#9fb3d9;margin:14px 0 4px}
.settings-form input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #33415f;background:#0b1220;color:#e8eefc;outline:none}
.settings-form input:focus{border-color:#3b82f6}
.settings-form .hint{font-size:11px;color:#8aa0c6;margin-top:2px}
.settings-form .save-row{display:flex;gap:8px;align-items:center;margin-top:18px}
.settings-form .save-row button{padding:10px 20px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#1a2740;border:1px solid #33415f;border-radius:10px;padding:10px 20px;font-size:13px;z-index:999;opacity:0;transition:opacity .25s}
.toast.show{opacity:1}
/* Modal */
.modal-overlay{position:fixed;inset:0;background:#0006;display:none;place-items:center;z-index:100}
.modal-overlay.open{display:grid}
.modal{background:#121a2b;border:1px solid #33415f;border-radius:14px;padding:24px;width:min(640px,94vw);max-height:80vh;overflow-y:auto}
.modal h2{font-size:16px;margin:0 0 4px}
.modal .desc{font-size:12px;color:#8aa0c6;margin-bottom:16px}
.modal label{display:block;font-size:12px;color:#9fb3d9;margin-bottom:4px}
.modal input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #33415f;background:#0b1220;color:#e8eefc;outline:none}
.modal input:focus{border-color:#3b82f6}
.modal .btn-row{display:flex;gap:8px;margin-top:14px;flex-wrap:wrap}
.modal .btn-row button{flex:1;min-width:80px;padding:10px}
.cmd-box{background:#0b1220;border:1px solid #33415f;border-radius:8px;padding:12px;margin:12px 0;font-family:monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;color:#c7d2fe;max-height:240px;overflow-y:auto}
.cmd-ok{color:#34d399;font-size:13px;display:flex;gap:8px;align-items:center}
</style>

<header>
  <div style="display:flex;align-items:center">
    <h1>流量看板</h1>
    <div class="nav">
      <a id="tabDash" class="active" onclick="switchTab('dash')">看板</a>
      <a id="tabSet" onclick="switchTab('settings')">设置</a>
    </div>
  </div>
  <div class="actions">
    <form method="post" action="/logout" style="margin:0"><button type="submit">退出</button></form>
  </div>
</header>

<main>
  <!-- 看板页 -->
  <div id="pageDash" class="page active">
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
      <button class="primary" onclick="openAddVps()">＋ 添加 VPS</button>
      <select id="range" onchange="loadHistory()">
        <option value="24">24 小时</option>
        <option value="72">3 天</option>
        <option value="168" selected>7 天</option>
        <option value="720">30 天</option>
      </select>
      <button onclick="refresh()">刷新</button>
    </div>
    <div class="cards" id="summary"></div>
    <div class="panel">
      <h2>历史曲线 · 今日累计（字节→GB）</h2>
      <div class="chart-wrap"><canvas id="chart"></canvas></div>
    </div>
    <div class="panel">
      <h2>机器列表</h2>
      <div style="overflow:auto">
        <table>
          <thead><tr>
            <th>机器</th><th>主机</th><th>网卡</th>
            <th>今日入/出</th><th>本月入/出</th><th>最后上报</th><th>状态</th>
          </tr></thead>
          <tbody id="tbody"><tr><td colspan="7">加载中…</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- 设置页 -->
  <div id="pageSettings" class="page">
    <div class="panel settings-form">
      <h2>全局配置</h2>
      <p class="muted" style="font-size:12px">保存后可在看板页「添加 VPS」一键生成安装命令</p>
      <label for="s_ttoken">Telegram Bot Token</label>
      <input id="s_ttoken" type="password" placeholder="123456:ABCdef...">
      <div class="hint">agent 发 TG 日报用</div>

      <label for="s_tid">Telegram Chat ID</label>
      <input id="s_tid" type="text" placeholder="-1001234567890">
      <div class="hint">接收日报的 TG 会话 ID</div>

      <label for="s_ttime">TG 汇报时间</label>
      <input id="s_ttime" type="text" placeholder="20:00:00">
      <div class="hint">HH:MM:SS 格式，默认 20:00:00</div>

      <label for="s_cftime">CF 汇报 cron</label>
      <input id="s_cftime" type="text" placeholder="0 * * * *">
      <div class="hint">5 段 cron，默认 0 * * * *（每小时）</div>

      <div class="save-row">
        <button class="primary" onclick="saveConfig()">保存设置</button>
        <span id="saveStatus" class="muted"></span>
      </div>
    </div>
  </div>
</main>

<!-- 添加 VPS 弹窗 -->
<div class="modal-overlay" id="modalVps">
  <div class="modal">
    <h2>添加 VPS</h2>
    <p class="desc">输入机器 ID 后点击生成，复制命令到 VPS 执行即可</p>
    <label for="vpsMid">机器 ID</label>
    <input id="vpsMid" type="text" placeholder="hk-1 / jp-2 / us-west" autocomplete="off">
    <div id="vpsCmdRegion" style="display:none">
      <div class="cmd-ok" id="vpsOk"></div>
      <div class="cmd-box" id="vpsCmd"></div>
      <div class="btn-row">
        <button class="primary" onclick="copyCmd()">复制命令</button>
        <button onclick="closeAddVps()">关闭</button>
      </div>
    </div>
    <div id="vpsBtnRegion" class="btn-row">
      <button class="green" onclick="genCmd()">生成命令</button>
      <button onclick="closeAddVps()">取消</button>
    </div>
  </div>
</div>

<!-- Toast -->
<div class="toast" id="toast"></div>

<script>
const gb = (n) => ((Number(n)||0)/1e9).toFixed(3) + 'GB';
const fmtTime = (ts) => ts ? new Date(ts*1000).toLocaleString() : '-';
let machines = [];
let selected = null;
let chart;

// ─── 页面切换 ───
function switchTab(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav a').forEach(a => a.classList.remove('active'));
  document.getElementById('page' + name[0].toUpperCase() + name.slice(1)).classList.add('active');
  document.getElementById('tab' + name[0].toUpperCase() + name.slice(1)).classList.add('active');
  if (name === 'settings') loadConfig();
  if (name === 'dash') refresh();
}

// ─── API ───
async function api(path, opts) {
  const r = await fetch(path, { credentials: 'same-origin', ...opts });
  if (r.status === 401) { location.href = '/login'; throw new Error('unauthorized'); }
  if (!r.ok) throw new Error((await r.json()).error || r.statusText);
  return r.json();
}

function toast(msg) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 3000);
}

// ─── 看板 ───
function online(ts) { return ts && ((Date.now()/1000 - ts) < 2*3600); }

function renderSummary() {
  const sum = machines.reduce((a,m)=>({
    today_rx: a.today_rx + (m.today?.rx||0), today_tx: a.today_tx + (m.today?.tx||0),
    month_rx: a.month_rx + (m.month?.rx||0), month_tx: a.month_tx + (m.month?.tx||0),
  }), {today_rx:0,today_tx:0,month_rx:0,month_tx:0});
  const on = machines.filter(m => online(m.ts)).length;
  document.getElementById('summary').innerHTML = \`
    <div class="card"><div class="label">机器数</div><div class="val">${machines.length}</div></div>
    <div class="card"><div class="label">在线（2h）</div><div class="val">${on}</div></div>
    <div class="card"><div class="label">今日合计</div><div class="val">${gb(sum.today_rx+sum.today_tx)}</div></div>
    <div class="card"><div class="label">本月合计</div><div class="val">${gb(sum.month_rx+sum.month_tx)}</div></div>\`;
}

function renderTable() {
  const tb = document.getElementById('tbody');
  if (!machines.length) { tb.innerHTML = '<tr><td colspan="7">暂无数据</td></tr>'; return; }
  tb.innerHTML = machines.map(m => {
    const active = m.machine_id === selected ? 'active' : '';
    const st = online(m.ts) ? '<span class="badge">在线</span>' : '<span class="badge off">离线</span>';
    return '<tr class="' + active + '" data-mid="' + (m.machine_id||'') + '">' +
      '<td>' + (m.machine_id||'') + '</td><td>' + (m.hostname||'') + '</td><td>' + (m.interface||'') + '</td>' +
      '<td>' + gb(m.today?.rx) + ' / ' + gb(m.today?.tx) + '</td>' +
      '<td>' + gb(m.month?.rx) + ' / ' + gb(m.month?.tx) + '</td>' +
      '<td>' + fmtTime(m.ts) + '</td><td>' + st + '</td></tr>';
  }).join('');
  tb.querySelectorAll('tr[data-mid]').forEach(tr => {
    tr.addEventListener('click', () => { selected = tr.dataset.mid; renderTable(); loadHistory(); });
  });
}

async function loadHistory() {
  if (!selected) return;
  const hours = document.getElementById('range').value;
  const data = await api('/api/history?mid=' + encodeURIComponent(selected) + '&hours=' + hours);
  const pts = data.points || [];
  const labels = pts.map(p => { const d = new Date(p.ts*1000); return d.toLocaleString(); });
  const rx = pts.map(p => (Number(p.today_rx)||0)/1e9);
  const tx = pts.map(p => (Number(p.today_tx)||0)/1e9);
  const total = pts.map((p,i) => rx[i]+tx[i]);
  const ctx = document.getElementById('chart');
  if (chart) chart.destroy();
  chart = new Chart(ctx, {
    type: 'line',
    data: { labels, datasets: [
      { label: '今日入站 GB', data: rx, borderColor: '#60a5fa', tension: 0.25, pointRadius: 0, borderWidth: 2 },
      { label: '今日出站 GB', data: tx, borderColor: '#34d399', tension: 0.25, pointRadius: 0, borderWidth: 2 },
      { label: '今日合计 GB', data: total, borderColor: '#fbbf24', tension: 0.25, pointRadius: 0, borderWidth: 2 },
    ]},
    options: { responsive: true, maintainAspectRatio: false, interaction: { mode: 'index', intersect: false },
      scales: { x: { ticks: { maxTicksLimit: 8, color: '#8aa0c6' }, grid: { color: '#1e2a42' } },
        y: { ticks: { color: '#8aa0c6' }, grid: { color: '#1e2a42' }, title: { display: true, text: 'GB', color: '#8aa0c6' } } },
      plugins: { legend: { labels: { color: '#c7d2fe' } }, title: { display: true, text: selected, color: '#e8eefc' } }
    }
  });
}

async function refresh() {
  const data = await api('/api/machines');
  machines = data.machines || [];
  if (!selected && machines[0]) selected = machines[0].machine_id;
  if (selected && !machines.find(m => m.machine_id === selected)) selected = machines[0]?.machine_id || null;
  renderSummary();
  renderTable();
  await loadHistory();
}

// ─── 设置 ───
async function loadConfig() {
  const data = await api('/api/config');
  document.getElementById('s_ttoken').value = data.ttoken || '';
  document.getElementById('s_tid').value = data.tid || '';
  document.getElementById('s_ttime').value = data.ttime || '20:00:00';
  document.getElementById('s_cftime').value = data.cftime || '0 * * * *';
}

async function saveConfig() {
  const btn = document.querySelector('.save-row .primary');
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = '保存中…';
  try {
    await api('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ttoken: document.getElementById('s_ttoken').value.trim(),
        tid: document.getElementById('s_tid').value.trim(),
        ttime: document.getElementById('s_ttime').value.trim() || '20:00:00',
        cftime: document.getElementById('s_cftime').value.trim() || '0 * * * *',
      }),
    });
    document.getElementById('saveStatus').textContent = '✓ 已保存';
    setTimeout(() => document.getElementById('saveStatus').textContent = '', 3000);
  } catch(e) {
    toast('保存失败：' + e.message);
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
  }
}

// ─── 添加 VPS ───
function openAddVps() {
  document.getElementById('modalVps').classList.add('open');
  document.getElementById('vpsMid').value = '';
  document.getElementById('vpsCmdRegion').style.display = 'none';
  document.getElementById('vpsBtnRegion').style.display = 'flex';
  document.getElementById('vpsMid').focus();
}

function closeAddVps() {
  document.getElementById('modalVps').classList.remove('open');
}

async function genCmd() {
  const mid = document.getElementById('vpsMid').value.trim();
  if (!mid) { toast('请输入机器 ID'); return; }
  const btn = document.querySelector('#vpsBtnRegion .green');
  btn.disabled = true; btn.textContent = '生成中…';
  try {
    const data = await api('/api/generate?mid=' + encodeURIComponent(mid));
    if (!data.ok) { toast(data.error || '生成失败'); return; }
    document.getElementById('vpsOk').textContent = '✓ 命令已生成，复制到 VPS 执行';
    document.getElementById('vpsCmd').textContent = data.command;
    document.getElementById('vpsCmdRegion').style.display = 'block';
    document.getElementById('vpsBtnRegion').style.display = 'none';
  } catch(e) {
    toast('生成失败：' + e.message);
  } finally {
    btn.disabled = false; btn.textContent = '生成命令';
  }
}

async function copyCmd() {
  try {
    await navigator.clipboard.writeText(document.getElementById('vpsCmd').textContent);
    toast('已复制到剪贴板');
  } catch {
    // fallback
    const r = document.createRange();
    r.selectNode(document.getElementById('vpsCmd'));
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
    document.execCommand('copy');
    toast('已复制（请 Ctrl+C 备份）');
  }
}

// 点击 modal 外部关闭
document.getElementById('modalVps').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeAddVps();
});

// 回车触发生成
document.getElementById('vpsMid').addEventListener('keydown', e => {
  if (e.key === 'Enter') genCmd();
});

// 初始化
refresh();
</script>`;
}

// ─── 路由 ───

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // 自动初始化表结构（幂等）
    if (env.DB) {
      try { await ensureSchema(env); } catch { /* 忽略竞争 */ }
    }

    // POST /api/report — agent 上报
    if (req.method === "POST" && url.pathname === "/api/report") {
      if (!reportAuth(req, env)) return json({ ok: false, error: "unauthorized" }, 401);
      if (!env.DB) return json({ ok: false, error: "DB not bound" }, 500);
      let body;
      try { body = await req.json(); } catch { return json({ ok: false, error: "invalid json" }, 400); }
      const mid = body.machine_id || req.headers.get("x-machine-id");
      if (!mid || !/^[A-Za-z0-9._:-]{1,64}$/.test(mid)) return json({ ok: false, error: "machine_id invalid" }, 400);
      await upsertReport(env, { ...body, machine_id: mid });
      return json({ ok: true });
    }

    // /login /logout
    if (url.pathname === "/login") {
      if (req.method === "GET") {
        if (await requireDash(req, env)) return Response.redirect(new URL("/", url).toString(), 302);
        return html(loginPage());
      }
      if (req.method === "POST") {
        const form = await req.formData();
        const pw = String(form.get("password") || "");
        if (!env.DASH_PASSWORD) return Response.redirect(new URL("/", url).toString(), 302);
        if (pw !== env.DASH_PASSWORD) return html(loginPage("密码错误"), 401);
        const token = await makeSessionToken(env);
        return new Response(null, { status: 302, headers: { Location: "/", "Set-Cookie": sessionCookie(token) } });
      }
    }

    if (req.method === "POST" && url.pathname === "/logout") {
      return new Response(null, { status: 302, headers: { Location: "/login", "Set-Cookie": sessionCookie("", 0) } });
    }

    // 以下路由需登录
    if (!(await requireDash(req, env))) {
      if (url.pathname.startsWith("/api/")) return json({ ok: false, error: "unauthorized" }, 401);
      return Response.redirect(new URL("/login", url).toString(), 302);
    }

    // GET /api/machines — 机器列表
    if (req.method === "GET" && url.pathname === "/api/machines") {
      if (!env.DB) return json({ ok: true, machines: [] });
      return json({ ok: true, machines: await listMachines(env) });
    }

    // GET /api/history — 历史曲线
    if (req.method === "GET" && url.pathname === "/api/history") {
      if (!env.DB) return json({ ok: true, points: [] });
      const mid = url.searchParams.get("mid") || "";
      const hours = Math.min(24 * 90, Math.max(1, Number(url.searchParams.get("hours") || 168)));
      if (!/^[A-Za-z0-9._:-]{1,64}$/.test(mid)) return json({ ok: false, error: "mid invalid" }, 400);
      return json({ ok: true, machine_id: mid, hours, points: await getHistory(env, mid, hours) });
    }

    // GET /api/config — 读配置
    if (req.method === "GET" && url.pathname === "/api/config") {
      const cfg = await getConfig(env);
      return json({ ok: true, ...cfg });
    }

    // POST /api/config — 写配置
    if (req.method === "POST" && url.pathname === "/api/config") {
      try {
        const body = await req.json();
        await saveConfig(env, body);
        return json({ ok: true });
      } catch (e) {
        return json({ ok: false, error: String(e) }, 400);
      }
    }

    // GET /api/generate — 生成一键命令
    if (req.method === "GET" && url.pathname === "/api/generate") {
      const mid = url.searchParams.get("mid") || "";
      const result = await generateCommand(env, req, mid);
      if (!result.ok) return json(result, 400);
      return json(result);
    }

    // GET / — 看板页面
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      return html(dashboardPage());
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};
