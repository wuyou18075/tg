/**
 * Cloudflare Worker：多机流量中心
 * - D1 自动初始化（无需手动 schema.sql）
 * - 密码登录看板 + 配置面板（t_token/t_id/t_time/cf_time）
 * - 添加 VPS：生成唯一独立密码，VPS 用此密码上报（不暴露全局 TG 密钥）
 * - TG 汇总：看板「发送 TG 汇总」→ 聚合所有机器 → 发 Telegram
 * - D1 日/月堆叠柱统计 + Chart.js
 *
 * 部署：
 *   1. 创建 D1 数据库 traffic-db
 *   2. 部署本 Worker（wrangler / 一键部署 / 粘贴代码）
 *   3. 绑定 D1：变量名必须是 DB
 *   4. 加密变量：PASSWORD（看板密码，必填）
 *                 TG_ID / TG_BOT_TOKEN（TG 汇总，可选；页面未填时使用）
 * - access_token：Web(Worker) ↔ VPS 通信密钥（每台独立，看板生成）
 * - TG_TOKEN：TG 机器人 Token，VPS 用它给 TG 发消息（tgSummary）；与上报鉴权无关
 *   5. 再部署一次使绑定生效
 */

import { connect as cfTcpConnect } from "cloudflare:sockets";

const SESSION_TTL = 60 * 60 * 24 * 7;
const COOKIE_NAME = "dash_session";
/** 登录失败限流：同 IP 窗口内最多失败次数 */
const LOGIN_FAIL_MAX = 8;
const LOGIN_FAIL_WINDOW_SEC = 15 * 60;

/** 运行时无 DB 时的说明（列出 env 键名，不含密钥值） */
function missingDbError(env) {
  const keys = env && typeof env === "object" ? Object.keys(env).sort() : [];
  return (
    "D1 未绑定：运行时 env.DB 不存在。" +
    "请在 wrangler.toml 写入真实 database_id 后重新部署，" +
    "或 Dashboard 绑定 DB 后点「部署」最新版本。" +
    (keys.length ? " 当前 env 键：" + keys.join(", ") : " 当前 env 为空")
  );
}


/** JSON 中非 ASCII 一律 \uXXXX，避免链路把 UTF-8 多字节解错成乱码 */
function jsonStringifySafe(data) {
  return JSON.stringify(data).replace(/[-￿]/g, (ch) => {
    const cp = ch.codePointAt(0);
    if (cp > 0xffff) {
      const s = String.fromCodePoint(cp);
      return (
        "\\u" + s.charCodeAt(0).toString(16).padStart(4, "0") +
        "\\u" + s.charCodeAt(1).toString(16).padStart(4, "0")
      );
    }
    return "\\u" + cp.toString(16).padStart(4, "0");
  });
}

const json = (data, status = 200, extra = {}) =>
  new Response(jsonStringifySafe(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-language": "zh-CN",
      ...extra,
    },
  });

const html = (body, status = 200, extra = {}) =>
  new Response(body, {
    status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "content-language": "zh-CN",
      ...extra,
    },
  });

function gb(n) {
  return ((Number(n) || 0) / 1e9).toFixed(3) + "GB";
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}


/** 机器 ID：1-64 字符，允许中英文、数字、._-: ，禁止空白与引号 */
function isValidMachineId(mid) {
  const id = String(mid || "").trim();
  if (!id || id.length > 64) return false;
  // 字母/数字/CJK/常见符号，禁止空白、引号、斜杠等
  return /^[\u4e00-\u9fffA-Za-z0-9._:-]{1,64}$/.test(id);
}


function isValidCallbackUrl(u) {
  if (!u || typeof u !== "string") return false;
  if (u.length < 12 || u.length > 256) return false;
  try {
    const x = new URL(u);
    if (x.protocol !== "http:" && x.protocol !== "https:") return false;
    if (!x.pathname || x.pathname === "/") return false;
    return true;
  } catch {
    return false;
  }
}

/** 回调端口校验：1024-65535 */
function isValidPort(p) {
  const n = Number(p);
  return /^\d+$/.test(String(p)) && n >= 1024 && n <= 65535;
}
/** 默认回调端口 */
const DEFAULT_CB_PORT = 19840;
/** 从 callback_url 解析端口；失败回退默认 */
function portFromCallback(cb) {
  try {
    const u = new URL(cb);
    if (u.port) return u.port;
    return u.protocol === "https:" ? "443" : String(DEFAULT_CB_PORT);
  } catch {
    return String(DEFAULT_CB_PORT);
  }
}

function toHex(buf) {
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hmacSha256Hex(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  return toHex(sig);
}

function randomNonce(len = 16) {
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return toHex(buf);
}

function bashSingleQuote(s) {
  return String(s).replace(/'/g, `'\''`);
}

/** 从请求取出 Bearer token（已 trim） */
function extractBearer(req) {
  const h = req.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m ? String(m[1] || "").replace(/\r/g, "").trim() : "";
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

/** 会话签名密钥：优先 SESSION_SECRET，否则回退 PASSWORD（兼容旧部署） */
function sessionSecret(env) {
  const s = (env && (env.SESSION_SECRET || env.PASSWORD)) || "";
  return String(s);
}

async function makeSessionToken(env) {
  const secret = sessionSecret(env);
  if (!secret) return "";
  const rnd = crypto.randomUUID() + crypto.randomUUID();
  const exp = Math.floor(Date.now() / 1000) + SESSION_TTL;
  // rnd.exp.sig —— 签名含过期时间；改 PASSWORD 或 SESSION_SECRET 会使旧会话失效
  const sig = await sha256Hex(`${rnd}:${exp}:${secret}:dash`);
  return `${rnd}.${exp}.${sig}`;
}

async function verifySessionToken(token, env) {
  if (!token || !env.PASSWORD) return false;
  const secret = sessionSecret(env);
  if (!secret) return false;
  const parts = String(token).split(".");
  // 新格式 rnd.exp.sig
  if (parts.length === 3) {
    const [rnd, expStr, sig] = parts;
    const exp = Number(expStr);
    if (!rnd || rnd.length < 32 || !Number.isFinite(exp)) return false;
    if (Math.floor(Date.now() / 1000) > exp) return false;
    return sig === (await sha256Hex(`${rnd}:${exp}:${secret}:dash`));
  }
  // 兼容旧格式 rnd.sig（无 exp；仅当仍用 PASSWORD 作 secret 时可验）
  if (parts.length === 2) {
    const [rnd, sig] = parts;
    return !!rnd && rnd.length >= 32 && sig === (await sha256Hex(`${rnd}:${secret}:dash`));
  }
  return false;
}

function sessionCookie(token, maxAge = SESSION_TTL) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function requireDash(req, env) {
  // 未配 PASSWORD：视为未登录，拦截到登录页并提示配置（不再裸奔放行）
  if (!env.PASSWORD) return false;
  return verifySessionToken(parseCookies(req)[COOKIE_NAME], env);
}

/** 登录失败计数 key（按 IP） */
function loginFailKey(ip) {
  return "login_fail:" + String(ip || "-").slice(0, 64);
}

/** 是否处于登录锁定；返回 { locked, remainSec, fails } */
async function getLoginLock(env, ip) {
  if (!env.DB) return { locked: false, remainSec: 0, fails: 0 };
  try {
    const row = await env.DB.prepare(`SELECT value, updated_at FROM config WHERE key = ?`)
      .bind(loginFailKey(ip)).first();
    if (!row) return { locked: false, remainSec: 0, fails: 0 };
    const fails = Number(row.value) || 0;
    const updated = Number(row.updated_at) || 0;
    const now = Math.floor(Date.now() / 1000);
    if (now - updated > LOGIN_FAIL_WINDOW_SEC) {
      // 窗口过期：清零
      try { await env.DB.prepare(`DELETE FROM config WHERE key = ?`).bind(loginFailKey(ip)).run(); } catch {}
      return { locked: false, remainSec: 0, fails: 0 };
    }
    if (fails >= LOGIN_FAIL_MAX) {
      return { locked: true, remainSec: Math.max(1, LOGIN_FAIL_WINDOW_SEC - (now - updated)), fails };
    }
    return { locked: false, remainSec: 0, fails };
  } catch {
    return { locked: false, remainSec: 0, fails: 0 };
  }
}

async function recordLoginFail(env, ip) {
  if (!env.DB) return;
  const now = Math.floor(Date.now() / 1000);
  const key = loginFailKey(ip);
  try {
    const row = await env.DB.prepare(`SELECT value, updated_at FROM config WHERE key = ?`).bind(key).first();
    let fails = 1;
    if (row) {
      const updated = Number(row.updated_at) || 0;
      if (now - updated <= LOGIN_FAIL_WINDOW_SEC) fails = (Number(row.value) || 0) + 1;
    }
    await env.DB.prepare(
      `INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
    ).bind(key, String(fails), now).run();
  } catch { /* ignore */ }
}

async function clearLoginFail(env, ip) {
  if (!env.DB) return;
  try { await env.DB.prepare(`DELETE FROM config WHERE key = ?`).bind(loginFailKey(ip)).run(); } catch {}
}

/** 密码比较：长度不同直接 false；等长逐字节 OR，降低时序差异 */
function passwordEqual(a, b) {
  const x = String(a ?? "");
  const y = String(b ?? "");
  if (x.length !== y.length) return false;
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x.charCodeAt(i) ^ y.charCodeAt(i);
  return d === 0;
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
      )`),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS snapshots (
        id INTEGER PRIMARY KEY AUTOINCREMENT, machine_id TEXT NOT NULL,
        ts INTEGER NOT NULL, today_rx INTEGER, today_tx INTEGER,
        month_rx INTEGER, month_tx INTEGER
      )`),
    env.DB.prepare(
      `CREATE INDEX IF NOT EXISTS idx_snap_mid_ts ON snapshots(machine_id, ts)`),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS config (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at INTEGER)`),
    env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS vps_tokens (
        machine_id TEXT PRIMARY KEY, token TEXT NOT NULL, created_at INTEGER
      )`),
  ]);
  try {
    await env.DB.prepare(`ALTER TABLE machines ADD COLUMN callback_url TEXT`).run();
  } catch {}
  try {
    await env.DB.prepare(`ALTER TABLE machines ADD COLUMN online_sec INTEGER DEFAULT 0`).run();
  } catch {}
  try {
    await env.DB.prepare(`ALTER TABLE vps_tokens ADD COLUMN pending_token TEXT`).run();
  } catch {}
  try {
    await env.DB.prepare(`ALTER TABLE machines ADD COLUMN in_tg_report INTEGER DEFAULT 1`).run();
  } catch {}
  try {
    await env.DB.prepare(
      `CREATE TABLE IF NOT EXISTS login_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER NOT NULL,
        ip TEXT, ua TEXT, success INTEGER, reason TEXT
      )`).run();
  } catch {}
  try {
    await env.DB.prepare(`ALTER TABLE machines ADD COLUMN offline_notified INTEGER DEFAULT 0`).run();
  } catch {}
}

/** 上报间隔 ≤ 此秒数视为连续在线，计入累积在线时长（与看板「在线」2h 一致） */
const ONLINE_GAP_SEC = 7200;

// ─── 数据操作 ───

async function upsertReport(env, rec) {
  const mid = rec.machine_id;
  const ts = Number(rec.ts) || Math.floor(Date.now() / 1000);
  const today = rec.today || {};
  const month = rec.month || {};
  const now = Math.floor(Date.now() / 1000);
  const cbRaw = rec.callback_url != null ? String(rec.callback_url).trim() : "";
  const callback_url = isValidCallbackUrl(cbRaw) ? cbRaw : null;

  // 累积在线 + 跨日封存：先读旧行（含 today_*），日切时把「昨天最终累计」写入 snapshot，避免被新一天覆盖后图上只剩今天
  const prev = await env.DB.prepare(
    `SELECT last_ts, online_sec, today_rx, today_tx, month_rx, month_tx FROM machines WHERE machine_id = ?`
  ).bind(mid).first();
  let online_sec = prev ? (Number(prev.online_sec) || 0) : 0;
  if (prev && prev.last_ts != null) {
    const gap = ts - Number(prev.last_ts);
    if (gap > 0 && gap <= ONLINE_GAP_SEC) {
      online_sec += gap;
    }
  }

  // 上海自然日切换：用旧行 today_* 补一条「昨日封存」snapshot（节流也不会丢整天）
  if (prev && prev.last_ts != null) {
    const prevTs = Number(prev.last_ts) || 0;
    const prevDay = shanghaiBucket(prevTs, false);
    const curDay = shanghaiBucket(ts, false);
    if (prevDay && curDay && prevDay !== curDay) {
      try {
        await env.DB.prepare(
          `INSERT INTO snapshots (machine_id, ts, today_rx, today_tx, month_rx, month_tx)
           VALUES (?, ?, ?, ?, ?, ?)`
        ).bind(
          mid,
          prevTs,
          Number(prev.today_rx) || 0,
          Number(prev.today_tx) || 0,
          Number(prev.month_rx) || 0,
          Number(prev.month_tx) || 0,
        ).run();
      } catch { /* ignore seal errors */ }
    }
  }

  await env.DB.prepare(
    `INSERT INTO machines (machine_id, hostname, interface, last_ts, today_rx, today_tx, month_rx, month_tx, updated_at, callback_url, online_sec)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(machine_id) DO UPDATE SET
       hostname=excluded.hostname, interface=excluded.interface,
       last_ts=excluded.last_ts, today_rx=excluded.today_rx, today_tx=excluded.today_tx,
       month_rx=excluded.month_rx, month_tx=excluded.month_tx, updated_at=excluded.updated_at,
       callback_url=COALESCE(excluded.callback_url, machines.callback_url),
       online_sec=excluded.online_sec`
  ).bind(mid, rec.hostname || "", rec.interface || "", ts,
    Number(today.rx) || 0, Number(today.tx) || 0,
    Number(month.rx) || 0, Number(month.tx) || 0, now, callback_url, online_sec
  ).run();

  // 写历史：5 分钟节流；跨上海自然日必须立刻落一条（当天第一笔）
  const last = await env.DB.prepare(
    `SELECT ts FROM snapshots WHERE machine_id = ? ORDER BY ts DESC LIMIT 1`
  ).bind(mid).first();
  const lastTs = last ? Number(last.ts) || 0 : 0;
  const crossedDay = !lastTs || shanghaiBucket(lastTs, false) !== shanghaiBucket(ts, false);
  if (!lastTs || crossedDay || (ts - lastTs) >= 300) {
    await env.DB.prepare(
      `INSERT INTO snapshots (machine_id, ts, today_rx, today_tx, month_rx, month_tx)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(mid, ts, Number(today.rx) || 0, Number(today.tx) || 0,
      Number(month.rx) || 0, Number(month.tx) || 0).run();
  }
  // 90 天清理改到 scheduled 每日一次，避免每条上报都扫表
}

/** 清理过期 snapshot（90 天）；每日最多执行一次（用 config 日锁） */
async function cleanupOldSnapshots(env) {
  if (!env.DB) return;
  const now = Math.floor(Date.now() / 1000);
  const today = shanghaiBucket(now, false);
  try {
    const last = await getConfigValue(env, "last_snapshot_cleanup_date");
    if (last === today) return;
    await env.DB.prepare(`DELETE FROM snapshots WHERE ts < ?`).bind(now - 90 * 86400).run();
    await setConfigValue(env, "last_snapshot_cleanup_date", today);
  } catch (e) {
    console.log("[cleanup] snapshots", e && e.message);
  }
}

async function listMachines(env) {
  const { results } = await env.DB.prepare(
    `SELECT * FROM machines ORDER BY last_ts DESC`
  ).all();
  const nowSec = Math.floor(Date.now() / 1000);
  return (results || []).map((r) => {
    const base = Number(r.online_sec) || 0;
    const lastTs = Number(r.last_ts) || 0;
    // 当前仍在线：把距上次上报的时间也算进展示值
    const liveExtra = (lastTs && (nowSec - lastTs) >= 0 && (nowSec - lastTs) < ONLINE_GAP_SEC)
      ? (nowSec - lastTs)
      : 0;
    return {
      machine_id: r.machine_id, hostname: r.hostname, interface: r.interface, ts: r.last_ts,
      today: { rx: r.today_rx || 0, tx: r.today_tx || 0, total: (r.today_rx || 0) + (r.today_tx || 0) },
      month: { rx: r.month_rx || 0, tx: r.month_tx || 0, total: (r.month_rx || 0) + (r.month_tx || 0) },
      updated_at: r.updated_at,
      callback_url: r.callback_url || "",
      in_tg_report: r.in_tg_report === 0 ? false : true,
      offline_notified: !!r.offline_notified,
      online_sec: base,
      online_sec_live: base + liveExtra,
    };
  });
}

async function getHistory(env, mid, hours) {
  const since = Math.floor(Date.now() / 1000) - hours * 3600;
  const { results } = await env.DB.prepare(
    `SELECT ts, today_rx, today_tx, month_rx, month_tx
     FROM snapshots WHERE machine_id = ? AND ts >= ? ORDER BY ts ASC`
  ).bind(mid, since).all();
  return results || [];
}

/** 秒级时间戳 → 上海时区日历部件 {y,m,d}（Worker 默认 UTC，不能直接 getDate） */
function shanghaiYmd(tsSec) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date(Number(tsSec) * 1000));
  const get = (t) => parts.find((p) => p.type === t)?.value || "00";
  return { y: Number(get("year")), m: Number(get("month")), d: Number(get("day")) };
}

/** 上海时区「今天」的 day/month bucket 标签 */
function shanghaiBucket(tsSec, isMonth) {
  const { y, m, d } = shanghaiYmd(tsSec);
  if (isMonth) return y + "-" + String(m).padStart(2, "0");
  return y + "-" + String(m).padStart(2, "0") + "-" + String(d).padStart(2, "0");
}

/** 从上海时区今天起，往前推 i 天/月 的 bucket 标签 */
function shanghaiLabelOffset(i, isMonth) {
  // 用「上海当前时刻」的 epoch，再偏移；避免 UTC 午夜边界
  const nowSec = Math.floor(Date.now() / 1000);
  const { y, m, d } = shanghaiYmd(nowSec);
  if (isMonth) {
    // 月份：y/m 减 i
    let yy = y, mm = m - i;
    while (mm <= 0) { mm += 12; yy -= 1; }
    return yy + "-" + String(mm).padStart(2, "0");
  }
  // 日：构造上海日历日的近似 epoch（UTC+8 正午防 DST 边界），再减 i 天
  const noonUtcMs = Date.UTC(y, m - 1, d, 4, 0, 0); // 上海 12:00 = UTC 04:00
  const t = Math.floor(noonUtcMs / 1000) - i * 86400;
  return shanghaiBucket(t, false);
}

/** 上海时区小时桶标签：YYYY-MM-DD HH:00 */
function shanghaiHourBucket(tsSec) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", hourCycle: "h23",
  }).formatToParts(new Date(Number(tsSec) * 1000));
  const get = (t) => parts.find((p) => p.type === t)?.value || "00";
  return get("year") + "-" + get("month") + "-" + get("day") + " " + get("hour") + ":00";
}

/** 当前上海时刻往前第 i 小时的整点标签（i=0 当前小时） */
function shanghaiHourLabelOffset(i) {
  const nowSec = Math.floor(Date.now() / 1000);
  // 取当前上海小时，再减 i 小时：用 UTC 近似减 3600*i（上海无夏令时，安全）
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Shanghai",
    year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", hourCycle: "h23",
  }).formatToParts(new Date(nowSec * 1000));
  const get = (t) => Number(parts.find((p) => p.type === t)?.value || 0);
  // 构造该上海小时的 UTC epoch：上海 HH:30 = UTC (HH-8):30
  const y = get("year"), m = get("month"), d = get("day"), h = get("hour");
  const utcMs = Date.UTC(y, m - 1, d, h - 8, 30, 0) - i * 3600 * 1000;
  return shanghaiHourBucket(Math.floor(utcMs / 1000));
}

/**
 * 日内小时折线：近 span 小时内，各整点「该小时新增流量」
 *  - 用 snapshot 的 today_rx/tx 累计值差分（跨自然日重置时不减前一日）
 *  - mid 空 = 全部机器求和
 */
async function getHistoryHourly(env, { mid, span }) {
  const n = Math.min(72, Math.max(6, Number(span) || 24));
  const now = Math.floor(Date.now() / 1000);
  const since = now - n * 3600 - 3600; // 多取 1h 便于首点差分

  let sql = `SELECT machine_id, ts, today_rx, today_tx
             FROM snapshots WHERE ts >= ?`;
  const binds = [since];
  if (mid) {
    sql += ` AND machine_id = ?`;
    binds.push(mid);
  }
  sql += ` ORDER BY ts ASC`;
  const { results } = await env.DB.prepare(sql).bind(...binds).all();
  const rows = results || [];

  // 每机每小时取最后一条累计值
  const lastByHourMid = new Map(); // hour|mid -> {hour, mid, day, rx, tx}
  for (const r of rows) {
    const ts = Number(r.ts) || 0;
    const hour = shanghaiHourBucket(ts);
    const day = shanghaiBucket(ts, false);
    const k = hour + "|" + r.machine_id;
    lastByHourMid.set(k, {
      hour, mid: r.machine_id, day,
      rx: Number(r.today_rx) || 0,
      tx: Number(r.today_tx) || 0,
    });
  }

  // 按机分组，按小时排序后差分
  const byMid = new Map();
  for (const v of lastByHourMid.values()) {
    if (!byMid.has(v.mid)) byMid.set(v.mid, []);
    byMid.get(v.mid).push(v);
  }
  const deltaByHour = new Map(); // hour -> {rx, tx}
  for (const list of byMid.values()) {
    list.sort((a, b) => (a.hour < b.hour ? -1 : a.hour > b.hour ? 1 : 0));
    let prev = null;
    for (const cur of list) {
      let drx = cur.rx, dtx = cur.tx;
      if (prev && prev.day === cur.day) {
        drx = Math.max(0, cur.rx - prev.rx);
        dtx = Math.max(0, cur.tx - prev.tx);
      }
      // 跨日：首点用累计本身（即当天截至该小时的量）；若同日多点则差分
      // 若跨日且 prev 存在：用 cur 累计（从 0 起的今日量），合理
      if (prev && prev.day !== cur.day) {
        drx = Math.max(0, cur.rx);
        dtx = Math.max(0, cur.tx);
      }
      if (!prev) {
        // 序列第一点：无前值，无法可靠估「本小时增量」，记 0 避免把全天累计当小时增量
        drx = 0;
        dtx = 0;
      }
      const acc = deltaByHour.get(cur.hour) || { rx: 0, tx: 0 };
      acc.rx += drx;
      acc.tx += dtx;
      deltaByHour.set(cur.hour, acc);
      prev = cur;
    }
  }

  // 时间轴：近 n 小时（含当前小时）
  const labels = [];
  for (let i = n - 1; i >= 0; i--) labels.push(shanghaiHourLabelOffset(i));

  const points = labels.map((bucket) => {
    const v = deltaByHour.get(bucket) || { rx: 0, tx: 0 };
    return { bucket, rx: v.rx, tx: v.tx, total: v.rx + v.tx };
  });
  return { mode: "hour", span: n, machine_id: mid || null, points };
}

/** 日/月聚合：单机 mid 或全部（mid 空）。
 *  day:  每天取各机最后一条 snapshot 的 today_rx/tx，再按日求和
 *  month: 每月取各机最后一条 snapshot 的 month_rx/tx，再按月求和
 *  分桶统一用 Asia/Shanghai，与 VPS 本机「今日」对齐
 */
async function getHistoryAgg(env, { mid, mode, span }) {
  const isMonth = mode === "month";
  // 日聚合最长 31 天（一个月）；月聚合最长 24 个月
  const n = Math.min(isMonth ? 24 : 31, Math.max(1, Number(span) || (isMonth ? 12 : 31)));
  const now = Math.floor(Date.now() / 1000);
  const since = isMonth ? now - n * 31 * 86400 : now - n * 86400;

  let sql = `SELECT machine_id, ts, today_rx, today_tx, month_rx, month_tx
             FROM snapshots WHERE ts >= ?`;
  const binds = [since];
  if (mid) {
    sql += ` AND machine_id = ?`;
    binds.push(mid);
  }
  sql += ` ORDER BY ts ASC`;
  const { results } = await env.DB.prepare(sql).bind(...binds).all();
  const rows = results || [];

  // key → { rx, tx }  先按 (bucket, machine) 取最后一条，再跨机求和
  const lastByBucketMid = new Map();
  for (const r of rows) {
    const bucket = shanghaiBucket(Number(r.ts) || 0, isMonth);
    const k = bucket + "|" + r.machine_id;
    lastByBucketMid.set(k, {
      bucket,
      rx: Number(isMonth ? r.month_rx : r.today_rx) || 0,
      tx: Number(isMonth ? r.month_tx : r.today_tx) || 0,
    });
  }

  const byBucket = new Map();
  for (const v of lastByBucketMid.values()) {
    const cur = byBucket.get(v.bucket) || { rx: 0, tx: 0 };
    cur.rx += v.rx;
    cur.tx += v.tx;
    byBucket.set(v.bucket, cur);
  }

  // 用 machines 表「当前值」覆盖今天/本月桶：获取流量已更新列表但 snapshot 尚未写入时，图也能显示当天
  try {
    let liveSql = `SELECT machine_id, today_rx, today_tx, month_rx, month_tx, last_ts FROM machines`;
    const liveBinds = [];
    if (mid) {
      liveSql += ` WHERE machine_id = ?`;
      liveBinds.push(mid);
    }
    const live = liveBinds.length
      ? await env.DB.prepare(liveSql).bind(...liveBinds).all()
      : await env.DB.prepare(liveSql).all();
    const liveRows = live.results || [];
    if (liveRows.length) {
      const todayKey = shanghaiBucket(now, false);
      const monthKey = shanghaiBucket(now, true);
      if (isMonth) {
        let rx = 0, tx = 0;
        for (const r of liveRows) {
          rx += Number(r.month_rx) || 0;
          tx += Number(r.month_tx) || 0;
        }
        byBucket.set(monthKey, { rx, tx });
      } else {
        let rx = 0, tx = 0;
        for (const r of liveRows) {
          rx += Number(r.today_rx) || 0;
          tx += Number(r.today_tx) || 0;
        }
        byBucket.set(todayKey, { rx, tx });
      }
    }
  } catch { /* ignore live overlay */ }

  // 补齐时间轴空桶（上海时区）
  const labels = [];
  for (let i = n - 1; i >= 0; i--) {
    labels.push(shanghaiLabelOffset(i, isMonth));
  }

  const points = labels.map((bucket) => {
    const v = byBucket.get(bucket) || { rx: 0, tx: 0 };
    return { bucket, rx: v.rx, tx: v.tx, total: v.rx + v.tx };
  });
  return { mode: isMonth ? "month" : "day", span: n, machine_id: mid || null, points };
}

async function getConfig(env) {
  const raw = {};
  if (env.DB) {
    try {
      const { results } = await env.DB.prepare(`SELECT key, value FROM config`).all();
      for (const r of results || []) raw[r.key] = r.value;
    } catch {}
  }
  // 页面有值用页面；空则环境变量；时间类始终有默认
  const pageToken = raw.t_token != null ? String(raw.t_token).trim() : "";
  const pageId = raw.t_id != null ? String(raw.t_id).trim() : "";
  const envToken = env.TG_TOKEN || env.TG_BOT_TOKEN || env.BOT_TOKEN || env.TELEGRAM_BOT_TOKEN || "";
  const envId = env.TG_ID || "";
  const t_token = pageToken || envToken || "";
  const t_id = pageId || envId || "";
  const t_time = (raw.t_time != null && String(raw.t_time).trim()) || "20:00:00";
  const cf_time = (raw.cf_time != null && String(raw.cf_time).trim()) || "0 * * * *";
  return {
    t_token,
    t_id,
    t_time,
    cf_time,
    t_token_from_env: !pageToken && !!envToken,
    t_id_from_env: !pageId && !!envId,
  };
}

/** TG 配置状态：not_configured / incomplete / invalid / ready / ok */
async function getTgStatus(env, verify = false) {
  const cfg = await getConfig(env);
  const token = cfg.t_token || "";
  const id = cfg.t_id || "";
  const source = {
    token: cfg.t_token_from_env ? "环境变量 TG_BOT_TOKEN" : (token ? "看板设置" : "未配置"),
    id: cfg.t_id_from_env ? "环境变量 TG_ID" : (id ? "看板设置" : "未配置"),
  };
  if (!token && !id) {
    return { state: "not_configured", detail: "未配置 Bot Token 与 Chat ID", source };
  }
  if (!token) return { state: "incomplete", detail: "缺少 Bot Token", source };
  if (!id) return { state: "incomplete", detail: "缺少 Chat ID", source };
  if (!/^\d{5,20}:[A-Za-z0-9_-]{20,100}$/.test(token)) {
    return { state: "invalid", detail: "Bot Token 格式错误", source };
  }
  if (!/^-?\d{5,20}$/.test(id)) {
    return { state: "invalid", detail: "Chat ID 格式错误", source };
  }
  if (verify) {
    try {
      const r1 = await fetch(`https://api.telegram.org/bot${token}/getMe`);
      const j1 = await r1.json();
      if (!j1.ok) {
        return { state: "invalid", detail: "Bot Token 验证失败：" + (j1.description || "无效"), source };
      }
      const bot = (j1.result && j1.result.username) ? ("@" + j1.result.username) : "";
      const r2 = await fetch(`https://api.telegram.org/bot${token}/getChat?chat_id=${encodeURIComponent(id)}`);
      const j2 = await r2.json();
      if (!j2.ok) {
        return { state: "invalid", detail: "Chat ID 不可达：" + (j2.description || "需先向 bot 发消息/加群"), source, bot };
      }
      return { state: "ok", detail: "验证通过" + (bot ? "，Bot " + bot : ""), source, bot };
    } catch (e) {
      return { state: "invalid", detail: "验证请求失败：" + (e && e.message ? e.message : e), source };
    }
  }
  return { state: "ready", detail: "配置完整（点测试可真实校验）", source };
}

async function saveConfig(env, data) {
  if (!env.DB) throw new Error(missingDbError(env));
  const now = Math.floor(Date.now() / 1000);
  // t_token / t_id：空字符串表示「回退环境变量」，删除 D1 中的 key，避免空串污染
  // t_time / cf_time：空则写默认值
  const stmts = [];
  if (data.t_token !== undefined) {
    const v = String(data.t_token).trim();
    if (v) {
      stmts.push(env.DB.prepare(
        `INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
      ).bind("t_token", v, now));
    } else {
      stmts.push(env.DB.prepare(`DELETE FROM config WHERE key = ?`).bind("t_token"));
    }
  }
  if (data.t_id !== undefined) {
    const v = String(data.t_id).trim();
    if (v) {
      stmts.push(env.DB.prepare(
        `INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
      ).bind("t_id", v, now));
    } else {
      stmts.push(env.DB.prepare(`DELETE FROM config WHERE key = ?`).bind("t_id"));
    }
  }
  if (data.t_time !== undefined) {
    const v = String(data.t_time).trim() || "20:00:00";
    stmts.push(env.DB.prepare(
      `INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
    ).bind("t_time", v, now));
  }
  if (data.cf_time !== undefined) {
    const v = String(data.cf_time).trim() || "0 * * * *";
    stmts.push(env.DB.prepare(
      `INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
    ).bind("cf_time", v, now));
  }
  if (stmts.length) await env.DB.batch(stmts);
}

// ─── VPS Token 管理 ───

/** 生成随机 access_token（32 字节 hex） */
function randomAccessToken() {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join("");
}

async function getOrCreateVpsToken(env, mid) {
  if (!env.DB) throw new Error(missingDbError(env));
  const existing = await env.DB.prepare(
    `SELECT token FROM vps_tokens WHERE machine_id = ?`
  ).bind(mid).first();
  if (existing) return String(existing.token || "").trim();

  const token = randomAccessToken();
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO vps_tokens (machine_id, token, created_at) VALUES (?, ?, ?)`
  ).bind(mid, token, now).run();
  return token;
}

/**
 * 验证上报 Bearer，并处理 token 轮换协商：
 *  - VPS 主动：body.refresh_access_token 有值 → 切换为新 token
 *  - Web 主动：pending_token 有值且 VPS 仍用旧 token → 下发 pending
 *  - 重装：VPS 直接用 pending_token 上报 → 确认应用
 * 返回 { ok, new_access_token? }
 */
async function verifyAndRotate(env, mid, bearer, refreshRaw) {
  if (!bearer) return { ok: false };
  const row = await env.DB.prepare(
    `SELECT token, pending_token FROM vps_tokens WHERE machine_id = ?`
  ).bind(mid).first();
  if (!row) return { ok: false };

  const cur = String(row.token || "").replace(/\r/g, "").trim();
  const pend = String(row.pending_token || "").replace(/\r/g, "").trim();
  const b = String(bearer).replace(/\r/g, "").trim();

  let usingCurrent = !!(cur && b === cur);
  let usingPending = !!(pend && b === pend);
  if (!usingCurrent && !usingPending) return { ok: false };

  const refresh = String(refreshRaw || "").replace(/\r/g, "").trim();
  let newTok = null;
  if (refresh && /^[A-Za-z0-9._~+/-]{8,256}$/.test(refresh)) {
    newTok = refresh;
  } else if (pend && usingCurrent) {
    newTok = pend;
  }

  if (newTok) {
    await env.DB.prepare(
      `UPDATE vps_tokens SET token = ?, pending_token = NULL WHERE machine_id = ?`
    ).bind(newTok, mid).run();
    return { ok: true, new_access_token: newTok };
  }
  // 用 pending 上报（重装场景），确认应用
  if (usingPending && pend && pend !== cur) {
    await env.DB.prepare(
      `UPDATE vps_tokens SET token = ?, pending_token = NULL WHERE machine_id = ?`
    ).bind(pend, mid).run();
  }
  return { ok: true };
}

/** 写入/覆盖某机 access_token（上报成功时同步，保证获取流量一致） */
async function upsertVpsToken(env, mid, token) {
  if (!env.DB || !mid || !token) return;
  const tok = String(token).replace(/\r/g, "").trim();
  if (!tok || tok.length < 8) return;
  const now = Math.floor(Date.now() / 1000);
  // 成功确认的 token 提正：同时清掉 pending，避免 force 推送后状态不一致
  await env.DB.prepare(
    `INSERT INTO vps_tokens (machine_id, token, created_at, pending_token) VALUES (?, ?, ?, NULL)
     ON CONFLICT(machine_id) DO UPDATE SET token = excluded.token, pending_token = NULL`,
  ).bind(mid, tok, now).run();
}

async function verifyVpsToken(env, mid, token) {
  const row = await env.DB.prepare(
    `SELECT token FROM vps_tokens WHERE machine_id = ?`
  ).bind(mid).first();
  if (!row) return false;
  const a = String(row.token || "").replace(/\r/g, "").trim();
  const b = String(token || "").replace(/\r/g, "").trim();
  if (!a || !b || a.length !== b.length) return false;
  // 简单等长比较（token 为 hex/ASCII，非密码学时序敏感场景）
  let ok = 0;
  for (let i = 0; i < a.length; i++) ok |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return ok === 0;
}

async function deleteVpsToken(env, mid) {
  await env.DB.prepare(`DELETE FROM vps_tokens WHERE machine_id = ?`).bind(mid).run();
}

// ─── 生成一键命令 ───


async function getVpsTokenFull(env, mid) {
  if (!env.DB) return null;
  const row = await env.DB.prepare(
    `SELECT token FROM vps_tokens WHERE machine_id = ?`,
  ).bind(mid).first();
  return row ? row.token : null;
}

/** 轮换 VPS token（强制新密钥） */
async function rotateVpsToken(env, mid) {
  if (!env.DB) throw new Error(missingDbError(env));
  await deleteVpsToken(env, mid);
  return getOrCreateVpsToken(env, mid);
}

/** 删除机器：上报数据 + 历史 + token */
async function deleteMachine(env, mid) {
  if (!env.DB) throw new Error(missingDbError(env));
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM snapshots WHERE machine_id = ?`).bind(mid),
    env.DB.prepare(`DELETE FROM machines WHERE machine_id = ?`).bind(mid),
    env.DB.prepare(`DELETE FROM vps_tokens WHERE machine_id = ?`).bind(mid),
  ]);
}

/** 批量操作：delete / include_tg / exclude_tg */
async function machineBatch(env, ids, action) {
  if (!env.DB) throw new Error(missingDbError(env));
  const mids = (ids || []).map(x => String(x || "").trim()).filter(Boolean);
  if (!mids.length) return { ok: false, error: "未选择机器" };
  if (!["delete", "include_tg", "exclude_tg"].includes(action)) {
    return { ok: false, error: "未知操作" };
  }
  const ph = mids.map(() => "?").join(",");
  if (action === "delete") {
    for (const mid of mids) { try { await deleteMachine(env, mid); } catch {} }
  } else {
    const val = action === "include_tg" ? 1 : 0;
    await env.DB.prepare(
      `UPDATE machines SET in_tg_report = ? WHERE machine_id IN (${ph})`
    ).bind(val, ...mids).run();
  }
  return { ok: true, action, affected: mids.length };
}

function buildInstallCommand(mid, accessToken, cf_url, cf_time, cb_port) {
  const midQ = bashSingleQuote(mid);
  const timeQ = bashSingleQuote(cf_time || "0 * * * *");
  const port = isValidPort(cb_port) ? String(cb_port) : String(DEFAULT_CB_PORT);
  return [
    "m_id='" + midQ + "' \\",
    "access_token='" + accessToken + "' \\",
    "cf_url='" + cf_url + "' \\",
    "cf_time='" + timeQ + "' \\",
    "cb_port='" + port + "' \\",
    "  bash <(curl -fsSL 'https://raw.githubusercontent.com/wuyou18075/tg/refs/heads/main/sum.sh')",
  ].join("\n");
}

async function generateCommand(env, request, rawMid) {
  const mid = String(rawMid || "").trim();
  // 先校验再写库，避免无效 ID 污染 vps_tokens
  if (!isValidMachineId(mid)) {
    return {
      ok: false,
      error: "机器 ID 应为 1-64 字，支持中英文、数字及 ._-:（如 香港-1 / hk-1），不要空格",
    };
  }

  if (!env.DB) {
    return { ok: false, error: missingDbError(env) };
  }

  let vpsToken;
  let cf_time = "0 * * * *";
  try {
    const cfg = await getConfig(env);
    cf_time = cfg.cf_time || "0 * * * *";
    vpsToken = await getOrCreateVpsToken(env, mid);
  } catch (e) {
    return { ok: false, error: "生成失败：" + (e && e.message ? e.message : String(e)) };
  }
  const url = new URL(request.url);
  const cf_url = url.origin + "/api/report";
  const cb_port = String(url.searchParams.get("cb_port") || "").trim();
  if (cb_port && !isValidPort(cb_port)) {
    return { ok: false, error: "cb_port 应为 1024-65535" };
  }
  const cmd = buildInstallCommand(mid, vpsToken, cf_url, cf_time, cb_port || DEFAULT_CB_PORT);

  return {
    ok: true,
    command: cmd,
    machine_id: mid,
    token: vpsToken.slice(0, 8) + "...", // 只展示前缀
  };
}


/**
 * 更新注册：复用/编辑参数后生成安装升级命令
 * body: { machine_id, access_token?, cf_url?, cf_time?, rotate_token? }
 */
async function generateUpdateCommand(env, request, body) {
  const mid = String((body && body.machine_id) || "").trim();
  if (!isValidMachineId(mid)) {
    return {
      ok: false,
      error: "机器 ID 应为 1-64 字，支持中英文、数字及 ._-:（如 香港-1 / hk-1），不要空格",
    };
  }
  if (!env.DB) return { ok: false, error: missingDbError(env) };

  const cfg = await getConfig(env);
  let cf_time = String((body && body.cf_time) || cfg.cf_time || "0 * * * *").trim() || "0 * * * *";
  if (!/^\S+\s+\S+\s+\S+\s+\S+\s+\S+$/.test(cf_time)) {
    return { ok: false, error: "cf_time 应为 5 段 cron，如 0 * * * *" };
  }

  const url = new URL(request.url);
  let cf_url = String((body && body.cf_url) || (url.origin + "/api/report")).trim();
  if (!cf_url.startsWith("https://") || cf_url.includes(" ")) {
    return { ok: false, error: "cf_url 应为 https:// 开头" };
  }
  // cb_port：未提供则复用该机之前的端口（从 callback_url 解析），再不行用默认
  let cb_port = String((body && body.cb_port) || "").trim();
  if (cb_port) {
    if (!isValidPort(cb_port)) return { ok: false, error: "cb_port 应为 1024-65535" };
  } else {
    const row0 = await env.DB.prepare(`SELECT callback_url FROM machines WHERE machine_id = ?`).bind(mid).first();
    cb_port = row0 && row0.callback_url ? portFromCallback(row0.callback_url) : String(DEFAULT_CB_PORT);
  }

  let vpsToken;
  try {
    if (body && body.rotate_token) {
      // 生成新 token 写入 pending_token；VPS 下次上报自动切换，或重装直接用新 token
      vpsToken = randomAccessToken();
      const nowR = Math.floor(Date.now() / 1000);
      await env.DB.prepare(
        `INSERT INTO vps_tokens (machine_id, token, created_at, pending_token) VALUES (?, ?, ?, ?)
         ON CONFLICT(machine_id) DO UPDATE SET pending_token = excluded.pending_token`,
      ).bind(mid, vpsToken, nowR, vpsToken).run();
    } else {
      const provided = String((body && body.access_token) || "").trim();
      const existing = await getVpsTokenFull(env, mid);
      if (provided) {
        if (!/^[A-Za-z0-9._~+/-]{8,256}$/.test(provided)) {
          return { ok: false, error: "access_token 格式无效" };
        }
        const now = Math.floor(Date.now() / 1000);
        await env.DB.prepare(
          `INSERT INTO vps_tokens (machine_id, token, created_at) VALUES (?, ?, ?)
           ON CONFLICT(machine_id) DO UPDATE SET token=excluded.token`,
        ).bind(mid, provided, now).run();
        vpsToken = provided;
      } else if (existing) {
        vpsToken = existing;
      } else {
        vpsToken = await getOrCreateVpsToken(env, mid);
      }
    }
  } catch (e) {
    return { ok: false, error: "生成失败：" + (e && e.message ? e.message : String(e)) };
  }

  const cmd = buildInstallCommand(mid, vpsToken, cf_url, cf_time, cb_port);
  return {
    ok: true,
    command: cmd,
    machine_id: mid,
    cf_url,
    cf_time,
    cb_port,
    // 命令本身含完整 token；响应体不再单独回传明文，只给预览
    token_preview: vpsToken.slice(0, 8) + "...",
  };
}

/** 看板「更新注册」弹窗预填。
 *  默认不返回完整 access_token（仅前缀）；?reveal=1 才返回明文（生成命令时仍走 generate-update）。
 */
async function getMachineReg(env, request, mid, opts = {}) {
  if (!isValidMachineId(mid)) {
    return { ok: false, error: "机器 ID 无效" };
  }
  if (!env.DB) return { ok: false, error: missingDbError(env) };
  const row = await env.DB.prepare(
    `SELECT machine_id, hostname, interface, last_ts, callback_url FROM machines WHERE machine_id = ?`,
  ).bind(mid).first();
  const cfg = await getConfig(env);
  const url = new URL(request.url);
  // 统一使用 per-machine access_token；没有就生成。不再回退全局 TG_TOKEN。
  let token = await getVpsTokenFull(env, mid);
  if (token) token = String(token).replace(/\r/g, "").trim();
  if (!token) token = await getOrCreateVpsToken(env, mid);
  const reveal = !!(opts && opts.reveal);
  return {
    ok: true,
    machine_id: mid,
    hostname: (row && row.hostname) || "",
    interface: (row && row.interface) || "",
    last_ts: (row && row.last_ts) || 0,
    exists: !!row,
    // 完整 token 仅 reveal=1；默认只给预览，降低 XSS/共享浏览器泄露面
    access_token: reveal ? token : "",
    token_preview: token ? (token.slice(0, 8) + "...") : "",
    has_token: !!token,
    cf_url: url.origin + "/api/report",
    cf_time: cfg.cf_time || "0 * * * *",
    cb_port: row && row.callback_url ? portFromCallback(row.callback_url) : String(DEFAULT_CB_PORT),
  };
}

async function setForceReportAll(env) {
  if (!env.DB) throw new Error(missingDbError(env));
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO config (key, value, updated_at) VALUES ('force_report_at', ?, ?)
     ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`
  ).bind(String(now), now).run();
  return now;
}

async function getForceReportAt(env) {
  if (!env.DB) return 0;
  try {
    const row = await env.DB.prepare(
      `SELECT value FROM config WHERE key = 'force_report_at'`
    ).first();
    return row ? Number(row.value) || 0 : 0;
  } catch {
    return 0;
  }
}

/**
 * Agent 轮询：若全局强制时间晚于本机 last_ts，则要求立即上报。
 * 强制指令 15 分钟后过期。
 */
async function agentShouldForceReport(env, mid) {
  const forceAt = await getForceReportAt(env);
  if (!forceAt) return false;
  const now = Math.floor(Date.now() / 1000);
  if (now - forceAt > 15 * 60) return false;
  const row = await env.DB.prepare(
    `SELECT last_ts FROM machines WHERE machine_id = ?`
  ).bind(mid).first();
  const lastTs = row ? Number(row.last_ts) || 0 : 0;
  return lastTs < forceAt;
}


/**
 * 主机名是否为 IPv4 / IPv6（Workers fetch 直连 IP 会 403/1003）
 */
function isIpHostname(host) {
  const h = String(host || "").replace(/^\[|\]$/g, "");
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(h)) {
    const parts = h.split(".").map(Number);
    return parts.length === 4 && parts.every((n) => n >= 0 && n <= 255);
  }
  // IPv6（含压缩形式）
  if (h.includes(":")) return true;
  return false;
}

/**
 * 错误对象 → 可读字符串（避免空 message）
 */
function errText(e) {
  if (e == null) return "unknown error";
  if (typeof e === "string") return e;
  const parts = [];
  if (e.name) parts.push(e.name);
  if (e.message) parts.push(e.message);
  if (e.cause) parts.push("cause=" + errText(e.cause));
  if (!parts.length) {
    try { return String(e); } catch { return "error"; }
  }
  return parts.join(": ");
}

/**
 * 经 TCP Socket 发送裸 HTTP/1.1 POST（绕过 fetch 禁止直连 IP 的 1003）
 * 仅用于 http://IP:port/... 回调
 */
async function httpPostViaTcpSocket(urlStr, headerMap, bodyStr, timeoutMs = 10000) {
  const u = new URL(urlStr);
  if (u.protocol !== "http:") {
    return {
      ok: false,
      status: 0,
      body: "IP 回调仅支持 http://，当前为 " + u.protocol + "（Worker 无法对裸 IP 做 HTTPS）",
    };
  }
  const hostname = u.hostname.replace(/^\[|\]$/g, "");
  const port = Number(u.port) || 80;
  const path = (u.pathname || "/") + (u.search || "");
  const body = bodyStr || "";
  const hostHeader = u.host;
  const target = hostname + ":" + port + path;

  if (typeof cfTcpConnect !== "function") {
    return {
      ok: false,
      status: 0,
      body: "cfTcpConnect 不可用：请确认 Worker 已部署含 cloudflare:sockets 的版本",
    };
  }

  const encoder = new TextEncoder();
  const bodyBytes = encoder.encode(body);
  const headerLines = [
    "POST " + path + " HTTP/1.1",
    "Host: " + hostHeader,
    "Connection: close",
    "Content-Type: " + (headerMap["Content-Type"] || "application/json"),
    "Content-Length: " + String(bodyBytes.byteLength),
  ];
  for (const [k, v] of Object.entries(headerMap)) {
    if (/^content-type$/i.test(k) || /^content-length$/i.test(k) || /^host$/i.test(k)) continue;
    headerLines.push(k + ": " + v);
  }
  const headBytes = encoder.encode(headerLines.join("\r\n") + "\r\n\r\n");

  let socket;
  try {
    socket = cfTcpConnect({ hostname, port });
  } catch (e) {
    return { ok: false, status: 0, body: "TCP connect() 失败 → " + target + " · " + errText(e) };
  }

  let timer;
  const timeoutPromise = new Promise((_, rej) => {
    timer = setTimeout(() => rej(new Error("超时 " + timeoutMs + "ms → " + target + "（检查防火墙是否放行 " + port + "）")), timeoutMs);
  });

  const work = (async () => {
    // 等建连
    if (socket.opened) {
      try {
        await socket.opened;
      } catch (e) {
        throw new Error("TCP 建连失败 → " + target + " · " + errText(e) + "（VPS 未监听/防火墙拦截/IP 错误）");
      }
    }

    // 一次写完请求体；读响应前不要 close writable（整连接关闭会导致服务端回包失败、客户端读到空）
    const reqBytes = new Uint8Array(headBytes.byteLength + bodyBytes.byteLength);
    reqBytes.set(headBytes, 0);
    reqBytes.set(bodyBytes, headBytes.byteLength);

    const writer = socket.writable.getWriter();
    try {
      await writer.write(reqBytes);
    } catch (e) {
      throw new Error("TCP 写入失败 → " + target + " · " + errText(e));
    } finally {
      try { writer.releaseLock(); } catch { /* ignore */ }
    }

    const reader = socket.readable.getReader();
    const chunks = [];
    let total = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength) {
          chunks.push(value);
          total += value.byteLength;
          // 已拿到完整 HTTP 头+一点 body 即可停（短 JSON 响应）
          if (total > 256) {
            let peek = "";
            const dec = new TextDecoder();
            for (const c of chunks) peek += dec.decode(c, { stream: true });
            if (peek.includes("\r\n\r\n")) break;
          }
          if (total > 65536) break;
        }
      }
    } catch (e) {
      throw new Error("TCP 读取失败 → " + target + " · " + errText(e));
    } finally {
      try { reader.releaseLock(); } catch { /* ignore */ }
      try { socket.close(); } catch { /* ignore */ }
    }

    if (!total) {
      return {
        ok: false,
        status: 0,
        body: "TCP 已连接但无 HTTP 响应 → " + target + "（读前勿关连接；或 VPS 回调未回包，请更新 sum.sh 回调服务）",
      };
    }

    const decoder = new TextDecoder();
    let raw = "";
    for (const c of chunks) raw += decoder.decode(c, { stream: true });
    raw += decoder.decode();

    const sep = raw.indexOf("\r\n\r\n");
    const head = sep >= 0 ? raw.slice(0, sep) : raw.slice(0, 200);
    const respBody = sep >= 0 ? raw.slice(sep + 4) : "";
    const statusLine = (head.split("\r\n")[0] || "").trim();
    const m = /^HTTP\/\d(?:\.\d)?\s+(\d{3})/i.exec(statusLine);
    if (!m) {
      return {
        ok: false,
        status: 0,
        body: "非 HTTP 响应 → " + target + " · " + statusLine.slice(0, 80),
      };
    }
    const status = Number(m[1]);
    return {
      ok: status >= 200 && status < 300,
      status,
      body: (respBody || statusLine).slice(0, 200),
    };
  })();

  try {
    return await Promise.race([work, timeoutPromise]);
  } catch (e) {
    try { socket.close(); } catch { /* ignore */ }
    return { ok: false, status: 0, body: errText(e).slice(0, 240) };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 向单台 VPS 回调口发送签名请求（Bearer + HMAC + 时间窗）
 * - 域名：fetch
 * - 裸 IP：TCP sockets 发 HTTP（避免 CF Error 1003）
 */
async function pushForceToCallback(callbackUrl, token, forceAt) {
  // 与 VPS conf 一致：去掉首尾空白，避免 D1/复制带入空格导致 401 unauthorized
  token = String(token || "").replace(/\r/g, "").trim();
  const bodyObj = { cmd: "force_report", at: forceAt };
  const body = JSON.stringify(bodyObj);
  const ts = String(Math.floor(Date.now() / 1000));
  const nonce = randomNonce(16);
  const sig = await hmacSha256Hex(token, [ts, nonce, body].join(String.fromCharCode(10)));
  const headers = {
    "Content-Type": "application/json",
    "Authorization": "Bearer " + token,
    "X-Timestamp": ts,
    "X-Nonce": nonce,
    "X-Signature": sig,
  };

  let urlObj;
  try {
    urlObj = new URL(callbackUrl);
  } catch {
    return { ok: false, status: 0, body: "callback_url 非法: " + String(callbackUrl).slice(0, 80) };
  }

  if (isIpHostname(urlObj.hostname)) {
    const r = await httpPostViaTcpSocket(callbackUrl, headers, body, 10000);
    // 保证 detail 非空
    if (!r.body) {
      r.body = r.ok
        ? "OK"
        : ("推送失败 status=" + r.status + " → " + urlObj.host + urlObj.pathname);
    }
    return r;
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 10000);
  try {
    const res = await fetch(callbackUrl, {
      method: "POST",
      headers,
      body,
      signal: ctrl.signal,
    });
    const textBody = await res.text().catch(() => "");
    if (res.status === 403 && /1003/.test(textBody)) {
      return {
        ok: false,
        status: 403,
        body: "CF 1003 禁止 fetch 直连 IP。callback=" + urlObj.host + " 应走 TCP sockets 路径",
      };
    }
    return {
      ok: res.ok,
      status: res.status,
      body: (textBody || ("HTTP " + res.status)).slice(0, 200),
    };
  } catch (e) {
    return {
      ok: false,
      status: 0,
      body: "fetch 失败 → " + urlObj.host + " · " + errText(e),
    };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * 看板「获取流量」：写 force 标记 + 并发推送到有 callback_url 的机器
 */
async function forceReportPushAll(env) {
  const force_at = await setForceReportAll(env);
  const { results } = await env.DB.prepare(
    `SELECT m.machine_id, m.callback_url, t.token, t.pending_token
     FROM machines m
     LEFT JOIN vps_tokens t ON t.machine_id = m.machine_id
     ORDER BY m.last_ts DESC`,
  ).all();
  const rows = results || [];
  const targets = [];
  const skipped = [];
  // 统一用 access_token（vps_tokens）。轮换后 pending 也可能在 VPS 生效，两者都试。
  for (const r of rows) {
    const mid = r.machine_id;
    const cb = (r.callback_url || "").trim();
    const accessToken = String(r.token || "").replace(/\r/g, "").trim();
    const pendToken = String(r.pending_token || "").replace(/\r/g, "").trim();
    // 先试当前 token，再试 pending（重装后 VPS 可能已用新密钥）
    const tokens = [];
    if (accessToken) tokens.push(accessToken);
    if (pendToken && pendToken !== accessToken) tokens.push(pendToken);
    if (!isValidCallbackUrl(cb)) {
      skipped.push({ machine_id: mid, reason: "no_callback_url" });
      continue;
    }
    if (!tokens.length) {
      skipped.push({ machine_id: mid, reason: "no_token" });
      continue;
    }
    targets.push({ machine_id: mid, callback_url: cb, tokens });
  }

  const resultsPush = [];
  const concurrency = 10;
  for (let i = 0; i < targets.length; i += concurrency) {
    const chunk = targets.slice(i, i + concurrency);
    const part = await Promise.all(chunk.map(async (t) => {
      let last = { ok: false, status: 0, body: "no token tried" };
      const triedMeta = [];
      for (const tok of t.tokens) {
        const r = await pushForceToCallback(t.callback_url, tok, force_at);
        last = r;
        triedMeta.push(tok.slice(0, 6) + "…(len=" + tok.length + ")");
        if (r.ok) {
          try { await upsertVpsToken(env, t.machine_id, tok); } catch { /* ignore */ }
          break;
        }
        const body = String(r.body || "");
        const isAuth =
          r.status === 401 ||
          /unauthor|token mismatch|token length|bad signature|missing bearer/i.test(body);
        if (!isAuth) break;
      }
      if (!last.ok && triedMeta.length) {
        last = {
          ...last,
          body: String(last.body || "") + " · 已尝试密钥前缀: " + triedMeta.join(" | "),
        };
      }
      return {
        machine_id: t.machine_id,
        callback_url: t.callback_url,
        tried: t.tokens.length,
        ...last,
      };
    }));
    resultsPush.push(...part);
  }

  const okN = resultsPush.filter((x) => x.ok).length;
  const fail = resultsPush.filter((x) => !x.ok);
  const detail = [
    ...resultsPush.map((x) => ({
      machine_id: x.machine_id,
      state: x.ok ? "pushed" : "push_fail",
      status: x.status == null ? 0 : x.status,
      detail: String(x.body || (x.ok ? "OK" : "无错误详情")).slice(0, 240),
      callback_url: x.callback_url || "",
    })),
    ...skipped.map((x) => ({
      machine_id: x.machine_id,
      state: "skipped",
      status: 0,
      detail: x.reason || "skipped",
    })),
  ];
  return {
    ok: true,
    force_at,
    machines: rows.length,
    pushed: resultsPush.length,
    accepted: okN,
    failed: fail.length,
    skipped: skipped.length,
    detail: detail.slice(0, 100),
    fail_detail: fail.slice(0, 20).map((x) => ({
      machine_id: x.machine_id,
      status: x.status,
      error: x.body,
    })),
    skip_detail: skipped.slice(0, 20),
    message: `推送 ${okN}/${resultsPush.length} 成功，跳过 ${skipped.length}，失败 ${fail.length}`,
  };
}


// ─── TG 汇总模板 ───

const BUILTIN_TEMPLATES = [
  { id:"card", name:"📊 卡片日报", builtin:true,
    body: "📊 流量日报\n━━━━━━━━━━━━\n🕐 时间：{time}\n🖥 主机：{host_count} 台（🟢 {online_count} 在线）\n\n📥 今日入站  {today_rx}\n📤 今日出站  {today_tx}\n📦 今日合计  {today_total}\n\n📥 本月入站  {month_rx}\n📤 本月出站  {month_tx}\n📦 本月合计  {month_total}\n━━━━━━━━━━━━\n{machine_lines}",
    machine_line: "{status} {m_id}\n    📥 {today_rx}  ·  📤 {today_tx}",
  },
  { id:"detail", name:"🏆 今日排行", builtin:true,
    body: "🏆 今日排行\n🕐 时间：{time}\n🟢 在线：{online_count}/{host_count} 台\n📦 今日合计：{today_total}\n━━━━━━━━━━━━\n{machine_lines}\n━━━━━━━━━━━━\n📅 本月累计：{month_total}",
    machine_line: "{status} {m_id}\n    📥 {today_rx}  ·  📤 {today_tx}",
  },
  { id:"brief", name:"📋 详细日报", builtin:true,
    body: "📋 详细日报\n🕐 时间：{time}\n🖥 主机：{host_count} 台（🟢 {online_count} 在线）\n\n📦 今日  📥 {today_rx}  ·  📤 {today_tx}  ·  共 {today_total}\n📦 本月  📥 {month_rx}  ·  📤 {month_tx}  ·  共 {month_total}\n━━━━━━━━━━━━\n{machine_lines}",
    machine_line: "{status} {m_id} · {hostname}\n    📅 今日  📥 {today_rx}  ·  📤 {today_tx}\n    📅 本月  📥 {month_rx}  ·  📤 {month_tx}",
  },
];

async function getConfigValue(env, key) {
  if (!env.DB) return null;
  try {
    const r = await env.DB.prepare(`SELECT value FROM config WHERE key = ?`).bind(key).first();
    return r ? r.value : null;
  } catch { return null; }
}

async function setConfigValue(env, key, value) {
  if (!env.DB) throw new Error(missingDbError(env));
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
     ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
  ).bind(key, value, now).run();
}

/** 规范化模板列表：trim id、去空、去重，保证下拉 value 可回显 */
function normalizeTemplateList(templates) {
  const arr = Array.isArray(templates) ? templates : [];
  const seen = new Set();
  const out = [];
  let dirty = false;
  for (const x of arr) {
    if (!x || typeof x !== "object") { dirty = true; continue; }
    let id = String(x.id || "").trim();
    if (!id) { id = "tpl_" + Math.random().toString(36).slice(2, 8); dirty = true; }
    if (String(x.id || "") !== id) dirty = true;
    if (seen.has(id)) { dirty = true; continue; }
    seen.add(id);
    out.push({
      id,
      name: String(x.name || id).slice(0, 40),
      builtin: !!x.builtin,
      body: String(x.body || ""),
      machine_line: String(x.machine_line || ""),
    });
  }
  return { list: out, dirty };
}

/** 读取所有模板（首次自动写入内置）；active 默认 card */
async function getTemplates(env) {
  let raw = await getConfigValue(env, "tg_templates");
  let arr = null;
  let dirty = false;
  if (raw) {
    try { arr = JSON.parse(raw); } catch { arr = null; dirty = true; }
  }
  const norm = normalizeTemplateList(arr);
  arr = norm.list;
  dirty = dirty || norm.dirty;
  if (!arr.length) {
    arr = BUILTIN_TEMPLATES.map(x => ({ ...x }));
    await setConfigValue(env, "tg_templates", JSON.stringify(arr));
  } else if (dirty) {
    // 空 id / 重复 id 会导致 <select> 无法回显；写回干净列表
    try { await setConfigValue(env, "tg_templates", JSON.stringify(arr)); } catch { /* ignore */ }
  }
  let active = String((await getConfigValue(env, "tg_active")) || "card").trim();
  if (!arr.some((x) => x && x.id === active)) {
    active = (arr[0] && arr[0].id) || "card";
    try { await setConfigValue(env, "tg_active", active); } catch { /* ignore */ }
  }
  return { templates: arr, active };
}

async function saveTemplates(env, templates, active) {
  if (!Array.isArray(templates)) return { ok: false, error: "templates 应为数组" };
  const { list: clean } = normalizeTemplateList(templates.map(x => ({
    id: x && x.id,
    name: x && x.name,
    builtin: x && x.builtin,
    body: x && String(x.body || "").slice(0, 4000),
    machine_line: x && String(x.machine_line || "").slice(0, 500),
  })));
  if (!clean.length) return { ok: false, error: "模板列表为空" };
  await setConfigValue(env, "tg_templates", JSON.stringify(clean));
  let act = active != null && active !== ""
    ? String(active).trim()
    : String((await getConfigValue(env, "tg_active")) || "card").trim();
  if (!clean.some((x) => x.id === act)) {
    act = clean[0].id;
  }
  await setConfigValue(env, "tg_active", act);
  return { ok: true, templates: clean, active: act };
}

/** 渲染模板为 TG 消息文本 */
function renderTemplate(tpl, machines, totals) {
  const time = new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });
  const onlineCount = machines.filter(m => m.ts && (Date.now() / 1000 - m.ts) < 7200).length;
  const fillGlobal = (s) => String(s || "")
    .split("{time}").join(time)
    .split("{host_count}").join(String(machines.length))
    .split("{online_count}").join(String(onlineCount))
    .split("{today_rx}").join(gb(totals.today_rx))
    .split("{today_tx}").join(gb(totals.today_tx))
    .split("{today_total}").join(gb(totals.today_rx + totals.today_tx))
    .split("{month_rx}").join(gb(totals.month_rx))
    .split("{month_tx}").join(gb(totals.month_tx))
    .split("{month_total}").join(gb(totals.month_rx + totals.month_tx));
  // 排行类模板：按今日总流量降序，方便一眼看出谁最吃流量
  const sorted = machines.slice().sort((a, b) => {
    const ta = ((a.today && a.today.rx) || 0) + ((a.today && a.today.tx) || 0);
    const tb = ((b.today && b.today.rx) || 0) + ((b.today && b.today.tx) || 0);
    return tb - ta;
  });
  const shown = sorted.slice(0, 20);
  const lines = shown.map(m => {
    const isOn = m.ts && (Date.now() / 1000 - m.ts) < 7200;
    const dayTotal = ((m.today && m.today.rx) || 0) + ((m.today && m.today.tx) || 0);
    const monthTotal = ((m.month && m.month.rx) || 0) + ((m.month && m.month.tx) || 0);
    const ln = String((tpl && tpl.machine_line) || "{status} {m_id}")
      .split("{status}").join(isOn ? "●" : "○")
      .split("{m_id}").join(m.machine_id || "?")
      .split("{hostname}").join(m.hostname || "")
      .split("{iface}").join(m.interface || "")
      .split("{today_rx}").join(gb(m.today && m.today.rx))
      .split("{today_tx}").join(gb(m.today && m.today.tx))
      .split("{today_total}").join(gb(dayTotal))
      .split("{month_rx}").join(gb(m.month && m.month.rx))
      .split("{month_tx}").join(gb(m.month && m.month.tx))
      .split("{month_total}").join(gb(monthTotal));
    return ln;
  });
  const more = sorted.length > 20 ? ("\n...及其他 " + (sorted.length - 20) + " 台") : "";
  return fillGlobal((tpl && tpl.body) || "")
    .split("{machine_lines}").join(lines.join("\n") + more);
}

/** 发送单条 TG 消息（用于登录通知等），未配置返回 not_configured */
async function sendTgMessage(env, text) {
  const cfg = await getConfig(env);
  const token = cfg.t_token || "";
  const id = cfg.t_id || "";
  if (!token || !id) return { ok: false, reason: "not_configured" };
  try {
    const r = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ chat_id: id, text, disable_web_page_preview: "true" }),
    });
    if (!r.ok) return { ok: false, reason: "api_error" };
    return { ok: true };
  } catch { return { ok: false, reason: "fetch_failed" }; }
}

async function addLoginLog(env, rec) {
  if (!env.DB) return;
  try {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO login_logs (ts, ip, ua, success, reason) VALUES (?, ?, ?, ?, ?)`
    ).bind(now, String(rec.ip || "-").slice(0, 64), String(rec.ua || "-").slice(0, 300),
      rec.success ? 1 : 0, String(rec.reason || "").slice(0, 200)).run();
    await env.DB.prepare(`DELETE FROM login_logs WHERE ts < ?`).bind(now - 90 * 86400).run();
  } catch { /* ignore */ }
}

async function getLoginLogs(env, limit = 100) {
  if (!env.DB) return [];
  const n = Math.min(500, Math.max(10, Number(limit) || 100));
  const { results } = await env.DB.prepare(
    `SELECT id, ts, ip, ua, success, reason FROM login_logs ORDER BY id DESC LIMIT ?`
  ).bind(n).all();
  return (results || []).map(r => ({
    id: r.id, ts: r.ts, ip: r.ip || "-", ua: r.ua || "-",
    success: !!r.success, reason: r.reason || "",
  }));
}

/** 离线检测：离线且未通知 → 发 TG + 标记；重新在线 → 清标记。
 *  仅在 TG 发送成功后才写 offline_notified，避免「发失败却永不再告警」。
 *  TG 未配置时不写标记，配置好后仍会告警一次。
 */
async function checkOffline(env) {
  if (!env.DB) return;
  const machines = await listMachines(env);
  const now = Math.floor(Date.now() / 1000);
  for (const m of machines) {
    const isOn = !!(m.ts && (now - m.ts) < 7200);
    const notified = !!m.offline_notified;
    if (!isOn && !notified) {
      const last = m.ts
        ? new Date(m.ts * 1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false })
        : "无";
      let sent = false;
      try {
        const r = await sendTgMessage(env,
          "⚠️ 机器离线\n" + (m.machine_id || "?") +
          "\n最后上报：" + last + "\n（已记录，恢复在线前不再重复通知）");
        sent = !!(r && r.ok);
      } catch { /* ignore */ }
      if (sent) {
        try {
          await env.DB.prepare(`UPDATE machines SET offline_notified = 1 WHERE machine_id = ?`).bind(m.machine_id).run();
        } catch { /* ignore */ }
      }
    } else if (isOn && notified) {
      try {
        await env.DB.prepare(`UPDATE machines SET offline_notified = 0 WHERE machine_id = ?`).bind(m.machine_id).run();
      } catch { /* ignore */ }
    }
  }
}

// ─── TG 汇总 ───

async function tgSummary(env) {
  const cfg = await getConfig(env);
  // 页面空 → 环境变量（getConfig 已合并）；时间类已有默认
  const t_token = cfg.t_token || "";
  const t_id = cfg.t_id || "";
  if (!t_token || !t_id) {
    return {
      ok: false,
      error: "请配置 Bot Token 与 Chat ID（看板设置，或环境变量 TG_BOT_TOKEN / TG_ID）",
    };
  }

  const allMachines = await listMachines(env);
  const machines = allMachines.filter(m => m.in_tg_report !== false);
  if (!machines.length) {
    return { ok: false, error: "暂无参与 TG 汇报的机器（在列表勾选后再试）" };
  }

  // 汇总统计
  const total = machines.reduce((a, m) => ({
    today_rx: a.today_rx + (m.today?.rx || 0),
    today_tx: a.today_tx + (m.today?.tx || 0),
    month_rx: a.month_rx + (m.month?.rx || 0),
    month_tx: a.month_tx + (m.month?.tx || 0),
    online: a.online + (m.ts && (Date.now() / 1000 - m.ts) < 7200 ? 1 : 0),
  }), { today_rx: 0, today_tx: 0, month_rx: 0, month_tx: 0, online: 0 });

  const now = new Date();
  const dateStr = now.toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });

  // 用选中模板渲染
  const { templates, active } = await getTemplates(env);
  const tpl = templates.find(x => x.id === active) || templates[0] || BUILTIN_TEMPLATES[0];
  const msg = renderTemplate(tpl, machines, total);

  // 发送到 Telegram
  const apiUrl = `https://api.telegram.org/bot${t_token}/sendMessage`;
  const resp = await fetch(apiUrl, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      chat_id: t_id,
      text: msg,
      disable_web_page_preview: "true",
    }),
  });

  if (!resp.ok) {
    const text = await resp.text();
    return { ok: false, error: `Telegram API 错误: ${text.slice(0, 200)}` };
  }

  const rj = await resp.json();
  if (!rj.ok) {
    return { ok: false, error: rj.description || "Telegram 返回失败" };
  }

  return { ok: true, machines: machines.length, online: total.online };
}

// ─── 页面 ───

function loginPage(err = "", opts = {}) {
  const noPwd = !!opts.noPassword;
  const tip = noPwd
    ? `<div class="warn">⚠️ 尚未配置登录密码。请在 Cloudflare Dashboard → Worker → 设置 → 加密变量 添加 <code>PASSWORD</code> 后再登录。</div>`
    : "";
  const form = noPwd
    ? `<div class="err">${err ? esc(err) : "未配置密码，无法登录。"}</div>
       <form method="post" action="/login" onsubmit="return false;">
         <label for="pw">密码</label>
         <input id="pw" name="password" type="password" autocomplete="current-password" disabled>
         <button type="submit" disabled>登录</button>
       </form>`
    : `<div class="err">${err ? esc(err) : ""}</div>
       <form method="post" action="/login">
         <label for="pw">密码</label>
         <input id="pw" name="password" type="password" autocomplete="current-password" required autofocus>
         <button type="submit">登录</button>
       </form>`;
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · 流量看板</title>
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;background:#0b1220;color:#e8eefc}
.card{width:min(380px,92vw);background:#121a2b;border:1px solid #243049;border-radius:14px;padding:28px 24px;box-shadow:0 12px 40px #0006}
h1{font-size:18px;margin:0 0 6px}
p{margin:0 0 18px;color:#8aa0c6;font-size:13px}
label{display:block;font-size:12px;color:#9fb3d9;margin-bottom:6px}
input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #33415f;background:#0b1220;color:#e8eefc;margin-bottom:14px;outline:none}
input:focus{border-color:#3b82f6}
input:disabled{opacity:.5}
button{width:100%;padding:10px 12px;border:0;border-radius:8px;background:#3b82f6;color:#fff;font-weight:600;cursor:pointer}
button:disabled{background:#33415f;cursor:not-allowed}
.err{color:#fca5a5;font-size:13px;margin-bottom:10px;min-height:1.2em}
.warn{background:#2a2008;border:1px solid #78350f;color:#fbbf24;padding:12px;border-radius:8px;font-size:12px;line-height:1.6;margin-bottom:14px}
.warn code{background:#1a1407;padding:1px 5px;border-radius:4px}
</style>
<div class="card">
  <h1>流量看板</h1>
  <p>${noPwd ? "需要配置密码" : "请输入管理密码"}</p>
  ${tip}
  ${form}
</div>`;
}

function dashboardPage() {
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>流量看板</title>
<link rel="preconnect" href="https://cdn.jsdelivr.net" crossorigin>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js" defer></script>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:"Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;background:#0b1220;color:#e8eefc}
header{display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;padding:14px 20px;border-bottom:1px solid #1e2a42;background:#0e1628}
header h1{font-size:18px;margin:0}
.nav{display:flex;gap:4px;margin-left:16px}
.nav a{color:#8aa0c6;text-decoration:none;padding:6px 12px;border-radius:8px;font-size:13px;cursor:pointer}
.nav a.active,.nav a:hover{background:#1a2740;color:#e8eefc}
.muted{color:#8aa0c6;font-size:13px}
.actions{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
select,button{background:#121a2b;color:#e8eefc;border:1px solid #33415f;border-radius:8px;padding:8px 10px;font-size:13px;outline:none}
button{cursor:pointer}
button.primary{background:#3b82f6;border-color:#3b82f6;font-weight:600}
button.primary:hover{background:#2563eb}
button.green{background:#16a34a;border-color:#16a34a;font-weight:600}
button.green:hover{background:#15803d}
button.warn{background:#d97706;border-color:#d97706;font-weight:600}
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
button.sm{padding:4px 8px;font-size:12px;border-radius:6px}
button.danger{background:#b91c1c;border-color:#b91c1c;color:#fff}
button.danger:hover{background:#991b1b}
td.ops{white-space:nowrap;min-width:240px}
td.ops button{margin-right:4px}
.settings-form{max-width:520px}
.settings-form label{display:block;font-size:12px;color:#9fb3d9;margin:14px 0 4px}
.settings-form input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #33415f;background:#0b1220;color:#e8eefc;outline:none}
.settings-form input:focus{border-color:#3b82f6}
.settings-form .hint{font-size:11px;color:#8aa0c6;margin-top:2px}
.settings-form .save-row{display:flex;gap:8px;align-items:center;margin-top:18px}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#1a2740;border:1px solid #33415f;border-radius:10px;padding:10px 20px;font-size:13px;z-index:999;opacity:0;transition:opacity .25s}
.toast.show{opacity:1}
.modal-overlay{position:fixed;inset:0;background:#0006;display:none;place-items:center;z-index:100}
.modal-overlay.open{display:grid}
.modal{background:#121a2b;border:1px solid #33415f;border-radius:14px;padding:24px;width:min(640px,94vw);max-height:80vh;overflow-y:auto}
.modal h2{font-size:16px;margin:0 0 4px}
.modal .desc{font-size:12px;color:#8aa0c6;margin-bottom:16px}
.modal label{display:block;font-size:12px;color:#9fb3d9;margin-bottom:4px}
.modal input{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #33415f;background:#0b1220;color:#e8eefc;outline:none;margin-bottom:8px}
.modal input:focus{border-color:#3b82f6}
.modal .btn-row{display:flex;gap:8px;margin-top:12px;flex-wrap:wrap}
.modal .btn-row button{flex:1;min-width:80px;padding:10px}
.cmd-box{background:#0b1220;border:1px solid #33415f;border-radius:8px;padding:12px;margin:12px 0;font-family:monospace;font-size:12px;line-height:1.6;white-space:pre-wrap;word-break:break-all;color:#c7d2fe;max-height:240px;overflow-y:auto;user-select:all}
.cmd-ok{color:#34d399;font-size:13px;margin:8px 0 4px;display:flex;gap:8px;align-items:center}
.token-preview{color:#8aa0c6;font-size:11px}
.tg-summary-result{background:#0b1220;border:1px solid #243049;border-radius:8px;padding:12px;margin-top:8px;font-size:12px;white-space:pre-wrap;line-height:1.5}
.chart-toolbar{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin-bottom:12px}
.seg{display:inline-flex;border:1px solid #33415f;border-radius:8px;overflow:hidden}
.seg button{border:0;border-radius:0;background:#0b1220;padding:7px 14px;font-size:12px}
.seg button.active{background:#3b82f6;border-color:#3b82f6;color:#fff}
.chk{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:#9fb3d9;cursor:pointer;user-select:none}
.chk input{accent-color:#3b82f6}
.chart-title-row{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:8px}
.chart-title-row h2{margin:0}
.result-sum{display:flex;gap:10px;flex-wrap:wrap;margin:8px 0 14px}
.result-sum .pill{padding:6px 12px;border-radius:999px;font-size:12px;border:1px solid #33415f;background:#0b1220}
.result-sum .pill.ok{color:#34d399;border-color:#14532d}
.result-sum .pill.fail{color:#f87171;border-color:#7f1d1d}
.result-sum .pill.skip{color:#fbbf24;border-color:#78350f}
.result-sum .pill.wait{color:#93c5fd;border-color:#1e3a5f}
.result-table{width:100%;border-collapse:collapse;font-size:12px}
.result-table th,.result-table td{padding:8px 10px;border-bottom:1px solid #1e2a42;text-align:left;vertical-align:top}
.result-table th{color:#8aa0c6;font-weight:500}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;border:1px solid #33415f}
.badge.ok{background:#052e1a;color:#34d399;border-color:#14532d}
.badge.fail{background:#2a0f0f;color:#f87171;border-color:#7f1d1d}
.badge.skip{background:#2a2008;color:#fbbf24;border-color:#78350f}
.badge.wait{background:#0b1a2e;color:#93c5fd;border-color:#1e3a5f}
.badge.reported{background:#0c2a1a;color:#6ee7b7;border-color:#065f46}
.result-note{font-size:12px;color:#8aa0c6;margin:10px 0 0;line-height:1.5}
.tg-pill{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:999px;font-size:12px;border:1px solid #33415f;background:#0b1220;cursor:pointer;user-select:none;white-space:nowrap}
.tg-pill .dot{width:8px;height:8px;border-radius:50%}
.tg-pill.s-ok{color:#34d399;border-color:#14532d;background:#052e1a}
.tg-pill.s-ok .dot{background:#34d399}
.tg-pill.s-ready{color:#93c5fd;border-color:#1e3a5f;background:#0b1a2e}
.tg-pill.s-ready .dot{background:#93c5fd}
.tg-pill.s-incomplete{color:#fbbf24;border-color:#78350f;background:#2a2008}
.tg-pill.s-incomplete .dot{background:#fbbf24}
.tg-pill.s-invalid{color:#f87171;border-color:#7f1d1d;background:#2a0f0f}
.tg-pill.s-invalid .dot{background:#f87171}
.tg-pill.s-not_configured{color:#8aa0c6;border-color:#33415f;background:#0b1220}
.tg-pill.s-not_configured .dot{background:#8aa0c6}
.tg-tip{font-size:11px;color:#8aa0c6;margin-left:4px}
.batch-bar{display:none;align-items:center;gap:8px;flex-wrap:wrap;margin:0 0 10px;padding:8px 10px;background:#0e1628;border:1px solid #243049;border-radius:8px;font-size:12px}
.batch-bar.show{display:flex}
.batch-bar button{padding:5px 10px;font-size:12px}
textarea{width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #33415f;background:#0b1220;color:#e8eefc;outline:none;font-family:monospace;font-size:12px;resize:vertical}
textarea:focus{border-color:#3b82f6}
.tpl-col{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.tpl-help{font-size:11px;color:#8aa0c6;line-height:1.6;background:#0b1220;border:1px solid #1e2a42;border-radius:8px;padding:10px;margin-top:8px}
.tpl-help code{background:#1a2740;padding:1px 4px;border-radius:3px}
.tpl-preview{background:#0b1220;border:1px solid #243049;border-radius:8px;padding:12px;font-family:monospace;font-size:12px;white-space:pre-wrap;line-height:1.6;max-height:300px;overflow:auto;color:#c7d2fe}
.tpl-active-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:10px}
.tpl-active-row select{flex:0 0 auto}

.row-check{width:18px;height:18px;cursor:pointer;accent-color:#3b82f6}
.clock{font-variant-numeric:tabular-nums;font-size:12px;color:#9fb3d9;padding:6px 10px;border:1px solid #243049;border-radius:8px;background:#0b1220;white-space:nowrap;user-select:none}
.clock b{color:#e8eefc;font-weight:600;margin-left:4px}



</style>

<header>
  <div style="display:flex;align-items:center">
    <h1>流量看板</h1>
    <div class="nav">
      <a id="tabDash" class="active" onclick="switchTab('dash')">看板</a>
      <a id="tabSet" onclick="switchTab('settings')">设置</a>
      <a id="tabLogs" onclick="switchTab('logs')">日志</a>
    </div>
  </div>
  <div class="actions">
    <span class="clock" id="dashClock" title="上海时间（浏览器本地计算，不请求服务器）">上海 <b>--</b></span>
    <button class="warn" onclick="sendTgSummary()" id="btnTgSum" title="向 Telegram 发送所有机器汇总">📊 TG 汇总</button>
    <form method="post" action="/logout" style="margin:0"><button type="submit">退出</button></form>
  </div>
</header>

<main>
  <!-- 看板页 -->
  <div id="pageDash" class="page active">
    <div style="display:flex;gap:8px;align-items:center;margin-bottom:12px;flex-wrap:wrap">
      <button class="primary" onclick="openAddVps()">＋ 添加 VPS</button>
      <button onclick="refresh()">刷新</button>
      <button class="green" onclick="forceFetchAll()" id="btnForceFetch" title="签名推送到各 VPS 回调口立即上报（需公网；无 poll）">获取流量</button>
      <label class="chk"><input type="checkbox" id="filterOnline" onchange="renderTable()"> 只看在线</label>
      <select id="sortBy" onchange="renderTable()" title="排序">
        <option value="last">默认（最后上报）</option>
        <option value="today_desc">今日流量 ↓</option>
        <option value="today_asc">今日流量 ↑</option>
        <option value="month_desc">本月流量 ↓</option>
        <option value="uptime_desc">累积在线 ↓</option>
      </select>
      <span id="tgStatus" class="tg-pill s-not_configured" title="点击重新检测" onclick="loadTgStatus(true)">
        <span class="dot"></span><span id="tgStatusText">TG: 检测中</span>
      </span>
      <span id="tgSumStatus" class="muted" style="font-size:12px;margin-left:4px"></span>
    </div>
    <div class="cards" id="summary"></div>
    <div class="panel">
      <div class="chart-title-row">
        <h2 id="chartPanelTitle">总流量统计</h2>
      </div>
      <div class="chart-toolbar">
        <div class="seg" id="modeSeg">
          <button type="button" data-mode="hour" onclick="setChartMode('hour')">日内</button>
          <button type="button" class="active" data-mode="week" onclick="setChartMode('week')">周报</button>
          <button type="button" data-mode="month" onclick="setChartMode('month')">月报</button>
          <button type="button" data-mode="year" onclick="setChartMode('year')">年报</button>
        </div>
        <label class="chk"><input type="checkbox" id="chkRx" checked onchange="renderMainChart()"> 入站</label>
        <label class="chk"><input type="checkbox" id="chkTx" checked onchange="renderMainChart()"> 出站</label>
        <select id="range" onchange="loadHistory()" title="选择统计跨度"></select>
      </div>
      <div class="chart-wrap"><canvas id="chart"></canvas></div>
    </div>
    <div class="panel">
      <h2>机器列表</h2>
      <div class="batch-bar" id="batchBar">
        <span>已选 <b id="batchCount">0</b> 台</span>
        <button class="warn" onclick="batchAction('include_tg')">加入 TG 汇报</button>
        <button onclick="batchAction('exclude_tg')">移出 TG 汇报</button>
        <button class="danger" onclick="batchAction('delete')">批量删除</button>
        <span style="flex:1"></span>
        <button onclick="clearSelection()">取消选择</button>
      </div>
      <div style="overflow:auto">
        <table>
          <thead><tr>
            <th style="width:36px"><input type="checkbox" id="checkAll" class="row-check" onchange="toggleAll(this.checked)"></th>
            <th>机器</th><th>主机</th><th>网卡</th>
            <th>今日入/出</th><th>本月入/出</th><th>累积在线</th><th>最后上报</th><th>状态</th><th>操作</th>
          </tr></thead>
          <tbody id="tbody"><tr><td colspan="10">加载中…</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- 设置页 -->
  <div id="pageSettings" class="page">
    <div class="panel settings-form">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
        <h2 style="margin:0">全局配置</h2>
        <button type="button" onclick="switchTab('dash')">← 返回看板</button>
      </div>
      <p class="muted" style="font-size:12px;margin-top:10px">空字段自动用默认值；TG 凭证页面留空则读 Worker 环境变量（TG_BOT_TOKEN / TG_ID）。<br>保存后可在看板「添加 VPS」生成命令；「📊 TG 汇总」发聚合日报。</p>
      <label for="s_t_token">Telegram Bot Token（汇总用）</label>
      <input id="s_t_token" type="password" placeholder="留空则用环境变量 TG_BOT_TOKEN">
      <div class="hint" id="hint_t_token">页面未填时使用环境变量 TG_BOT_TOKEN</div>

      <label for="s_t_id">Telegram Chat ID</label>
      <input id="s_t_id" type="text" placeholder="留空则用环境变量 TG_ID">
      <div class="hint" id="hint_t_id">页面未填时使用环境变量 TG_ID</div>

      <label for="s_t_time">TG 汇报时间（HH:MM:SS，定时自动发送）</label>
      <input id="s_t_time" type="text" placeholder="20:00:00">
      <div class="hint">Worker 每小时整点检查，按小时匹配（如 20:00:00 → 上海时间 20 点发）；留空默认 20:00:00</div>

      <label for="s_cf_time">CF 上报 cron（VPS 端默认）</label>
      <input id="s_cf_time" type="text" placeholder="0 * * * *">
      <div class="hint">写入安装命令的 VPS 上报周期。越密图表越细，但 CF/D1 调用越多：每小时=24次/台/天；每 6 小时=4次/台/天。看板统计（周/月/年）不依赖秒级上报。</div>

      <div class="save-row">
        <button class="primary" onclick="saveConfig()">保存设置</button>
        <button type="button" onclick="switchTab('dash')">关闭</button>
        <span id="saveStatus" class="muted"></span>
      </div>
    </div>

    <div class="panel settings-form">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
        <h2 style="margin:0">TG 汇报模板</h2>
        <button type="button" class="green" onclick="sendTgSummary()" id="btnTgNow" title="立即发送一次 TG 汇总">立即汇报</button>
      </div>
      <p class="muted" style="font-size:12px;margin-top:8px">选择/编辑汇报模板，支持内置与自定义。改完点「保存模板」。</p>
      <div class="tpl-active-row">
        <label style="margin:0">当前模板：</label>
        <select id="tplActive" onchange="onTplActiveChange()"></select>
        <button type="button" onclick="tplNew()">新建模板</button>
        <button type="button" onclick="tplDelete()" class="danger">删除</button>
        <button type="button" onclick="tplReset()">恢复内置</button>
      </div>
      <label for="tplName">模板名称</label>
      <input id="tplName" type="text" placeholder="如：我的日报">
      <div class="tpl-col">
        <div>
          <label for="tplBody">正文（{machine_lines} 处循环各机）</label>
          <textarea id="tplBody" rows="9" placeholder="📊 流量汇总..."></textarea>
        </div>
        <div>
          <label for="tplLine">每机行模板</label>
          <textarea id="tplLine" rows="9" placeholder="{status} {m_id} 入{today_rx}/出{today_tx}"></textarea>
        </div>
      </div>
      <div class="tpl-help">
        占位符：<code>{"{time}","{host_count}","{online_count}","{today_rx}","{today_tx}","{today_total}","{month_rx}","{month_tx}","{month_total}"}</code> 用于正文；
        每机行还可用 <code>{"{status}","{m_id}","{hostname}","{iface}"}</code> 及该机的 today/month。<code>{"{machine_lines}"}</code> 放正文里代表各机列表。
      </div>
      <div class="save-row" style="margin-top:14px">
        <button class="primary" onclick="tplSave()">保存模板</button>
        <button type="button" onclick="tplPreview()">预览</button>
        <span id="tplStatus" class="muted"></span>
      </div>
      <details style="margin-top:8px">
        <summary style="cursor:pointer;color:#9fb3d9;font-size:12px">预览结果（点开）</summary>
        <pre class="tpl-preview" id="tplPreview" style="margin-top:8px">（点「预览」用当前数据渲染）</pre>
      </details>
    </div>
  </div>

  <!-- 登录日志页 -->
  <div id="pageLogs" class="page">
    <div class="panel">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
        <h2 style="margin:0">登录日志</h2>
        <button type="button" onclick="loadLoginLogs()">刷新</button>
      </div>
      <p class="muted" style="font-size:12px;margin-top:8px">最近登录记录（保留 90 天）。登录成功且已配置 TG 时会发通知。</p>
      <div style="overflow:auto">
        <table>
          <thead><tr>
            <th>时间</th><th>结果</th><th>IP</th><th>原因</th><th>设备</th>
          </tr></thead>
          <tbody id="loginLogsBody"><tr><td colspan="5">加载中…</td></tr></tbody>
        </table>
      </div>
    </div>
  </div>
</main>

<!-- 添加 VPS 弹窗 -->
<div class="modal-overlay" id="modalVps">
  <div class="modal">
    <h2>添加 VPS</h2>
    <p class="desc">输入机器 ID，生成独立密码和安装命令。复制到 VPS 执行即可。</p>
    <label for="vpsMid">机器 ID</label>
    <input id="vpsMid" type="text" placeholder="香港-1 / hk-1 / jp-2" autocomplete="off">
    <label for="vpsCbPort">回调端口（「获取流量」推送用，需 VPS 放行）</label>
    <input id="vpsCbPort" type="text" value="19840" placeholder="19840">
    <div id="vpsCmdRegion" style="display:none">
      <div class="cmd-ok" id="vpsOk"></div>
      <div class="cmd-box" id="vpsCmd"></div>
      <p class="token-preview" id="vpsTokenPreview"></p>
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

<!-- 更新注册弹窗 -->
<div class="modal-overlay" id="modalUpdate">
  <div class="modal">
    <h2>更新注册</h2>
    <p class="desc">复用该机器已有参数（可编辑）。确定后生成升级/重装命令，在 VPS 上执行即可更新脚本。</p>
    <label for="upMid">机器 ID</label>
    <input id="upMid" type="text" autocomplete="off">
    <label for="upToken">access_token（默认隐藏；生成命令时用服务端已存密钥，可留空）</label>
    <input id="upToken" type="password" autocomplete="off" spellcheck="false" placeholder="•••• 已隐藏，留空=沿用原密钥">
    <div class="hint" id="upTokenHint" style="margin:-4px 0 8px;font-size:11px;color:#8aa0c6">仅显示前缀；完整密钥不在页面默认加载。需要改密钥可粘贴新值或勾选轮换。</div>
    <label for="upUrl">cf_url</label>
    <input id="upUrl" type="text" autocomplete="off" spellcheck="false">
    <label for="upTime">cf_time（cron）</label>
    <input id="upTime" type="text" placeholder="0 * * * *" autocomplete="off">
    <label for="upCbPort">回调端口（cb_port）</label>
    <input id="upCbPort" type="text" placeholder="19840" autocomplete="off">
    <label style="display:flex;align-items:center;gap:8px;margin:10px 0;cursor:pointer">
      <input id="upRotate" type="checkbox" style="width:auto;margin:0"> 轮换新密钥（VPS 下次上报自动同步，无需重装）
    </label>
    <div id="upCmdRegion" style="display:none">
      <div class="cmd-ok" id="upOk"></div>
      <div class="cmd-box" id="upCmd"></div>
      <div class="btn-row">
        <button class="green" onclick="copyUpCmd()">复制命令</button>
        <button onclick="closeUpdateVps()">关闭</button>
      </div>
    </div>
    <div class="btn-row" id="upBtnRegion">
      <button class="green" onclick="confirmUpdateVps()">确定并生成命令</button>
      <button onclick="closeUpdateVps()">取消</button>
    </div>
  </div>
</div>

<!-- 单机流量统计弹窗 -->
<div class="modal-overlay" id="histModal">
  <div class="modal" style="width:min(860px,96vw)">
    <h2 id="histModalTitle">流量统计</h2>
    <p class="desc" id="histModalDesc">单机日/月累计（入站+出站堆叠）</p>
    <div class="chart-toolbar">
      <div class="seg" id="histModeSeg">
        <button type="button" data-mode="hour" onclick="setHistMode('hour')">日内</button>
        <button type="button" class="active" data-mode="week" onclick="setHistMode('week')">周报</button>
        <button type="button" data-mode="month" onclick="setHistMode('month')">月报</button>
        <button type="button" data-mode="year" onclick="setHistMode('year')">年报</button>
      </div>
      <label class="chk"><input type="checkbox" id="histChkRx" checked onchange="renderHistChart()"> 入站</label>
      <label class="chk"><input type="checkbox" id="histChkTx" checked onchange="renderHistChart()"> 出站</label>
      <select id="histRange" onchange="loadHistModal()" title="选择统计跨度"></select>
    </div>
    <div class="chart-wrap" style="height:320px"><canvas id="histChart"></canvas></div>
    <div class="btn-row" style="margin-top:14px">
      <button onclick="closeHistModal()">关闭</button>
    </div>
  </div>
</div>

<!-- 获取流量结果弹窗 -->
<div class="modal-overlay" id="forceResultModal">
  <div class="modal" style="width:min(720px,96vw)">
    <h2 id="forceResultTitle">获取流量结果</h2>
    <p class="desc" id="forceResultDesc">推送回调后，等待 VPS 上报…</p>
    <div class="result-sum" id="forceResultSum"></div>
    <div style="max-height:360px;overflow:auto;border:1px solid #243049;border-radius:8px">
      <table class="result-table">
        <thead>
          <tr>
            <th style="width:28%">机器</th>
            <th style="width:18%">推送</th>
            <th style="width:18%">上报</th>
            <th>说明</th>
          </tr>
        </thead>
        <tbody id="forceResultBody"></tbody>
      </table>
    </div>
    <p class="result-note" id="forceResultNote"></p>
    <div class="btn-row" style="margin-top:14px">
      <button class="primary" onclick="closeForceResult()">关闭</button>
      <button onclick="refresh(); toast('已刷新列表')">刷新列表</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
const gb = (n) => ((Number(n)||0)/1e9).toFixed(3) + "GB";
const fmtTime = (ts) => ts ? new Date(ts*1000).toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false }) : "-";
/** 顶栏时钟：纯前端，上海时区，不请求 Worker */
function tickDashClock() {
  const el = document.getElementById("dashClock");
  if (!el) return;
  try {
    const s = new Date().toLocaleString("zh-CN", {
      timeZone: "Asia/Shanghai", hour12: false,
      year: "numeric", month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
    el.innerHTML = "上海 <b>" + s + "</b>";
  } catch {
    el.innerHTML = "上海 <b>" + new Date().toISOString().slice(0, 19).replace("T", " ") + "</b>";
  }
}
/** 秒 → 可读时长，如 3天5小时 / 12小时30分 / 45分 */
const fmtDuration = (sec) => {
  let s = Math.max(0, Math.floor(Number(sec) || 0));
  if (s < 60) return s + "秒";
  const d = Math.floor(s / 86400); s %= 86400;
  const h = Math.floor(s / 3600); s %= 3600;
  const m = Math.floor(s / 60);
  const parts = [];
  if (d) parts.push(d + "天");
  if (h) parts.push(h + "小时");
  if (m && d < 30) parts.push(m + "分"); // 很长时省略分钟
  if (!parts.length) parts.push(m + "分");
  return parts.join("");
};
const esc = (s) => String(s ?? "")
  .replace(/&/g, "&amp;").replace(/</g, "&lt;")
  .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
let machines = [];
let selected = null;
let chart;
const selectedMids = new Set();
let histChart;
let chartMode = "week";      // hour | week | month | year  （总览）
let histMode = "week";       // hour | week | month | year  （单机弹窗）
let mainPoints = [];         // 总览聚合点
let histPoints = [];         // 单机聚合点
let histMid = null;

/** 统计口径：UI mode → API mode + 默认跨度 + 文案
 *  周报=按日；月报=按日可选天数；年报=按月；日内=小时折线
 */
const CHART_PRESETS = {
  hour:  { api: "hour",  span: 24, chart: "line", title: "日内小时增量", desc: "近 N 小时各整点新增流量（折线）" },
  week:  { api: "day",   span: 7,  chart: "bar",  title: "周报", desc: "按日累计柱状（可选近 7/14 天）" },
  month: { api: "day",   span: 31, chart: "bar",  title: "月报", desc: "按日累计柱状（最长近 31 天）" },
  year:  { api: "month", span: 12, chart: "bar",  title: "年报", desc: "按月累计柱状（可选近 6/12/24 月）" },
};
function normalizeChartMode(m) {
  if (m === "hour" || m === "week" || m === "month" || m === "year") return m;
  if (m === "day") return "week";
  return "week";
}
function chartPreset(mode) {
  return CHART_PRESETS[normalizeChartMode(mode)] || CHART_PRESETS.week;
}
/** 各模式下可选跨度 */
function rangeOptionsFor(mode) {
  mode = normalizeChartMode(mode);
  if (mode === "hour") return [["12","近 12 小时"],["24","近 24 小时"],["48","近 48 小时"],["72","近 72 小时"]];
  if (mode === "week") return [["7","近 7 天"],["14","近 14 天"]];
  // 月报按「一个自然月」口径，最长 31 天
  if (mode === "month") return [["7","近 7 天"],["14","近 14 天"],["31","近 31 天"]];
  if (mode === "year") return [["6","近 6 月"],["12","近 12 月"],["24","近 24 月"]];
  return [["7","近 7 天"]];
}
function clampSpan(mode, span) {
  const n = Math.max(1, Number(span) || 0);
  mode = normalizeChartMode(mode);
  if (mode === "hour") return Math.min(72, n || 24);
  if (mode === "week") return Math.min(14, n || 7);
  if (mode === "month") return Math.min(31, n || 31); // 月报最大 31 天
  if (mode === "year") return Math.min(24, n || 12);
  return n || 7;
}
function chartTitleWithSpan(mode, span) {
  const p = chartPreset(mode);
  const n = Number(span) || p.span;
  if (mode === "hour") return p.title + " · 近 " + n + " 小时";
  if (mode === "year") return p.title + " · 近 " + n + " 月";
  return p.title + " · 近 " + n + " 天";
}
function readSpan(selId, mode) {
  const p = chartPreset(mode);
  const el = document.getElementById(selId);
  const v = el ? Number(el.value) : NaN;
  const raw = (Number.isFinite(v) && v > 0) ? v : p.span;
  return clampSpan(mode, raw);
}

function switchTab(name) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav a").forEach(a => a.classList.remove("active"));
  const pname = name[0].toUpperCase() + name.slice(1);
  document.getElementById("page" + pname).classList.add("active");
  document.getElementById("tab" + pname).classList.add("active");
  if (name === "settings") { loadConfig(); loadTemplates(); }
  // 回看板只刷新列表，图表有数据则不强制重拉，减少卡顿感
  if (name === "dash") refresh({ history: !mainPoints.length, tg: false });
  if (name === "logs") loadLoginLogs();
}

async function api(path, opts) {
  const r = await fetch(path, { credentials: "same-origin", ...opts });
  if (r.status === 401) { location.href = "/login"; return null; }
  let body = null;
  try { body = await r.json(); } catch {}
  if (!r.ok) {
    const msg = (body && body.error) || r.statusText || ("HTTP " + r.status);
    throw new Error(msg);
  }
  return body;
}

/** Chart.js 以 defer 加载：画图前等它就绪，避免首屏被同步脚本堵住 */
function whenChartReady() {
  if (typeof Chart !== "undefined") return Promise.resolve();
  return new Promise((resolve) => {
    let n = 0;
    const t = setInterval(() => {
      n++;
      if (typeof Chart !== "undefined" || n > 100) {
        clearInterval(t);
        resolve();
      }
    }, 50);
  });
}

function toast(msg) {
  const el = document.getElementById("toast");
  el.textContent = msg;
  el.classList.add("show");
  setTimeout(() => el.classList.remove("show"), 3000);
}

function online(ts) { return ts && ((Date.now()/1000 - ts) < 7200); }

function renderSummary() {
  const sum = machines.reduce((a,m)=>({
    today_rx: a.today_rx + (m.today?.rx||0), today_tx: a.today_tx + (m.today?.tx||0),
    month_rx: a.month_rx + (m.month?.rx||0), month_tx: a.month_tx + (m.month?.tx||0),
  }), {today_rx:0,today_tx:0,month_rx:0,month_tx:0});
  const on = machines.filter(m => online(m.ts)).length;
  document.getElementById("summary").innerHTML = [
    '<div class="card"><div class="label">机器数</div><div class="val">' + machines.length + "</div></div>",
    '<div class="card"><div class="label">在线（2h）</div><div class="val">' + on + "</div></div>",
    '<div class="card"><div class="label">今日合计</div><div class="val">' + gb(sum.today_rx+sum.today_tx) + "</div></div>",
    '<div class="card"><div class="label">本月合计</div><div class="val">' + gb(sum.month_rx+sum.month_tx) + "</div></div>",
  ].join("");
}

function machineView() {
  let arr = machines.slice();
  const fo = document.getElementById("filterOnline");
  if (fo && fo.checked) arr = arr.filter(m => online(m.ts));
  const sel = document.getElementById("sortBy");
  const by = sel ? sel.value : "last";
  const tot = (m) => ((m.today?.rx || 0) + (m.today?.tx || 0));
  const mtot = (m) => ((m.month?.rx || 0) + (m.month?.tx || 0));
  const up = (m) => (m.online_sec_live != null ? m.online_sec_live : (Number(m.online_sec) || 0));
  if (by === "today_desc") arr.sort((a,b) => tot(b) - tot(a));
  else if (by === "today_asc") arr.sort((a,b) => tot(a) - tot(b));
  else if (by === "month_desc") arr.sort((a,b) => mtot(b) - mtot(a));
  else if (by === "uptime_desc") arr.sort((a,b) => up(b) - up(a));
  else arr.sort((a,b) => (b.ts||0) - (a.ts||0));
  return arr;
}

function renderTable() {
  const tb = document.getElementById("tbody");
  const view = machineView();
  if (!view.length) {
    tb.replaceChildren();
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 10;
    td.textContent = machines.length ? "当前筛选下无数据" : "暂无数据";
    tr.appendChild(td);
    tb.appendChild(tr);
    updateBatchBar();
    return;
  }
  // 用 DocumentFragment 一次挂载，减少多次回流
  const frag = document.createDocumentFragment();
  for (const m of view) {
    const tr = document.createElement("tr");
    if (m.machine_id === selected) tr.classList.add("active");
    tr.dataset.mid = m.machine_id || "";

    const tdCheck = document.createElement("td");
    const cb = document.createElement("input");
    cb.type = "checkbox";
    cb.className = "row-check";
    cb.dataset.mid = m.machine_id || "";
    cb.checked = selectedMids.has(m.machine_id);
    cb.addEventListener("change", (e) => {
      e.stopPropagation();
      toggleSelect(m.machine_id, cb.checked);
    });
    tdCheck.appendChild(cb);
    tr.appendChild(tdCheck);

    const uptime = (m.online_sec_live != null)
      ? m.online_sec_live
      : (Number(m.online_sec) || 0);
    const texts = [
      m.machine_id || "",
      m.hostname || "",
      m.interface || "",
      gb(m.today && m.today.rx) + " / " + gb(m.today && m.today.tx),
      gb(m.month && m.month.rx) + " / " + gb(m.month && m.month.tx),
      fmtDuration(uptime),
      fmtTime(m.ts),
    ];
    for (const text of texts) {
      const td = document.createElement("td");
      td.textContent = text;
      td.title = text;
      tr.appendChild(td);
    }

    const tdSt = document.createElement("td");
    const badge = document.createElement("span");
    const isOn = online(m.ts);
    badge.className = isOn ? "badge" : "badge off";
    badge.textContent = isOn ? "在线" : "离线";
    tdSt.appendChild(badge);
    tr.appendChild(tdSt);

    const tdOps = document.createElement("td");
    tdOps.className = "ops";
    const btnHist = document.createElement("button");
    btnHist.type = "button";
    btnHist.className = "sm green";
    btnHist.textContent = "流量统计";
    btnHist.addEventListener("click", (e) => {
      e.stopPropagation();
      openHistModal(m.machine_id);
    });
    const btnUp = document.createElement("button");
    btnUp.type = "button";
    btnUp.className = "sm primary";
    btnUp.textContent = "更新注册";
    btnUp.addEventListener("click", (e) => {
      e.stopPropagation();
      openUpdateVps(m.machine_id);
    });
    const btnDel = document.createElement("button");
    btnDel.type = "button";
    btnDel.className = "sm danger";
    btnDel.textContent = "删除";
    btnDel.addEventListener("click", (e) => {
      e.stopPropagation();
      deleteMachineRow(m.machine_id);
    });
    tdOps.appendChild(btnHist);
    tdOps.appendChild(btnUp);
    tdOps.appendChild(btnDel);
    tr.appendChild(tdOps);

    tr.addEventListener("click", (e) => {
      if (e.target.closest("button") || e.target.closest("input")) return;
      // 仅切换高亮，避免整表重绘造成「刷新感」
      const prev = tb.querySelector("tr.active");
      if (prev) prev.classList.remove("active");
      selected = m.machine_id;
      tr.classList.add("active");
    });
    frag.appendChild(tr);
  }
  tb.replaceChildren(frag);
  updateBatchBar();
}

function toggleSelect(mid, checked) {
  if (checked) selectedMids.add(mid); else selectedMids.delete(mid);
  updateBatchBar();
}
function toggleAll(checked) {
  selectedMids.clear();
  if (checked) for (const m of machineView()) selectedMids.add(m.machine_id);
  document.querySelectorAll("#tbody .row-check").forEach(cb => {
    cb.checked = selectedMids.has(cb.dataset.mid);
  });
  updateBatchBar();
}
function clearSelection() {
  selectedMids.clear();
  document.querySelectorAll("#tbody .row-check").forEach(cb => cb.checked = false);
  const ca = document.getElementById("checkAll");
  if (ca) ca.checked = false;
  updateBatchBar();
}
function updateBatchBar() {
  const bar = document.getElementById("batchBar");
  const cnt = document.getElementById("batchCount");
  const n = selectedMids.size;
  if (cnt) cnt.textContent = String(n);
  if (bar) bar.classList.toggle("show", n > 0);
}
async function batchAction(action) {
  const ids = [...selectedMids];
  if (!ids.length) { toast("未选择机器"); return; }
  const label = action === "delete" ? "删除" : (action === "include_tg" ? "加入 TG 汇报" : "移出 TG 汇报");
  if (action === "delete") {
    if (!confirm("确认批量" + label + " " + ids.length + " 台机器？删除不可恢复。")) return;
  } else if (action === "exclude_tg") {
    if (!confirm("确认将 " + ids.length + " 台机器移出 TG 汇报？")) return;
  }
  try {
    const data = await api("/api/machine-batch", {
      method: "POST",
      body: JSON.stringify({ ids, action }),
    });
    if (!data || !data.ok) { toast(data?.error || "批量操作失败"); return; }
    toast(label + " " + (data.affected || ids.length) + " 台完成");
    clearSelection();
    await refresh();
  } catch (e) {
    toast("批量操作失败：" + (e && e.message ? e.message : String(e)));
  }
}

function fillRangeOptions(sel, mode) {
  if (!sel) return;
  mode = normalizeChartMode(mode);
  const opts = rangeOptionsFor(mode);
  const p = chartPreset(mode);
  let prefer = null;
  try { prefer = localStorage.getItem("dash_chart_span_" + mode); } catch { /* ignore */ }
  const cur = prefer || sel.value || String(p.span);
  sel.disabled = false;
  sel.replaceChildren();
  for (const [v, t] of opts) {
    const o = document.createElement("option");
    o.value = v; o.textContent = t;
    sel.appendChild(o);
  }
  sel.value = opts.some(x => x[0] === String(cur)) ? String(cur) : String(p.span);
}

function saveChartPrefs() {
  try {
    const r = document.getElementById("range");
    const rx = document.getElementById("chkRx");
    const tx = document.getElementById("chkTx");
    localStorage.setItem("dash_chart_mode", chartMode);
    if (r && r.value) localStorage.setItem("dash_chart_span_" + chartMode, r.value);
    if (rx) localStorage.setItem("dash_chart_rx", rx.checked ? "1" : "0");
    if (tx) localStorage.setItem("dash_chart_tx", tx.checked ? "1" : "0");
  } catch { /* ignore */ }
}
function loadChartPrefs() {
  try {
    chartMode = normalizeChartMode(localStorage.getItem("dash_chart_mode"));
  } catch { /* ignore */ }
}
function setChartMode(mode) {
  chartMode = normalizeChartMode(mode);
  document.querySelectorAll("#modeSeg button").forEach(b => {
    b.classList.toggle("active", b.dataset.mode === chartMode);
  });
  fillRangeOptions(document.getElementById("range"), chartMode);
  saveChartPrefs();
  loadHistory();
}

function setHistMode(mode) {
  histMode = normalizeChartMode(mode);
  document.querySelectorAll("#histModeSeg button").forEach(b => {
    b.classList.toggle("active", b.dataset.mode === histMode);
  });
  const desc = document.getElementById("histModalDesc");
  if (desc) desc.textContent = chartPreset(histMode).desc;
  fillRangeOptions(document.getElementById("histRange"), histMode);
  loadHistModal();
}

/** 格式化图上数值标签（GB）：0 不画；<10 留 2 位，否则 1 位，避免挤 */
function fmtChartLabel(v) {
  const n = Number(v) || 0;
  if (!(n > 0)) return "";
  if (n < 0.01) return n.toFixed(3);
  if (n < 10) return n.toFixed(2);
  if (n < 100) return n.toFixed(1);
  return String(Math.round(n));
}

/** 柱顶 / 折线点旁显示数值（无第三方 datalabels 依赖） */
const valueLabelPlugin = {
  id: "valueLabels",
  afterDatasetsDraw(chart) {
    const { ctx, data, chartArea } = chart;
    if (!chartArea) return;
    const isBar = chart.config.type === "bar";
    const n = (data.labels && data.labels.length) || 0;
    if (!n) return;

    ctx.save();
    ctx.textAlign = "center";
    ctx.font = "11px system-ui,Segoe UI,sans-serif";

    if (isBar) {
      // 堆叠柱：在整柱顶部标「入+出」合计
      ctx.textBaseline = "bottom";
      ctx.fillStyle = "#c7d2fe";
      for (let i = 0; i < n; i++) {
        let sum = 0;
        let topMeta = null;
        for (let di = 0; di < data.datasets.length; di++) {
          const ds = data.datasets[di];
          if (ds.hidden) continue;
          const v = Number(ds.data[i]) || 0;
          sum += v;
          const meta = chart.getDatasetMeta(di);
          if (meta && meta.data && meta.data[i]) topMeta = meta.data[i];
        }
        if (!topMeta || !(sum > 0)) continue;
        const t = fmtChartLabel(sum);
        if (!t) continue;
        const x = topMeta.x;
        const y = Math.min(topMeta.y, chartArea.bottom) - 4;
        if (y < chartArea.top + 2) continue;
        ctx.fillText(t, x, y);
      }
    } else {
      // 折线：每个可见数据集的点旁标自身值（略上移，双线时第二层再抬一点）
      let visibleIdx = 0;
      for (let di = 0; di < data.datasets.length; di++) {
        const ds = data.datasets[di];
        const meta = chart.getDatasetMeta(di);
        if (!meta || meta.hidden || ds.hidden) continue;
        const color = ds.borderColor || "#c7d2fe";
        ctx.fillStyle = typeof color === "string" ? color : "#c7d2fe";
        ctx.textBaseline = "bottom";
        const lift = 6 + visibleIdx * 12;
        for (let i = 0; i < n; i++) {
          const el = meta.data[i];
          if (!el) continue;
          const v = Number(ds.data[i]) || 0;
          const t = fmtChartLabel(v);
          if (!t) continue;
          const y = el.y - lift;
          if (y < chartArea.top + 2) continue;
          ctx.fillText(t, el.x, y);
        }
        visibleIdx++;
      }
    }
    ctx.restore();
  },
};

/** 折线：日内小时增量（入/出分色） */
function buildLineChart(canvas, points, opts) {
  const showRx = opts.showRx !== false;
  const showTx = opts.showTx !== false;
  const title = opts.title || "";
  const labels = (points || []).map(p => {
    // "2026-07-17 14:00" → "14:00"，跨天保留月-日
    const b = String(p.bucket || "");
    const m = /^(\d{4})-(\d{2})-(\d{2}) (\d{2}:\d{2})$/.exec(b);
    if (!m) return b;
    return m[4];
  });
  const fullLabels = (points || []).map(p => p.bucket);
  const rx = (points || []).map(p => (Number(p.rx) || 0) / 1e9);
  const tx = (points || []).map(p => (Number(p.tx) || 0) / 1e9);
  const datasets = [];
  if (showRx) {
    datasets.push({
      label: "入站 GB/时",
      data: rx,
      borderColor: "#60a5fa",
      backgroundColor: "rgba(96,165,250,0.15)",
      borderWidth: 2,
      pointRadius: 2,
      pointHoverRadius: 4,
      tension: 0.25,
      fill: true,
    });
  }
  if (showTx) {
    datasets.push({
      label: "出站 GB/时",
      data: tx,
      borderColor: "#34d399",
      backgroundColor: "rgba(52,211,153,0.12)",
      borderWidth: 2,
      pointRadius: 2,
      pointHoverRadius: 4,
      tension: 0.25,
      fill: true,
    });
  }
  if (!datasets.length) {
    datasets.push({
      label: "无筛选",
      data: labels.map(() => 0),
      borderColor: "rgba(100,116,139,0.6)",
      backgroundColor: "rgba(100,116,139,0.1)",
      fill: true,
    });
  }
  return new Chart(canvas, {
    type: "line",
    data: { labels, datasets },
    plugins: [valueLabelPlugin],
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      layout: { padding: { top: 18, right: 8 } },
      scales: {
        x: {
          ticks: { maxTicksLimit: 12, color: "#8aa0c6", maxRotation: 0, autoSkip: true },
          grid: { color: "#1e2a42" },
        },
        y: {
          beginAtZero: true,
          ticks: { color: "#8aa0c6" },
          grid: { color: "#1e2a42" },
          title: { display: true, text: "GB / 小时", color: "#8aa0c6" },
        },
      },
      plugins: {
        legend: { labels: { color: "#c7d2fe" } },
        title: { display: !!title, text: title, color: "#e8eefc" },
        tooltip: {
          callbacks: {
            title: (items) => {
              const i = items && items[0] ? items[0].dataIndex : 0;
              return fullLabels[i] || (items[0] && items[0].label) || "";
            },
            footer: (items) => {
              const sum = items.reduce((a, it) => a + (Number(it.parsed.y) || 0), 0);
              return "合计 " + sum.toFixed(3) + " GB";
            },
          },
        },
      },
    },
  });
}

/** 堆叠柱：入站/出站分色叠成一根，高度=合计；勾选控制显示哪一层 */
function buildStackedChart(canvas, points, opts) {
  const showRx = opts.showRx !== false;
  const showTx = opts.showTx !== false;
  const title = opts.title || "";
  const labels = (points || []).map(p => p.bucket);
  const rx = (points || []).map(p => (Number(p.rx) || 0) / 1e9);
  const tx = (points || []).map(p => (Number(p.tx) || 0) / 1e9);
  const datasets = [];
  if (showRx) {
    datasets.push({
      label: "入站 GB",
      data: rx,
      backgroundColor: "rgba(96,165,250,0.85)",
      borderColor: "#60a5fa",
      borderWidth: 1,
      borderRadius: 3,
      stack: "t",
    });
  }
  if (showTx) {
    datasets.push({
      label: "出站 GB",
      data: tx,
      backgroundColor: "rgba(52,211,153,0.85)",
      borderColor: "#34d399",
      borderWidth: 1,
      borderRadius: 3,
      stack: "t",
    });
  }
  if (!datasets.length) {
    datasets.push({
      label: "无筛选",
      data: labels.map(() => 0),
      backgroundColor: "rgba(100,116,139,0.3)",
      stack: "t",
    });
  }
  return new Chart(canvas, {
    type: "bar",
    data: { labels, datasets },
    plugins: [valueLabelPlugin],
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      layout: { padding: { top: 22, right: 6 } },
      datasets: { bar: { categoryPercentage: 0.65, barPercentage: 0.9, maxBarThickness: 36 } },
      scales: {
        x: {
          stacked: true,
          ticks: {
            // 月报最长 31 天，刻度上限对齐
            maxTicksLimit: 31,
            color: "#8aa0c6",
            maxRotation: 45,
            minRotation: 0,
            autoSkip: true,
            autoSkipPadding: 4,
          },
          grid: { display: false },
        },
        y: {
          stacked: true,
          beginAtZero: true,
          ticks: { color: "#8aa0c6" },
          grid: { color: "#1e2a42" },
          title: { display: true, text: "GB", color: "#8aa0c6" },
        },
      },
      plugins: {
        legend: { labels: { color: "#c7d2fe" } },
        title: { display: !!title, text: title, color: "#e8eefc" },
        tooltip: {
          callbacks: {
            footer: (items) => {
              const sum = items.reduce((a, it) => a + (Number(it.parsed.y) || 0), 0);
              return "合计 " + sum.toFixed(3) + " GB";
            },
          },
        },
      },
    },
  });
}

function renderMainChart() {
  const ctx = document.getElementById("chart");
  if (!ctx) return;
  if (typeof Chart === "undefined") return; // Chart.js 尚未就绪
  if (chart) chart.destroy();
  const showRx = document.getElementById("chkRx").checked;
  const showTx = document.getElementById("chkTx").checked;
  saveChartPrefs();
  const p = chartPreset(chartMode);
  const span = readSpan("range", chartMode);
  const title = "全部机器 · " + chartTitleWithSpan(chartMode, span);
  if (p.chart === "line") {
    chart = buildLineChart(ctx, mainPoints, { showRx, showTx, title });
  } else {
    chart = buildStackedChart(ctx, mainPoints, { showRx, showTx, title });
  }
}

function renderHistChart() {
  const ctx = document.getElementById("histChart");
  if (!ctx) return;
  if (typeof Chart === "undefined") return;
  if (histChart) histChart.destroy();
  const showRx = document.getElementById("histChkRx").checked;
  const showTx = document.getElementById("histChkTx").checked;
  const p = chartPreset(histMode);
  const span = readSpan("histRange", histMode);
  const title = (histMid || "") + " · " + chartTitleWithSpan(histMode, span);
  if (p.chart === "line") {
    histChart = buildLineChart(ctx, histPoints, { showRx, showTx, title });
  } else {
    histChart = buildStackedChart(ctx, histPoints, { showRx, showTx, title });
  }
}

async function loadHistory() {
  try {
    const p = chartPreset(chartMode);
    const span = readSpan("range", chartMode);
    const q = "/api/history?mode=" + p.api + "&span=" + encodeURIComponent(span);
    const data = await api(q);
    mainPoints = (data && data.points) || [];
    await whenChartReady();
    renderMainChart();
    saveChartPrefs();
  } catch (e) {
    toast("加载统计失败：" + (e && e.message ? e.message : String(e)));
  }
}

function openHistModal(mid) {
  histMid = mid;
  histMode = normalizeChartMode(chartMode);
  document.getElementById("histModalTitle").textContent = "流量统计 · " + mid;
  document.getElementById("histModalDesc").textContent = chartPreset(histMode).desc;
  document.querySelectorAll("#histModeSeg button").forEach(b => {
    b.classList.toggle("active", b.dataset.mode === histMode);
  });
  fillRangeOptions(document.getElementById("histRange"), histMode);
  document.getElementById("histChkRx").checked = document.getElementById("chkRx").checked;
  document.getElementById("histChkTx").checked = document.getElementById("chkTx").checked;
  document.getElementById("histModal").classList.add("open");
  loadHistModal();
}

function closeHistModal() {
  document.getElementById("histModal").classList.remove("open");
  if (histChart) { histChart.destroy(); histChart = null; }
  histMid = null;
}

async function loadHistModal() {
  if (!histMid) return;
  try {
    const p = chartPreset(histMode);
    const span = readSpan("histRange", histMode);
    const q = "/api/history?mode=" + p.api + "&span=" + encodeURIComponent(span)
      + "&mid=" + encodeURIComponent(histMid);
    const data = await api(q);
    histPoints = (data && data.points) || [];
    await whenChartReady();
    renderHistChart();
  } catch (e) {
    toast("加载单机统计失败：" + (e && e.message ? e.message : String(e)));
  }
}

const TG_LABEL = {
  ok: "TG 正常",
  ready: "TG 待验证",
  incomplete: "TG 配置不完整",
  invalid: "TG 不可用",
  not_configured: "TG 未配置",
};

async function loadTgStatus(verify = false) {
  const el = document.getElementById("tgStatus");
  const txt = document.getElementById("tgStatusText");
  if (!el) return;
  // 非强制校验时不要先刷成「检测中」，减少首屏闪烁
  if (verify) {
    el.className = "tg-pill s-not_configured";
    txt.textContent = "TG: 检测中";
  }
  let lastErr = "";
  const maxTry = verify ? 3 : 1;
  for (let attempt = 1; attempt <= maxTry; attempt++) {
    try {
      const q = verify ? "?verify=1" : "";
      const d = await api("/api/tg-status" + q);
      if (!d) { lastErr = "无响应"; continue; }
      const s = d.state || "not_configured";
      el.className = "tg-pill s-" + s;
      txt.textContent = TG_LABEL[s] || s;
      let tip = d.detail || "";
      if (d.source) {
        const parts = [];
        if (d.source.token) parts.push("Token来源:" + d.source.token);
        if (d.source.id) parts.push("ChatID来源:" + d.source.id);
        if (parts.length) tip += (tip ? " · " : "") + parts.join(" ");
      }
      el.title = (tip || "") + "（点击重新检测）";
      return;
    } catch (e) {
      lastErr = String(e && e.message ? e.message : e);
    }
  }
  el.className = "tg-pill s-invalid";
  txt.textContent = "TG: 检测失败";
  el.title = (maxTry > 1 ? "重试后仍失败：" : "检测失败：") + lastErr;
}

/**
 * 刷新看板。opts:
 *  - history: 是否拉统计（默认 true）
 *  - tg: 是否拉 TG 状态（默认 true；首屏与列表并行）
 */
let _refreshInFlight = null;
let _refreshQueued = null;
async function refresh(opts = {}) {
  // 合并并发：进行中再点刷新，只排队一次，避免连点打爆 API
  if (_refreshInFlight) {
    _refreshQueued = opts;
    return _refreshInFlight;
  }
  const wantHistory = opts.history !== false;
  const wantTg = opts.tg !== false;
  _refreshInFlight = (async () => {
    try {
      const p = chartPreset(chartMode);
      const span = readSpan("range", chartMode);
      const histQ = "/api/history?mode=" + p.api + "&span=" + encodeURIComponent(span);

      const tasks = [api("/api/machines")];
      if (wantHistory) tasks.push(api(histQ));
      else tasks.push(Promise.resolve(null));
      if (wantTg) tasks.push(loadTgStatus(false));
      else tasks.push(Promise.resolve(null));

      const [machData, histData] = await Promise.all(tasks);

      machines = (machData && machData.machines) || [];
      if (selected && !machines.find(m => m.machine_id === selected)) selected = null;
      renderSummary();
      renderTable();

      if (wantHistory && histData) {
        mainPoints = histData.points || [];
        await whenChartReady();
        renderMainChart();
        saveChartPrefs();
      }
    } catch (e) {
      toast("刷新失败：" + (e && e.message ? e.message : String(e)));
    } finally {
      _refreshInFlight = null;
      if (_refreshQueued) {
        const q = _refreshQueued;
        _refreshQueued = null;
        refresh(q);
      }
    }
  })();
  return _refreshInFlight;
}

async function loadHistory() {
  try {
    const p = chartPreset(chartMode);
    const span = readSpan("range", chartMode);
    const q = "/api/history?mode=" + p.api + "&span=" + encodeURIComponent(span);
    const data = await api(q);
    mainPoints = (data && data.points) || [];
    await whenChartReady();
    renderMainChart();
    saveChartPrefs();
  } catch (e) {
    toast("加载统计失败：" + (e && e.message ? e.message : String(e)));
  }
}

// ─── TG 汇总 ───
async function sendTgSummary() {
  const btn = document.getElementById("btnTgSum");
  const st = document.getElementById("tgSumStatus");
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "发送中…";
  st.textContent = "";
  try {
    const data = await api("/api/tg-summary", { method: "POST" });
    if (!data || !data.ok) {
      st.textContent = "✗ " + (data?.error || "失败");
      toast("TG 汇总发送失败：" + (data?.error || "未知错误"));
    } else {
      st.textContent = "✓ 已发送（" + data.machines + "台，在线" + data.online + "）";
      toast("TG 汇总已发送！");
    }
  } catch(e) {
    st.textContent = "✗ " + e.message;
    toast("发送失败：" + e.message);
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
    setTimeout(() => { st.textContent = ""; }, 6000);
  }
}

// ─── 设置 ───
async function loadConfig() {
  const data = await api("/api/config");
  if (!data) return;
  // 环境变量来源：输入框留空，避免保存时把 env 值写进 D1
  document.getElementById("s_t_token").value = data.t_token_from_env ? "" : (data.t_token || "");
  document.getElementById("s_t_id").value = data.t_id_from_env ? "" : (data.t_id || "");
  document.getElementById("s_t_time").value = data.t_time || "20:00:00";
  document.getElementById("s_cf_time").value = data.cf_time || "0 * * * *";
  const ht = document.getElementById("hint_t_token");
  const hi = document.getElementById("hint_t_id");
  if (ht) ht.textContent = data.t_token_from_env
    ? "✓ 已使用环境变量 TG_BOT_TOKEN（页面留空即可）"
    : "页面未填时使用环境变量 TG_BOT_TOKEN";
  if (hi) hi.textContent = data.t_id_from_env
    ? "✓ 已使用环境变量 TG_ID（页面留空即可）"
    : "页面未填时使用环境变量 TG_ID";
}

async function loadLoginLogs() {
  const tb = document.getElementById("loginLogsBody");
  if (!tb) return;
  try {
    const data = await api("/api/login-logs?limit=100");
    if (!data || !data.ok) { tb.innerHTML = '<tr><td colspan="5">加载失败</td></tr>'; return; }
    const logs = data.logs || [];
    if (!logs.length) { tb.innerHTML = '<tr><td colspan="5" style="color:#8aa0c6">暂无登录记录</td></tr>'; return; }
    tb.replaceChildren();
    for (const lg of logs) {
      const tr = document.createElement("tr");
      tr.style.cursor = "default";
      const cells = [
        fmtTime(lg.ts),
        lg.success ? "✓ 成功" : "✗ 失败",
        lg.ip,
        lg.reason || "",
        lg.ua,
      ];
      for (let i = 0; i < cells.length; i++) {
        const td = document.createElement("td");
        td.textContent = cells[i];
        if (i === 1) {
          const b = document.createElement("span");
          b.className = "badge " + (lg.success ? "" : "off");
          b.textContent = cells[i];
          td.replaceChild(b, td.firstChild);
        }
        td.title = cells[i];
        if (i === 4) td.style.fontSize = "11px";
        tr.appendChild(td);
      }
      tb.appendChild(tr);
    }
  } catch (e) {
    tb.innerHTML = '<tr><td colspan="5">加载失败</td></tr>';
  }
}

// ─── TG 模板 ───
let tplList = [];
let tplActiveId = "card";
let tplEditingId = "";

function normalizeTplClient(list) {
  const arr = Array.isArray(list) ? list : [];
  const seen = new Set();
  const out = [];
  for (const x of arr) {
    if (!x || typeof x !== "object") continue;
    let id = String(x.id || "").trim();
    if (!id) id = "tpl_" + Math.random().toString(36).slice(2, 8);
    if (seen.has(id)) continue;
    seen.add(id);
    out.push({
      id,
      name: String(x.name || id).slice(0, 40),
      builtin: !!x.builtin,
      body: String(x.body || ""),
      machine_line: String(x.machine_line || ""),
    });
  }
  return out;
}

async function loadTemplates() {
  try {
    const d = await api("/api/tg-templates");
    if (!d || !d.ok) return;
    tplList = normalizeTplClient(d.templates || []);
    tplActiveId = String(d.active || "card").trim();
    if (!tplList.some(t => t.id === tplActiveId)) {
      tplActiveId = (tplList[0] && tplList[0].id) || "card";
    }
    tplEditingId = tplActiveId;
    renderTplUI();
  } catch (e) { /* ignore */ }
}
function curTpl() {
  const id = String(tplEditingId || tplActiveId || "").trim();
  return tplList.find(x => x.id === id) || tplList[0] || { id:"", name:"", body:"", machine_line:"" };
}
function renderTplUI() {
  const sel = document.getElementById("tplActive");
  if (sel) {
    const keep = String(tplEditingId || tplActiveId || "").trim();
    sel.replaceChildren();
    for (const t of tplList) {
      const o = document.createElement("option");
      o.value = t.id;
      o.textContent = (t.builtin ? "★ " : "") + (t.name || t.id);
      sel.appendChild(o);
    }
    // 优先回显正在编辑的项；对不上则回退 active / 第一项
    if (keep && tplList.some(t => t.id === keep)) {
      sel.value = keep;
      tplEditingId = keep;
    } else if (tplActiveId && tplList.some(t => t.id === tplActiveId)) {
      sel.value = tplActiveId;
      tplEditingId = tplActiveId;
    } else if (tplList[0]) {
      sel.value = tplList[0].id;
      tplEditingId = tplList[0].id;
      tplActiveId = tplList[0].id;
    }
  }
  const c = curTpl();
  if (c && c.id) tplEditingId = c.id;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v || ""; };
  set("tplName", c.name); set("tplBody", c.body); set("tplLine", c.machine_line);
}
async function onTplActiveChange() {
  const sel = document.getElementById("tplActive");
  const id = sel ? String(sel.value || "").trim() : "";
  if (!id || !tplList.some(t => t.id === id)) {
    renderTplUI();
    return;
  }
  // 切换前把当前编辑框写回列表，避免「改了没保存就丢」
  const prev = curTpl();
  if (prev && prev.id) {
    const idx = tplList.findIndex(x => x.id === prev.id);
    if (idx >= 0) {
      tplList[idx] = {
        ...tplList[idx],
        name: (document.getElementById("tplName") || {}).value || tplList[idx].name,
        body: (document.getElementById("tplBody") || {}).value || "",
        machine_line: (document.getElementById("tplLine") || {}).value || "",
      };
    }
  }
  tplEditingId = id;
  tplActiveId = id; // 下拉即当前汇报用模板
  renderTplUI();
  // 立即持久化 active + 列表（含刚才写回的编辑），避免下次进来下拉空白/错位
  await saveTplAll("已切换模板", { quiet: true });
}
function tplNew() {
  const id = "tpl_" + Math.random().toString(36).slice(2, 8);
  const t = {
    id,
    name: "新模板",
    builtin: false,
    body: "流量汇总\\n时间：{time}\\n{machine_lines}",
    machine_line: "{status} {m_id} 入{today_rx}/出{today_tx}",
  };
  tplList.push(t); tplEditingId = id; tplActiveId = id;
  renderTplUI();
}
function tplDelete() {
  const c = curTpl();
  if (!c || !c.id) return;
  if (c.builtin) { toast("内置模板不可删除"); return; }
  if (!confirm("删除模板「" + (c.name || c.id) + "」？")) return;
  tplList = tplList.filter(x => x.id !== c.id);
  if (tplActiveId === c.id) tplActiveId = (tplList[0] && tplList[0].id) || "card";
  tplEditingId = tplActiveId;
  saveTplAll("已删除");
}
async function tplReset() {
  if (!confirm("恢复为内置 3 个模板？自定义模板会丢失。")) return;
  // 直接用接口返回的内置结构：body 中的 \\n 在本文件模板字符串里会变成浏览器源码的 \\n 字面量？
  // 这里用 String.fromCharCode(10) 拼换行，避免转义层次混乱。
  const NL = String.fromCharCode(10);
  tplList = [
    { id:"card", name:"📊 卡片日报", builtin:true, body:["📊 流量日报","━━━━━━━━━━━━","🕐 时间：{time}","🖥 主机：{host_count} 台（🟢 {online_count} 在线）","","📥 今日入站  {today_rx}","📤 今日出站  {today_tx}","📦 今日合计  {today_total}","","📥 本月入站  {month_rx}","📤 本月出站  {month_tx}","📦 本月合计  {month_total}","━━━━━━━━━━━━","{machine_lines}"].join(NL), machine_line:["{status} {m_id}","    📥 {today_rx}  ·  📤 {today_tx}"].join(NL) },
    { id:"detail", name:"🏆 今日排行", builtin:true, body:["🏆 今日排行","🕐 时间：{time}","🟢 在线：{online_count}/{host_count} 台","📦 今日合计：{today_total}","━━━━━━━━━━━━","{machine_lines}","━━━━━━━━━━━━","📅 本月累计：{month_total}"].join(NL), machine_line:["{status} {m_id}","    📥 {today_rx}  ·  📤 {today_tx}"].join(NL) },
    { id:"brief", name:"📋 详细日报", builtin:true, body:["📋 详细日报","🕐 时间：{time}","🖥 主机：{host_count} 台（🟢 {online_count} 在线）","","📦 今日  📥 {today_rx}  ·  📤 {today_tx}  ·  共 {today_total}","📦 本月  📥 {month_rx}  ·  📤 {month_tx}  ·  共 {month_total}","━━━━━━━━━━━━","{machine_lines}"].join(NL), machine_line:["{status} {m_id} · {hostname}","    📅 今日  📥 {today_rx}  ·  📤 {today_tx}","    📅 本月  📥 {month_rx}  ·  📤 {month_tx}"].join(NL) },
  ];
  tplActiveId = "card"; tplEditingId = "card";
  await saveTplAll("已恢复内置");
}
async function tplSave() {
  const c = curTpl();
  if (!c.id) { toast("请新建或选择模板"); return; }
  const idx = tplList.findIndex(x => x.id === c.id);
  const updated = {
    id: c.id, builtin: c.builtin,
    name: document.getElementById("tplName").value.trim() || c.id,
    body: document.getElementById("tplBody").value,
    machine_line: document.getElementById("tplLine").value,
  };
  if (idx >= 0) tplList[idx] = updated; else tplList.push(updated);
  tplEditingId = updated.id;
  tplActiveId = updated.id;
  await saveTplAll("模板已保存");
}
async function saveTplAll(msg, opts) {
  const quiet = !!(opts && opts.quiet);
  try {
    tplList = normalizeTplClient(tplList);
    if (!tplList.length) { toast("模板列表为空"); return; }
    if (!tplList.some(t => t.id === tplActiveId)) {
      tplActiveId = tplList[0].id;
    }
    const d = await api("/api/tg-templates", {
      method: "POST",
      body: JSON.stringify({ templates: tplList, active: tplActiveId }),
    });
    if (!d || !d.ok) { toast(d?.error || "保存失败"); return; }
    tplList = normalizeTplClient(d.templates || tplList);
    tplActiveId = String(d.active || tplActiveId).trim();
    if (!tplList.some(t => t.id === tplActiveId)) {
      tplActiveId = (tplList[0] && tplList[0].id) || "card";
    }
    if (!tplList.some(t => t.id === tplEditingId)) tplEditingId = tplActiveId;
    renderTplUI();
    if (!quiet) {
      const st = document.getElementById("tplStatus");
      if (st) { st.textContent = "✓ " + msg; setTimeout(() => st.textContent = "", 2500); }
    }
  } catch (e) { toast("保存失败：" + (e && e.message ? e.message : e)); }
}
async function tplPreview() {
  const tpl = {
    name: document.getElementById("tplName").value,
    body: document.getElementById("tplBody").value,
    machine_line: document.getElementById("tplLine").value,
  };
  try {
    const d = await api("/api/tg-preview", { method: "POST", body: JSON.stringify({ template: tpl }) });
    if (!d || !d.ok) { toast(d?.error || "预览失败"); return; }
    const el = document.getElementById("tplPreview");
    if (el) el.textContent = d.text || "(空)";
  } catch (e) { toast("预览失败：" + (e && e.message ? e.message : e)); }
}

async function saveConfig() {
  const btn = document.querySelector(".save-row .primary");
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "保存中…";
  try {
    await api("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        t_token: document.getElementById("s_t_token").value.trim(),
        t_id: document.getElementById("s_t_id").value.trim(),
        t_time: document.getElementById("s_t_time").value.trim() || "20:00:00",
        cf_time: document.getElementById("s_cf_time").value.trim() || "0 * * * *",
      }),
    });
    document.getElementById("saveStatus").textContent = "✓ 已保存";
    setTimeout(() => document.getElementById("saveStatus").textContent = "", 3000);
  } catch(e) {
    toast("保存失败：" + e.message);
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
  }
}


// ─── 获取流量（签名推送到各 VPS 回调） ───
let forcePollTimer = null;
let forceTrack = null; // { force_at, rows:[{machine_id,state,status,detail,reported,last_ts}] }

function reasonLabel(state, detail, status) {
  if (state === "pushed") return "回调已接受";
  if (state === "push_fail") {
    const d = String(detail || "").trim();
    if (!d) return "推送失败（无详情，status=" + (status || 0) + "）";
    if (/1003|Direct IP|直连 IP|禁止直连/i.test(d)) {
      return "CF 1003：fetch 不能直连 IP。应走 TCP；若仍见此文请确认已部署最新 Worker";
    }
    if (/cfTcpConnect 不可用|sockets/i.test(d)) {
      return d.slice(0, 160);
    }
    if (/建连失败|connect\(\) 失败|ECONNREFUSED|Connection refused/i.test(d)) {
      return "连不上回调口 · " + d.slice(0, 140);
    }
    if (/超时|Timeout|timeout|abort/i.test(d)) {
      return "超时 · " + d.slice(0, 140);
    }
    if (/无 HTTP 响应|非 HTTP/i.test(d)) {
      return d.slice(0, 160);
    }
    if (/token length mismatch|token mismatch|missing bearer|unauthorized/i.test(d)) {
      return "鉴权失败：VPS 的 access_token 与看板不一致。用看板「更新注册」复制完整命令在 VPS 重装，两边 access_token 即统一 · " + d.slice(0, 80);
    }
    if (/bad signature/i.test(d)) {
      return "HMAC 签名不匹配（token 可能一致但 body/时间戳异常）· " + d.slice(0, 80);
    }
    if (/401|403|签名|sig|auth/i.test(d) && status) {
      return "HTTP " + status + " 鉴权/拒绝 · " + d.slice(0, 100);
    }
    return (status ? ("HTTP " + status + " · ") : "") + d.slice(0, 160);
  }
  if (state === "skipped") {
    if (detail === "no_callback_url") return "未登记回调地址（需重装/更新注册）";
    if (detail === "no_token") return "无 token";
    return String(detail || "已跳过");
  }
  return String(detail || "");
}

function openForceResult(data) {
  const forceAt = Number(data.force_at) || Math.floor(Date.now() / 1000);
  const detail = Array.isArray(data.detail) ? data.detail : [];
  // 若无 detail，从 fail/skip 拼
  let rows = detail.map((x) => ({
    machine_id: x.machine_id,
    state: x.state || (x.ok ? "pushed" : "push_fail"),
    status: x.status || 0,
    detail: x.detail || x.error || x.reason || "",
    callback_url: x.callback_url || "",
    reported: false,
    abandoned: false,
    last_ts: 0,
  }));
  if (!rows.length) {
    const fail = data.fail_detail || [];
    const skip = data.skip_detail || [];
    rows = [
      ...fail.map((x) => ({ machine_id: x.machine_id, state: "push_fail", status: x.status || 0, detail: x.error || "", reported: false, abandoned: false, last_ts: 0 })),
      ...skip.map((x) => ({ machine_id: x.machine_id, state: "skipped", status: 0, detail: x.reason || "", reported: false, abandoned: false, last_ts: 0 })),
    ];
  }
  forceTrack = { force_at: forceAt, rows };
  document.getElementById("forceResultTitle").textContent = "获取流量结果";
  document.getElementById("forceResultDesc").textContent =
    data.message || ("推送完成：成功 " + (data.accepted || 0) + " / 失败 " + (data.failed || 0) + " / 跳过 " + (data.skipped || 0));
  const pendingN = rows.filter((r) => r.state === "pushed").length;
  document.getElementById("forceResultNote").textContent = pendingN
    ? "推送成功表示回调已收到；列表时间等实际上报。每 2 秒刷新；全部成功立即停，最多 30 秒后舍弃未上报机器并停止。"
    : "没有可等待上报的机器（全部跳过或推送失败），无需自动刷新。";
  document.getElementById("forceResultModal").classList.add("open");
  renderForceResult();
  if (pendingN > 0) startForcePoll();
}

function renderForceResult() {
  if (!forceTrack) return;
  const body = document.getElementById("forceResultBody");
  const sum = document.getElementById("forceResultSum");
  if (!body || !sum) return;

  let nPushOk = 0, nPushFail = 0, nSkip = 0, nReported = 0;
  body.replaceChildren();
  for (const r of forceTrack.rows) {
    if (r.state === "pushed") nPushOk++;
    else if (r.state === "push_fail") nPushFail++;
    else nSkip++;
    if (r.reported) nReported++;

    const tr = document.createElement("tr");
    const td1 = document.createElement("td");
    td1.textContent = r.machine_id;
    const td2 = document.createElement("td");
    const b2 = document.createElement("span");
    b2.className = "badge " + (r.state === "pushed" ? "ok" : r.state === "push_fail" ? "fail" : "skip");
    b2.textContent = r.state === "pushed" ? "成功" : r.state === "push_fail" ? "失败" : "跳过";
    td2.appendChild(b2);
    const td3 = document.createElement("td");
    const b3 = document.createElement("span");
    if (r.reported) {
      b3.className = "badge reported";
      b3.textContent = "已上报";
    } else if (r.abandoned) {
      b3.className = "badge fail";
      b3.textContent = "超时放弃";
    } else if (r.state === "pushed") {
      b3.className = "badge wait";
      b3.textContent = "等待中";
    } else {
      b3.className = "badge skip";
      b3.textContent = "—";
    }
    td3.appendChild(b3);
    const td4 = document.createElement("td");
    let tip = reasonLabel(r.state, r.detail, r.status);
    if (r.abandoned) tip = "超过 30 秒未上报，已停止等待";
    if (r.reported && r.last_ts) tip += " · 上报时间 " + fmtTime(r.last_ts);
    if (r.state === "push_fail" && r.callback_url) tip += " · " + r.callback_url;
    td4.textContent = tip;
    td4.style.color = "#9fb3d9";
    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4);
    body.appendChild(tr);
  }

  sum.replaceChildren();
  const pills = [
    ["ok", "推送成功 " + nPushOk],
    ["fail", "推送失败 " + nPushFail],
    ["skip", "跳过 " + nSkip],
    ["wait", "已上报 " + nReported + "/" + nPushOk],
  ];
  for (const [cls, text] of pills) {
    const s = document.createElement("span");
    s.className = "pill " + cls;
    s.textContent = text;
    sum.appendChild(s);
  }
}

function closeForceResult() {
  document.getElementById("forceResultModal").classList.remove("open");
  if (forcePollTimer) { clearTimeout(forcePollTimer); forcePollTimer = null; }
}

function startForcePoll() {
  if (forcePollTimer) { clearTimeout(forcePollTimer); forcePollTimer = null; }
  if (!forceTrack) return;
  // 仅等待「推送成功」的机器；每台成功上报一次即标记，全部完成后立即停
  const needWait = forceTrack.rows.some((r) => r.state === "pushed" && !r.reported);
  if (!needWait) return;

  let n = 0;
  const max = 15; // 最长约 30s，成功则提前结束
  const tick = async () => {
    n++;
    try {
      await refresh();
      if (!forceTrack) {
        forcePollTimer = null;
        return;
      }
      const byId = new Map(machines.map((m) => [m.machine_id, m]));
      for (const r of forceTrack.rows) {
        if (r.state !== "pushed" || r.reported) continue;
        const m = byId.get(r.machine_id);
        const ts = m ? (Number(m.ts) || 0) : 0;
        if (ts >= forceTrack.force_at) {
          r.reported = true;
          r.last_ts = ts;
        }
      }
      renderForceResult();
      const pending = forceTrack.rows.filter((r) => r.state === "pushed" && !r.reported).length;
      const note = document.getElementById("forceResultNote");
      if (pending === 0) {
        note.textContent = "全部可推送机器已完成上报，列表时间已更新。已停止自动刷新。";
        forcePollTimer = null;
        return; // 全部成功 → 立即停止，不再空转
      }
      if (n >= max) {
        // 最多 30 秒：未上报的机器直接舍弃，不再刷新
        for (const r of forceTrack.rows) {
          if (r.state === "pushed" && !r.reported) r.abandoned = true;
        }
        renderForceResult();
        note.textContent = "已达 30 秒上限：舍弃 " + pending + " 台未上报机器，停止自动刷新。可稍后手动点「刷新列表」。";
        forcePollTimer = null;
        return;
      }
      note.textContent = "等待上报中… 剩余 " + pending + " 台 · 已刷新 " + n + " 次 · 最多 " + Math.max(0, (max - n) * 2) + " 秒后舍弃未上报";
    } catch (e) { /* ignore poll errors */ }
    // 仅在仍有待上报时继续
    if (forceTrack && forceTrack.rows.some((r) => r.state === "pushed" && !r.reported && !r.abandoned)) {
      forcePollTimer = setTimeout(tick, 2000);
    } else {
      forcePollTimer = null;
    }
  };
  forcePollTimer = setTimeout(tick, 1500);
}

async function forceFetchAll() {
  const btn = document.getElementById("btnForceFetch");
  const st = document.getElementById("tgSumStatus");
  btn.disabled = true;
  const orig = btn.textContent;
  btn.textContent = "推送中…";
  st.textContent = "正在推送到各 VPS…";
  try {
    const data = await api("/api/force-report", { method: "POST" });
    if (!data || !data.ok) {
      st.textContent = "✗ " + (data?.error || "失败");
      openForceResult({
        ok: false,
        force_at: Math.floor(Date.now() / 1000),
        accepted: 0,
        failed: 1,
        skipped: 0,
        message: "获取流量失败：" + (data?.error || "未知错误"),
        detail: [{ machine_id: "—", state: "push_fail", status: 0, detail: data?.error || "未知错误" }],
      });
      document.getElementById("forceResultTitle").textContent = "获取流量失败";
      document.getElementById("forceResultNote").textContent = "请求未成功，未向 VPS 发起推送。";
    } else {
      const acc = data.accepted != null ? data.accepted : 0;
      const push = data.pushed != null ? data.pushed : 0;
      st.textContent = "✓ 推送 " + acc + "/" + push + "（失败 " + (data.failed || 0) + "，跳过 " + (data.skipped || 0) + "）";
      openForceResult(data);
      // 立即刷一次列表
      await refresh();
    }
  } catch (e) {
    st.textContent = "✗ " + e.message;
    openForceResult({
      ok: false,
      force_at: Math.floor(Date.now() / 1000),
      message: "获取流量失败：" + e.message,
      detail: [{ machine_id: "—", state: "push_fail", status: 0, detail: e.message }],
    });
    document.getElementById("forceResultTitle").textContent = "获取流量失败";
  } finally {
    btn.textContent = orig;
    btn.disabled = false;
    setTimeout(() => { if (st && st.textContent.startsWith("✓")) st.textContent = ""; }, 15000);
  }
}

// ─── 更新注册 / 删除 ───
async function openUpdateVps(mid) {
  document.getElementById("modalUpdate").classList.add("open");
  document.getElementById("upCmdRegion").style.display = "none";
  document.getElementById("upBtnRegion").style.display = "flex";
  document.getElementById("upMid").value = mid || "";
  document.getElementById("upToken").value = "";
  document.getElementById("upToken").placeholder = "加载中…";
  document.getElementById("upUrl").value = "";
  document.getElementById("upTime").value = "";
  const upCbInit = document.getElementById("upCbPort");
  if (upCbInit) upCbInit.value = "";
  document.getElementById("upRotate").checked = false;
  const hint = document.getElementById("upTokenHint");
  if (hint) hint.textContent = "加载中…";
  try {
    // 默认不 reveal 完整 token
    const data = await api("/api/machine-reg?mid=" + encodeURIComponent(mid));
    if (!data || !data.ok) {
      toast(data?.error || "加载注册信息失败");
      closeUpdateVps();
      return;
    }
    document.getElementById("upMid").value = data.machine_id || mid;
    document.getElementById("upToken").value = "";
    document.getElementById("upToken").placeholder = data.token_preview
      ? ("已隐藏 · " + data.token_preview + " · 留空=沿用")
      : "留空=沿用服务端密钥";
    if (hint) {
      hint.textContent = data.has_token
        ? ("服务端已有密钥（" + (data.token_preview || "****") + "）。留空生成命令时沿用；粘贴新值可覆盖；勾选轮换则下发 pending。")
        : "尚无密钥，生成时将自动创建。";
    }
    document.getElementById("upUrl").value = data.cf_url || "";
    document.getElementById("upTime").value = data.cf_time || "0 * * * *";
    const upCb = document.getElementById("upCbPort");
    if (upCb) upCb.value = data.cb_port || "19840";
  } catch (e) {
    toast("加载失败：" + (e && e.message ? e.message : String(e)));
    closeUpdateVps();
  }
}

function closeUpdateVps() {
  document.getElementById("modalUpdate").classList.remove("open");
}

async function confirmUpdateVps() {
  const machine_id = document.getElementById("upMid").value.trim();
  // 空字符串 = 不覆盖，服务端沿用已有 token
  let access_token = document.getElementById("upToken").value.trim();
  if (access_token === "加载中…" || access_token.indexOf("已隐藏") === 0) access_token = "";
  const cf_url = document.getElementById("upUrl").value.trim();
  const cf_time = document.getElementById("upTime").value.trim();
  const cb_port = ((document.getElementById("upCbPort") || {}).value || "").trim();
  const rotate_token = document.getElementById("upRotate").checked;
  if (!machine_id) { toast("请填写机器 ID"); return; }
  if (cb_port && !/^\d+$/.test(cb_port)) { toast("回调端口应为纯数字"); return; }
  if (cb_port && (Number(cb_port) < 1024 || Number(cb_port) > 65535)) { toast("回调端口需在 1024-65535，当前 " + cb_port); return; }
  const btn = document.querySelector("#upBtnRegion .green");
  if (btn) { btn.disabled = true; btn.textContent = "生成中…"; }
  try {
    const data = await api("/api/generate-update", {
      method: "POST",
      body: JSON.stringify({ machine_id, access_token, cf_url, cf_time, cb_port, rotate_token }),
    });
    if (!data || !data.ok) {
      toast(data?.error || "生成失败");
      return;
    }
    document.getElementById("upOk").textContent = "✓ 更新命令已生成（密钥：" + (data.token_preview || "") + "）";
    document.getElementById("upCmd").textContent = data.command;
    // 不回填完整 token 到输入框
    document.getElementById("upToken").value = "";
    document.getElementById("upToken").placeholder = data.token_preview
      ? ("已隐藏 · " + data.token_preview)
      : "留空=沿用";
    document.getElementById("upCmdRegion").style.display = "block";
    document.getElementById("upBtnRegion").style.display = "none";
    toast("命令已生成，复制到 VPS 执行即可升级脚本");
  } catch (e) {
    toast("生成失败：" + (e && e.message ? e.message : String(e)));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "确定并生成命令"; }
  }
}

async function copyUpCmd() {
  try {
    await navigator.clipboard.writeText(document.getElementById("upCmd").textContent);
    toast("已复制到剪贴板");
  } catch {
    const r = document.createRange();
    r.selectNode(document.getElementById("upCmd"));
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
    document.execCommand("copy");
    toast("已复制");
  }
}

async function deleteMachineRow(mid) {
  if (!mid) return;
  if (!confirm("确定删除机器「" + mid + "」？将清除看板数据、历史曲线与注册密钥（不可恢复）。")) return;
  try {
    const data = await api("/api/machine?mid=" + encodeURIComponent(mid), { method: "DELETE" });
    if (!data || !data.ok) {
      toast(data?.error || "删除失败");
      return;
    }
    toast("已删除 " + mid);
    if (selected === mid) selected = null;
    await refresh();
  } catch (e) {
    toast("删除失败：" + (e && e.message ? e.message : String(e)));
  }
}

// ─── 添加 VPS ───
function openAddVps() {
  document.getElementById("modalVps").classList.add("open");
  document.getElementById("vpsMid").value = "";
  document.getElementById("vpsCbPort").value = "19840";
  document.getElementById("vpsCmdRegion").style.display = "none";
  document.getElementById("vpsBtnRegion").style.display = "flex";
  document.getElementById("vpsMid").focus();
}

function closeAddVps() {
  document.getElementById("modalVps").classList.remove("open");
}

async function genCmd() {
  const mid = document.getElementById("vpsMid").value.trim();
  if (!mid) { toast("请输入机器 ID"); return; }
  if (!/^[一-鿿A-Za-z0-9._:-]{1,64}$/.test(mid)) {
    toast("机器 ID 1-64 字，支持中英文/数字/._-:（如 香港-1）");
    return;
  }
  const cbRaw = ((document.getElementById("vpsCbPort") || {}).value || "").trim();
  let cbPort = /^\d+$/.test(cbRaw) ? Number(cbRaw) : 19840;
  if (cbPort < 1024 || cbPort > 65535) { toast("回调端口需在 1024-65535，当前 " + cbPort); return; }
  const btn = document.querySelector("#vpsBtnRegion .green");
  if (btn) { btn.disabled = true; btn.textContent = "生成中…"; }
  try {
    const data = await api("/api/generate?mid=" + encodeURIComponent(mid) + "&cb_port=" + encodeURIComponent(cbPort));
    if (!data || !data.ok) { toast(data?.error || "生成失败"); return; }
    document.getElementById("vpsOk").textContent = "✓ 命令已生成（独立密码： " + (data.token || data.token_preview || "") + "）";
    document.getElementById("vpsCmd").textContent = data.command;
    document.getElementById("vpsTokenPreview").textContent = "每台 VPS 有独立的随机密码，此密码只需在生成时使用，D1 中安全存储。";
    document.getElementById("vpsCmdRegion").style.display = "block";
    document.getElementById("vpsBtnRegion").style.display = "none";
  } catch(e) {
    toast("生成失败：" + (e && e.message ? e.message : String(e || "未知错误")));
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "生成命令"; }
  }
}

async function copyCmd() {
  try {
    await navigator.clipboard.writeText(document.getElementById("vpsCmd").textContent);
    toast("已复制到剪贴板");
  } catch {
    const r = document.createRange();
    r.selectNode(document.getElementById("vpsCmd"));
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
    document.execCommand("copy");
    toast("已复制");
  }
}

document.getElementById("modalVps").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeAddVps();
});
document.getElementById("modalUpdate").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeUpdateVps();
});
document.getElementById("histModal").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeHistModal();
});
document.getElementById("forceResultModal").addEventListener("click", e => {
  if (e.target === e.currentTarget) closeForceResult();
});
document.getElementById("vpsMid").addEventListener("keydown", e => {
  if (e.key === "Enter") genCmd();
});

loadChartPrefs();
// 恢复勾选
try {
  const rx = document.getElementById("chkRx");
  const tx = document.getElementById("chkTx");
  if (localStorage.getItem("dash_chart_rx") === "0") rx.checked = false;
  if (localStorage.getItem("dash_chart_tx") === "0") tx.checked = false;
} catch { /* ignore */ }
// 高亮恢复的 mode 按钮
document.querySelectorAll("#modeSeg button").forEach(b => {
  b.classList.toggle("active", b.dataset.mode === chartMode);
});
fillRangeOptions(document.getElementById("range"), chartMode);
tickDashClock();
setInterval(tickDashClock, 1000);
refresh();
</script>`;
}

// ─── 路由 ───

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    // 自动初始化（失败时带上原因，避免生成命令时无表）
    let schemaErr = "";
    if (env.DB) {
      try { await ensureSchema(env); }
      catch (e) { schemaErr = e && e.message ? e.message : String(e); }
    }

    // POST /api/report — agent 上报
    if (req.method === "POST" && url.pathname === "/api/report") {
      if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
      let body;
      try { body = await req.json(); } catch { return json({ ok: false, error: "invalid json" }, 400); }
      const mid = String(body.machine_id || req.headers.get("x-machine-id") || "").trim();
      if (!isValidMachineId(mid)) {
        return json({ ok: false, error: "machine_id invalid" }, 400);
      }

      // 鉴权 + token 轮换协商
      const bearer = extractBearer(req);
      const auth = await verifyAndRotate(env, mid, bearer, body && body.refresh_access_token);
      if (!auth.ok) {
        return json({ ok: false, error: "unauthorized" }, 401);
      }

      await upsertReport(env, { ...body, machine_id: mid });
      return json(auth.new_access_token ? { ok: true, new_access_token: auth.new_access_token } : { ok: true });
    }

    // /login /logout
    if (url.pathname === "/login") {
      if (req.method === "GET") {
        if (env.PASSWORD && (await requireDash(req, env))) {
          return Response.redirect(new URL("/", url).toString(), 302);
        }
        return html(loginPage("", { noPassword: !env.PASSWORD }));
      }
      if (req.method === "POST") {
        const form = await req.formData();
        const pw = String(form.get("password") || "");
        const ip = (req.headers.get("cf-connecting-ip") || req.headers.get("x-forwarded-for") || "-").toString().split(",")[0].trim();
        const ua = req.headers.get("user-agent") || "-";
        if (!env.PASSWORD) {
          await addLoginLog(env, { ip, ua, success: false, reason: "PASSWORD 未配置" });
          return html(loginPage("未配置 PASSWORD 加密变量，无法登录。请先到 Cloudflare Dashboard 添加。", { noPassword: true }), 401);
        }
        // 失败限流：同 IP 15 分钟内超 8 次锁定
        const lock = await getLoginLock(env, ip);
        if (lock.locked) {
          const mins = Math.ceil(lock.remainSec / 60);
          await addLoginLog(env, { ip, ua, success: false, reason: "登录锁定" });
          return html(loginPage("尝试过多，请 " + mins + " 分钟后再试。"), 429);
        }
        const ok = passwordEqual(pw, env.PASSWORD);
        if (!ok) {
          await recordLoginFail(env, ip);
          await addLoginLog(env, { ip, ua, success: false, reason: "密码错误" });
          return html(loginPage("密码错误"), 401);
        }
        await clearLoginFail(env, ip);
        await addLoginLog(env, { ip, ua, success: true, reason: "登录成功" });
        // TG 通知（已配置则发）
        try {
          const time = new Date().toLocaleString("zh-CN", { timeZone: "Asia/Shanghai", hour12: false });
          await sendTgMessage(env,
            "🔐 看板登录成功\n时间：" + time + "\nIP：" + ip + "\n设备：" + String(ua).slice(0, 120));
        } catch { /* ignore */ }
        const token = await makeSessionToken(env);
        return new Response(null, { status: 302, headers: { Location: "/", "Set-Cookie": sessionCookie(token) } });
      }
    }

    if (req.method === "POST" && url.pathname === "/logout") {
      return new Response(null, { status: 302, headers: { Location: "/login", "Set-Cookie": sessionCookie("", 0) } });
    }

    // GET /api/agent/pull — VPS 轮询是否需要立即上报（Bearer VPS token）
    if (req.method === "GET" && url.pathname === "/api/agent/pull") {
      if (!env.DB) return json({ ok: true, force_report: false });
      const mid = String(req.headers.get("x-machine-id") || url.searchParams.get("mid") || "").trim();
      if (!isValidMachineId(mid)) return json({ ok: false, error: "machine_id invalid" }, 400);
      const token = extractBearer(req);
      if (!token || !(await verifyVpsToken(env, mid, token))) {
        return json({ ok: false, error: "unauthorized" }, 401);
      }
      const force_report = await agentShouldForceReport(env, mid);
      return json({ ok: true, force_report, machine_id: mid });
    }

    // 以下需登录
    if (!(await requireDash(req, env))) {
      if (url.pathname.startsWith("/api/")) return json({ ok: false, error: "unauthorized" }, 401);
      return Response.redirect(new URL("/login", url).toString(), 302);
    }

    // GET /api/tg-status — TG 配置状态（可选 verify=1 真实验证）
    if (req.method === "GET" && url.pathname === "/api/tg-status") {
      try {
        const verify = url.searchParams.get("verify") === "1";
        const s = await getTgStatus(env, verify);
        return json({ ok: true, ...s });
      } catch (e) {
        return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
      }
    }

    // GET /api/login-logs — 登录日志
    if (req.method === "GET" && url.pathname === "/api/login-logs") {
      if (!env.DB) return json({ ok: true, logs: [] });
      const limit = Number(url.searchParams.get("limit") || 100);
      return json({ ok: true, logs: await getLoginLogs(env, limit) });
    }

    // GET /api/machines
    if (req.method === "GET" && url.pathname === "/api/machines") {
      if (!env.DB) return json({ ok: true, machines: [] });
      return json({ ok: true, machines: await listMachines(env) });
    }

    // GET /api/history — mode=hour|day|month, span=小时/天数/月数, mid 可选（空=全部合计）
    if (req.method === "GET" && url.pathname === "/api/history") {
      if (!env.DB) return json({ ok: true, points: [] });
      const mid = String(url.searchParams.get("mid") || "").trim();
      const modeRaw = String(url.searchParams.get("mode") || "day").toLowerCase();
      const mode = modeRaw === "month" ? "month" : modeRaw === "hour" ? "hour" : "day";
      const span = Number(url.searchParams.get("span") || url.searchParams.get("hours") || (mode === "month" ? 6 : mode === "hour" ? 24 : 14));
      if (mid && !isValidMachineId(mid)) return json({ ok: false, error: "mid invalid" }, 400);
      // 兼容旧 hours 参数：有 mid 且无 mode 时仍可返回原始点
      if (mid && url.searchParams.has("hours") && !url.searchParams.has("mode") && !url.searchParams.has("span")) {
        const hours = Math.min(24 * 90, Math.max(1, Number(url.searchParams.get("hours") || 168)));
        return json({ ok: true, machine_id: mid, hours, points: await getHistory(env, mid, hours) });
      }
      if (mode === "hour") {
        const agg = await getHistoryHourly(env, { mid: mid || null, span });
        return json({ ok: true, ...agg });
      }
      const agg = await getHistoryAgg(env, { mid: mid || null, mode, span });
      return json({ ok: true, ...agg });
    }

    // GET /api/config / POST /api/config
    if (req.method === "GET" && url.pathname === "/api/config") {
      return json({ ok: true, ...(await getConfig(env)) });
    }
    if (req.method === "POST" && url.pathname === "/api/config") {
      try { const body = await req.json(); await saveConfig(env, body); return json({ ok: true }); }
      catch (e) { return json({ ok: false, error: String(e) }, 400); }
    }

    // GET /api/generate — 生成一键命令（含独立密码）
    if (req.method === "GET" && url.pathname === "/api/generate") {
      const mid = String(url.searchParams.get("mid") || "").trim();
      try {
        if (!env.DB) {
          return json({ ok: false, error: missingDbError(env) }, 500);
        }
        if (schemaErr) {
          try { await ensureSchema(env); schemaErr = ""; }
          catch (e) {
            return json({ ok: false, error: "D1 初始化失败：" + (e && e.message ? e.message : String(e)) }, 500);
          }
        }
        const result = await generateCommand(env, req, mid);
        if (!result.ok) return json(result, 400);
        return json(result);
      } catch (e) {
        return json({ ok: false, error: "生成异常：" + (e && e.message ? e.message : String(e)) }, 500);
      }
    }

    // GET /api/machine-reg — 更新注册弹窗预填（默认不回完整 token；?reveal=1 才返回）
    if (req.method === "GET" && url.pathname === "/api/machine-reg") {
      const mid = String(url.searchParams.get("mid") || "").trim();
      const reveal = url.searchParams.get("reveal") === "1";
      try {
        if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
        const result = await getMachineReg(env, req, mid, { reveal });
        if (!result.ok) return json(result, 400);
        return json(result);
      } catch (e) {
        return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
      }
    }

    // POST /api/generate-update — 按可编辑参数生成升级命令
    if (req.method === "POST" && url.pathname === "/api/generate-update") {
      try {
        if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
        const body = await req.json();
        const result = await generateUpdateCommand(env, req, body || {});
        if (!result.ok) return json(result, 400);
        return json(result);
      } catch (e) {
        return json({ ok: false, error: "生成异常：" + (e && e.message ? e.message : String(e)) }, 500);
      }
    }

    // POST /api/machine-batch — 批量删除/加入TG/移出TG
    if (req.method === "POST" && url.pathname === "/api/machine-batch") {
      try {
        if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
        const b = await req.json();
        const r = await machineBatch(env, b && b.ids, b && b.action);
        if (!r.ok) return json(r, 400);
        return json(r);
      } catch (e) {
        return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
      }
    }

    // DELETE /api/machine — 删除机器数据与 token
    if (req.method === "DELETE" && url.pathname === "/api/machine") {
      const mid = String(url.searchParams.get("mid") || "").trim();
      if (!isValidMachineId(mid)) return json({ ok: false, error: "mid invalid" }, 400);
      try {
        if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
        await deleteMachine(env, mid);
        return json({ ok: true, machine_id: mid });
      } catch (e) {
        return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
      }
    }

    // POST /api/force-report — 看板「获取流量」：签名推送到各 VPS 回调 + force 标记
    if (req.method === "POST" && url.pathname === "/api/force-report") {
      if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
      try {
        const result = await forceReportPushAll(env);
        return json(result);
      } catch (e) {
        return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
      }
    }

    // GET /api/tg-templates — 模板列表
    if (req.method === "GET" && url.pathname === "/api/tg-templates") {
      try {
        if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
        return json({ ok: true, ...(await getTemplates(env)) });
      } catch (e) {
        return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
      }
    }
    // POST /api/tg-templates — 保存全部模板/active
    if (req.method === "POST" && url.pathname === "/api/tg-templates") {
      try {
        if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
        const b = await req.json();
        const r = await saveTemplates(env, b && b.templates, b && b.active);
        if (!r.ok) return json(r, 400);
        return json(r);
      } catch (e) {
        return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
      }
    }
    // POST /api/tg-preview — 用当前数据预览模板
    if (req.method === "POST" && url.pathname === "/api/tg-preview") {
      try {
        if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
        const b = await req.json();
        const machines = (await listMachines(env)).filter(m => m.in_tg_report !== false);
        const total = machines.reduce((a, m) => ({
          today_rx: a.today_rx + (m.today?.rx || 0), today_tx: a.today_tx + (m.today?.tx || 0),
          month_rx: a.month_rx + (m.month?.rx || 0), month_tx: a.month_tx + (m.month?.tx || 0),
        }), { today_rx: 0, today_tx: 0, month_rx: 0, month_tx: 0 });
        const text = renderTemplate(b && b.template, machines, total);
        return json({ ok: true, text });
      } catch (e) {
        return json({ ok: false, error: String(e && e.message ? e.message : e) }, 500);
      }
    }

    // POST /api/tg-summary — 发送 TG 汇总
    if (req.method === "POST" && url.pathname === "/api/tg-summary") {
      const result = await tgSummary(env);
      if (!result.ok) return json(result, 400);
      return json(result);
    }

    // GET / — 看板
    if (req.method === "GET" && (url.pathname === "/" || url.pathname === "/index.html")) {
      return html(dashboardPage());
    }

    return json({ ok: false, error: "not found" }, 404);
  },

  /** 定时触发：每小时整点检查一次；清理 snapshot、离线告警、到点发 TG（同日只发一次） */
  async scheduled(event, env, ctx) {
    ctx.waitUntil((async () => {
      try {
        if (!env.DB) return;
        await ensureSchema(env);
        // 每日最多清一次 90 天前 snapshot（不堵上报热路径）
        try { await cleanupOldSnapshots(env); } catch (e) { console.log("[scheduled] cleanup", e && e.message); }
        await checkOffline(env);
        const t_time = (await getConfigValue(env, "t_time")) || "20:00:00";
        // 小时级 cron：只比小时（20:00 / 20:30 都在上海时间 20 点整点发）
        const m = /^(\d{2}):/.exec(t_time);
        if (!m) return;
        const th = m[1];
        const sh = new Date(new Date().toLocaleString("en-US", { timeZone: "Asia/Shanghai" }));
        const hh = String(sh.getHours()).padStart(2, "0");
        if (hh !== th) return;
        // 日锁：上海日期 YYYY-MM-DD，同日不重复发
        const today = shanghaiBucket(Math.floor(Date.now() / 1000), false);
        const last = await getConfigValue(env, "last_tg_summary_date");
        if (last === today) {
          console.log("[scheduled] TG summary already sent today:", today);
          return;
        }
        const r = await tgSummary(env);
        if (!r || !r.ok) {
          console.log("[scheduled] TG summary skip:", r && r.error);
          return;
        }
        try { await setConfigValue(env, "last_tg_summary_date", today); } catch { /* ignore */ }
      } catch (e) { console.log("[scheduled] error", e && e.message); }
    })());
  },
};
