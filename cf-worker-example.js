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
 *                 TG_TOKEN（旧版全局上报密码，可选；新版用 VPS 独立 token）
 *   5. 再部署一次使绑定生效
 */

import { connect as cfTcpConnect } from "cloudflare:sockets";

const SESSION_TTL = 60 * 60 * 24 * 7;
const COOKIE_NAME = "dash_session";

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

function reportAuth(req, env) {
  const h = req.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return !!(env.TG_TOKEN && m && m[1] === env.TG_TOKEN);
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
  const sig = await sha256Hex(`${rnd}:${env.PASSWORD || ""}:dash`);
  return `${rnd}.${sig}`;
}

async function verifySessionToken(token, env) {
  if (!token || !env.PASSWORD) return false;
  const i = token.lastIndexOf(".");
  if (i < 0) return false;
  const rnd = token.slice(0, i);
  const sig = token.slice(i + 1);
  return sig === (await sha256Hex(`${rnd}:${env.PASSWORD}:dash`)) && rnd.length >= 32;
}

function sessionCookie(token, maxAge = SESSION_TTL) {
  return `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

async function requireDash(req, env) {
  if (!env.PASSWORD) return true;
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

  // 累积在线：若与上次上报间隔 ≤ ONLINE_GAP_SEC，则把间隔计入 online_sec
  const prev = await env.DB.prepare(
    `SELECT last_ts, online_sec FROM machines WHERE machine_id = ?`
  ).bind(mid).first();
  let online_sec = prev ? (Number(prev.online_sec) || 0) : 0;
  if (prev && prev.last_ts != null) {
    const gap = ts - Number(prev.last_ts);
    if (gap > 0 && gap <= ONLINE_GAP_SEC) {
      online_sec += gap;
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

  // 节流写历史（5 分钟窗口）
  const last = await env.DB.prepare(
    `SELECT ts FROM snapshots WHERE machine_id = ? ORDER BY ts DESC LIMIT 1`
  ).bind(mid).first();
  if (!last || ts - Number(last.ts) >= 300) {
    await env.DB.prepare(
      `INSERT INTO snapshots (machine_id, ts, today_rx, today_tx, month_rx, month_tx)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(mid, ts, Number(today.rx) || 0, Number(today.tx) || 0,
      Number(month.rx) || 0, Number(month.tx) || 0).run();
  }

  // 清理 90 天前
  await env.DB.prepare(`DELETE FROM snapshots WHERE ts < ?`).bind(now - 90 * 86400).run();
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

/** 日/月聚合：单机 mid 或全部（mid 空）。
 *  day:  每天取各机最后一条 snapshot 的 today_rx/tx，再按日求和
 *  month: 每月取各机最后一条 snapshot 的 month_rx/tx，再按月求和
 */
async function getHistoryAgg(env, { mid, mode, span }) {
  const isMonth = mode === "month";
  const n = Math.min(isMonth ? 24 : 90, Math.max(1, Number(span) || (isMonth ? 6 : 14)));
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
    const d = new Date(Number(r.ts) * 1000);
    const bucket = isMonth
      ? (d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0"))
      : (d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0"));
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

  // 补齐时间轴空桶
  const labels = [];
  if (isMonth) {
    const base = new Date();
    base.setDate(1);
    base.setHours(0, 0, 0, 0);
    for (let i = n - 1; i >= 0; i--) {
      const d = new Date(base);
      d.setMonth(d.getMonth() - i);
      labels.push(d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0"));
    }
  } else {
    const base = new Date();
    base.setHours(0, 0, 0, 0);
    for (let i = n - 1; i >= 0; i--) {
      const d = new Date(base);
      d.setDate(d.getDate() - i);
      labels.push(d.getFullYear() + "-" + String(d.getMonth() + 1).padStart(2, "0") + "-" + String(d.getDate()).padStart(2, "0"));
    }
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
  const envToken = env.TG_BOT_TOKEN || env.BOT_TOKEN || env.TELEGRAM_BOT_TOKEN || "";
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

async function saveConfig(env, data) {
  if (!env.DB) throw new Error(missingDbError(env));
  const now = Math.floor(Date.now() / 1000);
  const normalized = {
    t_token: data.t_token !== undefined ? String(data.t_token).trim() : undefined,
    t_id: data.t_id !== undefined ? String(data.t_id).trim() : undefined,
    t_time: data.t_time !== undefined ? (String(data.t_time).trim() || "20:00:00") : undefined,
    cf_time: data.cf_time !== undefined ? (String(data.cf_time).trim() || "0 * * * *") : undefined,
  };
  const keys = ["t_token", "t_id", "t_time", "cf_time"];
  const stmts = keys.filter(k => normalized[k] !== undefined).map(k =>
    env.DB.prepare(
      `INSERT INTO config (key, value, updated_at) VALUES (?, ?, ?)
       ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`
    ).bind(k, normalized[k], now)
  );
  if (stmts.length) await env.DB.batch(stmts);
}

// ─── VPS Token 管理 ───

async function getOrCreateVpsToken(env, mid) {
  if (!env.DB) throw new Error(missingDbError(env));
  const existing = await env.DB.prepare(
    `SELECT token FROM vps_tokens WHERE machine_id = ?`
  ).bind(mid).first();
  if (existing) return existing.token;

  // 生成 32 字节 hex token
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  const token = Array.from(buf).map(b => b.toString(16).padStart(2, "0")).join("");

  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO vps_tokens (machine_id, token, created_at) VALUES (?, ?, ?)`
  ).bind(mid, token, now).run();
  return token;
}

async function verifyVpsToken(env, mid, token) {
  const row = await env.DB.prepare(
    `SELECT token FROM vps_tokens WHERE machine_id = ?`
  ).bind(mid).first();
  if (!row) return false;
  return row.token === token;
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

function buildInstallCommand(mid, vpsToken, cf_url, cf_time) {
  const midQ = bashSingleQuote(mid);
  const timeQ = bashSingleQuote(cf_time || "0 * * * *");
  return [
    "m_id='" + midQ + "' \\",
    "cf_token='" + vpsToken + "' \\",
    "cf_url='" + cf_url + "' \\",
    "cf_time='" + timeQ + "' \\",
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
  const cmd = buildInstallCommand(mid, vpsToken, cf_url, cf_time);

  return {
    ok: true,
    command: cmd,
    machine_id: mid,
    token: vpsToken.slice(0, 8) + "...", // 只展示前缀
  };
}


/**
 * 更新注册：复用/编辑参数后生成安装升级命令
 * body: { machine_id, cf_token?, cf_url?, cf_time?, rotate_token? }
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

  let vpsToken;
  try {
    if (body && body.rotate_token) {
      vpsToken = await rotateVpsToken(env, mid);
    } else {
      const provided = String((body && body.cf_token) || "").trim();
      const existing = await getVpsTokenFull(env, mid);
      if (provided) {
        if (!/^[A-Za-z0-9._~+/-]{8,256}$/.test(provided)) {
          return { ok: false, error: "cf_token 格式无效" };
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

  const cmd = buildInstallCommand(mid, vpsToken, cf_url, cf_time);
  return {
    ok: true,
    command: cmd,
    machine_id: mid,
    cf_url,
    cf_time,
    token: vpsToken,
    token_preview: vpsToken.slice(0, 8) + "...",
  };
}

/** 看板「更新注册」弹窗预填 */
async function getMachineReg(env, request, mid) {
  if (!isValidMachineId(mid)) {
    return { ok: false, error: "机器 ID 无效" };
  }
  if (!env.DB) return { ok: false, error: missingDbError(env) };
  const row = await env.DB.prepare(
    `SELECT machine_id, hostname, interface, last_ts FROM machines WHERE machine_id = ?`,
  ).bind(mid).first();
  const cfg = await getConfig(env);
  const url = new URL(request.url);
  let token = await getVpsTokenFull(env, mid);
  if (!token) token = await getOrCreateVpsToken(env, mid);
  return {
    ok: true,
    machine_id: mid,
    hostname: (row && row.hostname) || "",
    interface: (row && row.interface) || "",
    last_ts: (row && row.last_ts) || 0,
    exists: !!row,
    cf_token: token,
    cf_url: url.origin + "/api/report",
    cf_time: cfg.cf_time || "0 * * * *",
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
    `SELECT m.machine_id, m.callback_url, t.token
     FROM machines m
     LEFT JOIN vps_tokens t ON t.machine_id = m.machine_id
     ORDER BY m.last_ts DESC`,
  ).all();
  const rows = results || [];
  const targets = [];
  const skipped = [];
  for (const r of rows) {
    const mid = r.machine_id;
    const cb = (r.callback_url || "").trim();
    const token = (r.token || "").trim();
    if (!isValidCallbackUrl(cb)) {
      skipped.push({ machine_id: mid, reason: "no_callback_url" });
      continue;
    }
    if (!token) {
      skipped.push({ machine_id: mid, reason: "no_token" });
      continue;
    }
    targets.push({ machine_id: mid, callback_url: cb, token });
  }

  const resultsPush = [];
  const concurrency = 10;
  for (let i = 0; i < targets.length; i += concurrency) {
    const chunk = targets.slice(i, i + concurrency);
    const part = await Promise.all(chunk.map(async (t) => {
      const r = await pushForceToCallback(t.callback_url, t.token, force_at);
      return { machine_id: t.machine_id, callback_url: t.callback_url, ...r };
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

  const machines = await listMachines(env);
  if (!machines.length) {
    return { ok: false, error: "暂无机器数据" };
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

  // 每台机器单行
  const lines = machines.slice(0, 20).map(m => {
    const online = m.ts && (Date.now() / 1000 - m.ts) < 7200 ? "●" : "○";
    const t = m.today || {};
    const mo = m.month || {};
    return `${online} ${m.machine_id || "?"}  入${gb(t.rx)}/出${gb(t.tx)}  月${gb(mo.rx)}/出${gb(mo.tx)}`;
  }).join("\n");

  const more = machines.length > 20 ? `\n...及其他 ${machines.length - 20} 台` : "";

  const msg = `📊 流量汇总
━━━━━━━━━━━━━━━━━━━━
主机数：${machines.length} 台（在线 ${total.online}）
时间：${dateStr}

今日总计：入 ${gb(total.today_rx)} / 出 ${gb(total.today_tx)} / 合计 ${gb(total.today_rx + total.today_tx)}
本月总计：入 ${gb(total.month_rx)} / 出 ${gb(total.month_tx)} / 合计 ${gb(total.month_rx + total.month_tx)}
━━━━━━━━━━━━━━━━━━━━
${lines}${more}`;

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

function loginPage(err = "") {
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>登录 · 流量看板</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{color-scheme:dark}
body{margin:0;min-height:100vh;display:grid;place-items:center;font-family:"Noto Sans SC","Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;background:#0b1220;color:#e8eefc}
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

function dashboardPage() {
  return `<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>流量看板</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Noto+Sans+SC:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
<style>
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;font-family:"Noto Sans SC","Segoe UI","PingFang SC","Hiragino Sans GB","Microsoft YaHei",system-ui,sans-serif;background:#0b1220;color:#e8eefc}
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
      <span id="tgSumStatus" class="muted" style="font-size:12px;margin-left:4px"></span>
    </div>
    <div class="cards" id="summary"></div>
    <div class="panel">
      <div class="chart-title-row">
        <h2 id="chartPanelTitle">总流量统计</h2>
      </div>
      <div class="chart-toolbar">
        <div class="seg" id="modeSeg">
          <button type="button" class="active" data-mode="day" onclick="setChartMode('day')">日统计</button>
          <button type="button" data-mode="month" onclick="setChartMode('month')">月统计</button>
        </div>
        <label class="chk"><input type="checkbox" id="chkRx" checked onchange="renderMainChart()"> 入站</label>
        <label class="chk"><input type="checkbox" id="chkTx" checked onchange="renderMainChart()"> 出站</label>
        <select id="range" onchange="loadHistory()"></select>
      </div>
      <div class="chart-wrap"><canvas id="chart"></canvas></div>
    </div>
    <div class="panel">
      <h2>机器列表</h2>
      <div style="overflow:auto">
        <table>
          <thead><tr>
            <th>机器</th><th>主机</th><th>网卡</th>
            <th>今日入/出</th><th>本月入/出</th><th>累积在线</th><th>最后上报</th><th>状态</th><th>操作</th>
          </tr></thead>
          <tbody id="tbody"><tr><td colspan="9">加载中…</td></tr></tbody>
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

      <label for="s_t_time">TG 汇报时间</label>
      <input id="s_t_time" type="text" placeholder="20:00:00">
      <div class="hint">留空默认 20:00:00</div>

      <label for="s_cf_time">CF 上报 cron（VPS 端默认）</label>
      <input id="s_cf_time" type="text" placeholder="0 * * * *">
      <div class="hint">留空默认 0 * * * *（每小时）</div>

      <div class="save-row">
        <button class="primary" onclick="saveConfig()">保存设置</button>
        <button type="button" onclick="switchTab('dash')">关闭</button>
        <span id="saveStatus" class="muted"></span>
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
    <label for="upToken">cf_token（注册密钥）</label>
    <input id="upToken" type="text" autocomplete="off" spellcheck="false">
    <label for="upUrl">cf_url</label>
    <input id="upUrl" type="text" autocomplete="off" spellcheck="false">
    <label for="upTime">cf_time（cron）</label>
    <input id="upTime" type="text" placeholder="0 * * * *" autocomplete="off">
    <label style="display:flex;align-items:center;gap:8px;margin:10px 0;cursor:pointer">
      <input id="upRotate" type="checkbox" style="width:auto;margin:0"> 轮换新密钥（旧 token 立即失效）
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
        <button type="button" class="active" data-mode="day" onclick="setHistMode('day')">日统计</button>
        <button type="button" data-mode="month" onclick="setHistMode('month')">月统计</button>
      </div>
      <label class="chk"><input type="checkbox" id="histChkRx" checked onchange="renderHistChart()"> 入站</label>
      <label class="chk"><input type="checkbox" id="histChkTx" checked onchange="renderHistChart()"> 出站</label>
      <select id="histRange" onchange="loadHistModal()"></select>
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
const fmtTime = (ts) => ts ? new Date(ts*1000).toLocaleString() : "-";
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
let histChart;
let chartMode = "day";       // day | month  （总览）
let histMode = "day";        // day | month  （单机弹窗）
let mainPoints = [];         // 总览聚合点
let histPoints = [];         // 单机聚合点
let histMid = null;

function switchTab(name) {
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  document.querySelectorAll(".nav a").forEach(a => a.classList.remove("active"));
  const pname = name[0].toUpperCase() + name.slice(1);
  document.getElementById("page" + pname).classList.add("active");
  document.getElementById("tab" + pname).classList.add("active");
  if (name === "settings") loadConfig();
  if (name === "dash") refresh();
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

function renderTable() {
  const tb = document.getElementById("tbody");
  tb.replaceChildren();
  if (!machines.length) {
    const tr = document.createElement("tr");
    const td = document.createElement("td");
    td.colSpan = 9;
    td.textContent = "暂无数据";
    tr.appendChild(td);
    tb.appendChild(tr);
    return;
  }
  for (const m of machines) {
    const tr = document.createElement("tr");
    if (m.machine_id === selected) tr.classList.add("active");
    tr.dataset.mid = m.machine_id || "";

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
      if (e.target.closest("button")) return;
      selected = m.machine_id;
      renderTable();
    });
    tb.appendChild(tr);
  }
}

function fillRangeOptions(sel, mode) {
  if (!sel) return;
  const cur = sel.value;
  const opts = mode === "month"
    ? [["3","近 3 月"],["6","近 6 月"],["12","近 12 月"]]
    : [["7","近 7 天"],["14","近 14 天"],["30","近 30 天"],["90","近 90 天"]];
  sel.replaceChildren();
  for (const [v, t] of opts) {
    const o = document.createElement("option");
    o.value = v; o.textContent = t;
    sel.appendChild(o);
  }
  const def = mode === "month" ? "6" : "14";
  sel.value = opts.some(x => x[0] === cur) ? cur : def;
}

function setChartMode(mode) {
  chartMode = mode === "month" ? "month" : "day";
  document.querySelectorAll("#modeSeg button").forEach(b => {
    b.classList.toggle("active", b.dataset.mode === chartMode);
  });
  fillRangeOptions(document.getElementById("range"), chartMode);
  loadHistory();
}

function setHistMode(mode) {
  histMode = mode === "month" ? "month" : "day";
  document.querySelectorAll("#histModeSeg button").forEach(b => {
    b.classList.toggle("active", b.dataset.mode === histMode);
  });
  fillRangeOptions(document.getElementById("histRange"), histMode);
  loadHistModal();
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
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: "index", intersect: false },
      datasets: { bar: { categoryPercentage: 0.65, barPercentage: 0.9, maxBarThickness: 36 } },
      scales: {
        x: {
          stacked: true,
          ticks: { maxTicksLimit: 14, color: "#8aa0c6", maxRotation: 0, autoSkip: true },
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
  if (chart) chart.destroy();
  const showRx = document.getElementById("chkRx").checked;
  const showTx = document.getElementById("chkTx").checked;
  chart = buildStackedChart(ctx, mainPoints, {
    showRx, showTx,
    title: "全部机器 · " + (chartMode === "month" ? "月累计" : "日累计"),
  });
}

function renderHistChart() {
  const ctx = document.getElementById("histChart");
  if (!ctx) return;
  if (histChart) histChart.destroy();
  const showRx = document.getElementById("histChkRx").checked;
  const showTx = document.getElementById("histChkTx").checked;
  histChart = buildStackedChart(ctx, histPoints, {
    showRx, showTx,
    title: (histMid || "") + " · " + (histMode === "month" ? "月累计" : "日累计"),
  });
}

async function loadHistory() {
  try {
    const span = document.getElementById("range").value || (chartMode === "month" ? "6" : "14");
    const q = "/api/history?mode=" + chartMode + "&span=" + encodeURIComponent(span);
    const data = await api(q);
    mainPoints = (data && data.points) || [];
    renderMainChart();
  } catch (e) {
    toast("加载统计失败：" + (e && e.message ? e.message : String(e)));
  }
}

function openHistModal(mid) {
  histMid = mid;
  histMode = chartMode;
  document.getElementById("histModalTitle").textContent = "流量统计 · " + mid;
  document.getElementById("histModalDesc").textContent = "该机器日/月累计；柱高=入站+出站，分色堆叠";
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
    const span = document.getElementById("histRange").value || (histMode === "month" ? "6" : "14");
    const q = "/api/history?mode=" + histMode + "&span=" + encodeURIComponent(span)
      + "&mid=" + encodeURIComponent(histMid);
    const data = await api(q);
    histPoints = (data && data.points) || [];
    renderHistChart();
  } catch (e) {
    toast("加载单机统计失败：" + (e && e.message ? e.message : String(e)));
  }
}

async function refresh() {
  try {
    const data = await api("/api/machines");
    machines = (data && data.machines) || [];
    if (selected && !machines.find(m => m.machine_id === selected)) selected = null;
    renderSummary();
    renderTable();
    await loadHistory();
  } catch (e) {
    toast("刷新失败：" + (e && e.message ? e.message : String(e)));
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
  document.getElementById("upToken").value = "加载中…";
  document.getElementById("upUrl").value = "";
  document.getElementById("upTime").value = "";
  document.getElementById("upRotate").checked = false;
  try {
    const data = await api("/api/machine-reg?mid=" + encodeURIComponent(mid));
    if (!data || !data.ok) {
      toast(data?.error || "加载注册信息失败");
      closeUpdateVps();
      return;
    }
    document.getElementById("upMid").value = data.machine_id || mid;
    document.getElementById("upToken").value = data.cf_token || "";
    document.getElementById("upUrl").value = data.cf_url || "";
    document.getElementById("upTime").value = data.cf_time || "0 * * * *";
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
  const cf_token = document.getElementById("upToken").value.trim();
  const cf_url = document.getElementById("upUrl").value.trim();
  const cf_time = document.getElementById("upTime").value.trim();
  const rotate_token = document.getElementById("upRotate").checked;
  if (!machine_id) { toast("请填写机器 ID"); return; }
  const btn = document.querySelector("#upBtnRegion .green");
  if (btn) { btn.disabled = true; btn.textContent = "生成中…"; }
  try {
    const data = await api("/api/generate-update", {
      method: "POST",
      body: JSON.stringify({ machine_id, cf_token, cf_url, cf_time, rotate_token }),
    });
    if (!data || !data.ok) {
      toast(data?.error || "生成失败");
      return;
    }
    document.getElementById("upOk").textContent = "✓ 更新命令已生成（密钥：" + (data.token_preview || "") + "）";
    document.getElementById("upCmd").textContent = data.command;
    document.getElementById("upToken").value = data.token || cf_token;
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
  const btn = document.querySelector("#vpsBtnRegion .green");
  if (btn) { btn.disabled = true; btn.textContent = "生成中…"; }
  try {
    const data = await api("/api/generate?mid=" + encodeURIComponent(mid));
    if (!data || !data.ok) { toast(data?.error || "生成失败"); return; }
    document.getElementById("vpsOk").textContent = "✓ 命令已生成（独立密码： " + (data.token||"") + "）";
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

fillRangeOptions(document.getElementById("range"), chartMode);
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

      // 优先用 TG_TOKEN（全局密码），其次校验每台 VPS 独立密码
      if (!reportAuth(req, env)) {
        const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
        if (!token || !(await verifyVpsToken(env, mid, token))) {
          return json({ ok: false, error: "unauthorized" }, 401);
        }
      }

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
        if (!env.PASSWORD) return Response.redirect(new URL("/", url).toString(), 302);
        if (pw !== env.PASSWORD) return html(loginPage("密码错误"), 401);
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
      const token = (req.headers.get("authorization") || "").replace(/^Bearer\s+/i, "");
      const okGlobal = reportAuth(req, env);
      if (!okGlobal) {
        if (!token || !(await verifyVpsToken(env, mid, token))) {
          return json({ ok: false, error: "unauthorized" }, 401);
        }
      }
      const force_report = await agentShouldForceReport(env, mid);
      return json({ ok: true, force_report, machine_id: mid });
    }

    // 以下需登录
    if (!(await requireDash(req, env))) {
      if (url.pathname.startsWith("/api/")) return json({ ok: false, error: "unauthorized" }, 401);
      return Response.redirect(new URL("/login", url).toString(), 302);
    }

    // GET /api/machines
    if (req.method === "GET" && url.pathname === "/api/machines") {
      if (!env.DB) return json({ ok: true, machines: [] });
      return json({ ok: true, machines: await listMachines(env) });
    }

    // GET /api/history — mode=day|month, span=天数/月数, mid 可选（空=全部合计）
    if (req.method === "GET" && url.pathname === "/api/history") {
      if (!env.DB) return json({ ok: true, points: [] });
      const mid = String(url.searchParams.get("mid") || "").trim();
      const mode = String(url.searchParams.get("mode") || "day").toLowerCase() === "month" ? "month" : "day";
      const span = Number(url.searchParams.get("span") || url.searchParams.get("hours") || (mode === "month" ? 6 : 14));
      if (mid && !isValidMachineId(mid)) return json({ ok: false, error: "mid invalid" }, 400);
      // 兼容旧 hours 参数：有 mid 且无 mode 时仍可返回原始点
      if (mid && url.searchParams.has("hours") && !url.searchParams.has("mode") && !url.searchParams.has("span")) {
        const hours = Math.min(24 * 90, Math.max(1, Number(url.searchParams.get("hours") || 168)));
        return json({ ok: true, machine_id: mid, hours, points: await getHistory(env, mid, hours) });
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

    // GET /api/machine-reg — 更新注册弹窗预填（含完整 token）
    if (req.method === "GET" && url.pathname === "/api/machine-reg") {
      const mid = String(url.searchParams.get("mid") || "").trim();
      try {
        if (!env.DB) return json({ ok: false, error: missingDbError(env) }, 500);
        const result = await getMachineReg(env, req, mid);
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
};
