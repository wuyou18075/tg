/**
 * 最小 Cloudflare Worker 示例：接收多机流量上报并列表展示。
 * 部署：wrangler deploy / 控制台粘贴。
 * 密钥：wrangler secret put REPORT_TOKEN
 * 绑定：KV 命名空间 TRAFFIC_KV（可选，也可用内存仅演示）
 *
 * 路由：
 *   POST /api/report  — agent 上报
 *   GET  /api/machines — 机器列表 JSON
 *   GET  /            — 简易 HTML 看板
 */

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });

function auth(req, env) {
  const h = req.headers.get("authorization") || "";
  const m = /^Bearer\s+(.+)$/i.exec(h);
  return m && m[1] === env.REPORT_TOKEN;
}

function gb(n) {
  const v = Number(n) || 0;
  return (v / 1e9).toFixed(3) + "GB";
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);

    if (req.method === "POST" && url.pathname === "/api/report") {
      if (!auth(req, env)) return json({ ok: false, error: "unauthorized" }, 401);
      let body;
      try {
        body = await req.json();
      } catch {
        return json({ ok: false, error: "invalid json" }, 400);
      }
      const mid = body.machine_id || req.headers.get("x-machine-id");
      if (!mid) return json({ ok: false, error: "machine_id required" }, 400);

      const rec = {
        ...body,
        machine_id: mid,
        received_at: Math.floor(Date.now() / 1000),
      };

      if (env.TRAFFIC_KV) {
        await env.TRAFFIC_KV.put(`machine:${mid}`, JSON.stringify(rec));
        // 维护机器 ID 集合
        const idsRaw = (await env.TRAFFIC_KV.get("machines:index")) || "[]";
        const ids = new Set(JSON.parse(idsRaw));
        ids.add(mid);
        await env.TRAFFIC_KV.put("machines:index", JSON.stringify([...ids]));
      }

      return json({ ok: true });
    }

    if (req.method === "GET" && url.pathname === "/api/machines") {
      if (!env.TRAFFIC_KV) return json({ ok: true, machines: [] });
      const ids = JSON.parse((await env.TRAFFIC_KV.get("machines:index")) || "[]");
      const machines = [];
      for (const id of ids) {
        const raw = await env.TRAFFIC_KV.get(`machine:${id}`);
        if (raw) machines.push(JSON.parse(raw));
      }
      machines.sort((a, b) => (b.ts || 0) - (a.ts || 0));
      return json({ ok: true, machines });
    }

    if (req.method === "GET" && url.pathname === "/") {
      let machines = [];
      if (env.TRAFFIC_KV) {
        const ids = JSON.parse((await env.TRAFFIC_KV.get("machines:index")) || "[]");
        for (const id of ids) {
          const raw = await env.TRAFFIC_KV.get(`machine:${id}`);
          if (raw) machines.push(JSON.parse(raw));
        }
      }
      machines.sort((a, b) => (b.ts || 0) - (a.ts || 0));
      const rows = machines
        .map((m) => {
          const t = m.today || {};
          const mo = m.month || {};
          const last = m.ts ? new Date(m.ts * 1000).toISOString() : "-";
          return `<tr>
            <td>${m.machine_id || ""}</td>
            <td>${m.hostname || ""}</td>
            <td>${m.interface || ""}</td>
            <td>${gb(t.rx)} / ${gb(t.tx)}</td>
            <td>${gb(mo.rx)} / ${gb(mo.tx)}</td>
            <td>${last}</td>
          </tr>`;
        })
        .join("");
      const html = `<!doctype html><html lang="zh-CN"><meta charset="utf-8">
<title>流量看板</title>
<style>
body{font-family:system-ui,sans-serif;margin:24px;background:#0b1220;color:#e8eefc}
table{border-collapse:collapse;width:100%;max-width:1100px}
th,td{border-bottom:1px solid #243049;padding:10px 12px;text-align:left}
th{color:#9fb3d9;font-weight:600}
h1{font-size:20px}
.muted{color:#8aa0c6;font-size:13px}
</style>
<h1>流量看板</h1>
<p class="muted">数据来自各机 agent 主动上报 · 刷新页面查看最新</p>
<table>
<thead><tr><th>机器</th><th>主机名</th><th>网卡</th><th>今日 入/出</th><th>本月 入/出</th><th>最后上报(UTC)</th></tr></thead>
<tbody>${rows || '<tr><td colspan="6">暂无数据</td></tr>'}</tbody>
</table>`;
      return new Response(html, { headers: { "content-type": "text/html; charset=utf-8" } });
    }

    return json({ ok: false, error: "not found" }, 404);
  },
};
