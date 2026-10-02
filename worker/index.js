// APA Software Ticketing - single Cloudflare Worker: serves the app page at "/" and every /api/* route.
// Security layers:
//  1. Only "/" (the app page) and /api/* exist; everything else is 404.
//  2. Every response carries CSP / no-framing / no-sniff / HSTS / no-referrer headers; API responses are no-store.
//  3. State-changing calls must come from this site (Origin / Sec-Fetch-Site check) on top of SameSite=Strict.
//  4. Sign-in locks out after repeated failures (routes/auth-routes.js).
//  5. Role checks are enforced in each route (auth.js requireUser), not just in the UI.
import HTML from "../src/index.html";
import { secure } from "./security.js";
import { handlePush, SW, MANIFEST } from "./push.js";
import { TicketChat, handleLive } from "./chat.js";
import { ICON192, FAV64 } from "./assets.js";

export { TicketChat };   // the Durable Object class must be exported from the main module
const png = (b64) => Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
const ICONS = { "/icon-192.png": png(ICON192), "/favicon.png": png(FAV64) };
import { HttpError, json } from "./util.js";
import { handleLogin, handleLogout, handleMe, handlePassword } from "./routes/auth-routes.js";
import { handleUsers } from "./routes/users.js";
import { handleBootstrap, handleCreate, handleAction, handleUpload, handleAttachment, handleReportLog } from "./routes/tickets.js";

async function route(req, env, url) {
  const p = url.pathname, m = req.method;
  const write = m !== "GET" && m !== "HEAD";

  if (p === "/" && (m === "GET" || m === "HEAD")) {
    return new Response(HTML, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-cache" } });
  }
  if (p === "/sw.js" && m === "GET") return new Response(SW, { headers: { "Content-Type": "application/javascript; charset=utf-8", "Cache-Control": "no-cache" } });
  if (ICONS[p] && m === "GET") return new Response(ICONS[p], { headers: { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" } });
  if (p === "/manifest.webmanifest" && m === "GET") return new Response(MANIFEST, { headers: { "Content-Type": "application/manifest+json" } });
  if (!p.startsWith("/api/")) return new Response("Not found", { status: 404, headers: { "Content-Type": "text/plain" } });

  if (write) {
    const origin = req.headers.get("Origin"), site = req.headers.get("Sec-Fetch-Site");
    if ((origin && origin !== url.origin) || (site && site !== "same-origin" && site !== "none"))
      return json({ error: "Cross-site request blocked." }, 403);
  }

  let r;
  if (p === "/api/login" && m === "POST") return handleLogin(req, env);
  if (p === "/api/logout" && m === "POST") return handleLogout(req, env);
  if (p === "/api/me" && m === "GET") return handleMe(req, env);
  if (p === "/api/me/password" && m === "POST") return handlePassword(req, env);
  if (p === "/api/bootstrap" && m === "GET") return handleBootstrap(req, env, url);
  if (p === "/api/tickets" && m === "POST") return handleCreate(req, env);
  if (p === "/api/users" && (m === "GET" || m === "POST")) return handleUsers(req, env);
  if (p.startsWith("/api/push/")) return handlePush(req, env, p);
  if (p === "/api/report" && m === "POST") return handleReportLog(req, env);
  if ((r = p.match(/^\/api\/tickets\/([\w-]{1,40})\/live$/)) && m === "GET") return handleLive(req, env, r[1], url);
  if ((r = p.match(/^\/api\/tickets\/([\w-]{1,40})$/)) && m === "POST") return handleAction(req, env, r[1]);
  if ((r = p.match(/^\/api\/tickets\/([\w-]{1,40})\/attachments$/)) && m === "POST") return handleUpload(req, env, r[1], url);
  if ((r = p.match(/^\/api\/attachments\/([\w-]{1,40})\/([\w-]{1,40})$/)) && m === "GET") return handleAttachment(req, env, r[1], r[2]);
  return json({ error: "Not found." }, 404);
}

export default {
  async fetch(req, env, ctx) {
    env = { ...env, ctx };   // routes hand slow work (notifications) to ctx.waitUntil
    const url = new URL(req.url);
    let resp;
    try {
      resp = await route(req, env, url);
    } catch (e) {
      if (e instanceof HttpError) resp = json({ error: e.message, ...(e.extra || {}) }, e.status);
      else { console.error(e && e.stack || e); resp = json({ error: "Server error." }, 500); }
    }
    if (resp.status === 101) return resp;   // WebSocket handshake: must be passed through untouched
    return secure(resp, { api: url.pathname.startsWith("/api/") });
  },
};
