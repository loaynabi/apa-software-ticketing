// Live chat for a ticket: one Durable Object per ticket relays new messages, "typing..." and "seen" instantly
// over WebSockets. Messages themselves are still saved through the normal ticket API (KV + audit log), so if
// the live connection drops nothing is lost -- the app simply falls back to refresh + push notifications.
import { requireUser } from "./auth.js";
import { readTickets } from "./kv.js";
import { fail } from "./util.js";

export class TicketChat {
  constructor(ctx) { this.ctx = ctx; }

  async fetch(req) {
    const url = new URL(req.url);
    if (url.pathname === "/post" && req.method === "POST") { this.send(await req.json(), null); return new Response("ok"); }
    if (url.pathname === "/ws") {
      const [client, server] = Object.values(new WebSocketPair());
      this.ctx.acceptWebSocket(server);   // hibernatable: an idle chat costs nothing
      server.serializeAttachment({ uid: url.searchParams.get("uid"), name: url.searchParams.get("name"), role: url.searchParams.get("role") });
      server.send(JSON.stringify({ type: "hello", online: this.online(), seen: (await this.ctx.storage.get("seen")) || {} }));
      this.send({ type: "presence", online: this.online() }, server);
      return new Response(null, { status: 101, webSocket: client });
    }
    return new Response("Not found", { status: 404 });
  }

  online(skip) {
    const m = {};
    for (const ws of this.ctx.getWebSockets()) {
      if (ws === skip) continue;
      const a = ws.deserializeAttachment();
      if (a && a.uid) m[a.uid] = { uid: a.uid, name: a.name, role: a.role };
    }
    return Object.values(m);
  }

  // staffOnly messages (internal notes) never reach a requester's connection.
  send(msg, skip) {
    const s = JSON.stringify(msg);
    for (const ws of this.ctx.getWebSockets()) {
      if (ws === skip) continue;
      const a = ws.deserializeAttachment() || {};
      if (msg.staffOnly && a.role === "user") continue;
      try { ws.send(s); } catch (e) { /* closing */ }
    }
  }

  async webSocketMessage(ws, data) {
    let m;
    try { m = JSON.parse(data); } catch (e) { return; }
    const a = ws.deserializeAttachment() || {};
    if (m.type === "typing") this.send({ type: "typing", uid: a.uid, name: a.name, role: a.role, on: !!m.on }, ws);
    else if (m.type === "seen" && typeof m.at === "string") {
      const seen = (await this.ctx.storage.get("seen")) || {};
      if (!seen[a.uid] || seen[a.uid].at < m.at) {
        seen[a.uid] = { name: a.name, role: a.role, at: m.at.slice(0, 30) };
        await this.ctx.storage.put("seen", seen);
        this.send({ type: "seen", uid: a.uid, ...seen[a.uid] }, null);
      }
    }
  }

  webSocketClose(ws) { this.send({ type: "presence", online: this.online(ws) }, ws); try { ws.close(); } catch (e) { /* already closed */ } }
  webSocketError(ws) { this.webSocketClose(ws); }
}

// GET /api/tickets/:id/live -> WebSocket. Same visibility rules as the ticket itself.
export async function handleLive(req, env, id, url) {
  if ((req.headers.get("Upgrade") || "").toLowerCase() !== "websocket") fail(426, "Expected a WebSocket connection.");
  const origin = req.headers.get("Origin");
  if (origin && origin !== url.origin) fail(403, "Cross-site request blocked.");
  const { me } = await requireUser(req, env);
  const t = (await readTickets(env)).find((x) => x.id === id && !x.deleted);
  if (!t || (me.role === "user" && t.requester.uid !== me.id)) fail(404, "Ticket not found.");
  const u = new URL("https://chat/ws");
  u.searchParams.set("uid", me.id); u.searchParams.set("name", me.name); u.searchParams.set("role", me.role);
  return env.CHAT.get(env.CHAT.idFromName(id)).fetch(u.toString(), { headers: { Upgrade: "websocket" } });
}

export async function livePost(env, id, msg) {
  try { await env.CHAT.get(env.CHAT.idFromName(id)).fetch("https://chat/post", { method: "POST", body: JSON.stringify(msg) }); }
  catch (e) { /* live layer is best-effort */ }
}
