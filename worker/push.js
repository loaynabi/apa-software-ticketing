// Desktop / phone notifications via standard Web Push (RFC 8030 + VAPID RFC 8292 + aes128gcm RFC 8291).
// Free, no third-party service: the browser's own push service (Google, Mozilla, Microsoft, Apple) delivers it.
// Keys: "push:vapid" (this app's signing key pair, made on first use), "push:sub:<uid>" (up to 5 devices per person).
import { requireUser } from "./auth.js";
import { appendAudit } from "./kv.js";
import { json, fail, readBody } from "./util.js";

const enc = new TextEncoder();
const b64u = (buf) => { let s = ""; for (const b of new Uint8Array(buf)) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); };
const ub64 = (s) => { s = String(s).replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; return Uint8Array.from(atob(s), (c) => c.charCodeAt(0)); };
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
// Only real browser push services -- the Worker never POSTs to an address a user made up.
const PUSH_HOSTS = /^(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|[a-z0-9-]+\.notify\.windows\.com|web\.push\.apple\.com|[a-z0-9.-]+\.push\.apple\.com)$/i;

async function vapidKeys(env) {
  let k = await env.KV.get("push:vapid", "json");
  if (k) return k;
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  k = { jwk: await crypto.subtle.exportKey("jwk", pair.privateKey), pub: b64u(await crypto.subtle.exportKey("raw", pair.publicKey)) };
  await env.KV.put("push:vapid", JSON.stringify(k));
  return k;
}

async function vapidHeader(endpoint, k, sub) {
  const h = b64u(enc.encode(JSON.stringify({ typ: "JWT", alg: "ES256" })));
  const p = b64u(enc.encode(JSON.stringify({ aud: new URL(endpoint).origin, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub })));
  const key = await crypto.subtle.importKey("jwk", k.jwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(h + "." + p));
  return `vapid t=${h}.${p}.${b64u(sig)}, k=${k.pub}`;
}

async function hkdf(salt, ikm, info, len) {
  const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: "SHA-256", salt, info }, key, len * 8));
}

async function encrypt(sub, payload) {
  const uaPub = ub64(sub.keys.p256dh), auth = ub64(sub.keys.auth);
  const eph = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const asPub = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const uaKey = await crypto.subtle.importKey("raw", uaPub, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: uaKey }, eph.privateKey, 256));
  const ikm = await hkdf(auth, secret, cat(enc.encode("WebPush: info\0"), uaPub, asPub), 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const cek = await hkdf(salt, ikm, enc.encode("Content-Encoding: aes128gcm\0"), 16);
  const nonce = await hkdf(salt, ikm, enc.encode("Content-Encoding: nonce\0"), 12);
  const aes = await crypto.subtle.importKey("raw", cek, "AES-GCM", false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, aes, cat(enc.encode(payload), new Uint8Array([2]))));
  return cat(salt, new Uint8Array([0, 0, 16, 0]), new Uint8Array([asPub.length]), asPub, ct);
}

// msg: {title, body, url, tag, urgent}. Devices whose subscription has expired (404/410) are dropped.
export async function notify(env, uids, msg, origin) {
  uids = [...new Set((uids || []).filter(Boolean))];
  if (!uids.length) return;
  const k = await vapidKeys(env), payload = JSON.stringify(msg);
  for (const uid of uids) {
    const key = "push:sub:" + uid, subs = (await env.KV.get(key, "json")) || [];
    if (!subs.length) continue;
    const keep = [];
    for (const s of subs) {
      try {
        const r = await fetch(s.endpoint, { method: "POST", body: await encrypt(s, payload), headers: {
          Authorization: await vapidHeader(s.endpoint, k, origin), "Content-Encoding": "aes128gcm",
          "Content-Type": "application/octet-stream", TTL: "86400", Urgency: msg.urgent ? "high" : "normal" } });
        if (r.status !== 404 && r.status !== 410) keep.push(s);
      } catch (e) { keep.push(s); }
    }
    if (keep.length !== subs.length) await env.KV.put(key, JSON.stringify(keep));
  }
}

export async function handlePush(req, env, p) {
  const { me } = await requireUser(req, env);
  if (p === "/api/push/key" && req.method === "GET") return json({ key: (await vapidKeys(env)).pub });
  if (req.method !== "POST") fail(405, "Method not allowed.");
  const b = await readBody(req, 4096);
  const key = "push:sub:" + me.id, subs = (await env.KV.get(key, "json")) || [];
  const ep = String(b.endpoint || "");
  let host = "";
  try { const u = new URL(ep); if (u.protocol === "https:") host = u.hostname; } catch (e) { /* invalid */ }
  if (p === "/api/push/subscribe") {
    const keys = b.keys || {};
    if (!PUSH_HOSTS.test(host) || !keys.p256dh || !keys.auth) fail(422, "This browser's notification service is not supported.");
    const known = subs.some((x) => x.endpoint === ep);
    const next = [{ endpoint: ep, keys: { p256dh: String(keys.p256dh).slice(0, 200), auth: String(keys.auth).slice(0, 100) } },
      ...subs.filter((x) => x.endpoint !== ep)].slice(0, 5);
    await env.KV.put(key, JSON.stringify(next));
    if (!known) await appendAudit(env, { actor: me.name, action: "push.on", detail: `Notifications turned on by ${me.name} on a device using ${host}` });
    return json({ ok: true });
  }
  if (p === "/api/push/unsubscribe") {
    const next = subs.filter((x) => x.endpoint !== ep);
    if (next.length !== subs.length) {
      await env.KV.put(key, JSON.stringify(next));
      await appendAudit(env, { actor: me.name, action: "push.off", detail: `Notifications turned off by ${me.name} on a device using ${host || "unknown service"}` });
    }
    return json({ ok: true });
  }
  if (p === "/api/push/test") {
    await notify(env, [me.id], { title: "Notifications are working", body: "You will get a pop-up like this when your tickets change.", url: "/", tag: "test" }, new URL(req.url).origin);
    return json({ ok: true });
  }
  fail(404, "Not found.");
}

// Service worker (served at /sw.js): shows the pop-up and opens the ticket when it is clicked.
export const SW = [
  "self.addEventListener('install', function () { self.skipWaiting(); });",
  "self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });",
  "self.addEventListener('push', function (e) {",
  "  var d = {}; try { d = e.data ? e.data.json() : {}; } catch (x) {}",
  "  e.waitUntil(self.registration.showNotification(d.title || 'APA Software Ticketing', { body: d.body || '', tag: d.tag || undefined, renotify: !!d.tag, requireInteraction: !!d.urgent, data: { url: d.url || '/' } }));",
  "});",
  "self.addEventListener('notificationclick', function (e) {",
  "  e.notification.close();",
  "  var url = new URL((e.notification.data && e.notification.data.url) || '/', self.location.origin).href;",
  "  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(function (list) {",
  "    for (var i = 0; i < list.length; i++) { if (list[i].url.indexOf(self.location.origin) === 0) { list[i].postMessage({ openUrl: url }); return list[i].focus(); } }",
  "    return self.clients.openWindow(url);",
  "  }));",
  "});",
].join("\n");

export const MANIFEST = JSON.stringify({ name: "APA Software Ticketing", short_name: "APA Tickets", start_url: "/", scope: "/",
  display: "standalone", background_color: "#050912", theme_color: "#050912",
  icons: [{ src: "/icon-192.png", sizes: "192x192", type: "image/png", purpose: "any" }] });
