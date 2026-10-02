// Workers KV access. One binding (KV). Keys: users, tickets, audit (JSON), att:<ticket>:<att> (binary), lockout:*.
// Free tier = 1,000 writes/day, so every handler does at most one data write + one audit write.
// (Ticket numbers come from max(number)+1 over the tickets array - tickets are only ever soft-deleted,
// so numbers are never reused and no separate counter write is needed.)
import { clip } from "./util.js";

export const readJson = async (env, key, fallback = []) => (await env.KV.get(key, "json")) ?? fallback;
export const writeJson = (env, key, v) => env.KV.put(key, JSON.stringify(v));
export const readTickets = (env) => readJson(env, "tickets");
export const writeTickets = (env, t) => writeJson(env, "tickets", t);
export const attKey = (tid, aid) => "att:" + tid + ":" + aid;

export const readAuditRaw = async (env) => (await env.KV.get("audit", "text")) || "[]";

// The audit log is a compact JSON array. Appending is done by string splicing (no JSON.parse of
// the whole log), which keeps CPU low on the free plan's 10 ms budget. The log is trimmed to the
// newest 5,000 entries once it grows 500 past that (so it holds 5,000-5,500 entries).
const AUDIT_CAP = 5000, AUDIT_SLACK = 500, MARK = '{"ts":';
function countEntries(raw) { let n = 0, i = -1; while ((i = raw.indexOf(MARK, i + 1)) !== -1) n++; return n; }

// entries: {actor, action, detail}. Returns the stamped entries that were stored.
export async function appendAudit(env, ...entries) {
  const ts = new Date().toISOString();
  const stamped = entries.map((e) => ({ ts, actor: e.actor, action: e.action, detail: clip(e.detail, 700) }));
  const add = stamped.map((e) => JSON.stringify(e)).join(",");
  const raw = ((await env.KV.get("audit", "text")) || "[]").trim();
  let out = raw.endsWith("]") && raw.length > 2 ? raw.slice(0, -1) + "," + add + "]" : "[" + add + "]";
  if (countEntries(out) > AUDIT_CAP + AUDIT_SLACK) out = JSON.stringify(JSON.parse(out).slice(-AUDIT_CAP));
  await env.KV.put("audit", out);
  return stamped;
}
