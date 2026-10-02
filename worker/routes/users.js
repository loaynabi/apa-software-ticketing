// User management. Admins manage accounts; executives may only view the list (server-enforced).
// Company-domain emails only; never returns hashes or salts.
// Actions: create | update (name/email/role) | reset_password | deactivate | reactivate.
import { writeJson, readTickets, writeTickets, appendAudit } from "../kv.js";
import { requireUser, hashPassword } from "../auth.js";
import { json, fail, readBody, clean, rid, roleOf, isCompanyEmail, DOMAIN_ERROR, weakPassword, pubUser } from "../util.js";

const activeAdmins = (list) => list.filter((u) => u.active !== false && u.role === "admin").length;
const who = (u) => `${u.name} (${u.email})`;

export async function handleUsers(req, env) {
  const get = req.method === "GET";
  const { me, users } = await requireUser(req, env, get ? { staff: true } : { admin: true });
  const list = () => users.map(pubUser);
  if (get) return json({ users: list() });

  const b = await readBody(req, 8192);
  const action = b.action;
  const now = new Date().toISOString();
  let detail = "", touchTickets = null;

  if (action === "create") {
    const name = clean(b.name, 80), email = String(b.email || "").trim().toLowerCase(), role = roleOf(b.role);
    if (name.length < 2) fail(422, "Full name is required.");
    if (!isCompanyEmail(email)) fail(422, DOMAIN_ERROR);
    if (users.some((u) => u.email === email)) fail(409, "An account with that email already exists.");
    const weak = weakPassword(b.password);
    if (weak) fail(422, weak);
    const { hash, salt } = await hashPassword(b.password);
    users.push({ id: "u_" + rid(5), name, email, role, passwordHash: hash, salt, active: true, initialPassword: true, createdAt: now });
    detail = `Account created for ${name} (${email}), role ${role}`;
  } else {
    const u = users.find((x) => x.id === b.id);
    if (!u) fail(404, "User not found.");
    const self = u.id === me.id;
    if (action === "update") {
      const ch = [];
      const name = b.name === undefined ? u.name : clean(b.name, 80);
      const email = b.email === undefined ? u.email : String(b.email).trim().toLowerCase();
      const role = b.role === undefined ? u.role : roleOf(b.role);
      if (name.length < 2) fail(422, "Full name is required.");
      if (!isCompanyEmail(email)) fail(422, DOMAIN_ERROR);
      if (email !== u.email && users.some((x) => x.email === email)) fail(409, "An account with that email already exists.");
      if (role !== u.role && u.role === "admin" && (self || activeAdmins(users) <= 1))
        fail(409, self ? "You cannot remove your own admin role. Ask another admin." : "There must be at least one active admin.");
      if (name !== u.name) ch.push(`name "${u.name}" -> "${name}"`);
      if (email !== u.email) ch.push(`email "${u.email}" -> "${email}"`);
      if (role !== u.role) ch.push(`role "${u.role}" -> "${role}"`);
      if (!ch.length) return json({ ok: true, unchanged: true, users: list() });
      detail = `Account ${who(u)}: ${ch.join("; ")}`;
      if (name !== u.name || email !== u.email) touchTickets = { id: u.id, name, email }; // keep tickets in sync
      u.name = name; u.email = email; u.role = role;
    } else if (action === "reset_password") {
      const weak = weakPassword(b.password);
      if (weak) fail(422, weak);
      const { hash, salt } = await hashPassword(b.password);
      u.passwordHash = hash; u.salt = salt; u.initialPassword = !self; // the admin knows it, so nudge the user to change it
      detail = `Password reset for ${who(u)} (new password not logged); their existing sessions ended`;
    } else if (action === "deactivate") {
      if (self) fail(409, "You cannot deactivate your own account.");
      if (u.active === false) return json({ ok: true, unchanged: true, users: list() });
      if (u.role === "admin" && activeAdmins(users) <= 1) fail(409, "There must be at least one active admin.");
      u.active = false;
      detail = `Account deactivated: ${who(u)}, role ${u.role} (sessions end immediately)`;
    } else if (action === "reactivate") {
      if (u.active !== false) return json({ ok: true, unchanged: true, users: list() });
      u.active = true;
      detail = `Account reactivated: ${who(u)}, role ${u.role}`;
    } else fail(400, "Unknown action.");
  }

  await writeJson(env, "users", users);
  if (touchTickets) {
    const tickets = await readTickets(env);
    let changed = false;
    for (const t of tickets) {
      if (t.assigneeId === touchTickets.id && t.assignee !== touchTickets.name) { t.assignee = touchTickets.name; changed = true; }
      if (t.requester.uid === touchTickets.id && (t.requester.name !== touchTickets.name || t.requester.email !== touchTickets.email)) {
        t.requester.name = touchTickets.name; t.requester.email = touchTickets.email; changed = true;
      }
    }
    if (changed) await writeTickets(env, tickets);
  }
  const audit = await appendAudit(env, { actor: me.name, action: "user." + action, detail });
  return json({ ok: true, users: list(), audit });
}
