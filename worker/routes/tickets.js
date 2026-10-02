// Tickets, attachments, bootstrap. All permission checks happen here (server-side), never only in the UI.
//  - admin (ticket agents): everything.
//  - executive: sees everything (incl. internal notes) but is strictly read-only.
//  - user: only own tickets; may create, reply, attach, and reopen their own Done tickets (with a reason).
// Audit entries name the ticket (number + title) and spell out every old -> new value.
import { readTickets, writeTickets, appendAudit, readAuditRaw, attKey } from "../kv.js";
import { requireUser } from "../auth.js";
import { notify } from "../push.js";
import { livePost } from "../chat.js";

// Notifications go out after the response, so saving never waits on (or fails because of) a push service.
const later = (env, p) => { const q = p.catch(() => {}); if (env.ctx && env.ctx.waitUntil) env.ctx.waitUntil(q); };
const admins = (users, exceptId) => users.filter((u) => u.role === "admin" && u.active !== false && u.id !== exceptId).map((u) => u.id);
const tlink = (t) => "/#t=" + t.id;
import { json, fail, readBody, clean, clip, rid, pubUser } from "../util.js";
import { ATTACHMENT_CSP } from "../security.js";

const STATUSES = ["Not started", "In progress", "Waiting on requester", "Done"];
const DONE = "Done";
const PRIORITIES = ["Low", "Normal", "High", "Urgent"];
const SOFTWARE = { weave: "Weave", amd: "AMD", df: "DF", credentialing: "APA Credentialing Workspace", other: "Other" };
const CATEGORIES = {
  bug: "Bug / error message", login: "Can't log in / account access", data: "Wrong or missing data", slow: "Slow or not loading",
  reports: "Reports & exports", access: "Permissions / access to a feature", feature: "Feature request / improvement", other: "Other",
};
const MAX_ATT_BYTES = 5 * 1024 * 1024, MAX_ATT = 10, MAX_COMMENTS = 300, MAX_EVENTS = 300;
const tnum = (t) => "T-" + String(t.number).padStart(4, "0");
const label = (t) => `${tnum(t)} "${clip(t.title, 80)}"`;
const swName = (t) => (t.software === "other" ? `Other: ${t.softwareOther}` : SOFTWARE[t.software] || t.software);
const READONLY = "Executives have read-only access.";

// ---- due time: Urgent 4 hours; High 1, Normal 2, Low 5 business days (weekends judged in Pacific time) ----
const dayFmt = new Intl.DateTimeFormat("en-US", { timeZone: "America/Los_Angeles", weekday: "short" });
const isWeekend = (d) => { const w = dayFmt.format(d); return w === "Sat" || w === "Sun"; };
function dueFor(priority, createdAt) {
  const c = new Date(createdAt);
  if (priority === "Urgent") return new Date(c.getTime() + 4 * 3600e3).toISOString();
  let d = c, n = { High: 1, Normal: 2, Low: 5 }[priority] || 2;
  while (n > 0) { d = new Date(d.getTime() + 24 * 3600e3); if (!isWeekend(d)) n--; }
  return d.toISOString();
}

// What a caller may see: requesters never get internal notes/events or internal ids. cid is never sent.
function view(t, seeAll) {
  const { cid, ...r } = t;
  if (seeAll) return r;
  delete r.assigneeId;
  r.comments = t.comments.filter((c) => !c.internal);
  r.events = t.events.filter((e) => !e.internal);
  return r;
}
// Moving a ticket to Done stamps resolvedAt; moving it out of Done clears it and restarts the due clock.
function statusChange(t, s, now, why = "") {
  const from = t.status, wasDone = from === DONE;
  t.status = s;
  t.resolvedAt = s === DONE ? t.resolvedAt || now : "";
  let extra = "";
  if (wasDone && s !== DONE) { const due = dueFor(t.priority, now); extra = `; due ${t.dueAt} -> ${due}`; t.dueAt = due; }
  return `status "${from}" -> "${s}"${why}${extra}`;
}

const MIN_PROBLEM = 10;
const checkProblem = (v) => {
  const p = clean(v, 5000);
  if (p.length < MIN_PROBLEM) fail(422, `Please describe the problem (at least ${MIN_PROBLEM} characters).`);
  return p;
};

function parseSoftware(b, cur) { // -> {software, softwareOther}; throws 422 if invalid
  const software = b.software === undefined ? cur && cur.software : b.software;
  if (!SOFTWARE[software]) fail(422, "Choose which software the ticket is about.");
  const other = software === "other" ? clean(b.softwareOther === undefined && cur ? cur.softwareOther : b.softwareOther, 80) : "";
  if (software === "other" && !other) fail(422, "Please name the software.");
  return { software, softwareOther: other };
}

export async function handleBootstrap(req, env, url) {
  const { me, users } = await requireUser(req, env);
  const staff = me.role !== "user";
  const all = await readTickets(env);
  const body = {
    me: pubUser(me),
    tickets: all.filter((t) => !t.deleted && (staff || t.requester.uid === me.id)).map((t) => view(t, staff)),
    admins: users.filter((u) => u.active !== false && u.role === "admin").map((u) => ({ id: u.id, name: u.name })),
    serverTime: new Date().toISOString(),
  };
  if (!staff) return json(body);
  body.users = users.map(pubUser);
  let s = JSON.stringify(body);
  // The audit log is spliced in as raw JSON text (no parse/stringify of up to ~1 MB on the free plan).
  if (url.searchParams.get("audit") !== "0") s = s.slice(0, -1) + ',"audit":' + (await readAuditRaw(env)) + "}";
  return new Response(s, { headers: { "Content-Type": "application/json" } });
}

export async function handleCreate(req, env) {
  const { me, users } = await requireUser(req, env);
  if (me.role === "executive") fail(403, READONLY);
  const admin = me.role === "admin";
  const b = await readBody(req);
  const title = clean(b.title, 150);
  if (!title) fail(422, "A title is required.");
  const problem = checkProblem(b.problem);
  const steps = clean(b.steps, 3000);
  const category = b.category === undefined ? "other" : b.category;
  const priority = b.priority === undefined ? "Normal" : b.priority;
  if (!CATEGORIES[category]) fail(422, "Unknown category.");
  if (!PRIORITIES.includes(priority)) fail(422, "Priority must be Low, Normal, High or Urgent.");
  const { software, softwareOther } = parseSoftware(b);
  let requester = me, onBehalf = "";
  if (admin && b.requesterId && b.requesterId !== me.id) { // admins may file on behalf of a colleague
    requester = users.find((u) => u.id === b.requesterId && u.active !== false);
    if (!requester) fail(422, "Requester not found.");
    onBehalf = ` on behalf of ${requester.name}`;
  }
  const cid = clean(b.cid, 40);
  const tickets = await readTickets(env);
  if (cid) { // double-submit guard: the same form submission twice returns the first ticket
    const dup = tickets.find((t) => t.cid === cid && t.requester.uid === requester.id);
    if (dup) return json({ ok: true, duplicate: true, ticket: view(dup, admin) });
  }
  const now = new Date().toISOString();
  const t = {
    id: "tk_" + rid(6), number: tickets.reduce((m, x) => Math.max(m, x.number), 0) + 1, title, problem, steps,
    software, softwareOther, category, priority, status: "Not started",
    requester: { uid: requester.id, name: requester.name, email: requester.email }, assignee: "", assigneeId: "",
    createdAt: now, updatedAt: now, resolvedAt: "", dueAt: dueFor(priority, now),
    comments: [], events: [{ at: now, by: me.name, text: "created the ticket" + onBehalf }], attachments: [], deleted: false, cid,
  };
  tickets.push(t);
  await writeTickets(env, tickets);
  const audit = await appendAudit(env, { actor: me.name, action: "ticket.create",
    detail: `${label(t)}: ticket created${onBehalf} by ${me.name} (requester ${requester.email}); software "${swName(t)}", category "${CATEGORIES[category]}", priority "${priority}", due ${t.dueAt}` +
      `; problem: "${clip(problem, 120)}"` + (steps ? `; steps to reproduce: "${clip(steps, 120)}"` : "; no steps given") });
  later(env, notify(env, admins(users, me.id), { title: `New ticket ${tnum(t)} - ${priority}`, body: `${requester.name}: ${clip(title, 90)} (${swName(t)})`,
    url: tlink(t), tag: t.id, urgent: priority === "Urgent" }, new URL(req.url).origin));
  return json({ ok: true, ticket: view(t, admin), ...(admin ? { audit } : {}) });
}

export async function handleAction(req, env, id) {
  const { me, users } = await requireUser(req, env);
  if (me.role === "executive") fail(403, READONLY);
  const admin = me.role === "admin";
  const b = await readBody(req);
  const tickets = await readTickets(env);
  const t = tickets.find((x) => x.id === id && !x.deleted);
  const mine = !!t && t.requester.uid === me.id;
  if (!t || (!admin && !mine)) fail(404, "Ticket not found."); // users cannot tell whether other tickets exist
  let action = b.action;
  const before = t.status;
  if (action === "assign" || action === "status") action = "update";
  const now = new Date().toISOString();
  const ch = [];          // human-readable changes: audit log + (for field changes) the activity timeline
  const ev = [];          // events shown on the ticket timeline
  let comment = null;
  const needAdmin = () => { if (!admin) fail(403, "Admin access required."); };
  const addComment = (text, internal) => {
    if (t.comments.length >= MAX_COMMENTS) fail(409, "This ticket has reached the maximum number of messages.");
    comment = { id: "c_" + rid(4), by: me.name, byRole: me.role, at: now, text };
    if (internal) comment.internal = true;
  };

  if (action === "update") {
    needAdmin();
    if (b.status !== undefined && b.status !== t.status) {
      if (!STATUSES.includes(b.status)) fail(422, "Invalid status.");
      ch.push(statusChange(t, b.status, now));
    }
    if (b.priority !== undefined && b.priority !== t.priority) {
      if (!PRIORITIES.includes(b.priority)) fail(422, "Invalid priority.");
      const due = dueFor(b.priority, t.createdAt);
      ch.push(`priority "${t.priority}" -> "${b.priority}"; due ${t.dueAt} -> ${due}`);
      t.priority = b.priority; t.dueAt = due;
    }
    if (b.category !== undefined && b.category !== t.category) {
      if (!CATEGORIES[b.category]) fail(422, "Invalid category.");
      ch.push(`category "${CATEGORIES[t.category] || t.category}" -> "${CATEGORIES[b.category]}"`);
      t.category = b.category;
    }
    if (b.software !== undefined || b.softwareOther !== undefined) {
      const sw = parseSoftware(b, t), old = swName(t);
      Object.assign(t, sw);
      if (swName(t) !== old) ch.push(`software "${old}" -> "${swName(t)}"`);
    }
    if (b.assignee !== undefined) {
      const name = clean(b.assignee, 80);
      const a = name ? users.find((u) => u.active !== false && u.role === "admin" && u.name === name) : null;
      if (name && !a) fail(422, "A ticket can only be assigned to an admin.");
      if ((a ? a.name : "") !== t.assignee) {
        ch.push(`assignee "${t.assignee || "(none)"}" -> "${a ? a.name : "(none)"}"`);
        t.assignee = a ? a.name : ""; t.assigneeId = a ? a.id : "";
      }
    }
    if (ch.length) ev.push("changed " + ch.join("; "));
  } else if (action === "edit") { // requester (until Done) or admin fixes the wording of their ticket
    if (!admin && t.status === DONE) fail(409, "This ticket is Done. Reopen it to edit it.");
    const q = (s) => `"${clip(s, 100)}"`;
    const fields = [];
    if (b.title !== undefined) {
      const v = clean(b.title, 150);
      if (!v) fail(422, "A title is required.");
      if (v !== t.title) { ch.push(`title ${q(t.title)} -> ${q(v)}`); fields.push("title"); t.title = v; }
    }
    if (b.problem !== undefined) {
      const v = checkProblem(b.problem);
      if (v !== t.problem) { ch.push(`problem changed from ${q(t.problem)} to ${q(v)}`); fields.push("problem"); t.problem = v; }
    }
    if (b.steps !== undefined) {
      const v = clean(b.steps, 3000);
      if (v !== t.steps) {
        ch.push(!t.steps ? `steps added: ${q(v)}` : !v ? `steps removed (was ${q(t.steps)})` : `steps changed from ${q(t.steps)} to ${q(v)}`);
        fields.push("steps"); t.steps = v;
      }
    }
    if (fields.length) ev.push("edited the " + fields.join(" and "));
  } else if (action === "reply" || action === "note") {
    const text = clean(b.text, 4000);
    if (!text) fail(422, "The message cannot be empty.");
    if (action === "note") needAdmin();
    if (!admin && t.status === DONE) fail(409, "This ticket is Done. Use Reopen and explain what is still wrong.");
    addComment(text, action === "note");
    ch.push(`${action === "note" ? "internal note" : "reply"} added${!admin ? " by requester" : ""}: "${clip(text, 160)}"`);
    if (action === "reply" && admin && b.status && b.status !== t.status) {
      if (!["In progress", "Waiting on requester", DONE].includes(b.status)) fail(422, "Invalid status.");
      const s = statusChange(t, b.status, now); ch.push(s); ev.push("changed " + s);
    } else if (action === "reply" && !admin && t.status === "Waiting on requester") {
      const s = statusChange(t, t.assignee ? "In progress" : "Not started", now, " (requester replied)"); ch.push(s); ev.push("changed " + s);
    }
  } else if (action === "reopen") { // requester reopens a Done ticket; a reason is required
    if (!mine) fail(403, "Only the requester can reopen from here.");
    if (t.status !== DONE) fail(409, "Only Done tickets can be reopened.");
    const text = clean(b.text, 4000);
    if (!text) fail(422, "Please explain why you are reopening this ticket.");
    const s = statusChange(t, "Not started", now, " (reopened by requester)");
    addComment(text, false);
    ch.push(s, `reason given: "${clip(text, 160)}"`); ev.push("reopened the ticket - " + s);
  } else if (action === "delete") {
    needAdmin();
    t.deleted = true; ch.push("ticket deleted (soft delete: hidden from everyone, kept in storage)");
  } else fail(400, "Unknown action.");

  if (!ch.length) return json({ ok: true, unchanged: true, ticket: view(t, admin) });
  if (comment) t.comments.push(comment);
  if (ev.length) { t.events.push(...ev.map((text) => ({ at: now, by: me.name, text }))); t.events = t.events.slice(-MAX_EVENTS); }
  t.updatedAt = now;
  await writeTickets(env, tickets);
  const audit = await appendAudit(env, { actor: me.name, action: "ticket." + action, detail: `${label(t)}: ${ch.join("; ")}` });
  const origin = new URL(req.url).origin, pub = comment && !comment.internal ? comment : null;
  if (!t.deleted && admin && !mine) {          // software team -> the requester
    let msg = null;
    if (t.status !== before) msg = t.status === "Waiting on requester"
      ? { title: `${tnum(t)}: we need information from you`, body: pub ? clip(pub.text, 160) : "The software team is waiting for your reply. Open the ticket to answer.", urgent: true }
      : { title: `${tnum(t)} is now ${t.status}`, body: pub ? `${me.name}: ${clip(pub.text, 140)}` : clip(t.title, 140) };
    else if (pub) msg = { title: `New reply on ${tnum(t)}`, body: `${me.name}: ${clip(pub.text, 160)}` };
    if (msg) later(env, notify(env, [t.requester.uid], { ...msg, url: tlink(t), tag: t.id }, origin));
  } else if (!t.deleted && !admin && pub) {     // requester -> the assigned agent (or the whole software team)
    later(env, notify(env, t.assigneeId ? [t.assigneeId] : admins(users, me.id),
      { title: `${me.name} ${action === "reopen" ? "reopened" : "replied on"} ${tnum(t)}`, body: clip(pub.text, 160), url: tlink(t), tag: t.id }, origin));
  }
  if (!t.deleted) later(env, livePost(env, t.id, { type: "update", byId: me.id, by: me.name, status: t.status, assignee: t.assignee,
    priority: t.priority, updatedAt: t.updatedAt, resolvedAt: t.resolvedAt, ...(comment ? { comment, staffOnly: !!comment.internal } : {}) }));
  return json({ ok: true, ticket: view(t, admin), ...(admin ? { audit } : {}) });
}

// ---- attachments (images + PDF only, max 5 MB, stored as KV binary values) ----
function sniff(b) {
  const at = (...s) => s.every((v, i) => b[i] === v);
  if (at(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) return "image/png";
  if (at(0xff, 0xd8, 0xff)) return "image/jpeg";
  if (at(0x47, 0x49, 0x46, 0x38)) return "image/gif";
  if (at(0x52, 0x49, 0x46, 0x46) && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
  if (at(0x25, 0x50, 0x44, 0x46, 0x2d)) return "application/pdf";
  return "";
}

export async function handleUpload(req, env, id, url) {
  const { me } = await requireUser(req, env);
  fail(410, "Attachments are turned off.");   // client decision 2026-10-01: no file uploads
  if (me.role === "executive") fail(403, READONLY);
  const admin = me.role === "admin";
  if (Number(req.headers.get("Content-Length") || 0) > MAX_ATT_BYTES + 1024) fail(413, "File too large (max 5 MB).");
  const buf = await req.arrayBuffer();
  if (!buf.byteLength) fail(422, "The file is empty.");
  if (buf.byteLength > MAX_ATT_BYTES) fail(413, "File too large (max 5 MB).");
  // The type comes from the file's own bytes, not from what the browser claims.
  const type = sniff(new Uint8Array(buf, 0, Math.min(16, buf.byteLength)));
  if (!type) fail(415, "Only images (PNG, JPEG, GIF, WebP) and PDF files are allowed.");
  const name = clean(url.searchParams.get("name"), 100).replace(/[\\/:*?"<>|\u0000-\u001f]+/g, "_") || "attachment";
  const tickets = await readTickets(env);
  const t = tickets.find((x) => x.id === id && !x.deleted);
  if (!t || (!admin && t.requester.uid !== me.id)) fail(404, "Ticket not found.");
  if (t.status === DONE && !admin) fail(409, "This ticket is Done. Reopen it to add files.");
  if (t.attachments.length >= MAX_ATT) fail(409, `A ticket can have at most ${MAX_ATT} attachments.`);
  const now = new Date().toISOString();
  const att = { id: "a_" + rid(4), name, type, size: buf.byteLength, by: me.name, at: now };
  await env.KV.put(attKey(t.id, att.id), buf);
  t.attachments.push(att);
  t.updatedAt = now;
  await writeTickets(env, tickets);
  const audit = await appendAudit(env, { actor: me.name, action: "ticket.attach",
    detail: `${label(t)}: attachment added: "${name}" (${type}, ${Math.max(1, Math.round(buf.byteLength / 1024))} KB)` });
  return json({ ok: true, ticket: view(t, admin), ...(admin ? { audit } : {}) });
}

// Served only to the ticket's requester, admins and executives; inline, with the sniffed Content-Type.
export async function handleAttachment(req, env, tid, aid) {
  const { me } = await requireUser(req, env);
  const tickets = await readTickets(env);
  const t = tickets.find((x) => x.id === tid && !x.deleted);
  const att = t && t.attachments.find((a) => a.id === aid);
  if (!att || (me.role === "user" && t.requester.uid !== me.id)) fail(404, "Not found.");
  const bytes = await env.KV.get(attKey(tid, aid), "arrayBuffer");
  if (!bytes) fail(404, "Not found.");
  const ascii = att.name.replace(/[^\x20-\x7e]/g, "_").replace(/"/g, "'");
  return new Response(bytes, { status: 200, headers: {
    "Content-Type": att.type,
    "Content-Disposition": `inline; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(att.name)}`,
    "X-Content-Type-Options": "nosniff", "Content-Security-Policy": ATTACHMENT_CSP,
  } });
}

// Records that an admin/executive downloaded an Excel report (the file itself is built in the browser).
export async function handleReportLog(req, env) {
  const { me } = await requireUser(req, env, { staff: true });
  const b = await readBody(req, 2048);
  const what = clean(b.what, 40) || "report";
  const sheets = (Array.isArray(b.sheets) ? b.sheets : []).slice(0, 8).map((s) => clean(s, 30)).join(", ");
  const audit = await appendAudit(env, { actor: me.name, action: "report.download",
    detail: `Excel ${what} downloaded (sheets: ${sheets}${b.rows != null ? `; ${Number(b.rows) || 0} rows` : ""})` });
  return json({ ok: true, audit });
}
