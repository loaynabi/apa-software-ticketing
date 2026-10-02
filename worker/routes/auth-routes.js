// Login / logout / me / change-own-password, with brute-force lockout.
// 5 wrong passwords for an account, or 10 failures from one IP, lock sign-in for 15 minutes. Counters are
// KV keys with a 15-minute TTL and stop being written once locked, so an attacker cannot burn the free
// KV write quota. Failed attempts, lockouts and successful sign-ins are written to the audit log.
import { readJson, writeJson, appendAudit } from "../kv.js";
import {
  getSession, issueSession, sessionCookie, clearSessionCookie, requireUser, verifyPassword, hashPassword,
} from "../auth.js";
import { json, fail, readBody, isCompanyEmail, DOMAIN, weakPassword, pubUser } from "../util.js";

const LOCK_MIN = 15, MAX_ACCT = 5, MAX_IP = 10;
const readN = async (env, k) => ((await env.KV.get(k, "json")) || {}).n || 0;
const bump = (env, k, n) => env.KV.put(k, JSON.stringify({ n: n + 1 }), { expirationTtl: LOCK_MIN * 60 });
const locked = () => json({ error: "Too many failed sign-in attempts. Try again in " + LOCK_MIN + " minutes." }, 429,
  { "Retry-After": String(LOCK_MIN * 60) });

export async function handleLogin(req, env) {
  const b = await readBody(req, 4096);
  const email = String(b.email || "").trim().toLowerCase().slice(0, 200);
  const password = String(b.password || "").slice(0, 200);
  if (!email || !password) fail(400, "Email and password are required.");
  if (!isCompanyEmail(email)) fail(401, "Only " + DOMAIN + " email addresses can sign in.");
  const ip = req.headers.get("CF-Connecting-IP") || "unknown";
  const ipKey = "lockout:ip:" + ip, acctKey = "lockout:acct:" + email;
  const [ipN, acctN] = await Promise.all([readN(env, ipKey), readN(env, acctKey)]);
  if (ipN >= MAX_IP || acctN >= MAX_ACCT) return locked();

  const users = await readJson(env, "users");
  const user = users.find((u) => u.email === email);
  let ok = false;
  if (user && user.active !== false) ok = await verifyPassword(password, user.passwordHash, user.salt);
  else await hashPassword(password, "00".repeat(16)); // same work either way: no timing hint about which accounts exist

  if (!ok) {
    const lockIp = ipN + 1 >= MAX_IP, lockAcct = !!user && acctN + 1 >= MAX_ACCT;
    const why = !user ? "no such account" : user.active === false ? "account is deactivated" : "wrong password";
    const writes = [bump(env, ipKey, ipN), appendAudit(env, {
      actor: email, action: lockIp || lockAcct ? "login.lockout" : "login.failed",
      detail: `Failed sign-in for ${email} (${why}) from IP ${ip}` +
        (lockAcct ? `; account locked for ${LOCK_MIN} minutes after ${MAX_ACCT} failed attempts` : "") +
        (lockIp ? `; IP ${ip} locked for ${LOCK_MIN} minutes after ${MAX_IP} failed attempts` : ""),
    })];
    if (user) writes.push(bump(env, acctKey, acctN)); // only real accounts get a counter
    await Promise.all(writes);
    return lockIp || lockAcct ? locked() : json({ error: "Incorrect email or password." }, 401);
  }

  const writes = [appendAudit(env, { actor: user.name, action: "login.ok",
    detail: `Signed in: ${user.name} (${user.email}), role ${user.role}` })];
  if (acctN > 0) writes.push(env.KV.delete(acctKey));
  await Promise.all(writes);
  const token = await issueSession(user, env);
  return json({ ok: true, ...pubUser(user) }, 200, { "Set-Cookie": sessionCookie(token) });
}

export async function handleLogout() {
  return json({ ok: true }, 200, { "Set-Cookie": clearSessionCookie() });
}

export async function handleMe(req, env) {
  const s = await getSession(req, env);
  if (!s) return json({ signedIn: false });
  try {
    const { me } = await requireUser(req, env, { allowInitial: true });
    return json({ signedIn: true, ...pubUser(me) });
  } catch (e) { return json({ signedIn: false }); }
}

// Own password change: needs the current password. Clears the "still on the initial password" flag.
export async function handlePassword(req, env) {
  const { me, users } = await requireUser(req, env, { allowInitial: true });
  const b = await readBody(req, 4096);
  const acctKey = "lockout:acct:" + me.email;
  const n = await readN(env, acctKey);
  if (n >= MAX_ACCT) return locked();
  const current = String(b.current || ""), pw = String(b.password || "");
  if (!(await verifyPassword(current, me.passwordHash, me.salt))) {
    await Promise.all([bump(env, acctKey, n), appendAudit(env, { actor: me.name, action: "password.failed",
      detail: `Password change refused for ${me.name} (${me.email}): current password was wrong` })]);
    fail(403, "Your current password is incorrect.");
  }
  const weak = weakPassword(pw);
  if (weak) fail(422, weak);
  if (pw === current) fail(422, "Choose a password different from your current one.");
  const { hash, salt } = await hashPassword(pw);
  me.passwordHash = hash; me.salt = salt; me.initialPassword = false;
  await writeJson(env, "users", users);
  await appendAudit(env, { actor: me.name, action: "password.change",
    detail: `Password changed by ${me.name} (${me.email}) for their own account` });
  const token = await issueSession(me, env);
  return json({ ok: true }, 200, { "Set-Cookie": sessionCookie(token) });
}
