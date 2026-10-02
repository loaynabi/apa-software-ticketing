// Stateless HMAC-signed session cookie + PBKDF2 password hashing (WebCrypto, no dependencies).
// Adapted from the credentialing app. Differences: cookie name, the session carries only {uid, ph, exp}
// and every request re-reads the user, so deactivation / role changes / password resets apply at once.
import { readJson } from "./kv.js";
import { fail } from "./util.js";

export const SESSION_COOKIE = "apa_swt_session";
export const SESSION_TTL_SECONDS = 12 * 60 * 60;

function b64urlEncode(bytes) {
  let bin = "";
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
const hmacKey = (secret) =>
  crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);

export async function signSession(payload, secret) {
  const p = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), new TextEncoder().encode(p));
  return p + "." + b64urlEncode(sig);
}
export async function verifySession(token, secret) {
  try {
    if (!token || token.indexOf(".") === -1) return null;
    const [p, s] = token.split(".");
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), b64urlDecode(s), new TextEncoder().encode(p));
    if (!ok) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(p)));
    return payload.exp && Date.now() / 1000 <= payload.exp ? payload : null; // {uid, ph, exp}
  } catch (e) { return null; }
}

function parseCookies(req) {
  const out = {};
  (req.headers.get("Cookie") || "").split(";").forEach((part) => {
    const i = part.indexOf("=");
    if (i !== -1) { try { out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim()); } catch (e) { /* ignore */ } }
  });
  return out;
}
export const sessionCookie = (token) => `${SESSION_COOKIE}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_TTL_SECONDS}`;
export const clearSessionCookie = () => `${SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0`;

// `ph` ties the session to the current password hash: changing/resetting a password ends old sessions.
export const issueSession = (user, env) =>
  signSession({ uid: user.id, ph: user.passwordHash.slice(0, 12), exp: Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS }, env.SESSION_SECRET);

export async function getSession(req, env) {
  const token = parseCookies(req)[SESSION_COOKIE];
  return token ? verifySession(token, env.SESSION_SECRET) : null;
}

// Every protected route starts here. Returns the live user record + the full users array.
//   admin: ticket agents only.  staff: admins + executives (read access to everything).
export async function requireUser(req, env, { admin = false, staff = false, allowInitial = false } = {}) {
  const s = await getSession(req, env);
  if (!s) fail(401, "Not signed in.");
  const users = await readJson(env, "users");
  const me = users.find((u) => u.id === s.uid);
  if (!me || me.active === false || me.passwordHash.slice(0, 12) !== s.ph) fail(401, "Not signed in.");
  if (me.initialPassword && !allowInitial) fail(403, "Please create your new password first.", { mustChangePassword: true });
  if (admin && me.role !== "admin") fail(403, me.role === "executive" ? "Executives have read-only access." : "Admin access required.");
  if (staff && me.role === "user") fail(403, "Staff access required.");
  return { me, users };
}

// PBKDF2-HMAC-SHA256, 100k iterations, 256-bit output, hex encoded (identical to seed_users.py).
const toHex = (bytes) => Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
const fromHex = (hex) => Uint8Array.from(hex.match(/../g) || [], (h) => parseInt(h, 16));

export async function hashPassword(password, saltHex) {
  const salt = saltHex ? fromHex(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, km, 256);
  return { hash: toHex(bits), salt: toHex(salt) };
}
export async function verifyPassword(password, hashHex, saltHex) {
  const { hash } = await hashPassword(password, saltHex);
  if (hash.length !== hashHex.length) return false;
  let diff = 0;
  for (let i = 0; i < hash.length; i++) diff |= hash.charCodeAt(i) ^ hashHex.charCodeAt(i);
  return diff === 0;
}
