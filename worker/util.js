// Small shared helpers: JSON responses, HTTP errors, input cleaning, validation.
export class HttpError extends Error {
  constructor(status, message, extra) { super(message); this.status = status; this.extra = extra; }
}
export const fail = (status, message, extra) => { throw new HttpError(status, message, extra); };
export const json = (body, status = 200, headers = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });

export const clip = (s, n) => { s = String(s ?? ""); return s.length > n ? s.slice(0, n - 3) + "..." : s; };
// Strip control characters (keeps \n and \t), trim, cap length.
export const clean = (s, max) =>
  String(s ?? "").replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "").trim().slice(0, max);
export const rid = (bytes = 6) =>
  Array.from(crypto.getRandomValues(new Uint8Array(bytes)), (b) => b.toString(16).padStart(2, "0")).join("");

export async function readBody(req, max = 65536) {
  if (Number(req.headers.get("Content-Length") || 0) > max) fail(413, "Request too large.");
  const text = await req.text();
  if (text.length > max) fail(413, "Request too large.");
  try { return text ? JSON.parse(text) : {}; } catch (e) { return fail(400, "Invalid JSON."); }
}

export const ROLES = ["admin", "executive", "user"];
export const roleOf = (r) => (ROLES.includes(r) ? r : "user");
export const DOMAIN = "@advancedpsychiatryassociates.com";
export const isCompanyEmail = (e) => /^[^\s@]+@advancedpsychiatryassociates\.com$/.test(String(e || "").trim().toLowerCase());
export const DOMAIN_ERROR = "Only " + DOMAIN + " email addresses can be used.";
// New or changed passwords: at least 8 characters with letters and digits.
export const weakPassword = (p) => {
  const s = String(p || "");
  return s.length < 8 || s.length > 200 || !/[A-Za-z]/.test(s) || !/[0-9]/.test(s)
    ? "Password must be at least 8 characters and include letters and numbers." : "";
};
// Never includes the hash or salt.
export const pubUser = (u) => ({
  id: u.id, name: u.name, email: u.email, role: u.role, active: u.active !== false,
  initialPassword: !!u.initialPassword, createdAt: u.createdAt || "",
});
