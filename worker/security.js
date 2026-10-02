// Security headers + Content-Security-Policy (kept in its own module so the dev
// harness can apply the exact same CSP to the page it tests).
export const CSP = [
  "default-src 'self'",
  "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src https://fonts.gstatic.com",
  "img-src 'self' data: blob:",
  "connect-src 'self' wss://apa-software-tickets.loaynabil8.workers.dev",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
].join("; ");

// Uploaded images/PDFs: no scripts ever (no object-src/default-src, so the browser's PDF viewer still works).
export const ATTACHMENT_CSP = "script-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

export function secure(resp, { api = false } = {}) {
  const r = new Response(resp.body, resp);
  const h = r.headers;
  if (!h.has("Content-Security-Policy")) h.set("Content-Security-Policy", CSP); // attachments bring their own
  h.set("X-Frame-Options", "DENY");
  h.set("X-Content-Type-Options", "nosniff");
  h.set("Referrer-Policy", "no-referrer");
  h.set("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  h.set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()");
  h.set("Cross-Origin-Opener-Policy", "same-origin");
  if (api) h.set("Cache-Control", "no-store");
  return r;
}
