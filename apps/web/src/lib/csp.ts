// Nonce-based Content Security Policy (spec §15: CorpSEC passes its own checks).
// Every page response gets a fresh nonce; Next.js reads it from the request's CSP header and
// stamps it on its own scripts and styles. 'strict-dynamic' lets those scripts load the
// chunks they need, and nothing else runs. Pages must render per request for this to work,
// so the root layout opts out of the prerendered shell.
export function csp(nonce: string, dev: boolean): string {
  return [
    "default-src 'self'",
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${dev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    // style="" attributes (colours, progress widths) can't carry a nonce and can't run code
    "style-src-attr 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join("; ");
}
