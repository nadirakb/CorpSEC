# CorpSEC web app

Next.js 16 (App Router, Cache Components) + Tailwind 4. Talks to the API through a
same-origin rewrite: `/api/v1/*` → `$CORPSEC_API_URL/v1/*` (default `http://localhost:8000`).

```bash
npm install
npm run dev        # http://localhost:3000 (needs the API running, see ../../README.md)
npm run lint && npm run typecheck && npm test && npm run build
```

- Security headers: the Content-Security-Policy is set per request with a fresh nonce in
  `src/proxy.ts` (built in `src/lib/csp.ts`); the other headers are in `next.config.ts`.
  Pages render per request (the root layout awaits `connection()`), because a prerendered
  page can't carry the nonce.
- Usage counting: `src/lib/track.ts` sends a few first-party events to the API (no cookies,
  skipped when the browser sends Global Privacy Control or Do Not Track).
- All user-facing text lives in `src/lib/i18n.ts`.
- Pure report logic (grouping, fix-first, caps) is in `src/lib/report.ts`, tested with Vitest.
- Severity is always shown with an icon and a word as well as colour; the grade seal has
  the letter, a word and the score. Animations respect `prefers-reduced-motion`.
