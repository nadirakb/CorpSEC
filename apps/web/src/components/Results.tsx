"use client";

import Link from "next/link";
import { useId, useState } from "react";

import { api, ApiError, type Scan } from "@/lib/api";
import { t } from "@/lib/i18n";
import { capApplied, fixFirst, gradeTone, groupFindings, isProblem, REDACTED_MARK, STAGES } from "@/lib/report";

import { FindingCard } from "./FindingCard";
import { GradeSeal } from "./GradeSeal";

type Props = { scan: Scan; share?: string | null; onChanged: () => Promise<void> };

export function Results({ scan, share = null, onChanged }: Props) {
  if (scan.status === "failed") {
    return (
      <section className="rise mx-auto max-w-2xl pt-10">
        <h1 className="font-display text-4xl font-semibold">{t.results.failedTitle}</h1>
        <p className="mt-4 text-lg text-ink-soft">{scan.error ?? t.errors.generic}</p>
        <Link href="/" className="mt-8 inline-block rounded-xl bg-accent px-6 py-3 font-semibold text-accent-ink">
          {t.results.newScan}
        </Link>
      </section>
    );
  }

  const letter = scan.grade ?? "F";
  const first = fixFirst(scan);
  const groups = groupFindings(scan.findings, new Set(first.map((s) => s.key)));

  return (
    <div className="space-y-14 pt-4">
      <header className="rise grid items-center gap-8 rounded-2xl border border-rule bg-raised p-6 sm:grid-cols-[auto_1fr] sm:p-10">
        <GradeSeal letter={letter} score={scan.score} />
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.14em] text-ink-soft">{scan.host}</p>
          <h1 className="font-display mt-2 text-3xl leading-tight font-semibold sm:text-4xl">
            {t.results.verdicts[letter] ?? ""}
          </h1>
          {capApplied(scan) && scan.grade_caps.slice(0, 1).map((c) => (
            <p key={c} className="mt-3 text-ink-soft">
              {t.results.capNote[c]}
            </p>
          ))}
          {scan.status === "partial" && <p className="mt-3 text-ink-soft">{t.results.partial}</p>}
          {scan.finished_at && (
            <p className="mt-3 text-sm text-ink-soft">
              {t.results.checkedAt(
                new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(
                  new Date(scan.finished_at),
                ),
              )}
            </p>
          )}
          <div className="mt-6 flex flex-wrap gap-3">
            <ShareButton />
            <Link
              href={`/scan/${scan.id}/print${share ? `?share=${encodeURIComponent(share)}` : ""}`}
              className="rounded-lg border-2 border-rule px-4 py-2 font-semibold hover:border-ink-soft"
            >
              {t.print.button}
            </Link>
            {scan.can_act && <SendToIt scanId={scan.id} />}
            <Link href="/" className="rounded-lg border-2 border-rule px-4 py-2 font-semibold hover:border-ink-soft">
              {t.results.newScan}
            </Link>
          </div>
        </div>
      </header>

      {scan.redacted && scan.findings.some((f) => isProblem(f) && f.evidence.observed === REDACTED_MARK) && (
        <aside className="rounded-2xl border border-rule bg-raised p-5" role="note">
          <p className="font-semibold">{t.redacted.title}</p>
          <p className="mt-1 text-ink-soft">{t.redacted.text}</p>
          <Link
            href={scan.site_id ? `/sites/${scan.site_id}` : `/login?next=${encodeURIComponent(`/dashboard?add=${scan.host}`)}`}
            className="mt-3 inline-block font-semibold text-accent underline"
          >
            {t.redacted.cta}
          </Link>
        </aside>
      )}

      <section aria-labelledby="areas-heading" className="rise" style={{ animationDelay: "80ms" }}>
        <h2 id="areas-heading" className="font-display text-2xl font-semibold">
          {t.results.stagesHeading}
        </h2>
        <ul className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-5">
          {STAGES.map((stage) => {
            const g = scan.stage_grades[stage];
            if (!g) return null;
            return (
              <li key={stage} className="rounded-xl border border-rule bg-raised p-4">
                <p className="text-sm text-ink-soft">{t.stages[stage]}</p>
                <p className="font-display mt-1 text-3xl font-bold" style={{ color: `var(--grade-${gradeTone(g.letter)})` }}>
                  <span className="sr-only">{t.results.gradeLabel(g.letter)}: </span>
                  {g.letter}
                </p>
              </li>
            );
          })}
        </ul>
      </section>

      <section aria-labelledby="fix-first-heading" className="rise" style={{ animationDelay: "160ms" }}>
        <h2 id="fix-first-heading" className="font-display text-3xl font-semibold">
          {t.results.fixFirst}
        </h2>
        {first.length ? (
          <>
            <p className="mt-1 text-ink-soft">{t.results.fixFirstLede}</p>
            <ol className="mt-5 space-y-4">
              {first.map((set, i) => (
                <li key={set.key} className="flex gap-4">
                  <span aria-hidden className="font-display mt-4 hidden text-4xl font-bold text-ink-soft/40 sm:block">
                    {i + 1}
                  </span>
                  <div className="flex-1">
                    <FindingCard findings={set.findings} defaultOpen={i === 0} canAct={scan.can_act} onChanged={onChanged} />
                  </div>
                </li>
              ))}
            </ol>
          </>
        ) : (
          <p className="mt-3 text-lg">{t.results.nothingToFix}</p>
        )}
      </section>

      {scan.site_id ? (
        <Link href={`/sites/${scan.site_id}`} className="inline-block font-semibold text-accent underline">
          ← {t.cta.backToSite}
        </Link>
      ) : (
        <aside className="rounded-2xl border-2 border-accent/40 bg-raised p-6 sm:flex sm:items-center sm:justify-between sm:gap-6">
          <div>
            <h2 className="font-display text-2xl font-semibold">{t.cta.title}</h2>
            <p className="mt-1 text-ink-soft">{t.cta.text}</p>
          </div>
          <Link
            href={`/login?next=${encodeURIComponent(`/dashboard?add=${scan.host}`)}`}
            className="mt-4 inline-block shrink-0 rounded-xl bg-accent px-6 py-3 font-semibold text-accent-ink sm:mt-0"
          >
            {t.cta.button}
          </Link>
        </aside>
      )}

      <section aria-labelledby="all-heading">
        <h2 id="all-heading" className="font-display text-3xl font-semibold">
          {t.results.allResults}
        </h2>
        <div className="mt-6 space-y-10">
          {groups.map(([key, sets]) => {
            const list = (
              <ul className="mt-3 space-y-3">
                {sets.map((set) => (
                  <li key={set.key}>
                    <FindingCard findings={set.findings} canAct={scan.can_act} onChanged={onChanged} />
                  </li>
                ))}
              </ul>
            );
            const heading = `${t.results.groups[key]} (${sets.length})`;
            // Long, reassuring lists start collapsed so problems stay in focus.
            if (key === "pass" || key === "dismissed" || key === "fixed") {
              return (
                <details key={key} className="group">
                  <summary className="cursor-pointer text-xl font-semibold">
                    {heading}
                  </summary>
                  {list}
                </details>
              );
            }
            return (
              <div key={key}>
                <h3 className="text-xl font-semibold">{heading}</h3>
                {list}
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

function ShareButton() {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(window.location.href);
          setCopied(true);
          setTimeout(() => setCopied(false), 2500);
        } catch {
          /* clipboard blocked: the URL bar still works */
        }
      }}
      className="rounded-lg bg-accent px-4 py-2 font-semibold text-accent-ink"
    >
      <span aria-live="polite">{copied ? t.results.copied : t.results.share}</span>
    </button>
  );
}


function SendToIt({ scanId }: { scanId: string }) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [note, setNote] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "sent">("idle");
  const [error, setError] = useState<string | null>(null);
  const emailId = useId();
  const noteId = useId();

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} className="rounded-lg border-2 border-rule px-4 py-2 font-semibold hover:border-ink-soft">
        {t.share.button}
      </button>
    );
  }
  return (
    <form
      className="mt-2 w-full rounded-xl border border-rule bg-paper p-4"
      aria-label={t.share.title}
      onSubmit={async (e) => {
        e.preventDefault();
        setState("sending");
        setError(null);
        try {
          await api.shareScan(scanId, email.trim(), note.trim());
          setState("sent");
        } catch (err) {
          setError(err instanceof ApiError && err.status === 401 ? t.share.signIn : err instanceof ApiError ? err.message : t.errors.generic);
          setState("idle");
        }
      }}
    >
      <p className="font-semibold">{t.share.title}</p>
      <p className="text-sm text-ink-soft">{t.share.lede}</p>
      {state === "sent" ? (
        <p role="status" className="mt-3 font-semibold" style={{ color: "var(--sev-pass)" }}>{t.share.sent(email.trim())}</p>
      ) : (
        <>
          <label htmlFor={emailId} className="mt-3 block text-sm font-semibold">{t.share.email}</label>
          <input id={emailId} type="email" required value={email} onChange={(e) => setEmail(e.target.value)} className="mt-1 min-h-11 w-full rounded-lg border-2 border-rule bg-raised px-3" />
          <label htmlFor={noteId} className="mt-3 block text-sm font-semibold">{t.share.note}</label>
          <textarea id={noteId} value={note} maxLength={1000} onChange={(e) => setNote(e.target.value)} rows={2} className="mt-1 w-full rounded-lg border-2 border-rule bg-raised px-3 py-2" />
          <div className="mt-3 flex gap-3">
            <button type="submit" disabled={state === "sending" || !email.trim()} className="rounded-lg bg-accent px-4 py-2 font-semibold text-accent-ink disabled:opacity-60">
              {state === "sending" ? t.share.sending : t.share.send}
            </button>
            <button type="button" onClick={() => setOpen(false)} className="rounded-lg px-4 py-2 font-semibold">{t.share.cancel}</button>
          </div>
          <p role="alert" className="mt-2 min-h-6 text-sm font-medium text-[var(--sev-critical)]">
            {error === t.share.signIn ? (
              <Link href={`/login?next=${encodeURIComponent(`/scan/${scanId}`)}`} className="underline">{error}</Link>
            ) : (
              error
            )}
          </p>
        </>
      )}
    </form>
  );
}
