"use client";

import { useId, useState } from "react";

import {
  type ActionResult,
  api,
  ApiError,
  type DismissReason,
  type FeedbackReason,
  type Finding,
} from "@/lib/api";
import { t } from "@/lib/i18n";
import { attributions, itemLabel } from "@/lib/report";
import { track } from "@/lib/track";

import { SeverityTag } from "./SeverityTag";

type Props = {
  /** Findings of one check with the same status, e.g. TLS 1.0 and TLS 1.1 accepted. */
  findings: Finding[];
  defaultOpen?: boolean;
  /** False for read-only viewers (shared links). */
  canAct?: boolean;
  onChanged: () => Promise<void> | void;
};

export function FindingCard({ findings, defaultOpen = false, canAct = true, onChanged }: Props) {
  const finding = findings[0];
  const e = finding.explanation;
  const items = findings.map(itemLabel).filter(Boolean);
  const [open, setOpen] = useState(defaultOpen);
  const bodyId = useId();
  if (!e) return null;
  const problem = finding.severity !== "pass" && finding.severity !== "info";
  const fixed = finding.status === "fixed";
  const dismissed = finding.status === "dismissed";

  return (
    <article
      className="rounded-xl border border-rule bg-raised shadow-[0_1px_0_var(--rule)]"
      style={{ borderLeft: `5px solid var(--sev-${fixed ? "pass" : finding.severity})` }}
    >
      <h3 className="m-0">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={bodyId}
          onClick={() => {
            if (!open && problem) track("report.fix_opened", { check_id: finding.check_id });
            setOpen((o) => !o);
          }}
          className="flex w-full items-start gap-4 rounded-xl px-5 py-4 text-left hover:bg-[color-mix(in_srgb,var(--ink)_3%,transparent)]"
        >
          <span className="flex-1">
            <span className="flex flex-wrap items-center gap-2">
              <SeverityTag severity={fixed ? "pass" : finding.severity} />
              {finding.confidence === "possible" && problem && (
                <span className="text-sm text-ink-soft">({t.finding.maybe})</span>
              )}
            </span>
            <span className={`mt-2 block text-lg font-semibold ${fixed || dismissed ? "line-through decoration-1 opacity-70" : ""}`}>
              {e.title}
            </span>
            {!open && problem && e.why_it_matters[0] && (
              <span className="mt-1 block text-ink-soft">{e.why_it_matters[0]}</span>
            )}
          </span>
          <Chevron open={open} />
          <span className="sr-only">{open ? t.finding.collapse : t.finding.expand}</span>
        </button>
      </h3>

      <div id={bodyId} hidden={!open} className="space-y-6 px-5 pb-6">
        {e.summary && <Section title={t.finding.whatIsIt}>
          <p>{e.summary}</p>
          {items.length > 0 && problem && (
            <p className="mt-3">
              <span className="font-semibold">{t.finding.foundIn}: </span>
              {items.map((item, i) => (
                <span key={item}>
                  {i > 0 && ", "}
                  <code className="rounded bg-paper px-1.5 py-0.5 font-mono text-[0.92em]">{item}</code>
                </span>
              ))}
            </p>
          )}
          {e.analogy && (
            <p className="mt-3 border-l-2 border-rule pl-3 italic text-ink-soft">
              <span className="sr-only">{t.finding.analogy}: </span>
              {e.analogy}
            </p>
          )}
        </Section>}

        {e.why_it_matters.length > 0 && (
          <Section title={t.finding.why}>
            <ul className="list-disc space-y-1 pl-5">
              {e.why_it_matters.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          </Section>
        )}

        {e.fix_steps.length > 0 && !fixed && (
          <Section title={t.finding.howToFix}>
            {t.fixForNames[e.fix_for] && (
              <p className="mb-2 text-sm font-semibold text-accent">
                {t.finding.fixFor(t.fixForNames[e.fix_for])}
              </p>
            )}
            <ol className="space-y-2">
              {e.fix_steps.map((step, i) => (
                <li key={step} className="flex gap-3">
                  <span
                    aria-hidden
                    className="font-display flex size-7 shrink-0 items-center justify-center rounded-full bg-accent text-sm font-semibold text-accent-ink"
                  >
                    {i + 1}
                  </span>
                  <span className="pt-0.5"><Rich text={step} /></span>
                </li>
              ))}
            </ol>
            <dl className="mt-4 grid gap-x-8 gap-y-1 text-sm sm:grid-cols-[auto_1fr]">
              {e.effort && (
                <>
                  <dt className="font-semibold">{t.finding.effort}</dt>
                  <dd className="text-ink-soft">{e.effort}</dd>
                </>
              )}
              {e.who_can_fix && (
                <>
                  <dt className="font-semibold">{t.finding.who}</dt>
                  <dd className="text-ink-soft">{e.who_can_fix}</dd>
                </>
              )}
            </dl>
          </Section>
        )}

        {findings.map((f) => (
          <Technical key={f.id} finding={f} label={findings.length > 1 ? itemLabel(f) : undefined} />
        ))}

        {problem && canAct && <Actions findings={findings} onChanged={onChanged} />}
        {problem && canAct && <Feedback finding={finding} />}
      </div>
    </article>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h4 className="mb-2 text-sm font-bold uppercase tracking-[0.1em] text-ink-soft">{title}</h4>
      <div className="leading-relaxed">{children}</div>
    </section>
  );
}

/** Renders `code` spans from templates (DNS values to copy). */
function Rich({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`)/g);
  return (
    <>
      {parts.map((p, i) =>
        p.startsWith("`") && p.endsWith("`") ? (
          <code key={i} className="rounded bg-paper px-1.5 py-0.5 font-mono text-[0.92em] break-all">
            {p.slice(1, -1)}
          </code>
        ) : (
          <span key={i}>{p}</span>
        ),
      )}
    </>
  );
}

function Technical({ finding, label }: { finding: Finding; label?: string }) {
  const { holders, records } = attributions(finding);
  return (
    <details className="group rounded-lg border border-rule">
      <summary className="cursor-pointer list-none px-4 py-3 text-sm font-semibold marker:hidden">
        <span className="inline-block transition group-open:rotate-90" aria-hidden>
          ▸
        </span>{" "}
        {t.finding.technical}
        {label && <span className="font-mono font-normal text-ink-soft"> · {label}</span>}
      </summary>
      <div className="space-y-4 px-4 pb-4 text-sm">
        <p className="font-mono">{finding.explanation?.technical}</p>
        <div>
          <p className="mb-1 font-semibold">{t.finding.evidence}</p>
          <pre className="max-h-72 overflow-auto rounded bg-paper p-3 font-mono text-xs leading-relaxed whitespace-pre-wrap break-all">
            {JSON.stringify(finding.evidence, null, 2)}
          </pre>
        </div>
        {finding.references.length > 0 && (
          <div>
            <p className="mb-1 font-semibold">{t.finding.references}</p>
            <ul className="space-y-1">
              {finding.references.map((r) => (
                <li key={r}>
                  <a href={r} target="_blank" rel="noreferrer noopener" className="break-all text-accent underline">
                    {r}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        )}
        {holders.length > 0 && (
          <div className="rounded border border-rule p-3">
            <p className="mb-1 font-semibold">{t.finding.sources}</p>
            {records.length > 0 && (
              <ul className="mb-2 space-y-1">
                {records.map((r) => (
                  <li key={r}>
                    <a href={r} target="_blank" rel="noreferrer noopener" className="break-all text-accent underline">
                      {t.finding.recordLink}: {r}
                    </a>
                  </li>
                ))}
              </ul>
            )}
            {holders.map(([key, a]) => (
              <div key={key} className="mt-2 text-xs text-ink-soft">
                <p className="font-semibold text-ink">{a.notice}</p>
                <p>{a.license}</p>
                <a href={a.license_url} target="_blank" rel="noreferrer noopener" className="text-accent underline">
                  {t.finding.licence}
                </a>
              </div>
            ))}
          </div>
        )}
      </div>
    </details>
  );
}

/** Combined outcome when one card covers several findings. */
function combine(results: ActionResult[]): string {
  if (results.every((r) => r.result === "fixed")) return "fixed";
  if (results.some((r) => r.result === "still_present")) return "still_present";
  return "inconclusive";
}

function Actions({ findings, onChanged }: { findings: Finding[]; onChanged: () => Promise<void> | void }) {
  const finding = findings[0];
  const [busy, setBusy] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [choosing, setChoosing] = useState(false);

  async function run(
    label: string,
    action: (f: Finding) => Promise<ActionResult>,
    showResult: boolean,
  ) {
    setBusy(label);
    setMessage(null);
    try {
      const results: ActionResult[] = [];
      for (const f of findings) results.push(await action(f)); // sequential: one scan at a time
      if (showResult) setMessage(t.finding.recheckResult[combine(results)] ?? null);
      await onChanged();
    } catch (err) {
      setMessage(err instanceof ApiError ? err.message : t.errors.generic);
    } finally {
      setBusy(null);
      setChoosing(false);
    }
  }

  if (finding.status === "dismissed") {
    return (
      <button type="button" disabled={!!busy} onClick={() => run("restore", (f) => api.restore(f.id), false)} className={secondaryBtn}>
        {t.finding.restore}
      </button>
    );
  }
  if (finding.status === "fixed") return null;

  const reasons: DismissReason[] =
    finding.severity === "critical" ? ["false_positive"] : ["accepted_risk", "not_applicable", "false_positive"];

  return (
    <div className="border-t border-rule pt-4">
      <div className="flex flex-wrap items-center gap-3">
        <button
          type="button"
          disabled={!!busy}
          onClick={() => run("recheck", (f) => api.recheck(f.id), true)}
          className="min-h-11 rounded-lg bg-accent px-5 font-semibold text-accent-ink disabled:opacity-60"
        >
          {busy === "recheck" ? t.finding.rechecking : t.finding.recheck}
        </button>
        <button type="button" disabled={!!busy} aria-expanded={choosing} onClick={() => setChoosing((c) => !c)} className={secondaryBtn}>
          {t.finding.notRelevant}
        </button>
      </div>
      {choosing && (
        <fieldset className="mt-3 rounded-lg border border-rule p-3">
          <legend className="px-1 text-sm font-semibold">{t.finding.notRelevant}</legend>
          {finding.severity === "critical" && (
            <p className="mb-2 text-sm text-ink-soft">{t.finding.dismissCriticalNote}</p>
          )}
          <div className="flex flex-col gap-2 sm:flex-row sm:flex-wrap">
            {reasons.map((r) => (
              <button
                key={r}
                type="button"
                disabled={!!busy}
                onClick={() => run("dismiss", (f) => api.dismiss(f.id, r), false)}
                className={secondaryBtn}
              >
                {t.finding.dismissReasons[r]}
              </button>
            ))}
          </div>
        </fieldset>
      )}
      <p role="status" aria-live="polite" className="mt-3 min-h-6 font-medium">
        {message}
      </p>
    </div>
  );
}

const secondaryBtn =
  "min-h-11 rounded-lg border-2 border-rule bg-raised px-4 font-semibold hover:border-ink-soft disabled:opacity-60";

function Chevron({ open }: { open: boolean }) {
  return (
    <svg
      aria-hidden
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      className={`mt-1 shrink-0 text-ink-soft transition ${open ? "rotate-180" : ""}`}
    >
      <path d="M6 9l6 6 6-6" />
    </svg>
  );
}

const FEEDBACK_REASONS: FeedbackReason[] = ["false_positive", "wrong_advice", "unclear", "other"];

/** "This looks wrong": goes to the CorpSEC team, doesn't change the report. */
function Feedback({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const [reason, setReason] = useState<FeedbackReason>("false_positive");
  const [note, setNote] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "sent">("idle");
  const [error, setError] = useState<string | null>(null);
  const noteId = useId();

  if (state === "sent") {
    return <p role="status" className="text-sm text-ink-soft">{t.feedback.thanks}</p>;
  }
  if (!open) {
    return (
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="text-sm font-semibold text-ink-soft underline underline-offset-4 hover:text-ink"
      >
        {t.feedback.open}
      </button>
    );
  }
  return (
    <form
      className="space-y-3 rounded-lg border border-rule p-4 text-sm"
      onSubmit={async (ev) => {
        ev.preventDefault();
        setState("sending");
        setError(null);
        try {
          await api.feedback(finding.id, reason, note);
          setState("sent");
        } catch (err) {
          setState("idle");
          setError(err instanceof ApiError ? err.message : t.errors.generic);
        }
      }}
    >
      <fieldset>
        <legend className="mb-2 font-semibold">{t.feedback.question}</legend>
        <div className="space-y-1">
          {FEEDBACK_REASONS.map((r) => (
            <label key={r} className="flex items-center gap-2">
              <input
                type="radio"
                name={`fb-${finding.id}`}
                value={r}
                checked={reason === r}
                onChange={() => setReason(r)}
                className="accent-[var(--accent)]"
              />
              {t.feedback.reasons[r]}
            </label>
          ))}
        </div>
      </fieldset>
      <label htmlFor={noteId} className="block font-semibold">{t.feedback.noteLabel}</label>
      <textarea
        id={noteId}
        value={note}
        maxLength={1000}
        rows={3}
        onChange={(ev) => setNote(ev.target.value)}
        className="w-full rounded-lg border-2 border-rule bg-paper px-3 py-2"
      />
      <p className="text-ink-soft">{t.feedback.privacy}</p>
      {error && <p role="alert" className="font-medium text-[var(--sev-critical)]">{error}</p>}
      <div className="flex gap-3">
        <button
          type="submit"
          disabled={state === "sending"}
          className="rounded-lg bg-accent px-4 py-2 font-semibold text-accent-ink disabled:opacity-50"
        >
          {state === "sending" ? t.feedback.sending : t.feedback.send}
        </button>
        <button type="button" onClick={() => setOpen(false)} className="font-semibold text-ink-soft">
          {t.feedback.cancel}
        </button>
      </div>
    </form>
  );
}
