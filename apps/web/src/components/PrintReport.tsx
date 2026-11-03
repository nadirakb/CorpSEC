"use client";

import { useSearchParams } from "next/navigation";
import { use, useEffect, useState } from "react";

import { api, ApiError, type Scan } from "@/lib/api";
import { formatDate } from "@/lib/dates";
import { t } from "@/lib/i18n";
import { attributions, fixFirst, groupFindings, isProblem, itemLabel, REDACTED_MARK } from "@/lib/report";

import { GradeSeal } from "./GradeSeal";
import { SeverityTag } from "./SeverityTag";

/** Printable report (spec §7.5): cover, plain-language summary, then a technical appendix.
 *  "Save as PDF" uses the browser's print dialog, so no server-side renderer is needed. */
export function PrintReport({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const share = useSearchParams().get("share");
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.getScan(id, share).then(
      (s) => active && setScan(s),
      (err) => active && setError(err instanceof ApiError ? err.message : t.errors.generic),
    );
    return () => {
      active = false;
    };
  }, [id, share]);

  if (error) return <p role="alert">{error}</p>;
  if (!scan) return <p>…</p>;

  const problems = scan.findings.filter((f) => isProblem(f) && f.explanation);
  const passed = scan.findings.filter((f) => f.severity === "pass").length;
  const sets = groupFindings(problems);
  return (
    <article className="print-report mx-auto max-w-3xl space-y-10 pt-4">
      <div className="no-print flex justify-end">
        <button type="button" onClick={() => window.print()} className="rounded-xl bg-accent px-5 py-3 font-semibold text-accent-ink">
          {t.print.save}
        </button>
      </div>

      <header className="flex flex-wrap items-center gap-8 border-b border-rule pb-8">
        <GradeSeal letter={scan.grade ?? "F"} score={scan.score} />
        <div>
          <h1 className="font-display text-4xl font-semibold">{t.print.title(scan.host)}</h1>
          <p className="mt-2 text-lg">{t.results.verdicts[scan.grade ?? "F"]}</p>
          {scan.finished_at && <p className="mt-2 text-sm text-ink-soft">{t.print.generated(formatDate(scan.finished_at))}</p>}
        </div>
      </header>

      <section>
        <h2 className="font-display text-2xl font-semibold">{t.print.summary}</h2>
        <ol className="mt-3 list-decimal space-y-1 pl-6">
          {fixFirst(scan).map((s) => (
            <li key={s.key}>{s.findings[0].explanation?.title}</li>
          ))}
        </ol>
        <p className="mt-3 text-ink-soft">{t.print.passedCount(passed)}</p>
        {scan.redacted && problems.some((f) => f.evidence.observed === REDACTED_MARK) && (
          <p className="mt-3 text-sm text-ink-soft">{t.redacted.text}</p>
        )}
      </section>

      <section>
        <h2 className="font-display text-2xl font-semibold">{t.print.problems}</h2>
        {sets.flatMap(([, group]) => group).map((set) => {
          const e = set.findings[0].explanation!;
          const items = set.findings.map(itemLabel).filter(Boolean);
          return (
            <div key={set.key} className="break-inside-avoid border-b border-rule py-5">
              <SeverityTag severity={set.findings[0].severity} />
              <h3 className="mt-2 text-lg font-semibold">{e.title}</h3>
              <p className="mt-1">{e.summary}</p>
              {items.length > 0 && <p className="mt-1 text-sm"><b>{t.finding.foundIn}:</b> {items.join(", ")}</p>}
              <p className="mt-3 text-sm font-semibold">{t.finding.howToFix}</p>
              <ol className="list-decimal pl-6">
                {e.fix_steps.map((step) => <li key={step}>{step.replaceAll("`", "")}</li>)}
              </ol>
              <p className="mt-2 text-sm text-ink-soft">{t.finding.effort}: {e.effort} · {t.finding.who}: {e.who_can_fix}</p>
            </div>
          );
        })}
      </section>

      <section className="break-before-page">
        <h2 className="font-display text-2xl font-semibold">{t.print.appendix}</h2>
        {problems.map((f) => {
          const { holders, records } = attributions(f);
          return (
            <div key={f.id} className="break-inside-avoid border-b border-rule py-4 text-sm">
              <p className="font-mono font-semibold">{f.check_id} · {f.host}{f.dedupe_key ? ` · ${itemLabel(f)}` : ""}</p>
              <p className="mt-1 font-mono">{f.explanation?.technical}</p>
              <pre className="mt-2 font-mono text-xs whitespace-pre-wrap break-all">{JSON.stringify(f.evidence, null, 2)}</pre>
              {[...f.references, ...records].map((r) => <p key={r} className="break-all">{r}</p>)}
              {holders.map(([k, a]) => (
                <p key={k} className="mt-1 text-xs text-ink-soft">{a.notice}. {a.license} ({a.license_url})</p>
              ))}
            </div>
          );
        })}
      </section>
    </article>
  );
}
