"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { use, useEffect, useState } from "react";

import { api, ApiError, type MonthlyReport, type ProblemLine } from "@/lib/api";
import { formatDate } from "@/lib/dates";
import { t } from "@/lib/i18n";
import { monthName, thisMonth } from "@/lib/insights";

import { GradeBadge } from "./GradeBadge";
import { SeverityTag } from "./SeverityTag";

function shiftMonth(month: string, by: number): string {
  const [y, m] = month.split("-").map(Number);
  return new Date(Date.UTC(y, m - 1 + by, 1)).toISOString().slice(0, 7);
}

/** One month of a site in plain words, for the owner's boss or client.
 *  "Save as PDF" uses the browser's print dialog, like the scan report. */
export function MonthlyReportView({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const search = useSearchParams();
  const month = /^\d{4}-\d{2}$/.test(search.get("month") ?? "") ? (search.get("month") as string) : thisMonth();
  const [report, setReport] = useState<MonthlyReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.monthly(id, month).then(
      (r) => active && setReport(r),
      (err) => {
        if (!active) return;
        if (err instanceof ApiError && err.status === 401) router.replace(`/login?next=${encodeURIComponent(`/sites/${id}/report?month=${month}`)}`);
        else setError(err instanceof ApiError ? err.message : t.errors.generic);
      },
    );
    return () => {
      active = false;
    };
  }, [id, month, router]);

  if (error) return <p role="alert" className="pt-10 text-lg">{error}</p>;
  if (!report) return <p className="pt-10 text-ink-soft">{t.admin.loading}</p>;
  const m = t.monthly;

  return (
    <article className="print-report mx-auto max-w-3xl space-y-10 pt-4">
      <nav className="no-print flex flex-wrap items-center justify-between gap-3">
        <Link href={`/sites/${id}`} className="text-sm font-semibold text-accent underline-offset-4 hover:underline">
          ← {report.domain}
        </Link>
        <div className="flex items-center gap-2">
          <Link href={`/sites/${id}/report?month=${shiftMonth(month, -1)}`} className="rounded-lg border-2 border-rule px-3 py-1.5 text-sm font-semibold">
            ← {m.previous}
          </Link>
          <Link href={`/sites/${id}/report?month=${shiftMonth(month, 1)}`} className="rounded-lg border-2 border-rule px-3 py-1.5 text-sm font-semibold">
            {m.next} →
          </Link>
          <button type="button" onClick={() => window.print()} className="rounded-xl bg-accent px-4 py-2 font-semibold text-accent-ink">
            {t.print.save}
          </button>
        </div>
      </nav>

      <header>
        <p className="text-sm font-semibold uppercase tracking-[0.1em] text-ink-soft">{m.kicker}</p>
        <h1 className="font-display mt-1 text-4xl font-semibold">{m.title(report.domain, monthName(report.month))}</h1>
      </header>

      {report.scans === 0 && report.end_grade === null ? (
        <p className="text-lg">{m.noScans}</p>
      ) : (
        <>
          <section className="flex flex-wrap items-center gap-6 rounded-xl border border-rule bg-raised p-6">
            <div className="text-center">
              <p className="mb-2 text-sm text-ink-soft">{m.start}</p>
              <GradeBadge letter={report.start_grade} />
            </div>
            <span aria-hidden className="text-3xl text-ink-soft">→</span>
            <div className="text-center">
              <p className="mb-2 text-sm text-ink-soft">{m.end}</p>
              <GradeBadge letter={report.end_grade} />
            </div>
            <p className="flex-1 text-lg">{m.summary(report.scans, report.fixed.length, report.new.length, report.open_at_end.length)}</p>
          </section>
          <Lines title={m.fixed} empty={m.noneFixed} lines={report.fixed} />
          <Lines title={m.new} empty={m.noneNew} lines={report.new} />
          <Lines title={m.open} empty={m.noneOpen} lines={report.open_at_end} />
          {report.alerts.length > 0 && (
            <section>
              <h2 className="font-display text-2xl font-semibold">{t.site.alerts}</h2>
              <ul className="mt-3 space-y-1">
                {report.alerts.map((a, i) => (
                  <li key={i}>{t.site.alertKinds[a.kind] ?? a.kind} · <span className="text-ink-soft">{formatDate(a.at)}</span></li>
                ))}
              </ul>
            </section>
          )}
        </>
      )}
    </article>
  );
}

function Lines({ title, empty, lines }: { title: string; empty: string; lines: ProblemLine[] }) {
  return (
    <section>
      <h2 className="font-display text-2xl font-semibold">{title}</h2>
      {lines.length === 0 ? (
        <p className="mt-2 text-ink-soft">{empty}</p>
      ) : (
        <ul className="mt-3 space-y-2">
          {lines.map((l) => (
            <li key={`${l.check_id}:${l.item}`} className="flex flex-wrap items-center gap-3">
              <SeverityTag severity={l.severity} />
              <span>{l.title}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
