"use client";

import Link from "next/link";
import { useState } from "react";

import type { Scan } from "@/lib/api";
import { t } from "@/lib/i18n";
import { capApplied, fixFirst, gradeTone, groupFindings, STAGES } from "@/lib/report";

import { FindingCard } from "./FindingCard";
import { GradeSeal } from "./GradeSeal";

export function Results({ scan, onChanged }: { scan: Scan; onChanged: () => Promise<void> }) {
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
            <Link href="/" className="rounded-lg border-2 border-rule px-4 py-2 font-semibold hover:border-ink-soft">
              {t.results.newScan}
            </Link>
          </div>
        </div>
      </header>

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
                    <FindingCard findings={set.findings} defaultOpen={i === 0} onChanged={onChanged} />
                  </div>
                </li>
              ))}
            </ol>
          </>
        ) : (
          <p className="mt-3 text-lg">{t.results.nothingToFix}</p>
        )}
      </section>

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
                    <FindingCard findings={set.findings} onChanged={onChanged} />
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
