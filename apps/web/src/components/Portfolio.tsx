"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api, type Portfolio } from "@/lib/api";
import { t } from "@/lib/i18n";

import { SeverityTag } from "./SeverityTag";

/** Across all of a person's sites: overall numbers and one combined "fix these first" list. */
export function PortfolioOverview({ refreshKey }: { refreshKey: number }) {
  const [data, setData] = useState<Portfolio | null>(null);

  useEffect(() => {
    let active = true;
    api.portfolio().then((p) => active && setData(p), () => undefined);
    return () => {
      active = false;
    };
  }, [refreshKey]);

  if (!data || data.sites.length < 2) return null; // one site: its own page says it all
  const p = t.portfolio;
  return (
    <section aria-labelledby="portfolio-heading" className="space-y-5">
      <h2 id="portfolio-heading" className="font-display text-2xl font-semibold">{p.title}</h2>
      <div className="grid gap-4 sm:grid-cols-3">
        <Stat label={p.sites} value={String(data.sites.length)} />
        <Stat label={p.average} value={data.average_score === null ? "–" : String(Math.round(data.average_score))} />
        <Stat label={p.serious} value={String(data.open_serious)} />
      </div>
      {data.fix_first.length > 0 && (
        <div className="rounded-xl border border-rule bg-raised p-5">
          <h3 className="font-semibold">{p.fixFirst}</h3>
          <ol className="mt-3 space-y-3">
            {data.fix_first.map((item, i) => (
              <li key={item.finding_id} className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span aria-hidden className="font-display w-6 text-lg font-semibold text-ink-soft">{i + 1}</span>
                <SeverityTag severity={item.severity} />
                <Link href={`/scan/${item.scan_id}`} className="font-semibold underline-offset-4 hover:underline">
                  {item.title}
                </Link>
                <span className="text-sm text-ink-soft">
                  {item.domain}
                  {item.effort ? ` · ${item.effort}` : ""}
                </span>
              </li>
            ))}
          </ol>
        </div>
      )}
    </section>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-xl border border-rule bg-raised p-5">
      <p className="text-sm font-semibold text-ink-soft">{label}</p>
      <p className="font-display mt-1 text-3xl font-semibold tabular-nums">{value}</p>
    </div>
  );
}
