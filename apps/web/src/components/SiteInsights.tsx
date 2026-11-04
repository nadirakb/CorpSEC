"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { api, type Benchmark, type Trends } from "@/lib/api";
import { formatDate } from "@/lib/dates";
import { t } from "@/lib/i18n";
import { benchmarkPercent, GRADE_LINES, plotPoints, STAGES, thisMonth } from "@/lib/insights";
import { gradeTone } from "@/lib/report";

const W = 640;
const H = 220;
const GUTTER = 28; // right edge, for the grade letters

/** Trends for one site: score over time, grade per area, time to fix, comparison. */
export function SiteInsights({ siteId, platformName }: { siteId: string; platformName: string | null }) {
  const [trends, setTrends] = useState<Trends | null>(null);
  const [bench, setBench] = useState<Benchmark | null>(null);

  useEffect(() => {
    let active = true;
    api.trends(siteId).then((x) => active && setTrends(x), () => undefined);
    api.benchmark(siteId).then((x) => active && setBench(x), () => undefined);
    return () => {
      active = false;
    };
  }, [siteId]);

  if (!trends || trends.points.length === 0) return null;
  const pct = benchmarkPercent(bench?.better_than ?? null);
  const recent = trends.points.slice(-8);

  return (
    <section aria-labelledby="trends-heading" className="space-y-6">
      <div className="flex flex-wrap items-baseline justify-between gap-3">
        <h2 id="trends-heading" className="font-display text-2xl font-semibold">{t.insights.title}</h2>
        <Link href={`/sites/${siteId}/report?month=${thisMonth()}`} className="text-sm font-semibold text-accent underline underline-offset-4">
          {t.insights.monthlyLink}
        </Link>
      </div>

      <div className="grid gap-4 sm:grid-cols-3">
        <Tile label={t.insights.openNow} value={String(trends.open_now)} />
        <Tile
          label={t.insights.timeToFix}
          value={trends.median_days_to_fix === null ? "–" : t.insights.days(trends.median_days_to_fix)}
          help={t.insights.fixedCount(trends.fixed_count)}
        />
        <Tile
          label={t.insights.comparison}
          value={pct === null ? "–" : `${pct}%`}
          help={
            pct === null
              ? t.insights.notEnough
              : t.insights.saferThan(pct, bench?.platform ? platformName : null, bench?.sample ?? 0)
          }
        />
      </div>

      {trends.points.length > 1 && <ScoreChart trends={trends} />}

      <div className="overflow-x-auto">
        <table className="w-full min-w-[28rem] text-left text-sm">
          <caption className="mb-2 text-left font-semibold">{t.insights.byArea}</caption>
          <thead>
            <tr className="text-ink-soft">
              <th className="py-1 pr-3 font-semibold">{t.insights.area}</th>
              {recent.map((p) => (
                <th key={p.scan_id} className="px-1 text-center font-normal tabular-nums">{formatDate(p.finished_at, false)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {STAGES.map((stage) => (
              <tr key={stage} className="border-t border-rule">
                <th scope="row" className="py-1.5 pr-3 font-semibold">{t.stages[stage]}</th>
                {recent.map((p) => {
                  const letter = p.stages[stage];
                  return (
                    <td key={p.scan_id} className="px-1 text-center">
                      {letter ? (
                        <span className="font-display font-bold" style={{ color: `var(--grade-${gradeTone(letter)})` }}>{letter}</span>
                      ) : (
                        <span className="text-ink-soft">–</span>
                      )}
                    </td>
                  );
                })}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}

function Tile({ label, value, help }: { label: string; value: string; help?: string }) {
  return (
    <div className="rounded-xl border border-rule bg-raised p-5">
      <p className="text-sm font-semibold text-ink-soft">{label}</p>
      <p className="font-display mt-1 text-3xl font-semibold tabular-nums">{value}</p>
      {help && <p className="mt-1 text-sm text-ink-soft">{help}</p>}
    </div>
  );
}

function ScoreChart({ trends }: { trends: Trends }) {
  const pts = plotPoints(trends.points, W - GUTTER, H, 12);
  const [hover, setHover] = useState<number | null>(null);
  const active = hover === null ? null : pts[hover];
  const path = pts.map((p, i) => `${i ? "L" : "M"}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
  const nearest = (clientX: number, rect: DOMRect) => {
    const x = ((clientX - rect.left) / rect.width) * W;
    let best = 0;
    pts.forEach((p, i) => {
      if (Math.abs(p.x - x) < Math.abs(pts[best].x - x)) best = i;
    });
    return best;
  };
  return (
    <figure className="rounded-xl border border-rule bg-raised p-5">
      <figcaption className="flex flex-wrap justify-between gap-2 text-sm">
        <span className="font-semibold">{t.insights.scoreOverTime}</span>
        <span aria-live="polite" className="tabular-nums text-ink-soft">
          {active
            ? t.insights.pointLabel(formatDate(active.point.finished_at, false), active.point.score ?? 0, active.point.grade ?? "?", active.point.open_problems)
            : t.insights.hoverHint}
        </span>
      </figcaption>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        className="mt-3 h-auto w-full touch-none"
        role="img"
        aria-label={t.insights.chartLabel(pts.length)}
        tabIndex={0}
        onPointerMove={(e) => setHover(nearest(e.clientX, e.currentTarget.getBoundingClientRect()))}
        onPointerLeave={() => setHover(null)}
        onKeyDown={(e) => {
          if (e.key === "ArrowRight") setHover((h) => Math.min(pts.length - 1, (h ?? -1) + 1));
          if (e.key === "ArrowLeft") setHover((h) => Math.max(0, (h ?? pts.length) - 1));
        }}
        onBlur={() => setHover(null)}
      >
        {GRADE_LINES.map(([score, letter]) => {
          const y = 12 + (1 - score / 100) * (H - 24);
          return (
            <g key={letter}>
              <line x1={0} x2={W - GUTTER} y1={y} y2={y} stroke="var(--rule)" strokeDasharray="3 4" strokeWidth={1} />
              <text x={W - 4} y={y + 4} textAnchor="end" fontSize={12} fill="var(--ink-soft)">{letter}</text>
            </g>
          );
        })}
        {active && <line x1={active.x} x2={active.x} y1={0} y2={H} stroke="var(--ink-soft)" strokeWidth={1} />}
        <path d={path} fill="none" stroke="var(--accent)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {pts.map((p, i) => (
          <circle
            key={p.point.scan_id}
            cx={p.x}
            cy={p.y}
            r={hover === i ? 6 : 4}
            fill="var(--accent)"
            stroke="var(--paper-raised)"
            strokeWidth={2}
          />
        ))}
      </svg>
      <details className="mt-3 text-sm">
        <summary className="cursor-pointer font-semibold">{t.admin.asTable}</summary>
        <table className="mt-2 w-full text-left tabular-nums">
          <thead><tr className="text-ink-soft"><th className="py-1">{t.admin.day}</th><th>{t.insights.score}</th><th>{t.insights.grade}</th><th>{t.insights.openNow}</th></tr></thead>
          <tbody>
            {[...trends.points].reverse().map((p) => (
              <tr key={p.scan_id} className="border-t border-rule">
                <td className="py-1"><Link href={`/scan/${p.scan_id}`} className="underline underline-offset-2">{formatDate(p.finished_at, false)}</Link></td>
                <td>{p.score ?? "–"}</td><td>{p.grade ?? "–"}</td><td>{p.open_problems}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </figure>
  );
}
