"use client";

import { useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { dailyTotals, duration, type MetricStatus, metricStatus, percent } from "@/lib/admin";
import { type AdminOverview, api, ApiError, type FeedbackItem, type MetricValue } from "@/lib/api";
import { formatDate } from "@/lib/dates";
import { t } from "@/lib/i18n";

const RANGES = [7, 30, 90] as const;
const STALE_INTEL_HOURS = 48;

export function AdminDashboard() {
  const router = useRouter();
  const [days, setDays] = useState<number>(30);
  const [data, setData] = useState<AdminOverview | null>(null);
  const [feedback, setFeedback] = useState<FeedbackItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [overview, items] = await Promise.all([api.adminOverview(days), api.adminFeedback()]);
      setData(overview);
      setFeedback(items);
      setError(null);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) router.replace("/login?next=%2Fadmin");
      else if (err instanceof ApiError && err.status === 404) setError(t.admin.notAllowed);
      else setError(err instanceof ApiError ? err.message : t.errors.generic);
    }
  }, [days, router]);

  useEffect(() => {
    void load(); // eslint-disable-line react-hooks/set-state-in-effect -- fetch on range change
  }, [load]);

  if (error) return <p role="alert" className="pt-6 font-medium text-[var(--sev-critical)]">{error}</p>;
  if (!data) return <p className="pt-6 text-ink-soft">{t.admin.loading}</p>;
  const m = data.metrics;

  return (
    <div className="space-y-12 pt-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="font-display text-5xl font-semibold tracking-tight">{t.admin.title}</h1>
          <p className="mt-2 text-ink-soft">{t.admin.lede}</p>
        </div>
        <div role="group" aria-label={t.admin.range} className="flex gap-1 rounded-lg border border-rule p-1">
          {RANGES.map((r) => (
            <button
              key={r}
              type="button"
              aria-pressed={days === r}
              onClick={() => setDays(r)}
              className={`rounded-md px-3 py-1.5 text-sm font-semibold ${days === r ? "bg-ink text-paper" : "text-ink-soft hover:text-ink"}`}
            >
              {t.admin.days(r)}
            </button>
          ))}
        </div>
      </header>

      <section aria-labelledby="goals">
        <h2 id="goals" className="font-display text-2xl font-semibold">{t.admin.goals}</h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Goal label={t.admin.activation} help={t.admin.activationHelp} m={m.activation}
                detail={`${m.activation.signups} / ${m.activation.anonymous_scanners}`} />
          <Goal label={t.admin.action} help={t.admin.actionHelp} m={m.action}
                detail={`${m.action.acted} / ${m.action.cohort}`} />
          <Goal label={t.admin.falseAlarms} help={t.admin.falseAlarmsHelp} m={m.false_positive} lowerIsBetter digits={1}
                detail={`${m.false_positive.reports} / ${m.false_positive.problems_shown}`} />
          <Tile label={t.admin.optouts} value={String(m.safety.optouts)} help={m.safety.note} />
        </div>
      </section>

      <section aria-labelledby="live">
        <h2 id="live" className="font-display text-2xl font-semibold">{t.admin.now}</h2>
        <div className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Tile label={t.admin.queued} value={String(data.live.queued)}
                help={data.live.queued ? t.admin.oldest(duration(data.live.oldest_queued_seconds)) : undefined} />
          <Tile label={t.admin.running} value={String(data.live.running)} />
          <Tile label={t.admin.scanTime} value={data.scans.avg_seconds === null ? "–" : duration(data.scans.avg_seconds)}
                help={data.scans.p95_seconds === null ? undefined : t.admin.p95(duration(data.scans.p95_seconds))} />
          <Tile
            label={t.admin.intel}
            value={data.live.intel_age_hours === null ? "–" : `${data.live.intel_age_hours} h`}
            status={data.live.intel_age_hours === null ? undefined
              : data.live.intel_age_hours > STALE_INTEL_HOURS ? "missed" : "met"}
            help={t.admin.intelHelp}
          />
        </div>
      </section>

      <ScansChart data={data} days={days} />

      <section aria-labelledby="funnel" className="grid gap-10 lg:grid-cols-2">
        <div>
          <h2 id="funnel" className="font-display text-2xl font-semibold">{t.admin.funnel}</h2>
          <p className="mt-1 text-sm text-ink-soft">{t.admin.funnelHelp}</p>
          <Funnel steps={data.funnel} />
        </div>
        <div className="space-y-8">
          <CountTable title={t.admin.commonProblems} rows={data.scans.common_problems} unit={t.admin.scansUnit} />
          <CountTable title={t.admin.failingChecks} rows={data.scans.failing_checks} unit={t.admin.scansUnit}
                      empty={t.admin.noFailures} />
        </div>
      </section>

      <FeedbackList items={feedback ?? []} byCheck={data.feedback_by_check} onResolved={load} />
    </div>
  );
}

const STATUS_ICON: Record<MetricStatus, string> = { met: "✓", missed: "!", no_data: "·" };

function StatusBadge({ status }: { status: MetricStatus }) {
  const color = status === "met" ? "var(--sev-pass)" : status === "missed" ? "var(--sev-high)" : "var(--ink-soft)";
  return (
    <span className="inline-flex items-center gap-1 text-sm font-semibold" style={{ color }}>
      <span aria-hidden className="inline-flex size-5 items-center justify-center rounded-full border-2 border-current text-xs">
        {STATUS_ICON[status]}
      </span>
      {t.admin.status[status]}
    </span>
  );
}

function Goal({ label, help, m, detail, lowerIsBetter = false, digits = 0 }: {
  label: string; help: string; m: MetricValue; detail: string; lowerIsBetter?: boolean; digits?: number;
}) {
  const status = metricStatus(m, lowerIsBetter);
  return (
    <div className="rounded-xl border border-rule bg-raised p-5">
      <p className="text-sm font-semibold text-ink-soft">{label}</p>
      <p className="font-display mt-1 text-4xl font-semibold tabular-nums">{percent(m.value, digits)}</p>
      <p className="mt-1 text-sm text-ink-soft tabular-nums">
        {detail} · {t.admin.target(`${lowerIsBetter ? "≤" : "≥"} ${percent(m.target ?? null, digits)}`)}
      </p>
      <div className="mt-3"><StatusBadge status={status} /></div>
      <p className="mt-3 text-sm text-ink-soft">{help}</p>
    </div>
  );
}

function Tile({ label, value, help, status }: { label: string; value: string; help?: string; status?: MetricStatus }) {
  return (
    <div className="rounded-xl border border-rule bg-raised p-5">
      <p className="text-sm font-semibold text-ink-soft">{label}</p>
      <p className="font-display mt-1 text-4xl font-semibold tabular-nums">{value}</p>
      {status && <div className="mt-2"><StatusBadge status={status} /></div>}
      {help && <p className="mt-2 text-sm text-ink-soft">{help}</p>}
    </div>
  );
}

function ScansChart({ data, days }: { data: AdminOverview; days: number }) {
  const rows = dailyTotals(data.scans.per_day, days);
  const max = Math.max(1, ...rows.map((r) => r.total));
  const [hover, setHover] = useState<number | null>(null);
  const total = rows.reduce((a, r) => a + r.total, 0);
  const failed = rows.reduce((a, r) => a + (r.byStatus.failed ?? 0), 0);
  const shown = hover === null ? null : rows[hover];
  return (
    <section aria-labelledby="scans">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h2 id="scans" className="font-display text-2xl font-semibold">{t.admin.scansPerDay}</h2>
        <p className="text-sm text-ink-soft tabular-nums">{t.admin.scansSummary(total, failed)}</p>
      </div>
      <div className="relative mt-4 rounded-xl border border-rule bg-raised p-5">
        <p aria-live="polite" className="min-h-6 text-sm tabular-nums">
          {shown ? (
            <>
              <span className="font-semibold">{formatDate(`${shown.day}T12:00:00Z`, false)}</span>
              {": "}
              {t.admin.scansCount(shown.total)}
              {Object.entries(shown.byStatus).map(([k, v]) => <span key={k} className="text-ink-soft"> · {k} {v}</span>)}
            </>
          ) : (
            <span className="text-ink-soft">{t.admin.hoverHint}</span>
          )}
        </p>
        <div className="mt-2 flex h-40 items-end gap-[2px] border-b border-rule" onMouseLeave={() => setHover(null)}>
          {rows.map((r, i) => (
            <button
              key={r.day}
              type="button"
              aria-label={`${r.day}: ${t.admin.scansCount(r.total)}`}
              onMouseEnter={() => setHover(i)}
              onFocus={() => setHover(i)}
              className="group flex h-full flex-1 items-end focus:outline-none"
            >
              <span
                className="block w-full rounded-t-[4px] bg-accent group-hover:opacity-80 group-focus-visible:outline group-focus-visible:outline-2 group-focus-visible:outline-ink"
                style={{ height: r.total ? `${Math.max(2, (r.total / max) * 100)}%` : "0" }}
              />
            </button>
          ))}
        </div>
        <div className="mt-1 flex justify-between text-xs text-ink-soft tabular-nums">
          <span>{rows[0]?.day}</span>
          <span>{t.admin.peak(max)}</span>
          <span>{rows[rows.length - 1]?.day}</span>
        </div>
        <details className="mt-3 text-sm">
          <summary className="cursor-pointer font-semibold">{t.admin.asTable}</summary>
          <table className="mt-2 w-full text-left tabular-nums">
            <thead><tr className="text-ink-soft"><th className="py-1">{t.admin.day}</th><th>{t.admin.scansUnit}</th><th>{t.admin.failed}</th></tr></thead>
            <tbody>
              {rows.filter((r) => r.total).map((r) => (
                <tr key={r.day} className="border-t border-rule"><td className="py-1">{r.day}</td><td>{r.total}</td><td>{r.byStatus.failed ?? 0}</td></tr>
              ))}
            </tbody>
          </table>
        </details>
      </div>
    </section>
  );
}

function Funnel({ steps }: { steps: AdminOverview["funnel"] }) {
  const first = Math.max(1, steps[0]?.visitors ?? 0);
  return (
    <ol className="mt-4 space-y-3">
      {steps.map((s) => (
        <li key={s.step}>
          <div className="flex justify-between text-sm">
            <span className="font-semibold">{s.step}</span>
            <span className="tabular-nums text-ink-soft">{s.visitors} · {percent(s.visitors / first)}</span>
          </div>
          <div className="mt-1 h-3 rounded-[4px] bg-[color-mix(in_srgb,var(--ink)_6%,transparent)]">
            <div className="h-3 rounded-[4px] bg-accent" style={{ width: `${(s.visitors / first) * 100}%` }} />
          </div>
        </li>
      ))}
    </ol>
  );
}

function CountTable({ title, rows, unit, empty }: {
  title: string; rows: { check_id: string; count: number }[]; unit: string; empty?: string;
}) {
  return (
    <div>
      <h2 className="font-display text-2xl font-semibold">{title}</h2>
      {rows.length === 0 ? (
        <p className="mt-2 text-ink-soft">{empty ?? t.admin.noData}</p>
      ) : (
        <table className="mt-3 w-full text-left text-sm tabular-nums">
          <thead><tr className="text-ink-soft"><th className="py-1">{t.admin.check}</th><th className="text-right">{unit}</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.check_id} className="border-t border-rule">
                <td className="py-1.5 font-mono">{r.check_id}</td>
                <td className="text-right">{r.count}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

function FeedbackList({ items, byCheck, onResolved }: {
  items: FeedbackItem[]; byCheck: AdminOverview["feedback_by_check"]; onResolved: () => Promise<void>;
}) {
  const [busy, setBusy] = useState<number | null>(null);
  return (
    <section aria-labelledby="feedback">
      <h2 id="feedback" className="font-display text-2xl font-semibold">{t.admin.feedback}</h2>
      {byCheck.length > 0 && (
        <p className="mt-1 text-sm text-ink-soft">
          {t.admin.openByCheck}: {byCheck.map((b) => `${b.check_id} (${b.open})`).join(", ")}
        </p>
      )}
      {items.length === 0 ? (
        <p className="mt-3 text-ink-soft">{t.admin.noFeedback}</p>
      ) : (
        <ul className="mt-4 space-y-3">
          {items.map((f) => (
            <li key={f.id} className="rounded-xl border border-rule bg-raised p-4">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <p>
                  <span className="font-mono font-semibold">{f.check_id}</span>
                  <span className="text-ink-soft"> v{f.check_version} · {t.feedback.reasons[f.reason]}</span>
                </p>
                <span className="text-sm text-ink-soft">{formatDate(f.created_at)}</span>
              </div>
              {f.note && <p className="mt-2">“{f.note}”</p>}
              <details className="mt-2 text-sm">
                <summary className="cursor-pointer font-semibold">{t.finding.evidence}</summary>
                <pre className="mt-2 max-h-60 overflow-auto rounded bg-paper p-3 font-mono text-xs whitespace-pre-wrap break-all">
                  {JSON.stringify(f.evidence, null, 2)}
                </pre>
              </details>
              <button
                type="button"
                disabled={busy === f.id}
                onClick={async () => {
                  setBusy(f.id);
                  await api.resolveFeedback(f.id).catch(() => undefined);
                  await onResolved();
                  setBusy(null);
                }}
                className="mt-3 rounded-lg border-2 border-rule px-3 py-1.5 text-sm font-semibold hover:border-ink-soft disabled:opacity-50"
              >
                {t.admin.resolve}
              </button>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
