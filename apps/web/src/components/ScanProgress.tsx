import type { Stage } from "@/lib/api";
import { t } from "@/lib/i18n";
import { STAGES, type StageState } from "@/lib/report";

type Props = {
  host: string;
  queued: boolean;
  completed: number;
  total: number;
  states: Record<Stage, StageState>;
  lost: boolean;
};

export function ScanProgress({ host, queued, completed, total, states, lost }: Props) {
  const pct = total ? Math.round((completed / total) * 100) : 0;
  return (
    <section aria-labelledby="progress-heading" className="rise mx-auto max-w-2xl pt-10">
      <h1 id="progress-heading" className="font-display text-4xl font-semibold tracking-tight sm:text-5xl">
        {t.progress.heading(host)}
      </h1>
      <p className="mt-3 text-lg text-ink-soft">{t.progress.lede}</p>

      <div className="mt-10">
        <div
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={pct}
          aria-label={total ? t.progress.counter(completed, total) : t.progress.queued}
          className="h-3 overflow-hidden rounded-full bg-[color-mix(in_srgb,var(--ink)_10%,transparent)]"
        >
          <div className="h-full rounded-full bg-accent transition-[width] duration-500" style={{ width: `${Math.max(pct, queued ? 2 : 4)}%` }} />
        </div>
        <p className="mt-2 text-sm text-ink-soft" aria-live="polite">
          {queued || !total ? t.progress.queued : t.progress.counter(completed, total)}
        </p>
      </div>

      <ol className="mt-8 divide-y divide-rule rounded-xl border border-rule bg-raised">
        {STAGES.map((stage) => (
          <li key={stage} className="flex items-center justify-between px-5 py-4">
            <span className="font-semibold">{t.stages[stage]}</span>
            <StageBadge state={states[stage]} />
          </li>
        ))}
      </ol>
      {lost && <p className="mt-4 text-sm text-ink-soft">{t.progress.lost}</p>}
    </section>
  );
}

function StageBadge({ state }: { state: StageState }) {
  const label = t.progress.stageState[state];
  if (state === "done") {
    return (
      <span className="inline-flex items-center gap-1.5 font-semibold" style={{ color: "var(--sev-pass)" }}>
        <svg aria-hidden width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4">
          <path d="M5 12l4 4 10-10" />
        </svg>
        {label}
      </span>
    );
  }
  if (state === "running") {
    return (
      <span className="inline-flex items-center gap-2 font-semibold text-accent">
        <span aria-hidden className="size-2.5 animate-pulse rounded-full bg-accent motion-reduce:animate-none" />
        {label}
      </span>
    );
  }
  return <span className="text-ink-soft">{label}</span>;
}
