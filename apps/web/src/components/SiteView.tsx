"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { use, useCallback, useEffect, useState } from "react";

import { api, ApiError, type SiteDetail } from "@/lib/api";
import { formatDate } from "@/lib/dates";
import { t } from "@/lib/i18n";
import { gradeTone } from "@/lib/report";

import { GradeBadge } from "./GradeBadge";
import { ScanSkeleton } from "./ScanView";
import { VerifyWizard } from "./VerifyWizard";

export function SiteView({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const router = useRouter();
  const [site, setSite] = useState<SiteDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const handle = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) router.replace(`/login?next=/sites/${id}`);
      else setError(err instanceof ApiError ? err.message : t.errors.generic);
    },
    [router, id],
  );
  const load = useCallback(async () => {
    try {
      setSite(await api.site(id));
    } catch (err) {
      handle(err);
    }
  }, [id, handle]);

  useEffect(() => {
    let active = true;
    api.site(id).then((s) => active && setSite(s), (err) => active && handle(err));
    return () => {
      active = false;
    };
  }, [id, handle]);

  if (error) return <p role="alert" className="pt-10 text-lg">{error}</p>;
  if (!site) return <ScanSkeleton />;

  const finished = site.history.filter((h) => h.grade);
  return (
    <div className="space-y-10 pt-4">
      <Link href="/dashboard" className="text-sm font-semibold text-accent underline-offset-4 hover:underline">
        ← {t.site.back}
      </Link>
      <header className="rise flex flex-wrap items-center gap-6">
        <GradeBadge letter={site.latest?.grade ?? null} size="lg" />
        <div className="flex-1">
          <h1 className="font-display text-4xl font-semibold tracking-tight sm:text-5xl">{site.domain}</h1>
          {site.latest?.finished_at && (
            <p className="mt-1 text-ink-soft">{t.dashboard.lastChecked(formatDate(site.latest.finished_at))}</p>
          )}
        </div>
        <div className="flex flex-wrap gap-3">
          {site.latest && (
            <Link href={`/scan/${site.latest.id}`} className="rounded-xl border-2 border-rule px-5 py-3 font-semibold hover:border-ink-soft">
              {t.site.viewReport}
            </Link>
          )}
          <button
            type="button"
            disabled={!!busy}
            onClick={async () => {
              setBusy("scan");
              try {
                const scan = await api.scanSite(site.id);
                router.push(`/scan/${scan.id}`);
              } catch (err) {
                handle(err);
                setBusy(null);
              }
            }}
            className="rounded-xl bg-accent px-5 py-3 font-semibold text-accent-ink disabled:opacity-60"
          >
            {busy === "scan" ? t.site.scanning : t.site.scanNow}
          </button>
        </div>
      </header>

      {!site.verified && site.instructions && <VerifyWizard site={site} onVerified={() => void load()} />}

      {site.verified && (
        <section aria-labelledby="monitoring-heading" className="rounded-2xl border border-rule bg-raised p-6">
          <div className="flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 id="monitoring-heading" className="text-xl font-semibold">{t.site.monitoring}</h2>
              {site.monitoring_paused_reason === "verification_lost" ? (
                <p className="mt-1 text-[var(--sev-high)]">{t.site.pausedLost}</p>
              ) : (
                site.monitoring_enabled && site.next_scan_at && (
                  <p className="mt-1 text-ink-soft">{t.site.nextScan(formatDate(site.next_scan_at))}</p>
                )
              )}
            </div>
            <button
              type="button"
              role="switch"
              aria-checked={site.monitoring_enabled}
              aria-labelledby="monitoring-heading"
              disabled={!!busy}
              onClick={async () => {
                setBusy("toggle");
                try {
                  await api.updateSite(site.id, { monitoring_enabled: !site.monitoring_enabled });
                  await load();
                } catch (err) {
                  handle(err);
                } finally {
                  setBusy(null);
                }
              }}
              className={`relative inline-flex h-9 w-24 items-center rounded-full border-2 px-1 font-semibold transition ${site.monitoring_enabled ? "border-accent bg-accent text-accent-ink" : "border-rule"}`}
            >
              <span className={`absolute size-6 rounded-full bg-current transition-[left] ${site.monitoring_enabled ? "left-[calc(100%-1.9rem)] opacity-90" : "left-1 opacity-40"}`} aria-hidden />
              <span className={`w-full text-sm ${site.monitoring_enabled ? "pr-7 text-left pl-2" : "pl-8 text-left"}`}>
                {site.monitoring_enabled ? t.site.monitoringOn : t.site.monitoringOff}
              </span>
            </button>
          </div>
        </section>
      )}

      <section aria-labelledby="history-heading">
        <h2 id="history-heading" className="font-display text-2xl font-semibold">{t.site.history}</h2>
        {finished.length === 0 ? (
          <p className="mt-3 text-ink-soft">{t.site.noHistory}</p>
        ) : (
          <ol className="mt-4 flex items-end gap-3 overflow-x-auto pb-2" aria-label={t.site.history}>
            {[...finished].reverse().map((h) => (
              <li key={h.id} className="flex flex-col items-center gap-1">
                <Link href={`/scan/${h.id}`} className="flex flex-col items-center gap-1 rounded-lg p-1 hover:bg-[color-mix(in_srgb,var(--ink)_5%,transparent)]">
                  <span
                    className="w-10 rounded-t-md"
                    style={{ height: `${Math.max(8, (h.score ?? 0) * 1.2)}px`, background: `var(--grade-${gradeTone(h.grade)})` }}
                    aria-hidden
                  />
                  <span className="font-display text-lg font-bold" style={{ color: `var(--grade-${gradeTone(h.grade)})` }}>{h.grade}</span>
                  <span className="text-xs text-ink-soft">{formatDate(h.finished_at, false)}</span>
                </Link>
              </li>
            ))}
          </ol>
        )}
      </section>

      {site.alerts.length > 0 && (
        <section aria-labelledby="alerts-heading">
          <h2 id="alerts-heading" className="font-display text-2xl font-semibold">{t.site.alerts}</h2>
          <ul className="mt-3 divide-y divide-rule rounded-xl border border-rule bg-raised">
            {site.alerts.map((a, i) => (
              <li key={i} className="flex justify-between gap-4 px-5 py-3">
                <span className="font-semibold">{t.site.alertKinds[a.kind] ?? a.kind}</span>
                <span className="text-sm text-ink-soft">{formatDate(a.created_at)}</span>
              </li>
            ))}
          </ul>
        </section>
      )}

      <button
        type="button"
        onClick={async () => {
          if (!window.confirm(t.site.removeConfirm)) return;
          try {
            await api.deleteSite(site.id);
            router.push("/dashboard");
          } catch (err) {
            handle(err);
          }
        }}
        className="text-sm font-semibold text-[var(--sev-critical)] underline-offset-4 hover:underline"
      >
        {t.site.remove}
      </button>
    </div>
  );
}
