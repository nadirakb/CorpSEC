"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useCallback, useEffect, useId, useState } from "react";

import { api, ApiError, type Platform, type Site } from "@/lib/api";
import { formatDate } from "@/lib/dates";
import { t } from "@/lib/i18n";

import { GradeBadge } from "./GradeBadge";

const PLATFORMS: Platform[] = ["wordpress", "shopify", "wix", "squarespace", "webflow", "joomla", "drupal", "custom", "unknown"];
const ORDER = ["A+", "A", "B", "C", "D", "F"];

export function Dashboard() {
  const router = useRouter();
  const params = useSearchParams();
  const [sites, setSites] = useState<Site[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handle = useCallback(
    (err: unknown) => {
      if (err instanceof ApiError && err.status === 401) {
        router.replace(`/login?next=${encodeURIComponent("/dashboard" + (params.size ? `?${params}` : ""))}`);
      } else {
        setError(err instanceof ApiError ? err.message : t.errors.generic);
      }
    },
    [router, params],
  );

  const load = useCallback(async () => {
    try {
      setSites(await api.sites());
    } catch (err) {
      handle(err);
    }
  }, [handle]);

  useEffect(() => {
    let active = true;
    api.sites().then((s) => active && setSites(s), (err) => active && handle(err));
    return () => {
      active = false;
    };
  }, [handle]);

  return (
    <div className="space-y-12 pt-6">
      <header className="rise">
        <h1 className="font-display text-5xl font-semibold tracking-tight">{t.dashboard.title}</h1>
        <p className="mt-3 max-w-2xl text-lg text-ink-soft">{t.dashboard.lede}</p>
      </header>

      {error && <p role="alert" className="font-medium text-[var(--sev-critical)]">{error}</p>}

      {sites && (
        <section aria-label={t.dashboard.title}>
          {sites.length === 0 ? (
            <p className="text-lg">{t.dashboard.empty}</p>
          ) : (
            <ul className="grid gap-4 md:grid-cols-2">
              {sites.map((site) => (
                <li key={site.id}>
                  <SiteCard site={site} />
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      <AddSite initial={params.get("add") ?? ""} onAdded={(site) => {
        void load();
        router.push(`/sites/${site.id}`);
      }} />
    </div>
  );
}

function SiteCard({ site }: { site: Site }) {
  const grade = site.latest?.grade ?? null;
  const status = !site.verified
    ? t.dashboard.status.unverified
    : site.monitoring_paused_reason
      ? t.dashboard.status.paused
      : site.monitoring_enabled
        ? t.dashboard.status.monitoring
        : t.dashboard.status.off;
  const prev = site.previous_grade;
  const trend =
    grade && prev && grade !== prev
      ? ORDER.indexOf(grade) < ORDER.indexOf(prev)
        ? { up: true, text: t.dashboard.trendUp(prev) }
        : { up: false, text: t.dashboard.trendDown(prev) }
      : null;
  return (
    <Link
      href={`/sites/${site.id}`}
      className="flex items-center gap-5 rounded-2xl border border-rule bg-raised p-5 transition hover:border-ink-soft"
    >
      <GradeBadge letter={grade} />
      <div className="min-w-0 flex-1">
        <p className="truncate text-xl font-semibold">{site.domain}</p>
        <p className="text-sm text-ink-soft">
          {site.latest?.finished_at ? t.dashboard.lastChecked(formatDate(site.latest.finished_at, false)) : t.dashboard.neverChecked}
        </p>
        <p className="mt-1 text-sm font-semibold">{status}</p>
        {trend && (
          <p className="mt-1 text-sm font-semibold" style={{ color: trend.up ? "var(--sev-pass)" : "var(--sev-high)" }}>
            <span aria-hidden>{trend.up ? "▲ " : "▼ "}</span>
            {trend.text}
          </p>
        )}
      </div>
    </Link>
  );
}

function AddSite({ initial, onAdded }: { initial: string; onAdded: (site: Site) => void }) {
  const domainId = useId();
  const platformId = useId();
  const [domain, setDomain] = useState(initial);
  const [platform, setPlatform] = useState<Platform | "">("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  return (
    <section aria-labelledby="add-heading" className="rounded-2xl border border-rule bg-raised p-6 sm:p-8">
      <h2 id="add-heading" className="font-display text-2xl font-semibold">{t.dashboard.add}</h2>
      <form
        className="mt-5 grid gap-4 sm:grid-cols-[2fr_1fr_auto] sm:items-end"
        onSubmit={async (e) => {
          e.preventDefault();
          setBusy(true);
          setError(null);
          try {
            onAdded(await api.addSite(domain.trim(), platform || null));
          } catch (err) {
            setError(err instanceof ApiError ? err.message : t.errors.generic);
          } finally {
            setBusy(false);
          }
        }}
      >
        <div>
          <label htmlFor={domainId} className="mb-2 block font-semibold">{t.dashboard.addLabel}</label>
          <input
            id={domainId}
            required
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder={t.landing.placeholder}
            autoCapitalize="none"
            spellCheck={false}
            className="min-h-12 w-full rounded-xl border-2 border-rule bg-paper px-4 focus:border-accent focus:outline-none"
          />
        </div>
        <div>
          <label htmlFor={platformId} className="mb-2 block font-semibold">{t.dashboard.platformLabel}</label>
          <select
            id={platformId}
            value={platform}
            onChange={(e) => setPlatform(e.target.value as Platform | "")}
            className="min-h-12 w-full rounded-xl border-2 border-rule bg-paper px-3 focus:border-accent focus:outline-none"
          >
            <option value="">—</option>
            {PLATFORMS.map((p) => (
              <option key={p} value={p}>{t.platforms[p]}</option>
            ))}
          </select>
        </div>
        <button type="submit" disabled={busy || !domain.trim()} className="min-h-12 rounded-xl bg-accent px-6 font-semibold text-accent-ink disabled:opacity-60">
          {busy ? t.dashboard.adding : t.dashboard.add}
        </button>
      </form>
      <p role="alert" className="mt-3 min-h-6 font-medium text-[var(--sev-critical)]">{error}</p>
    </section>
  );
}
