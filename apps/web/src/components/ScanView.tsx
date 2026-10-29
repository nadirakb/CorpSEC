"use client";

import Link from "next/link";
import { use, useCallback, useEffect, useState } from "react";

import { api, ApiError, type ProgressEvent, type Scan, type Stage } from "@/lib/api";
import { t } from "@/lib/i18n";
import { isFinished, stageStates } from "@/lib/report";

import { Results } from "./Results";
import { ScanProgress } from "./ScanProgress";

const POLL_MS = 3000;

export function ScanView({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [scan, setScan] = useState<Scan | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState<ProgressEvent | null>(null);
  const [lost, setLost] = useState(false);
  const [finishedChecks, setFinishedChecks] = useState(() => new Map<string, Stage>());

  const fail = useCallback((err: unknown) => {
    setError(err instanceof ApiError && err.status === 404 ? t.errors.notFound : t.errors.generic);
  }, []);

  /** Re-fetch the scan (after progress ends, or after a re-check/dismiss). */
  const load = useCallback(async () => {
    try {
      setScan(await api.getScan(id));
      setError(null);
    } catch (err) {
      fail(err);
    }
  }, [id, fail]);

  useEffect(() => {
    let active = true;
    api.getScan(id).then(
      (s) => active && setScan(s),
      (err) => active && fail(err),
    );
    return () => {
      active = false;
    };
  }, [id, fail]);

  const running = scan !== null && !isFinished(scan);

  // Live progress over SSE while the scan runs; polling if the stream drops.
  useEffect(() => {
    if (!running) return;
    const source = new EventSource(api.eventsUrl(id));
    let poll: ReturnType<typeof setInterval> | undefined;
    source.addEventListener("progress", (msg) => {
      const ev = JSON.parse((msg as MessageEvent).data) as ProgressEvent;
      if (ev.check_id && ev.stage) {
        const { check_id, stage } = ev;
        setFinishedChecks((prev) => new Map(prev).set(check_id, stage));
      }
      setProgress(ev);
      setLost(false);
    });
    source.addEventListener("done", () => {
      source.close();
      void load();
    });
    source.onerror = () => {
      setLost(true);
      poll ??= setInterval(() => void load(), POLL_MS);
    };
    return () => {
      source.close();
      if (poll) clearInterval(poll);
    };
  }, [running, id, load]);

  if (error) {
    return (
      <section className="mx-auto max-w-2xl pt-10">
        <h1 className="font-display text-3xl font-semibold">{error}</h1>
        <Link href="/" className="mt-6 inline-block font-semibold text-accent underline">
          {t.results.newScan}
        </Link>
      </section>
    );
  }
  if (!scan) return <ScanSkeleton />;
  if (running) {
    const total = progress?.total ?? 0;
    return (
      <ScanProgress
        host={scan.host}
        queued={scan.status === "queued" && !progress}
        completed={progress?.completed ?? 0}
        total={total}
        states={stageStates(finishedChecks, total, progress?.stage_totals ?? {})}
        lost={lost}
      />
    );
  }
  return <Results scan={scan} onChanged={load} />;
}

export function ScanSkeleton() {
  return (
    <div aria-busy="true" aria-live="polite" className="mx-auto max-w-2xl pt-10">
      <span className="sr-only">Loading…</span>
      <div className="h-12 w-3/4 animate-pulse rounded-lg bg-[color-mix(in_srgb,var(--ink)_8%,transparent)] motion-reduce:animate-none" />
      <div className="mt-6 h-40 animate-pulse rounded-xl bg-[color-mix(in_srgb,var(--ink)_6%,transparent)] motion-reduce:animate-none" />
    </div>
  );
}
