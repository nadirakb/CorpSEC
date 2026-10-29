"use client";

import { useRouter } from "next/navigation";
import { useId, useState } from "react";

import { api, ApiError } from "@/lib/api";
import { t } from "@/lib/i18n";

export function ScanForm() {
  const router = useRouter();
  const inputId = useId();
  const errorId = useId();
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (!target.trim()) return;
    setBusy(true);
    setError(null);
    try {
      const { id } = await api.startScan(target);
      router.push(`/scan/${id}`);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : t.errors.generic);
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} noValidate className="max-w-xl">
      <label htmlFor={inputId} className="mb-2 block font-semibold">
        {t.landing.label}
      </label>
      <div className="flex flex-col gap-3 sm:flex-row">
        <input
          id={inputId}
          name="target"
          type="text"
          inputMode="url"
          autoComplete="url"
          autoCapitalize="none"
          spellCheck={false}
          required
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder={t.landing.placeholder}
          aria-invalid={!!error}
          aria-describedby={error ? errorId : undefined}
          className="min-h-14 flex-1 rounded-xl border-2 border-rule bg-raised px-4 text-lg placeholder:text-ink-soft/60 focus:border-accent focus:outline-none"
        />
        <button
          type="submit"
          disabled={busy || !target.trim()}
          className="min-h-14 rounded-xl bg-accent px-7 text-lg font-semibold text-accent-ink shadow-sm transition hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {busy ? t.landing.submitting : t.landing.submit}
        </button>
      </div>
      <p id={errorId} role="alert" className="mt-3 min-h-6 font-medium text-[var(--sev-critical)]">
        {error}
      </p>
    </form>
  );
}
