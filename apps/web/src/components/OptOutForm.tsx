"use client";

import { useId, useState } from "react";

import { api, ApiError } from "@/lib/api";
import { t } from "@/lib/i18n";

import { CopyField } from "./CopyField";

export function OptOutForm() {
  const inputId = useId();
  const [domain, setDomain] = useState("");
  const [record, setRecord] = useState<{ domain: string; txt_value: string } | null>(null);
  const [message, setMessage] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function run(action: () => Promise<void>) {
    setBusy(true);
    setMessage(null);
    try {
      await action();
    } catch (err) {
      setMessage({ ok: false, text: err instanceof ApiError ? err.message : t.errors.generic });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <form
        className="flex flex-col gap-3 sm:flex-row sm:items-end"
        onSubmit={(e) => {
          e.preventDefault();
          void run(async () => {
            const info = await api.optoutInfo(domain.trim());
            setRecord(info);
            if (info.opted_out) setMessage({ ok: true, text: t.bot.done(info.domain) });
          });
        }}
      >
        <div className="flex-1">
          <label htmlFor={inputId} className="mb-2 block font-semibold">{t.bot.domainLabel}</label>
          <input id={inputId} required value={domain} onChange={(e) => setDomain(e.target.value)} placeholder={t.landing.placeholder} autoCapitalize="none" spellCheck={false} className="min-h-12 w-full rounded-xl border-2 border-rule bg-paper px-4" />
        </div>
        <button type="submit" disabled={busy || !domain.trim()} className="min-h-12 rounded-xl border-2 border-rule px-5 font-semibold disabled:opacity-60">
          {t.bot.getRecord}
        </button>
      </form>
      {record && (
        <div className="space-y-3">
          <p>{t.bot.addRecord}</p>
          <CopyField label={t.verify.valueLabel} value={record.txt_value} />
          <button
            type="button"
            disabled={busy}
            onClick={() => void run(async () => {
              const r = await api.optout(record.domain);
              if (r.opted_out) setMessage({ ok: true, text: t.bot.done(r.domain) });
            })}
            className="min-h-12 rounded-xl bg-accent px-6 font-semibold text-accent-ink disabled:opacity-60"
          >
            {t.bot.confirm}
          </button>
        </div>
      )}
      <p role="status" aria-live="polite" className="min-h-6 font-medium" style={{ color: message ? (message.ok ? "var(--sev-pass)" : "var(--sev-high)") : undefined }}>
        {message?.text}
      </p>
    </div>
  );
}
