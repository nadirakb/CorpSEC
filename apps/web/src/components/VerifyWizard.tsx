"use client";

import { useState } from "react";

import { api, ApiError, type Site, type VerifyMethod } from "@/lib/api";
import { t } from "@/lib/i18n";

import { CopyField } from "./CopyField";

const HOSTED = new Set(["wix", "shopify", "squarespace", "webflow"]);

export function VerifyWizard({ site, onVerified }: { site: Site; onVerified: () => void }) {
  const ins = site.instructions!;
  const [method, setMethod] = useState<VerifyMethod>(site.platform && HOSTED.has(site.platform) ? "meta" : "dns");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const methods: VerifyMethod[] = ["dns", "meta", "file"];

  return (
    <section aria-labelledby="verify-heading" className="rounded-2xl border-2 border-accent/40 bg-raised p-6 sm:p-8">
      <h2 id="verify-heading" className="font-display text-3xl font-semibold">{t.verify.title}</h2>
      <p className="mt-2 max-w-2xl text-ink-soft">{t.verify.lede}</p>

      <div role="tablist" aria-label={t.verify.title} className="mt-6 flex flex-wrap gap-2">
        {methods.map((m) => (
          <button
            key={m}
            role="tab"
            id={`tab-${m}`}
            aria-selected={method === m}
            aria-controls={`panel-${m}`}
            onClick={() => { setMethod(m); setResult(null); }}
            className={`rounded-xl border-2 px-4 py-2 text-left ${method === m ? "border-accent bg-accent/10" : "border-rule"}`}
          >
            <span className="block font-semibold">{t.verify.methods[m].tab}</span>
            <span className="block text-sm text-ink-soft">{t.verify.methods[m].best}</span>
          </button>
        ))}
      </div>

      <div role="tabpanel" id={`panel-${method}`} aria-labelledby={`tab-${method}`} className="mt-6 space-y-5">
        <ol className="list-decimal space-y-1 pl-5">
          {(method === "dns" ? t.verify.dnsSteps : method === "meta" ? t.verify.metaSteps : t.verify.fileSteps).map((s) => (
            <li key={s}>{s}</li>
          ))}
        </ol>
        {method === "dns" && <CopyField label={t.verify.valueLabel} value={ins.txt_value} />}
        {method === "meta" && <CopyField label={t.verify.valueLabel} value={ins.meta_tag} />}
        {method === "file" && (
          <>
            <CopyField label={t.verify.valueLabel} value={ins.file_content} />
            <CopyField label={t.verify.addressLabel} value={ins.file_url} />
          </>
        )}
        <button
          type="button"
          disabled={busy}
          onClick={async () => {
            setBusy(true);
            setResult(null);
            try {
              const r = await api.verifySite(site.id, method);
              setResult({ ok: r.verified, text: r.verified ? t.verify.success : r.message });
              if (r.verified) onVerified();
            } catch (err) {
              setResult({ ok: false, text: err instanceof ApiError ? err.message : t.errors.generic });
            } finally {
              setBusy(false);
            }
          }}
          className="min-h-12 rounded-xl bg-accent px-6 font-semibold text-accent-ink disabled:opacity-60"
        >
          {busy ? t.verify.checking : t.verify.check}
        </button>
        <p role="status" aria-live="polite" className="min-h-6 font-medium" style={{ color: result ? (result.ok ? "var(--sev-pass)" : "var(--sev-high)") : undefined }}>
          {result?.text}
        </p>
      </div>
    </section>
  );
}
