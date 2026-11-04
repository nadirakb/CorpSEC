"use client";

import { useRouter } from "next/navigation";
import { useEffect, useId, useState } from "react";

import { api, ApiError, type Me } from "@/lib/api";
import { t } from "@/lib/i18n";

export function AccountSettings() {
  const router = useRouter();
  const [me, setMe] = useState<Me | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [confirm, setConfirm] = useState("");
  const [deleting, setDeleting] = useState(false);
  const confirmId = useId();
  const digestId = useId();

  useEffect(() => {
    let active = true;
    api.me().then(
      (m) => active && setMe(m),
      (err) => {
        if (!active) return;
        if (err instanceof ApiError && err.status === 401) router.replace("/login?next=%2Faccount");
        else setError(err instanceof ApiError ? err.message : t.errors.generic);
      },
    );
    return () => {
      active = false;
    };
  }, [router]);

  if (!me) {
    return error ? <p role="alert" className="pt-6 font-medium text-[var(--sev-critical)]">{error}</p> : null;
  }

  const matches = confirm.trim().toLowerCase() === me.email.toLowerCase();

  return (
    <div className="max-w-2xl space-y-12 pt-6">
      <header className="rise">
        <h1 className="font-display text-5xl font-semibold tracking-tight">{t.accountPage.title}</h1>
        <p className="mt-3 text-lg text-ink-soft">{t.accountPage.signedInAs(me.email)}</p>
      </header>

      {error && <p role="alert" className="font-medium text-[var(--sev-critical)]">{error}</p>}

      <section aria-labelledby={`${digestId}-h`} className="space-y-3">
        <h2 id={`${digestId}-h`} className="font-display text-2xl font-semibold">{t.accountPage.digestTitle}</h2>
        <label htmlFor={digestId} className="flex items-start gap-3 text-lg">
          <input
            id={digestId}
            type="checkbox"
            className="mt-1.5 size-5 accent-[var(--accent)]"
            checked={me.weekly_digest}
            onChange={async (e) => {
              setSaved(false);
              setError(null);
              try {
                setMe(await api.updateMe({ weekly_digest: e.target.checked }));
                setSaved(true);
              } catch (err) {
                setError(err instanceof ApiError ? err.message : t.errors.generic);
              }
            }}
          />
          <span>{t.accountPage.digestLabel}</span>
        </label>
        <p className="text-ink-soft">{t.accountPage.digestHelp}</p>
        <p role="status" aria-live="polite" className="min-h-6 text-sm font-semibold">
          {saved ? t.accountPage.saved : ""}
        </p>
      </section>

      <section className="space-y-3">
        <h2 className="font-display text-2xl font-semibold">{t.accountPage.exportTitle}</h2>
        <p className="text-ink-soft">{t.accountPage.exportLede}</p>
        <a
          href={api.exportUrl}
          download="corpsec-account.json"
          className="inline-block rounded-lg border-2 border-rule px-5 py-3 font-semibold hover:border-ink-soft"
        >
          {t.accountPage.exportButton}
        </a>
      </section>

      <section className="space-y-3 rounded-xl border-2 border-[var(--sev-critical)] p-6">
        <h2 className="font-display text-2xl font-semibold">{t.accountPage.deleteTitle}</h2>
        <p className="text-ink-soft">{t.accountPage.deleteLede}</p>
        <form
          className="space-y-3"
          onSubmit={async (e) => {
            e.preventDefault();
            if (!matches) return;
            setDeleting(true);
            setError(null);
            try {
              await api.deleteAccount(confirm);
              router.push("/");
            } catch (err) {
              setDeleting(false);
              setError(err instanceof ApiError ? err.message : t.errors.generic);
            }
          }}
        >
          <label htmlFor={confirmId} className="block font-semibold">{t.accountPage.deleteLabel}</label>
          <input
            id={confirmId}
            type="email"
            autoComplete="off"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            className="w-full rounded-lg border-2 border-rule bg-raised px-4 py-3"
          />
          <button
            type="submit"
            disabled={!matches || deleting}
            className="rounded-lg bg-[var(--sev-critical)] px-5 py-3 font-semibold text-white disabled:opacity-40"
          >
            {deleting ? t.accountPage.deleting : t.accountPage.deleteButton}
          </button>
        </form>
      </section>
    </div>
  );
}
