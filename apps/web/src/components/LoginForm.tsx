"use client";

import { useSearchParams } from "next/navigation";
import { useId, useState } from "react";

import { api, ApiError } from "@/lib/api";
import { t } from "@/lib/i18n";

export function LoginForm() {
  const params = useSearchParams();
  const next = params.get("next") ?? undefined;
  const inputId = useId();
  const [email, setEmail] = useState("");
  const [state, setState] = useState<"idle" | "sending" | "sent">("idle");
  const [error, setError] = useState<string | null>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setState("sending");
    setError(null);
    try {
      await api.requestLink(email.trim(), next);
      setState("sent");
    } catch (err) {
      setError(err instanceof ApiError && err.status === 422 ? "Please enter a valid email address." : t.errors.generic);
      setState("idle");
    }
  }

  if (state === "sent") {
    return (
      <div role="status" className="rise">
        <h1 className="font-display text-4xl font-semibold">{t.login.sentTitle}</h1>
        <p className="mt-4 text-lg text-ink-soft">{t.login.sent(email.trim())}</p>
        <button type="button" onClick={() => setState("idle")} className="mt-6 font-semibold text-accent underline">
          {t.login.tryAgain}
        </button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="rise">
      <h1 className="font-display text-4xl font-semibold">{t.login.title}</h1>
      <p className="mt-3 text-lg text-ink-soft">{t.login.lede}</p>
      <label htmlFor={inputId} className="mt-8 mb-2 block font-semibold">
        {t.login.label}
      </label>
      <input
        id={inputId}
        type="email"
        autoComplete="email"
        required
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        className="min-h-14 w-full rounded-xl border-2 border-rule bg-raised px-4 text-lg focus:border-accent focus:outline-none"
      />
      <button
        type="submit"
        disabled={state === "sending" || !email.trim()}
        className="mt-4 min-h-14 w-full rounded-xl bg-accent px-6 text-lg font-semibold text-accent-ink disabled:opacity-60"
      >
        {state === "sending" ? t.login.sending : t.login.submit}
      </button>
      <p role="alert" className="mt-3 min-h-6 font-medium text-[var(--sev-critical)]">
        {error}
      </p>
    </form>
  );
}
