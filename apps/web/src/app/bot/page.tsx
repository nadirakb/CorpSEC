import type { Metadata } from "next";

import { OptOutForm } from "@/components/OptOutForm";
import { t } from "@/lib/i18n";

export const metadata: Metadata = { title: "How CorpSEC checks websites · CorpSEC" };

export default function BotPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-10 pt-6">
      <header>
        <h1 className="font-display text-5xl font-semibold tracking-tight">{t.bot.title}</h1>
        <p className="mt-4 text-lg text-ink-soft">{t.bot.lede}</p>
      </header>
      {t.bot.sections.map((s) => (
        <section key={s.h}>
          <h2 className="font-display text-2xl font-semibold">{s.h}</h2>
          <ul className="mt-3 list-disc space-y-2 pl-6">
            {s.p.map((p) => <li key={p}>{p}</li>)}
          </ul>
        </section>
      ))}
      <section id="opt-out" className="rounded-2xl border border-rule bg-raised p-6 sm:p-8">
        <h2 className="font-display text-2xl font-semibold">{t.bot.optoutTitle}</h2>
        <p className="mt-2 mb-5 text-ink-soft">{t.bot.optoutLede}</p>
        <OptOutForm />
      </section>
    </div>
  );
}
