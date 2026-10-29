import { ScanForm } from "@/components/ScanForm";
import { t } from "@/lib/i18n";

export default function Home() {
  return (
    <div className="grid gap-16 pt-6 sm:pt-14 lg:grid-cols-[1.25fr_1fr] lg:gap-20">
      <section className="rise" aria-labelledby="headline">
        <p className="mb-4 text-sm font-semibold uppercase tracking-[0.14em] text-accent">
          {t.landing.kicker}
        </p>
        <h1
          id="headline"
          className="font-display text-5xl leading-[1.02] font-semibold tracking-tight sm:text-7xl"
        >
          {t.landing.headline}
        </h1>
        <p className="mt-6 max-w-xl text-lg leading-relaxed text-ink-soft">{t.landing.lede}</p>
        <div className="mt-10">
          <ScanForm />
        </div>
        <p className="mt-5 flex items-center gap-2 text-sm text-ink-soft">
          <ShieldIcon />
          {t.landing.promise}
        </p>
      </section>

      <aside
        className="rise self-start rounded-2xl border border-rule bg-raised p-7 shadow-[0_1px_0_var(--rule),0_18px_40px_-28px_color-mix(in_srgb,var(--ink)_45%,transparent)]"
        style={{ animationDelay: "120ms" }}
        aria-labelledby="what-we-check"
      >
        <h2 id="what-we-check" className="font-display text-2xl font-semibold">
          {t.landing.what}
        </h2>
        <ol className="mt-5 space-y-4">
          {t.landing.areas.map((area, i) => (
            <li key={area.title} className="flex gap-4">
              <span
                aria-hidden
                className="font-display mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-full border border-rule text-sm font-semibold text-accent"
              >
                {i + 1}
              </span>
              <div>
                <p className="font-semibold">{area.title}</p>
                <p className="text-ink-soft">{area.text}</p>
              </div>
            </li>
          ))}
        </ol>
      </aside>
    </div>
  );
}

function ShieldIcon() {
  return (
    <svg aria-hidden width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </svg>
  );
}
