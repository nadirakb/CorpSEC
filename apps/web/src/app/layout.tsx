import type { Metadata } from "next";
import { Fraunces, Public_Sans } from "next/font/google";
import Link from "next/link";
import { Suspense } from "react";

import { AccountNav } from "@/components/AccountNav";
import { t } from "@/lib/i18n";

import "./globals.css";

const fraunces = Fraunces({
  subsets: ["latin"],
  variable: "--font-fraunces",
  axes: ["SOFT", "WONK", "opsz"],
});
const publicSans = Public_Sans({ subsets: ["latin"], variable: "--font-public-sans" });

export const metadata: Metadata = {
  title: t.meta.title,
  description: t.meta.description,
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className={`${fraunces.variable} ${publicSans.variable}`}>
      <body className="text-ink antialiased">
        <a
          href="#main"
          className="sr-only focus:not-sr-only focus:absolute focus:left-4 focus:top-4 focus:z-50 focus:rounded focus:bg-raised focus:px-4 focus:py-2"
        >
          {t.nav.skip}
        </a>
        <header className="mx-auto flex max-w-5xl items-center justify-between px-5 py-6 sm:px-8">
          <Link href="/" className="group flex items-baseline gap-2" aria-label={t.nav.home}>
            <span className="font-display text-2xl font-semibold tracking-tight">CorpSEC</span>
            <span className="hidden text-sm text-ink-soft lg:inline">{t.nav.tagline}</span>
          </Link>
          {/* reads the current path, so it streams in after the static shell */}
          <Suspense fallback={<span className="h-10" aria-hidden />}>
            <AccountNav />
          </Suspense>
        </header>
        <main id="main" className="mx-auto max-w-5xl px-5 pb-24 sm:px-8">
          {children}
        </main>
        <footer className="mx-auto max-w-5xl border-t border-rule px-5 py-8 text-sm text-ink-soft sm:px-8">
          <p>{t.footer.responsible}</p>
          <nav aria-label="Footer" className="mt-3 flex flex-wrap gap-x-6 gap-y-2 font-semibold">
            <Link href="/bot" className="underline-offset-4 hover:underline">{t.footer.links.bot}</Link>
            <Link href="/privacy" className="underline-offset-4 hover:underline">{t.footer.links.privacy}</Link>
            <Link href="/terms" className="underline-offset-4 hover:underline">{t.footer.links.terms}</Link>
          </nav>
        </footer>
      </body>
    </html>
  );
}
