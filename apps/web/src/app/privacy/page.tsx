import type { Metadata } from "next";

import { t } from "@/lib/i18n";

export const metadata: Metadata = { title: "Privacy · CorpSEC" };

// Plain-language draft (spec §10.4). Needs review by a lawyer before launch.
const SECTIONS = [
  ["What we store", [
    "Your email address, if you create an account.",
    "The sites you add, and the results of each check.",
    "For each check: the address it came from, kept for one year to stop abuse.",
    "Usage counts, like which pages are opened and how many checks run. We count visitors with a code that changes every day, so we can't follow you from one day to the next. No cookies, no addresses, no outside services. Kept 13 months.",
    "If you tell us a result looks wrong: your note and the technical details of that result.",
    "To show how a site compares with others, we keep each check's score with a code made from the site's name, never the name itself.",
  ]],
  ["How long we keep it", [
    "Checks made without an account: 7 days.",
    "Account data: until you delete your account or the site.",
  ]],
  ["What we don't do", [
    "We don't sell your data and don't use advertising trackers.",
    "If your browser asks sites not to track you (Global Privacy Control or Do Not Track), we don't count your visits at all.",
    "We never store full passwords or keys we find. We hide all but a few characters.",
  ]],
  ["Your rights", [
    "You can download a copy of your data or delete your account on the Account page, or write to privacy@corpsec.app.",
  ]],
] as const;

export default function PrivacyPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-8 pt-6">
      <h1 className="font-display text-5xl font-semibold">Privacy</h1>
      <p className="rounded-lg border border-rule bg-raised p-3 text-sm">{t.legal.draft}</p>
      {SECTIONS.map(([h, items]) => (
        <section key={h}>
          <h2 className="font-display text-2xl font-semibold">{h}</h2>
          <ul className="mt-3 list-disc space-y-2 pl-6">{items.map((i) => <li key={i}>{i}</li>)}</ul>
        </section>
      ))}
    </div>
  );
}
