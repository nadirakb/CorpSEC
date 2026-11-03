import type { Metadata } from "next";

import { t } from "@/lib/i18n";

export const metadata: Metadata = { title: "Terms · CorpSEC" };

// Plain-language draft (spec §10.4). Needs review by a lawyer before launch.
const RULES = [
  "Only check websites and domains you own, or that you have permission to check.",
  "Weekly monitoring and full details need proof that a site is yours.",
  "Don't use CorpSEC to find weaknesses in other people's sites.",
  "We may limit or block accounts that break these rules, and we keep a log of checks to spot abuse.",
  "CorpSEC gives advice, not a guarantee. A good grade does not mean a site can't be attacked.",
];

export default function TermsPage() {
  return (
    <div className="mx-auto max-w-3xl space-y-8 pt-6">
      <h1 className="font-display text-5xl font-semibold">Terms of use</h1>
      <p className="rounded-lg border border-rule bg-raised p-3 text-sm">{t.legal.draft}</p>
      <ol className="list-decimal space-y-3 pl-6 text-lg">{RULES.map((r) => <li key={r}>{r}</li>)}</ol>
    </div>
  );
}
