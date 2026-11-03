"use client";

import { useState } from "react";

import { t } from "@/lib/i18n";

export function CopyField({ label, value }: { label: string; value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <p className="mb-1 text-sm font-semibold">{label}</p>
      <div className="flex items-stretch gap-2">
        <code className="flex-1 overflow-x-auto rounded-lg border border-rule bg-paper px-3 py-2 font-mono text-sm break-all">
          {value}
        </code>
        <button
          type="button"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(value);
              setCopied(true);
              setTimeout(() => setCopied(false), 2000);
            } catch {
              /* clipboard blocked: the value can still be selected */
            }
          }}
          className="rounded-lg border-2 border-rule px-3 text-sm font-semibold hover:border-ink-soft"
        >
          <span aria-live="polite">{copied ? t.verify.copied : t.verify.copy}</span>
        </button>
      </div>
    </div>
  );
}
