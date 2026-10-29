import type { Severity } from "@/lib/api";
import { t } from "@/lib/i18n";

// Each severity has its own icon shape, so it never relies on colour alone.
const ICONS: Record<Severity, React.ReactNode> = {
  critical: <path d="M12 3l9 16H3L12 3zm0 6v4m0 3v.5" />,
  high: <path d="M12 3a9 9 0 100 18 9 9 0 000-18zm0 5v5m0 3v.5" />,
  medium: <path d="M12 3l9 9-9 9-9-9 9-9zm0 5v5m0 3v.5" />,
  low: <path d="M12 3a9 9 0 100 18 9 9 0 000-18zm-4 9h8" />,
  info: <path d="M12 3a9 9 0 100 18 9 9 0 000-18zm0 8v5m0-8.5V8" />,
  pass: <path d="M12 3a9 9 0 100 18 9 9 0 000-18zm-4 9l3 3 5-6" />,
};

export function SeverityIcon({ severity, size = 18 }: { severity: Severity; size?: number }) {
  return (
    <svg
      aria-hidden
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.2"
      strokeLinecap="round"
      strokeLinejoin="round"
    >
      {ICONS[severity]}
    </svg>
  );
}

export function SeverityTag({ severity }: { severity: Severity }) {
  return (
    <span
      className="inline-flex items-center gap-1.5 rounded-full px-2.5 py-0.5 text-sm font-semibold whitespace-nowrap"
      style={{ color: `var(--sev-${severity})`, background: `var(--sev-${severity}-bg)` }}
    >
      <SeverityIcon severity={severity} size={16} />
      {t.severity[severity]}
    </span>
  );
}
