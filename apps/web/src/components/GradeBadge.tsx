import { t } from "@/lib/i18n";
import { gradeTone } from "@/lib/report";

/** Small grade mark for lists. Letter is text, colour is extra. */
export function GradeBadge({ letter, size = "md" }: { letter: string | null; size?: "md" | "lg" }) {
  const dims = size === "lg" ? "size-20 text-4xl" : "size-14 text-2xl";
  if (!letter) {
    return (
      <span className={`font-display grid ${dims} shrink-0 place-items-center rounded-full border-2 border-dashed border-rule text-ink-soft`} aria-label="No grade yet">
        ?
      </span>
    );
  }
  return (
    <span
      className={`font-display grid ${dims} shrink-0 place-items-center rounded-full border-[3px] font-bold`}
      style={{ color: `var(--grade-${gradeTone(letter)})`, borderColor: "currentColor" }}
    >
      <span className="sr-only">{t.results.gradeLabel(letter)}: </span>
      {letter}
    </span>
  );
}
