import { t } from "@/lib/i18n";
import { gradeTone } from "@/lib/report";

/** The grade as an inspection stamp. Letter + word + score: never colour alone. */
export function GradeSeal({ letter, score }: { letter: string; score: number | null }) {
  const tone = `var(--grade-${gradeTone(letter)})`;
  const word = t.results.gradeWords[letter] ?? "";
  return (
    <div
      role="img"
      aria-label={`${t.results.gradeLabel(letter)}: ${word}${score !== null ? `, ${t.results.scoreOutOf(score)}` : ""}`}
      className="stamp relative grid size-44 shrink-0 place-items-center sm:size-52"
      style={{ color: tone }}
    >
      <svg viewBox="0 0 200 200" className="absolute inset-0" aria-hidden>
        <defs>
          <path id="seal-top" d="M 30 100 A 70 70 0 0 1 170 100" />
          <path id="seal-bottom" d="M 22 100 A 78 78 0 0 0 178 100" />
        </defs>
        <circle cx="100" cy="100" r="94" fill="none" stroke="currentColor" strokeWidth="3" />
        <circle cx="100" cy="100" r="86" fill="none" stroke="currentColor" strokeWidth="1.2" strokeDasharray="2 4" />
        <circle cx="100" cy="100" r="62" fill="none" stroke="currentColor" strokeWidth="1.5" />
        <text fontSize="13" fontWeight="700" letterSpacing="4" fill="currentColor">
          <textPath href="#seal-top" startOffset="50%" textAnchor="middle">
            CORPSEC · SECURITY
          </textPath>
        </text>
        <text fontSize="13" fontWeight="700" letterSpacing="3" fill="currentColor">
          <textPath href="#seal-bottom" startOffset="50%" textAnchor="middle">
            {word.toUpperCase()}
          </textPath>
        </text>
      </svg>
      <div className="relative text-center leading-none">
        <span className="font-display block text-7xl font-bold sm:text-8xl">{letter}</span>
        {score !== null && (
          <span className="mt-1 block text-sm font-semibold tracking-wide">{score}/100</span>
        )}
      </div>
    </div>
  );
}
