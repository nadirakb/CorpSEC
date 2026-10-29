export function formatDate(iso: string | null, withTime = true): string {
  if (!iso) return "";
  return new Intl.DateTimeFormat(undefined, withTime ? { dateStyle: "medium", timeStyle: "short" } : { dateStyle: "medium" }).format(new Date(iso));
}
