"use client";

import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";

import { api, ApiError } from "@/lib/api";
import { t } from "@/lib/i18n";

export function VerifyLink() {
  const params = useSearchParams();
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const started = useRef(false);

  useEffect(() => {
    // Strict mode runs effects twice in development; the token only works once.
    if (started.current) return;
    started.current = true;
    const token = params.get("token") ?? "";
    const next = params.get("next") ?? "/dashboard";
    api.verifyLink(token).then(
      () => router.replace(next.startsWith("/") && !next.startsWith("//") ? next : "/dashboard"),
      (err) => setError(err instanceof ApiError ? err.message : t.errors.generic),
    );
  }, [params, router]);

  if (error) {
    return (
      <div role="alert">
        <h1 className="font-display text-4xl font-semibold">{t.login.failed}</h1>
        <p className="mt-4 text-lg text-ink-soft">{error}</p>
        <Link href="/login" className="mt-6 inline-block rounded-xl bg-accent px-6 py-3 font-semibold text-accent-ink">
          {t.login.newLink}
        </Link>
      </div>
    );
  }
  return (
    <p role="status" className="text-lg text-ink-soft">
      {t.login.verifying}
    </p>
  );
}
