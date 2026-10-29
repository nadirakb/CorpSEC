"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { api, type Me } from "@/lib/api";
import { t } from "@/lib/i18n";

export function AccountNav() {
  const pathname = usePathname();
  const router = useRouter();
  const [me, setMe] = useState<Me | null | undefined>(undefined);

  useEffect(() => {
    let active = true;
    api.me().then(
      (m) => active && setMe(m),
      () => active && setMe(null),
    );
    return () => {
      active = false;
    };
  }, [pathname]); // refresh after signing in or out

  if (me === undefined) return <span className="h-10" aria-hidden />;
  if (me === null) {
    return (
      <Link href={`/login?next=${encodeURIComponent(pathname)}`} className={navBtn}>
        {t.account.signIn}
      </Link>
    );
  }
  return (
    <nav className="flex items-center gap-3" aria-label="Account">
      <span className="hidden text-sm text-ink-soft md:inline">{me.email}</span>
      <Link href="/dashboard" className={navBtn}>
        {t.account.dashboard}
      </Link>
      <button
        type="button"
        className="text-sm font-semibold text-ink-soft underline-offset-4 hover:underline"
        onClick={async () => {
          await api.logout().catch(() => undefined);
          setMe(null);
          router.push("/");
        }}
      >
        {t.account.signOut}
      </button>
    </nav>
  );
}

const navBtn = "rounded-lg border-2 border-rule px-4 py-2 text-sm font-semibold hover:border-ink-soft";
