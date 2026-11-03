import type { Metadata } from "next";
import { Suspense } from "react";

import { AccountSettings } from "@/components/AccountSettings";

export const metadata: Metadata = { title: "Your account · CorpSEC" };

export default function AccountPage() {
  return (
    <Suspense>
      <AccountSettings />
    </Suspense>
  );
}
