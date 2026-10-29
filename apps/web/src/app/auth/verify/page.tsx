import type { Metadata } from "next";
import { Suspense } from "react";

import { VerifyLink } from "@/components/VerifyLink";

export const metadata: Metadata = { title: "Signing in · CorpSEC" };

export default function VerifyPage() {
  return (
    <div className="mx-auto max-w-md pt-10">
      <Suspense>
        <VerifyLink />
      </Suspense>
    </div>
  );
}
