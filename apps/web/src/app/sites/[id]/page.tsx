import type { Metadata } from "next";
import { Suspense } from "react";

import { ScanSkeleton } from "@/components/ScanView";
import { SiteView } from "@/components/SiteView";

export const metadata: Metadata = { title: "Site · CorpSEC" };

export default function SitePage({ params }: { params: Promise<{ id: string }> }) {
  return (
    <Suspense fallback={<ScanSkeleton />}>
      <SiteView params={params} />
    </Suspense>
  );
}
