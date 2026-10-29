import type { Metadata } from "next";
import { Suspense } from "react";

import { ScanSkeleton, ScanView } from "@/components/ScanView";

export const metadata: Metadata = { title: "Your security report · CorpSEC" };

export default function ScanPage({ params }: { params: Promise<{ id: string }> }) {
  return (
    <Suspense fallback={<ScanSkeleton />}>
      <ScanView params={params} />
    </Suspense>
  );
}
