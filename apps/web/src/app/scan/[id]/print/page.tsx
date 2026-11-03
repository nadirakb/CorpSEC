import type { Metadata } from "next";
import { Suspense } from "react";

import { PrintReport } from "@/components/PrintReport";

export const metadata: Metadata = { title: "Security report (print) · CorpSEC" };

export default function PrintPage({ params }: { params: Promise<{ id: string }> }) {
  return (
    <Suspense>
      <PrintReport params={params} />
    </Suspense>
  );
}
