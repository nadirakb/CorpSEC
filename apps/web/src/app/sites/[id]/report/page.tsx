import type { Metadata } from "next";
import { Suspense } from "react";

import { MonthlyReportView } from "@/components/MonthlyReport";

export const metadata: Metadata = { title: "Monthly report · CorpSEC" };

export default function MonthlyReportPage({ params }: { params: Promise<{ id: string }> }) {
  return (
    <Suspense>
      <MonthlyReportView params={params} />
    </Suspense>
  );
}
