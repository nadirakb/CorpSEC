import type { Metadata } from "next";
import { Suspense } from "react";

import { Dashboard } from "@/components/Dashboard";

export const metadata: Metadata = { title: "My sites · CorpSEC" };

export default function DashboardPage() {
  return (
    <Suspense>
      <Dashboard />
    </Suspense>
  );
}
