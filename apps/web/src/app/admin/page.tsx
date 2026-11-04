import type { Metadata } from "next";
import { Suspense } from "react";

import { AdminDashboard } from "@/components/AdminDashboard";

export const metadata: Metadata = { title: "Dashboard · CorpSEC", robots: { index: false } };

export default function AdminPage() {
  return (
    <Suspense>
      <AdminDashboard />
    </Suspense>
  );
}
