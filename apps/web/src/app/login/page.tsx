import type { Metadata } from "next";
import { Suspense } from "react";

import { LoginForm } from "@/components/LoginForm";

export const metadata: Metadata = { title: "Sign in · CorpSEC" };

export default function LoginPage() {
  return (
    <div className="mx-auto max-w-md pt-10">
      <Suspense>
        <LoginForm />
      </Suspense>
    </div>
  );
}
