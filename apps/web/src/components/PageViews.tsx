"use client";

import { usePathname } from "next/navigation";
import { useEffect } from "react";

import { track } from "@/lib/track";

/** Counts page views (by page kind; the API strips report ids). Renders nothing. */
export function PageViews() {
  const pathname = usePathname();
  useEffect(() => {
    track("page.view");
  }, [pathname]);
  return null;
}
