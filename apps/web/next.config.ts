import type { NextConfig } from "next";

// The browser talks to the API through this app (same origin, no CORS):
// /api/v1/... -> $CORPSEC_API_URL/v1/...
const apiUrl = process.env.CORPSEC_API_URL ?? "http://localhost:8000";

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  output: "standalone",
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiUrl}/:path*` }];
  },
};

export default nextConfig;
