import type { NextConfig } from "next";

const H = process.env.BACKEND_HOST || "http://localhost";

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // Emit a self-contained server bundle (.next/standalone) for the production
  // container image. Gated behind NEXT_OUTPUT=standalone (set in the Docker build)
  // so local `next start` — used by the Playwright E2E webServer — keeps working
  // (`next start` is incompatible with standalone output).
  output: process.env.NEXT_OUTPUT === "standalone" ? "standalone" : undefined,
  async rewrites() {
    return [
      { source: "/api/auth/:path*", destination: `${H}:8081/v1/auth/:path*` },
      { source: "/api/users/:path*", destination: `${H}:8082/v1/users/:path*` },
      { source: "/api/assets/:path*", destination: `${H}:8083/v1/assets/:path*` },
      { source: "/api/alerts/:path*", destination: `${H}:8084/v1/alerts/:path*` },
      { source: "/api/alert-rules/:path*", destination: `${H}:8084/v1/alert-rules/:path*` },
      { source: "/api/dlm/:path*", destination: `${H}:8085/v1/dlm/:path*` },
      { source: "/api/clm/:path*", destination: `${H}:8086/v1/clm/:path*` },
      { source: "/api/dwm/:path*", destination: `${H}:8087/v1/dwm/:path*` },
      { source: "/api/brm/:path*", destination: `${H}:8088/v1/brm/:path*` },
      { source: "/api/phm/:path*", destination: `${H}:8089/v1/phm/:path*` },
      { source: "/api/investigations/:path*", destination: `${H}:8090/v1/investigations/:path*` },
      { source: "/api/notifications/:path*", destination: `${H}:8091/v1/notifications/:path*` },
      {
        source: "/api/notification-preferences/:path*",
        destination: `${H}:8091/v1/notification-preferences/:path*`,
      },
      { source: "/api/audit-logs/:path*", destination: `${H}:8092/v1/audit-logs/:path*` },
      { source: "/api/indicators/:path*", destination: `${H}:8093/v1/indicators/:path*` },
      { source: "/api/takedowns/:path*", destination: `${H}:8094/v1/takedowns/:path*` },
    ];
  },
};

export default nextConfig;
